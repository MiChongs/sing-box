package pseudovpn

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

// 协议物理帧命令字与控制报文类型常量
const (
	FrameCommandPseudoVPN byte = 0x20

	PacketTypeIPRequest  byte = 0x01
	PacketTypeIPResponse byte = 0x02
	PacketTypeIPExpired  byte = 0x03
)

const (
	DefaultMTU uint32 = 1400
	MinMTU     uint32 = 576
	// MinIPv6MTU 是 IPv6 要求的最小链路 MTU（RFC 8200）。
	MinIPv6MTU uint32 = 1280
	// MaxMTU 受 AnyX 帧载荷上限 65535 约束，并扣除上行帧的 8 字节 ClientID 前缀。
	MaxMTU uint32 = 65535 - 8
)

// NormalizeMTU 把 MTU 约束到隧道可承载的范围，0 取默认值。
func NormalizeMTU(mtu uint32) uint32 {
	switch {
	case mtu == 0:
		return DefaultMTU
	case mtu < MinMTU:
		return MinMTU
	case mtu > MaxMTU:
		return MaxMTU
	default:
		return mtu
	}
}

type UDPMode string

const (
	UDPModeDrop        UDPMode = "drop"
	UDPModeReject      UDPMode = "reject"
	UDPModeTransparent UDPMode = "transparent"
)

// ValidateUDPMode 校验配置中的 UDP 策略，空值表示默认的 drop。
func ValidateUDPMode(s string) error {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(UDPModeDrop), string(UDPModeReject), string(UDPModeTransparent):
		return nil
	default:
		return E.New("pseudovpn: unknown udp mode: ", s, ", expected drop, reject or transparent")
	}
}

func ParseUDPMode(s string) UDPMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(UDPModeReject):
		return UDPModeReject
	case string(UDPModeTransparent):
		return UDPModeTransparent
	default:
		return UDPModeDrop
	}
}

// isUplinkControlPacket 判断客户端上行帧是否为控制报文。上行只有 IPRequest 一种控制报文，
// 数据帧以 8 字节 ClientID 开头：若沿用双向判定，ClientID 首字节恰为 0x02 的客户端，其所有
// 不短于 75 字节的数据帧都会被当成 IPResponse 丢弃。
func isUplinkControlPacket(packet []byte) bool {
	return len(packet) > 0 && packet[0] == PacketTypeIPRequest && isControlPacket(packet)
}

func isControlPacket(packet []byte) bool {
	if len(packet) < 18 {
		return false
	}
	switch packet[0] {
	case PacketTypeIPRequest:
		// 若前置 8 字节为 ClientID，后续载荷若符合标准 IPv4/IPv6 报头与长度则为上行数据包
		if len(packet) >= 8+header.IPv4MinimumSize {
			v := packet[8] >> 4
			if v == 4 {
				ipTotalLen := int(binary.BigEndian.Uint16(packet[10:12]))
				if ipTotalLen >= header.IPv4MinimumSize && ipTotalLen+8 <= len(packet) {
					return false
				}
			} else if v == 6 {
				if len(packet) >= 8+header.IPv6MinimumSize {
					ipPayloadLen := int(binary.BigEndian.Uint16(packet[12:14]))
					if ipPayloadLen+header.IPv6MinimumSize+8 <= len(packet) {
						return false
					}
				}
			}
		}
		return len(packet) == 52
	case PacketTypeIPResponse:
		return len(packet) >= 75
	case PacketTypeIPExpired:
		return len(packet) == 18
	default:
		return false
	}
}

// isRoutableUnicast 校验目标 IP 是否为 PseudoVPN 三层隧道可承载的单播地址。
// 严格阻断组播、广播、未指定地址与回环地址在隧道流出。
func isRoutableUnicast(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() {
		return false
	}
	if ip.Is4() {
		b4 := ip.As4()
		if b4 == [4]byte{255, 255, 255, 255} || b4[0] == 0 {
			return false
		}
	} else if ip.Is6() {
		if ip.IsLinkLocalMulticast() {
			return false
		}
	}
	return true
}

// Tracer 负责追踪并记录 PseudoVPN 数据报与连接转发全周期的 Trace 日志。
type Tracer struct {
	role   string
	logger logger.ContextLogger
}

func NewTracer(role string, logger logger.ContextLogger) *Tracer {
	return &Tracer{
		role:   role,
		logger: logger,
	}
}

func (t *Tracer) Trace(args ...any) {
	if t != nil && t.logger != nil {
		t.logger.Trace(args...)
	}
}

// Session 定义 AnyX 物理会话向外部上层载荷暴露的核心通道接口。
// WriteFramePacket 返回后不得再引用 packet。写失败时若会话仍未关闭（例如抢写锁超时），
// 调用方只应丢弃该报文，不能关闭会话：会话上可能还承载着其他代理流。
type Session interface {
	WriteFramePacket(cmd byte, packet []byte) error
	Close() error
	IsClosed() bool
}

// BatchSession 是可选的批量写接口：一次加锁、一次写出多帧，每帧载荷为 prefix+packet。
type BatchSession interface {
	WriteFramePackets(cmd byte, prefix []byte, packets [][]byte) error
}

// generateClientID 生成首字节不落在控制报文类型区间（0x01-0x03）的 ClientID，
// 使数据帧与控制帧在不认识本修复的旧服务端上也不会混淆。
func generateClientID() uint64 {
	for {
		id := generateToken()
		if first := byte(id >> 56); first < PacketTypeIPRequest || first > PacketTypeIPExpired {
			return id
		}
	}
}

var (
	errNegotiationRejected = errors.New("pseudovpn: server rejected IP negotiation")
	errNegotiationFailed   = errors.New("pseudovpn: IP negotiation failed")
)

// negotiation 是一次在途的 IP 协商，并发的 Initialize 调用共享同一次结果。
type negotiation struct {
	done chan struct{}
	once sync.Once
	err  error
}

func newNegotiation() *negotiation {
	return &negotiation{done: make(chan struct{})}
}

func (n *negotiation) finish(err error) {
	n.once.Do(func() {
		n.err = err
		close(n.done)
	})
}

const (
	sessionDialTimeout    = 2 * time.Second
	sessionDialMinBackoff = 500 * time.Millisecond
	sessionDialMaxBackoff = 30 * time.Second
)

type returnPathState struct {
	returnPath tun.Return
	headroom   int
}

// ClientEngineOptions 客户端 PseudoVPN 引擎配置。
type ClientEngineOptions struct {
	Enabled        bool
	MTU            uint32
	TCPMSSClamping *bool
	UDP            string
	GetSession     func(ctx context.Context) (Session, error)
	Logger         logger.ContextLogger
}

// ClientEngine 负责客户端单 TUN 直通、双栈 IP 固化协商与无状态双向报文收发。
type ClientEngine struct {
	ctx            context.Context
	cancel         context.CancelFunc
	enabled        bool
	logger         logger.ContextLogger
	tracer         *Tracer
	configuredMTU  uint32
	mtu            atomic.Uint32
	clientID       atomic.Uint64
	leaseToken     atomic.Uint64
	tcpMSSClamping bool
	udpMode        UDPMode
	assignedIPv4   atomic.Pointer[netip.Addr]
	assignedIPv6   atomic.Pointer[netip.Addr]
	lastIPv4       atomic.Pointer[netip.Addr]
	lastIPv6       atomic.Pointer[netip.Addr]
	serverIPv4     atomic.Pointer[netip.Addr]
	serverIPv6     atomic.Pointer[netip.Addr]
	negotiated     atomic.Bool
	getSession     func(ctx context.Context) (Session, error)
	currentSession atomic.Pointer[Session]
	returnState    atomic.Pointer[returnPathState]

	lastAttemptTime atomic.Int64 // Unix (秒) 协商重试节流时间戳
	negotiation     atomic.Pointer[negotiation]

	// 物理会话重建：单飞 + 指数退避，避免服务端不可达时每批数据报都同步阻塞拨号。
	dialAccess    sync.Mutex
	dialNotBefore atomic.Int64 // UnixNano
	dialFailures  atomic.Int32
}

// NewClientEngine 创建客户端引擎实例。
func NewClientEngine(options ClientEngineOptions) *ClientEngine {
	mtu := NormalizeMTU(options.MTU)
	tcpMSSClamping := true
	if options.TCPMSSClamping != nil {
		tcpMSSClamping = *options.TCPMSSClamping
	}
	cid := generateClientID()

	ctx, cancel := context.WithCancel(context.Background())
	engine := &ClientEngine{
		ctx:            ctx,
		cancel:         cancel,
		configuredMTU:  mtu,
		enabled:        options.Enabled,
		logger:         options.Logger,
		tracer:         NewTracer("client", options.Logger),
		getSession:     options.GetSession,
		tcpMSSClamping: tcpMSSClamping,
		udpMode:        ParseUDPMode(options.UDP),
	}
	engine.mtu.Store(mtu)
	engine.clientID.Store(cid)

	return engine
}

func (e *ClientEngine) CurrentSession() Session {
	p := e.currentSession.Load()
	if p == nil {
		return nil
	}
	return *p
}

func (e *ClientEngine) SetCurrentSession(s Session) {
	if s == nil {
		e.currentSession.Store(nil)
	} else {
		e.currentSession.Store(&s)
	}
}

func (e *ClientEngine) UDPMode() UDPMode {
	return e.udpMode
}

func (e *ClientEngine) PreMatchAction(network string) adapter.PreMatchAction {
	if !e.enabled {
		return adapter.PreMatchContinue
	}
	if strings.EqualFold(network, "udp") {
		switch e.udpMode {
		case UDPModeDrop:
			return adapter.PreMatchDrop
		case UDPModeReject:
			return adapter.PreMatchReject
		default:
			return adapter.PreMatchContinue
		}
	}
	return adapter.PreMatchFlow
}

func (e *ClientEngine) PreMatchFlow(network string) bool {
	return e.PreMatchAction(network) == adapter.PreMatchFlow
}

func (e *ClientEngine) Close() error {
	e.cancel()
	if current := e.negotiation.Load(); current != nil {
		current.finish(net.ErrClosed)
	}
	e.Reset()
	return nil
}

func (e *ClientEngine) Enabled() bool {
	return e.enabled
}

func (e *ClientEngine) ClientID() uint64 {
	return e.clientID.Load()
}

func (e *ClientEngine) SetClientID(id uint64) {
	e.clientID.Store(id)
}

func (e *ClientEngine) LeaseToken() uint64 {
	return e.leaseToken.Load()
}

func (e *ClientEngine) SetLeaseToken(token uint64) {
	e.leaseToken.Store(token)
}

func (e *ClientEngine) IsReady() bool {
	if !e.enabled || !e.negotiated.Load() {
		return false
	}
	return e.AssignedIPv4().IsValid() || e.AssignedIPv6().IsValid()
}

func (e *ClientEngine) AssignedIPv4() netip.Addr {
	p := e.assignedIPv4.Load()
	if p == nil {
		return netip.Addr{}
	}
	return *p
}

func (e *ClientEngine) AssignedIPv6() netip.Addr {
	p := e.assignedIPv6.Load()
	if p == nil {
		return netip.Addr{}
	}
	return *p
}

func (e *ClientEngine) ServerIPv4() netip.Addr {
	p := e.serverIPv4.Load()
	if p == nil {
		return netip.Addr{}
	}
	return *p
}

func (e *ClientEngine) ServerIPv6() netip.Addr {
	p := e.serverIPv6.Load()
	if p == nil {
		return netip.Addr{}
	}
	return *p
}

// LocalIPv4 / LocalIPv6 返回本地端口地址：TUN 转发器把流的源地址改写为它们，引擎再与虚拟地址互转。
func (e *ClientEngine) LocalIPv4() netip.Addr {
	return LocalPortIPv4
}

func (e *ClientEngine) LocalIPv6() netip.Addr {
	return LocalPortIPv6
}

func (e *ClientEngine) MTU() uint32 {
	m := e.mtu.Load()
	if m == 0 {
		return DefaultMTU
	}
	return m
}

func (e *ClientEngine) SetSessionProvider(provider func(ctx context.Context) (Session, error)) {
	e.getSession = provider
}

// Reset 清空客户端运行时映射，但持久保留 ClientID 与历史分配 IP 供无感漫游恢复。
func (e *ClientEngine) Reset() {
	e.negotiated.Store(false)
	e.assignedIPv4.Store(nil)
	e.assignedIPv6.Store(nil)
	e.serverIPv4.Store(nil)
	e.serverIPv6.Store(nil)
	e.SetCurrentSession(nil)
}

// Start 在客户端启动阶段触发后台异步建连协商。
func (e *ClientEngine) Start() {
	if e.enabled && !e.IsReady() {
		go func() {
			ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
			defer cancel()
			err := e.Initialize(ctx)
			if err != nil && !E.IsClosedOrCanceled(err) {
				if e.logger != nil {
					e.logger.Debug("pseudovpn client: background IP negotiation deferred: ", err)
				}
			}
		}()
	}
}

// OnInterfaceUpdated 感知底层网络环境漫游变化，原子脱落失效会话，重建由数据面同步接管。
func (e *ClientEngine) OnInterfaceUpdated() {
	if !e.enabled {
		return
	}
	e.SetCurrentSession(nil)
}

// OnNegotiatedDualStack 固化双栈协商结果。
func (e *ClientEngine) OnNegotiatedDualStack(v4, sV4, v6, sV6 netip.Addr, mtu uint32) {
	// 本次未授予的地址族必须清空：重协商后服务端可能只给单栈，残留的旧地址会让该族
	// 数据报带着失效源地址上行，触发无休止的 IPExpired。
	storeAddr(&e.assignedIPv4, v4)
	storeAddr(&e.serverIPv4, sV4)
	storeAddr(&e.assignedIPv6, v6)
	storeAddr(&e.serverIPv6, sV6)
	if v4.IsValid() {
		e.lastIPv4.Store(&v4)
	}
	if v6.IsValid() {
		e.lastIPv6.Store(&v6)
	}
	// 隧道 MTU 取本端配置与服务端通告的较小值。
	effectiveMTU := e.configuredMTU
	if effectiveMTU == 0 {
		effectiveMTU = DefaultMTU
	}
	if mtu > 0 {
		effectiveMTU = min(effectiveMTU, NormalizeMTU(mtu))
	}
	e.mtu.Store(effectiveMTU)
	e.negotiated.Store(true)

	if e.logger != nil {
		e.logger.Info("pseudovpn: solidified virtual dual-stack IPv4=", v4, " (gw ", sV4, "), IPv6=", v6, " (gw ", sV6, "), mtu ", e.MTU())
	}
}

func storeAddr(target *atomic.Pointer[netip.Addr], addr netip.Addr) {
	if addr.IsValid() {
		target.Store(&addr)
	} else {
		target.Store(nil)
	}
}

// OnNegotiated 兼容单栈调用入口。
func (e *ClientEngine) OnNegotiated(assignedIP, serverIP netip.Addr, mtu uint32) {
	if assignedIP.Is4() {
		e.OnNegotiatedDualStack(assignedIP, serverIP, netip.Addr{}, netip.Addr{}, mtu)
	} else if assignedIP.Is6() {
		e.OnNegotiatedDualStack(netip.Addr{}, netip.Addr{}, assignedIP, serverIP, mtu)
	} else {
		e.OnNegotiatedDualStack(netip.Addr{}, netip.Addr{}, netip.Addr{}, netip.Addr{}, mtu)
	}
}

// Initialize 在客户端初始化或虚拟 IP 彻底失效时主动发起双栈协商。
// 并发调用共享同一次在途协商；服务端拒绝时立即返回错误而不是等到超时。
func (e *ClientEngine) Initialize(ctx context.Context) error {
	if !e.enabled {
		return nil
	}
	// 核心准则：只要当前持有的三层 IP 依然有效，严禁发起控制面重协商
	if e.IsReady() {
		return nil
	}
	if e.getSession == nil {
		return errors.New("pseudovpn: session provider not set")
	}

	var current *negotiation
	for {
		if inflight := e.negotiation.Load(); inflight != nil {
			select {
			case <-inflight.done:
				if inflight.err != nil {
					return inflight.err
				}
				if e.IsReady() {
					return nil
				}
				return errNegotiationFailed
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		current = newNegotiation()
		if e.negotiation.CompareAndSwap(nil, current) {
			break
		}
	}
	defer func() {
		current.finish(errNegotiationFailed)
		e.negotiation.CompareAndSwap(current, nil)
	}()
	e.lastAttemptTime.Store(time.Now().Unix())

	session, err := e.getSession(ctx)
	if err != nil {
		e.tracer.Trace("pseudovpn [client]: get session failed during init: ", err)
		current.finish(err)
		return err
	}
	if session == nil || session.IsClosed() {
		e.tracer.Trace("pseudovpn [client]: session is closed or nil during init")
		current.finish(net.ErrClosed)
		return net.ErrClosed
	}
	e.SetCurrentSession(session)

	req := make([]byte, 52)
	req[0] = PacketTypeIPRequest
	req[1] = 0x03 // 期望双栈同时协商 (0x01 | 0x02)

	oldV4 := e.AssignedIPv4()
	if !oldV4.IsValid() {
		if p := e.lastIPv4.Load(); p != nil {
			oldV4 = *p
		}
	}
	if oldV4.IsValid() {
		b16 := oldV4.As16()
		copy(req[2:18], b16[:])
	}

	oldV6 := e.AssignedIPv6()
	if !oldV6.IsValid() {
		if p := e.lastIPv6.Load(); p != nil {
			oldV6 = *p
		}
	}
	if oldV6.IsValid() {
		b16 := oldV6.As16()
		copy(req[18:34], b16[:])
	}

	binary.BigEndian.PutUint16(req[34:36], 2)
	binary.BigEndian.PutUint64(req[36:44], e.ClientID())
	binary.BigEndian.PutUint64(req[44:52], e.LeaseToken())

	e.tracer.Trace("pseudovpn [client]: sending dual-stack IP negotiation request, req_len=", len(req))
	err = session.WriteFramePacket(FrameCommandPseudoVPN, req)
	if err != nil {
		e.tracer.Trace("pseudovpn [client]: write IP negotiation request error: ", err)
		if session.IsClosed() {
			e.clearSession(session)
		}
		current.finish(err)
		return err
	}

	select {
	case <-current.done:
		if current.err != nil {
			return current.err
		}
		if !e.IsReady() {
			return errNegotiationFailed
		}
	case <-ctx.Done():
		e.tracer.Trace("pseudovpn [client]: in-band IP negotiation canceled: ", ctx.Err())
		current.finish(ctx.Err())
		return ctx.Err()
	case <-e.ctx.Done():
		current.finish(net.ErrClosed)
		return net.ErrClosed
	}
	e.tracer.Trace("pseudovpn [client]: in-band IP negotiation completed successfully")
	return nil
}

// isNegotiating 报告是否有在途协商。
func (e *ClientEngine) isNegotiating() bool {
	return e.negotiation.Load() != nil
}

// resolveNegotiation 以服务端应答结束在途协商。
func (e *ClientEngine) resolveNegotiation(err error) {
	if current := e.negotiation.Load(); current != nil {
		current.finish(err)
	}
}

// clearSession 仅当当前会话仍是 session 时清除，避免覆盖并发建立的新会话。
func (e *ClientEngine) clearSession(session Session) {
	current := e.currentSession.Load()
	if current != nil && *current == session {
		e.currentSession.CompareAndSwap(current, nil)
	}
}

// renegotiateAsync 在后台重新协商，绑定引擎生命周期。
func (e *ClientEngine) renegotiateAsync(timeout time.Duration) {
	go func() {
		ctx, cancel := context.WithTimeout(e.ctx, timeout)
		defer cancel()
		_ = e.Initialize(ctx)
	}()
}

// HandleDownlink 处理从物理会话接收到的下行报文或控制应答。
func (e *ClientEngine) HandleDownlink(packet []byte) {
	if len(packet) == 0 {
		return
	}

	if isControlPacket(packet) {
		e.tracer.Trace("pseudovpn [client]: unpacked control packet: type=", packet[0], ", len=", len(packet))
		switch packet[0] {
		case PacketTypeIPResponse:
			if len(packet) >= 75 {
				status := packet[1]
				if status == 0 {
					flags := packet[2]
					var v4, sV4, v6, sV6 netip.Addr
					if (flags & 0x01) != 0 {
						v4 = netip.AddrFrom16([16]byte(packet[3:19])).Unmap()
						sV4 = netip.AddrFrom16([16]byte(packet[19:35])).Unmap()
					}
					if (flags & 0x02) != 0 {
						v6 = netip.AddrFrom16([16]byte(packet[35:51])).Unmap()
						sV6 = netip.AddrFrom16([16]byte(packet[51:67])).Unmap()
					}

					// 防抖检查：若下发 IP 与当前已持有的 IP 完全一致且已就绪，跳过全量固化与日志刷新
					if e.IsReady() && e.AssignedIPv4() == v4 && e.AssignedIPv6() == v6 {
						if len(packet) >= 83 {
							token := binary.BigEndian.Uint64(packet[75:83])
							e.leaseToken.Store(token)
						}
						e.resolveNegotiation(nil)
						return
					}

					mtu := binary.BigEndian.Uint32(packet[67:71])
					if len(packet) >= 83 {
						token := binary.BigEndian.Uint64(packet[75:83])
						e.leaseToken.Store(token)
					}

					if !v4.IsValid() && !v6.IsValid() {
						e.tracer.Trace("pseudovpn [client]: server granted no address")
						e.negotiated.Store(false)
						e.resolveNegotiation(errNegotiationRejected)
						return
					}
					e.OnNegotiatedDualStack(v4, sV4, v6, sV6, mtu)
					e.resolveNegotiation(nil)
					e.tracer.Trace("pseudovpn [client]: granted dual-stack v4=", v4, ", v6=", v6, ", mtu=", mtu)
				} else {
					e.tracer.Trace("pseudovpn [client]: server rejected IP negotiation: status=", status)
					e.negotiated.Store(false)
					e.resolveNegotiation(errNegotiationRejected)
				}
			}
		case PacketTypeIPExpired:
			var expiredIP netip.Addr
			if len(packet) >= 18 {
				var ipBytes [16]byte
				copy(ipBytes[:], packet[2:18])
				expiredIP = netip.AddrFrom16(ipBytes).Unmap()
			}
			e.tracer.Trace("pseudovpn [client]: received IPExpired NACK from server for IP ", expiredIP)

			v4 := e.AssignedIPv4()
			v6 := e.AssignedIPv6()
			// 服务端对每个失效报文都会回 NACK：只有第一次把就绪态翻转为未就绪的 NACK 触发重协商，
			// 否则一阵突发流量会派生成百上千个协商协程。
			if expiredIP.IsValid() && ((v4.IsValid() && expiredIP == v4) || (v6.IsValid() && expiredIP == v6)) &&
				e.negotiated.CompareAndSwap(true, false) {
				if e.logger != nil {
					e.logger.Info("pseudovpn: lease of ", expiredIP, " expired on server, renegotiating")
				}
				e.renegotiateAsync(5 * time.Second)
			}
		}
		return
	}

	// 下行 1:1 NAT：虚拟地址 → 本地端口地址。不是发给当前虚拟地址的报文（换址前的残留、
	// 伪造报文）直接丢弃，不能交给转发器。
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		assigned := e.AssignedIPv4()
		if !assigned.IsValid() || PacketDestinationIP(packet) != assigned {
			e.tracer.Trace("pseudovpn [client]: dropped downlink packet not addressed to ", assigned)
			return
		}
		rewritePacketDstIPv4(packet, LocalPortIPv4)
	case header.IPv6Version:
		assigned := e.AssignedIPv6()
		if !assigned.IsValid() || PacketDestinationIP(packet) != assigned {
			e.tracer.Trace("pseudovpn [client]: dropped downlink packet not addressed to ", assigned)
			return
		}
		rewritePacketDstIPv6(packet, LocalPortIPv6)
	default:
		return
	}

	if e.tcpMSSClamping {
		clampTCPMSS(packet, e.MTU())
	}

	state := e.returnState.Load()
	if state == nil {
		e.tracer.Trace("pseudovpn [client]: dropped downlink packet (no return path attached)")
		return
	}

	// ReturnPackets 同步写回 TUN，返回后不再引用缓冲区，因此带头部预留时用池化缓冲。
	if state.headroom > 0 {
		buffer := buf.NewSize(state.headroom + len(packet))
		buffer.Extend(state.headroom)
		common.Must1(buffer.Write(packet))
		_ = state.returnPath.ReturnPackets([][]byte{buffer.Bytes()})
		buffer.Release()
	} else {
		_ = state.returnPath.ReturnPackets([][]byte{packet})
	}
}

func (e *ClientEngine) rejectPacket(packet []byte) {
	state := e.returnState.Load()
	if state == nil {
		return
	}
	dstIP := PacketDestinationIP(packet)
	if !dstIP.IsValid() {
		return
	}
	reply, ok := tun.BuildICMPError(packet, tun.ICMPErrorPortUnreachable, dstIP, 0, state.headroom)
	if ok {
		_ = state.returnPath.ReturnPackets([][]byte{reply})
	}
}

// writeUplinkPacketsWithSession 通过物理会话发送数据报并应用双栈 1:1 NAT 与 TCP MSS 钳制。
func (e *ClientEngine) writeUplinkPacketsWithSession(session Session, packets [][]byte) error {
	if !e.enabled || session == nil || session.IsClosed() {
		return nil
	}

	assignedV4 := e.AssignedIPv4()
	assignedV6 := e.AssignedIPv6()
	mtu := e.MTU()
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], e.ClientID())

	outgoing := make([][]byte, 0, len(packets))
	for _, packet := range packets {
		if len(packet) == 0 {
			continue
		}

		// 上行 1:1 NAT：本地端口地址 → 当前虚拟地址。其他源地址会被服务端 RPF 拒绝并回 NACK，
		// 在本地直接丢弃，免得触发无谓的重协商。
		switch header.IPVersion(packet) {
		case header.IPv4Version:
			if !assignedV4.IsValid() {
				continue
			}
			switch PacketSourceIP(packet) {
			case LocalPortIPv4:
				rewritePacketSrcIPv4(packet, assignedV4)
			case assignedV4:
			default:
				continue
			}
		case header.IPv6Version:
			if !assignedV6.IsValid() {
				continue
			}
			switch PacketSourceIP(packet) {
			case LocalPortIPv6:
				rewritePacketSrcIPv6(packet, assignedV6)
			case assignedV6:
			default:
				continue
			}
		default:
			continue
		}

		if e.tcpMSSClamping {
			clampTCPMSS(packet, mtu)
		}
		outgoing = append(outgoing, packet)
	}
	if len(outgoing) == 0 {
		return nil
	}

	err := writeFramedPackets(session, prefix[:], outgoing)
	if err != nil {
		// 会话已因写错误关闭则换会话重建；仍存活（如抢写锁超时）只丢弃本批，
		// 不能关闭一条可能还承载着其他代理流的复用会话。
		e.tracer.Trace("pseudovpn [client]: session write failed: ", err)
		if session.IsClosed() {
			e.clearSession(session)
		}
	}
	return nil
}

// writeFramedPackets 以 prefix+packet 为载荷批量写帧，优先走会话的批量写接口。
func writeFramedPackets(session Session, prefix []byte, packets [][]byte) error {
	if batch, isBatch := session.(BatchSession); isBatch {
		return batch.WriteFramePackets(FrameCommandPseudoVPN, prefix, packets)
	}
	for _, packet := range packets {
		buffer := buf.NewSize(len(prefix) + len(packet))
		common.Must1(buffer.Write(prefix))
		common.Must1(buffer.Write(packet))
		err := session.WriteFramePacket(FrameCommandPseudoVPN, buffer.Bytes())
		buffer.Release()
		if err != nil {
			return err
		}
	}
	return nil
}

// acquireSession 在物理会话失效时重建：单飞，失败后指数退避，期间直接丢包而不阻塞 TUN 写路径。
func (e *ClientEngine) acquireSession() Session {
	if e.getSession == nil {
		return nil
	}
	if notBefore := e.dialNotBefore.Load(); notBefore != 0 && time.Now().UnixNano() < notBefore {
		return nil
	}
	if !e.dialAccess.TryLock() {
		return nil
	}
	defer e.dialAccess.Unlock()
	if session := e.CurrentSession(); session != nil && !session.IsClosed() {
		return session
	}
	ctx, cancel := context.WithTimeout(e.ctx, sessionDialTimeout)
	session, err := e.getSession(ctx)
	cancel()
	if err != nil || session == nil || session.IsClosed() {
		failures := e.dialFailures.Add(1)
		backoff := sessionDialMinBackoff << min(failures-1, 6)
		if backoff > sessionDialMaxBackoff {
			backoff = sessionDialMaxBackoff
		}
		e.dialNotBefore.Store(time.Now().Add(backoff).UnixNano())
		if e.logger != nil && err != nil && !E.IsClosedOrCanceled(err) {
			e.logger.Debug("pseudovpn client: re-establish session failed, retry after ", backoff, ": ", err)
		}
		return nil
	}
	e.dialFailures.Store(0)
	e.dialNotBefore.Store(0)
	e.SetCurrentSession(session)
	return session
}

// WriteUplinkPackets 批量处理上行数据报，实现单栈独立 Fail-Closed 阻断与非单播报文就地静默丢弃。
func (e *ClientEngine) WriteUplinkPackets(packets [][]byte) error {
	if !e.enabled {
		return nil
	}

	isReady := e.IsReady()
	hasV4 := e.AssignedIPv4().IsValid()
	hasV6 := e.AssignedIPv6().IsValid()

	validPackets := make([][]byte, 0, len(packets))
	for _, packet := range packets {
		if len(packet) == 0 {
			continue
		}

		v := header.IPVersion(packet)

		// 1. UDP 顶层硬过滤：不经物理信道、不参与重连，本地处理完毕直接跳过
		switch v {
		case header.IPv4Version:
			if len(packet) >= header.IPv4MinimumSize && header.IPv4(packet).Protocol() == uint8(header.UDPProtocolNumber) {
				if e.udpMode == UDPModeReject {
					e.rejectPacket(packet)
				}
				continue
			}
		case header.IPv6Version:
			if len(packet) >= header.IPv6MinimumSize {
				proto, _, _ := findIPv6L4Header(packet)
				if proto == uint8(header.UDPProtocolNumber) {
					if e.udpMode == UDPModeReject {
						e.rejectPacket(packet)
					}
					continue
				}
			}
		}

		dstIP := PacketDestinationIP(packet)
		srcIP := PacketSourceIP(packet)

		if !isRoutableUnicast(dstIP) || !isRoutableUnicast(srcIP) {
			continue
		}

		switch v {
		case header.IPv4Version:
			if len(packet) < header.IPv4MinimumSize || (isReady && !hasV4) {
				continue
			}
			validPackets = append(validPackets, packet)
		case header.IPv6Version:
			if len(packet) < header.IPv6MinimumSize || (isReady && !hasV6) {
				continue
			}
			validPackets = append(validPackets, packet)
		default:
			continue
		}
	}

	if len(validPackets) == 0 {
		return nil
	}

	// 2. 门禁 1: 三层未就绪（仅冷启动或收到显式 NACK 降级生效）-> Fail-Closed 阻断并异步握手
	if !isReady {
		now := time.Now().Unix()
		last := e.lastAttemptTime.Load()
		if now-last >= 2 && !e.isNegotiating() && e.lastAttemptTime.CompareAndSwap(last, now) {
			e.renegotiateAsync(3 * time.Second)
		}
		return nil
	}

	// 3. 门禁 2: 物理连接失效 -> 同步就绪屏障（短超时同步建立物理链路，绝不异步微观丢弃首包）
	session := e.CurrentSession()
	if session == nil || session.IsClosed() {
		session = e.acquireSession()
		if session == nil {
			return nil
		}
	}

	return e.writeUplinkPacketsWithSession(session, validPackets)
}

func (e *ClientEngine) WritePackets(packets [][]byte) error {
	return e.WriteUplinkPackets(packets)
}

// PortAddresses 恒定返回本地端口地址（见 nat.go），双栈都通告以锁定三层直通：某一族尚未或
// 未被分配地址时，该族报文由引擎 fail-closed 丢弃，而不是退回本地 L4 栈绕过隧道。
func (e *ClientEngine) PortAddresses() (netip.Addr, netip.Addr) {
	if !e.enabled {
		return netip.Addr{}, netip.Addr{}
	}
	return LocalPortIPv4, LocalPortIPv6
}

func (e *ClientEngine) PortMTU() uint32 {
	return e.MTU()
}

func (e *ClientEngine) UpstreamPort() any {
	return nil
}

func (e *ClientEngine) AttachReturn(returnPath tun.Return) error {
	newState := &returnPathState{
		returnPath: returnPath,
		headroom:   returnPath.ReturnHeadroom(),
	}
	e.returnState.Store(newState)
	return nil
}

func (e *ClientEngine) DetachReturn(returnPath tun.Return) error {
	currentState := e.returnState.Load()
	if currentState != nil && currentState.returnPath == returnPath {
		e.returnState.CompareAndSwap(currentState, nil)
	}
	return nil
}

var _ tun.Port = (*ClientEngine)(nil)

type clientState struct {
	clientID uint64
	v4       netip.Addr
	v6       netip.Addr
}

type downlinkPacket struct {
	buf []byte
	len int
}

const (
	downlinkQueueSize = 1024
	downlinkBatchSize = 32
	// downlinkPooledBufferSize 之外的超大报文缓冲不放回池，避免池里囤积 64K 缓冲。
	downlinkPooledBufferSize = 16 * 1024
)

var downlinkPacketPool = sync.Pool{
	New: func() any {
		return &downlinkPacket{
			buf: make([]byte, 2048),
		}
	},
}

type sessionDownlink struct {
	session   Session
	ch        chan *downlinkPacket
	done      chan struct{}
	closeOnce sync.Once
}

func (dl *sessionDownlink) close() {
	dl.closeOnce.Do(func() {
		close(dl.done)
	})
}

type ServerEngineOptions struct {
	Context        context.Context
	Address        []netip.Prefix
	InterfaceName  string
	MTU            uint32
	LeaseDuration  time.Duration
	TCPMSSClamping *bool
	WriteTUN       func(packet []byte) error
	// Tun 注入现成的 TUN 设备（测试或平台提供），为空时按 InterfaceName 创建系统网卡。
	Tun tun.Tun
	// UserOf 返回会话所属的已认证用户，用于跨客户端重启的粘性分配；为空时只按 ClientID 粘性。
	UserOf func(session Session) string
	Logger logger.ContextLogger
}

type ServerEngine struct {
	ctx            context.Context
	logger         logger.ContextLogger
	tracer         *Tracer
	mtu            uint32
	leaseDuration  time.Duration
	tcpMSSClamping bool
	tunIf          tun.Tun
	tunOptions     tun.Options
	writeTUN       func(packet []byte) error
	userOf         func(session Session) string
	ipam           *IPAM
	routes         *Table[uint64]
	sessionsMu     sync.RWMutex
	clients        map[uint64]*clientState
	activeSessions map[uint64]Session
	sessionClients map[Session]uint64
	downlinks      map[Session]*sessionDownlink
	// nackAt 记录每个会话最近一次发送 IPExpired 的时间，用于限速：失效客户端的每个
	// 报文都会触发 NACK，不限速时一阵突发流量就会被放大成同样多的控制帧。
	nackAccess sync.Mutex
	nackAt     map[Session]nackRecord
	startOnce  sync.Once
	closed     atomic.Bool
	closeChan  chan struct{}
}

// nackInterval 是同一会话针对同一地址两次 IPExpired 之间的最短间隔。
const nackInterval = 200 * time.Millisecond

type nackRecord struct {
	ip       netip.Addr
	clientID uint64
	at       int64
}

func NewServerEngine(options ServerEngineOptions) (*ServerEngine, error) {
	ipam, err := NewIPAM(options.Address)
	if err != nil {
		return nil, err
	}

	if options.MTU != 0 && (options.MTU < MinMTU || options.MTU > MaxMTU) {
		return nil, E.New("pseudovpn: mtu must be in [", MinMTU, ", ", MaxMTU, "]")
	}
	mtu := NormalizeMTU(options.MTU)
	if ipam.HasV6() && mtu < MinIPv6MTU {
		return nil, E.New("pseudovpn: mtu must be at least ", MinIPv6MTU, " when an IPv6 subnet is configured")
	}
	ifName := options.InterfaceName
	if ifName == "" {
		ifName = "anyx-tun"
	}
	tcpMSSClamping := true
	if options.TCPMSSClamping != nil {
		tcpMSSClamping = *options.TCPMSSClamping
	}

	tunOpts := tun.Options{
		Name:                 ifName,
		MTU:                  mtu,
		DNSMode:              tun.DNSModeDisabled,
		InterfaceScope:       true,
		Logger:               options.Logger,
		EXP_DisableDNSHijack: true,
	}
	if options.Context != nil {
		networkManager := service.FromContext[adapter.NetworkManager](options.Context)
		if networkManager != nil {
			tunOpts.InterfaceMonitor = networkManager.InterfaceMonitor()
			tunOpts.InterfaceFinder = networkManager.InterfaceFinder()
		}
	}

	leaseDuration := ClampLeaseDuration(options.LeaseDuration)
	routes := NewTable[uint64]()
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	engine := &ServerEngine{
		ctx:            ctx,
		logger:         options.Logger,
		tracer:         NewTracer("server", options.Logger),
		mtu:            mtu,
		leaseDuration:  leaseDuration,
		tcpMSSClamping: tcpMSSClamping,
		tunOptions:     tunOpts,
		writeTUN:       options.WriteTUN,
		userOf:         options.UserOf,
		tunIf:          options.Tun,
		ipam:           ipam,
		routes:         routes,
		clients:        make(map[uint64]*clientState),
		activeSessions: make(map[uint64]Session),
		sessionClients: make(map[Session]uint64),
		downlinks:      make(map[Session]*sessionDownlink),
		nackAt:         make(map[Session]nackRecord),
		closeChan:      make(chan struct{}),
	}
	if engine.logger == nil {
		engine.logger = logger.NOP()
	}
	return engine, nil
}

// InterfaceAddresses 返回服务端 TUN 网卡的地址：每个地址族取服务端在该虚拟子网中的地址，
// 掩码沿用子网，使内核为整个虚拟子网建立指向网卡的路由。
func (e *ServerEngine) InterfaceAddresses() (inet4 []netip.Prefix, inet6 []netip.Prefix) {
	if sV4 := e.ipam.ServerV4(); sV4.IsValid() {
		if pfx, ok := e.ipam.PrefixFor(sV4); ok {
			inet4 = []netip.Prefix{netip.PrefixFrom(sV4, pfx.Bits())}
		}
	}
	if sV6 := e.ipam.ServerV6(); sV6.IsValid() {
		if pfx, ok := e.ipam.PrefixFor(sV6); ok {
			inet6 = []netip.Prefix{netip.PrefixFrom(sV6, pfx.Bits())}
		}
	}
	return
}

// Start 启动自包含系统 TUN 网卡、下行监听循环与租约回收循环。回收循环随 Start 启动，
// 构造后未启动（例如入站后续初始化失败）的引擎不会遗留协程。
func (e *ServerEngine) Start() error {
	if e.closed.Load() {
		return net.ErrClosed
	}
	e.startOnce.Do(func() {
		go e.leaseGCLoop()
	})
	if e.writeTUN != nil {
		return nil
	}
	if e.tunIf == nil {
		e.tunOptions.Inet4Address, e.tunOptions.Inet6Address = e.InterfaceAddresses()
		if e.tunOptions.MTU == 0 {
			e.tunOptions.MTU = e.mtu
		}
		tunIf, err := tun.New(e.tunOptions)
		if err != nil {
			return E.Cause(err, "create pseudovpn interface ", e.tunOptions.Name)
		}
		e.tunIf = tunIf
	}
	if err := e.tunIf.Start(); err != nil {
		_ = e.tunIf.Close()
		e.tunIf = nil
		return err
	}
	e.logger.Info("pseudovpn: started interface ", e.tunOptions.Name, " ", e.tunOptions.Inet4Address, " ", e.tunOptions.Inet6Address, ", mtu ", e.mtu)
	go e.tunReadLoop(e.tunIf)
	return nil
}

func (e *ServerEngine) tunReadLoop(tunIf tun.Tun) {
	readBuffer := make([]byte, 65535+tun.PacketOffset)
	for {
		readN, err := tunIf.Read(readBuffer)
		if err != nil {
			if e.closed.Load() || E.IsClosed(err) {
				return
			}
			e.logger.Error("pseudovpn server: tun read error, downlink stopped: ", err)
			return
		}
		if readN <= tun.PacketOffset {
			continue
		}
		packet := readBuffer[tun.PacketOffset:readN]

		dstIP := PacketDestinationIP(packet)
		if !isRoutableUnicast(dstIP) {
			continue
		}

		_ = e.HandleDownlink(packet)
	}
}

func (e *ServerEngine) writePacketToTUN(packet []byte) error {
	if e.tunIf == nil || len(packet) == 0 {
		return nil
	}
	if tun.PacketOffset == 0 {
		_, err := e.tunIf.Write(packet)
		return err
	}
	writeBuffer := make([]byte, tun.PacketOffset+len(packet))
	tun.PacketFillHeader(writeBuffer[:tun.PacketOffset], header.IPVersion(packet))
	copy(writeBuffer[tun.PacketOffset:], packet)
	_, err := e.tunIf.Write(writeBuffer)
	return err
}

func (e *ServerEngine) MTU() uint32 {
	return e.mtu
}

func (e *ServerEngine) LeaseDuration() time.Duration {
	return e.leaseDuration
}

func (e *ServerEngine) IPAM() *IPAM {
	return e.ipam
}

func (e *ServerEngine) Table() *Table[uint64] {
	return e.routes
}

func (e *ServerEngine) leaseGCLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if e.closed.Load() {
				return
			}
			e.collectGarbage()
		case <-e.closeChan:
			return
		}
	}
}

// collectGarbage 清扫已关闭会话的下行协程与映射，并按归属回收过期 / 被接管的租约路由。
func (e *ServerEngine) collectGarbage() {
	e.sessionsMu.Lock()
	for sess, cid := range e.sessionClients {
		if sess.IsClosed() {
			e.dropSessionLocked(sess, cid)
		}
	}
	for sess := range e.downlinks {
		if sess.IsClosed() {
			e.dropSessionLocked(sess, e.sessionClients[sess])
		}
	}
	e.sessionsMu.Unlock()

	e.nackAccess.Lock()
	for sess := range e.nackAt {
		if sess.IsClosed() {
			delete(e.nackAt, sess)
		}
	}
	e.nackAccess.Unlock()

	e.applyReleased(e.ipam.PurgeExpiredLeases())
}

// applyReleased 同步 IPAM 回收的租约：只删除仍指向原持有者的路由，只清空仍记着该地址且
// 已不再持有其租约的客户端状态。地址可能已被重新分配，不能无条件删除。
func (e *ServerEngine) applyReleased(released []ReleasedLease) {
	if len(released) == 0 {
		return
	}
	e.sessionsMu.Lock()
	defer e.sessionsMu.Unlock()
	for _, lease := range released {
		e.releaseClientAddrLocked(lease.ClientID, lease.IP)
		e.tracer.Trace("pseudovpn [server]: reclaimed lease and route for IP ", lease.IP, ", cid=", lease.ClientID)
	}
}

// releaseClientAddrLocked 在 clientID 已不再持有 ip 时清理其路由与状态。
func (e *ServerEngine) releaseClientAddrLocked(clientID uint64, ip netip.Addr) {
	if owner, owned := e.ipam.Owner(ip); owned && owner == clientID {
		return
	}
	e.routes.RemoveIf(netip.PrefixFrom(ip, ip.BitLen()), func(cid uint64) bool {
		return cid == clientID
	})
	client := e.clients[clientID]
	if client == nil {
		return
	}
	if client.v4 == ip {
		client.v4 = netip.Addr{}
	}
	if client.v6 == ip {
		client.v6 = netip.Addr{}
	}
	if !client.v4.IsValid() && !client.v6.IsValid() {
		delete(e.clients, clientID)
		if activeSess, ok := e.activeSessions[clientID]; ok {
			e.dropSessionLocked(activeSess, clientID)
		}
	}
}

// releaseClientLocked 回收客户端的全部地址与状态。
func (e *ServerEngine) releaseClientLocked(clientID uint64) {
	client := e.clients[clientID]
	if client == nil {
		return
	}
	for _, ip := range []netip.Addr{client.v4, client.v6} {
		if !ip.IsValid() {
			continue
		}
		e.ipam.ReleaseOwned(ip, clientID)
		e.routes.RemoveIf(netip.PrefixFrom(ip, ip.BitLen()), func(cid uint64) bool {
			return cid == clientID
		})
	}
	delete(e.clients, clientID)
}

// dropSessionLocked 解除会话的全部绑定并停止其下行协程。
func (e *ServerEngine) dropSessionLocked(session Session, clientID uint64) {
	if dl, ok := e.downlinks[session]; ok {
		dl.close()
		delete(e.downlinks, session)
	}
	if cid, ok := e.sessionClients[session]; ok {
		clientID = cid
		delete(e.sessionClients, session)
	}
	if clientID != 0 && e.activeSessions[clientID] == session {
		delete(e.activeSessions, clientID)
	}
}

func (e *ServerEngine) UnregisterSession(session Session) {
	if session == nil {
		return
	}
	e.sessionsMu.Lock()
	clientID := e.sessionClients[session]
	e.dropSessionLocked(session, clientID)
	if clientID == 0 {
		// 防御性兜底扫描，彻底清理 activeSessions 中残留的该会话
		for cid, s := range e.activeSessions {
			if s == session {
				clientID = cid
				delete(e.activeSessions, cid)
			}
		}
	}
	e.sessionsMu.Unlock()

	e.nackAccess.Lock()
	delete(e.nackAt, session)
	e.nackAccess.Unlock()

	if clientID != 0 {
		e.tracer.Trace("pseudovpn [server]: unregistered physical session for cid=", clientID)
	} else {
		e.tracer.Trace("pseudovpn [server]: unregistered physical session")
	}
}

// allowNACK 对同一会话、同一（源地址, ClientID）的 IPExpired 限速；每个会话只记最近一次，内存有界。
func (e *ServerEngine) allowNACK(session Session, ip netip.Addr, clientID uint64) bool {
	now := time.Now().UnixNano()
	e.nackAccess.Lock()
	defer e.nackAccess.Unlock()
	if last, ok := e.nackAt[session]; ok && last.ip == ip && last.clientID == clientID && now-last.at < int64(nackInterval) {
		return false
	}
	e.nackAt[session] = nackRecord{ip: ip, clientID: clientID, at: now}
	return true
}

func (e *ServerEngine) HandleUplink(session Session, packet []byte) error {
	if e.closed.Load() || len(packet) == 0 {
		return nil
	}

	if isUplinkControlPacket(packet) {
		return e.handleIPRequest(session, packet)
	}

	if len(packet) < 8+header.IPv4MinimumSize {
		return nil
	}

	clientID := binary.BigEndian.Uint64(packet[:8])
	ipPacket := packet[8:]

	switch header.IPVersion(ipPacket) {
	case header.IPv4Version:
		if header.IPv4(ipPacket).Protocol() == uint8(header.UDPProtocolNumber) {
			return nil
		}
	case header.IPv6Version:
		if len(ipPacket) < header.IPv6MinimumSize {
			return nil
		}
		proto, _, _ := findIPv6L4Header(ipPacket)
		if proto == uint8(header.UDPProtocolNumber) {
			return nil
		}
	default:
		return nil
	}

	srcIP := PacketSourceIP(ipPacket)
	if !srcIP.IsValid() || !isRoutableUnicast(srcIP) {
		return nil
	}

	// 1. Strict RPF 校验与被动续约
	if clientID == 0 || !e.ipam.ValidateClientAndTouch(srcIP, clientID, e.leaseDuration) {
		if _, managed := e.ipam.PrefixFor(srcIP); managed && e.allowNACK(session, srcIP, clientID) {
			e.tracer.Trace("pseudovpn [server]: dropped expired packet from src=", srcIP, ", cid=", clientID, ", sending IPExpired NACK")
			var nack [18]byte
			nack[0] = PacketTypeIPExpired
			b16 := srcIP.As16()
			copy(nack[2:18], b16[:])
			_ = session.WriteFramePacket(FrameCommandPseudoVPN, nack[:])
		}
		return nil
	}

	// 2. Level 2 物理漫游自愈: 更新 ClientID -> 活跃 Session。
	// 绝大多数报文绑定不变，先走读锁快路径，避免每个上行报文都争抢写锁。
	e.sessionsMu.RLock()
	bound := e.activeSessions[clientID] == session && e.sessionClients[session] == clientID
	e.sessionsMu.RUnlock()
	if !bound {
		e.sessionsMu.Lock()
		oldSession := e.activeSessions[clientID]
		if oldSession != session {
			e.activeSessions[clientID] = session
			if oldSession != nil {
				delete(e.sessionClients, oldSession)
				if dl, ok := e.downlinks[oldSession]; ok {
					dl.close()
					delete(e.downlinks, oldSession)
				}
			}
			if previous, ok := e.sessionClients[session]; ok && previous != clientID && e.activeSessions[previous] == session {
				delete(e.activeSessions, previous)
			}
		}
		e.sessionClients[session] = clientID
		e.sessionsMu.Unlock()
	}

	if e.tcpMSSClamping {
		clampTCPMSS(ipPacket, e.mtu)
	}

	if e.writeTUN != nil {
		return e.writeTUN(ipPacket)
	}
	return e.writePacketToTUN(ipPacket)
}

func (e *ServerEngine) handleIPRequest(session Session, packet []byte) error {
	if len(packet) < 52 {
		return nil
	}

	flags := packet[1]
	wantV4 := (flags & 0x01) != 0
	wantV6 := (flags & 0x02) != 0
	reqV4 := netip.AddrFrom16([16]byte(packet[2:18])).Unmap()
	reqV6 := netip.AddrFrom16([16]byte(packet[18:34])).Unmap()
	clientID := binary.BigEndian.Uint64(packet[36:44])
	leaseToken := binary.BigEndian.Uint64(packet[44:52])

	// 应答里不回传 ClientID：服务端代为生成的 ID 客户端无从得知，之后的数据帧全部无法通过
	// 校验，而每次请求都会白白占用一条租约。
	if clientID == 0 {
		e.tracer.Trace("pseudovpn [server]: rejected IP request without client id")
		return e.writeIPRejection(session)
	}

	if !wantV4 && !wantV6 {
		wantV4 = e.ipam.HasV4()
		wantV6 = e.ipam.HasV6()
	}

	var v4, v6 netip.Addr
	var token uint64
	var err error

	isReclaim := false
	if leaseToken != 0 {
		reclaimedV4 := wantV4 && reqV4.IsValid() && e.ipam.ReclaimLease(reqV4, clientID, leaseToken, e.leaseDuration)
		reclaimedV6 := wantV6 && reqV6.IsValid() && e.ipam.ReclaimLease(reqV6, clientID, leaseToken, e.leaseDuration)
		if (reclaimedV4 || !wantV4 || !e.ipam.HasV4()) && (reclaimedV6 || !wantV6 || !e.ipam.HasV6()) && (reclaimedV4 || reclaimedV6) {
			isReclaim = true
			token = leaseToken
			flags = 0
			if reclaimedV4 {
				v4 = reqV4
				flags |= 0x01
			}
			if reclaimedV6 {
				v6 = reqV6
				flags |= 0x02
			}
		}
	}

	if !isReclaim {
		userKey := e.userKey(session)
		online := e.onlineClients(clientID)
		offline := func(cid uint64) bool {
			_, isOnline := online[cid]
			return !isOnline
		}
		v4, v6, flags, token, err = e.ipam.AllocateDualStackForUser(clientID, userKey, offline, e.leaseDuration, wantV4, reqV4, wantV6, reqV6)
		if e.evictForAllocation(online, wantV4 && !v4.IsValid() && e.ipam.HasV4(), wantV6 && !v6.IsValid() && e.ipam.HasV6()) {
			v4, v6, flags, token, err = e.ipam.AllocateDualStackForUser(clientID, userKey, offline, e.leaseDuration, wantV4, reqV4, wantV6, reqV6)
		}
	}
	// 分配路径上清扫掉的租约要同步给路由表，否则旧主的路由与状态会残留。
	e.applyReleased(e.ipam.TakeReleased())

	if err != nil || flags == 0 {
		e.logger.Warn("pseudovpn: IP allocation failed: ", err)
		return e.writeIPRejection(session)
	}

	e.sessionsMu.Lock()
	// 一个物理会话只承载一个客户端：同一会话换用新 ClientID 申请地址时，回收旧客户端的
	// 租约（若它没有别的活跃会话），否则不断更换 ClientID 就能耗尽地址池。
	if oldCID, ok := e.sessionClients[session]; ok && oldCID != clientID {
		delete(e.sessionClients, session)
		if e.activeSessions[oldCID] == session {
			delete(e.activeSessions, oldCID)
			e.releaseClientLocked(oldCID)
		}
	}
	e.sessionClients[session] = clientID

	client := e.clients[clientID]
	if client == nil {
		client = &clientState{
			clientID: clientID,
		}
		e.clients[clientID] = client
	}

	oldSession := e.activeSessions[clientID]
	if oldSession != nil && oldSession != session {
		if oldCID, ok := e.sessionClients[oldSession]; ok && oldCID == clientID {
			delete(e.sessionClients, oldSession)
		}
		if dl, ok := e.downlinks[oldSession]; ok {
			dl.close()
			delete(e.downlinks, oldSession)
		}
	}
	e.activeSessions[clientID] = session

	if client.v4.IsValid() && client.v4 != v4 {
		e.routes.RemoveIf(netip.PrefixFrom(client.v4, client.v4.BitLen()), func(cid uint64) bool { return cid == clientID })
		e.ipam.ReleaseOwned(client.v4, clientID)
	}
	if client.v6.IsValid() && client.v6 != v6 {
		e.routes.RemoveIf(netip.PrefixFrom(client.v6, client.v6.BitLen()), func(cid uint64) bool { return cid == clientID })
		e.ipam.ReleaseOwned(client.v6, clientID)
	}
	client.v4 = v4
	client.v6 = v6

	// Level 1: 绑定 Virtual IP Prefix -> ClientID
	if v4.IsValid() {
		e.routes.Insert(netip.PrefixFrom(v4, v4.BitLen()), clientID)
	}
	if v6.IsValid() {
		e.routes.Insert(netip.PrefixFrom(v6, v6.BitLen()), clientID)
	}

	if _, ok := e.downlinks[session]; !ok && !e.closed.Load() {
		e.startDownlinkLocked(session)
	}
	e.sessionsMu.Unlock()

	resp := make([]byte, 83)
	resp[0] = PacketTypeIPResponse
	resp[1] = 0
	resp[2] = flags

	if v4.IsValid() {
		b4 := v4.As16()
		copy(resp[3:19], b4[:])
		sV4 := e.ipam.ServerV4()
		if sV4.IsValid() {
			sb4 := sV4.As16()
			copy(resp[19:35], sb4[:])
		}
	}

	if v6.IsValid() {
		b6 := v6.As16()
		copy(resp[35:51], b6[:])
		sV6 := e.ipam.ServerV6()
		if sV6.IsValid() {
			sb6 := sV6.As16()
			copy(resp[51:67], sb6[:])
		}
	}

	binary.BigEndian.PutUint32(resp[67:71], e.mtu)
	binary.BigEndian.PutUint32(resp[71:75], uint32(e.leaseDuration.Seconds()))
	binary.BigEndian.PutUint64(resp[75:83], token)

	if isReclaim {
		e.logger.Debug("pseudovpn: renewed lease v4=", v4, ", v6=", v6, " for client")
	} else {
		e.logger.Info("pseudovpn: granted dual-stack v4=", v4, ", v6=", v6, " to client, lease ", e.leaseDuration)
	}
	e.tracer.Trace("pseudovpn [server]: granted dual-stack v4=", v4, ", v6=", v6, " to client, sending response, len=", len(resp))

	return session.WriteFramePacket(FrameCommandPseudoVPN, resp)
}

func (e *ServerEngine) writeIPRejection(session Session) error {
	resp := make([]byte, 83)
	resp[0] = PacketTypeIPResponse
	resp[1] = 1
	return session.WriteFramePacket(FrameCommandPseudoVPN, resp)
}

// evictForAllocation 在地址池被占满时驱逐最久未活动的离线客户端租约，返回是否腾出了地址。
// 在线客户端（有存活会话）与请求者本身不会被驱逐。
func (e *ServerEngine) evictForAllocation(online map[uint64]struct{}, needV4, needV6 bool) bool {
	if !needV4 && !needV6 {
		return false
	}
	keep := func(cid uint64) bool {
		_, isOnline := online[cid]
		return isOnline
	}

	var evicted []ReleasedLease
	if needV4 {
		if lease, ok := e.ipam.EvictIdle(true, keep); ok {
			evicted = append(evicted, lease)
		}
	}
	if needV6 {
		if lease, ok := e.ipam.EvictIdle(false, keep); ok {
			evicted = append(evicted, lease)
		}
	}
	if len(evicted) == 0 {
		return false
	}
	for _, lease := range evicted {
		e.logger.Info("pseudovpn: address pool exhausted, evicted idle lease ", lease.IP)
	}
	e.applyReleased(evicted)
	return true
}

// onlineClients 返回有存活会话的客户端集合，并把请求者本身算作在线。
func (e *ServerEngine) onlineClients(requester uint64) map[uint64]struct{} {
	e.sessionsMu.RLock()
	online := make(map[uint64]struct{}, len(e.activeSessions)+1)
	for cid, sess := range e.activeSessions {
		if !sess.IsClosed() {
			online[cid] = struct{}{}
		}
	}
	e.sessionsMu.RUnlock()
	online[requester] = struct{}{}
	return online
}

// userKey 把会话的用户名映射为非零键。
func (e *ServerEngine) userKey(session Session) uint64 {
	if e.userOf == nil {
		return 0
	}
	user := e.userOf(session)
	if user == "" {
		return 0
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(user))
	key := hash.Sum64()
	if key == 0 {
		key = 1
	}
	return key
}

func (e *ServerEngine) startDownlinkLocked(session Session) *sessionDownlink {
	dl := &sessionDownlink{
		session: session,
		ch:      make(chan *downlinkPacket, downlinkQueueSize),
		done:    make(chan struct{}),
	}
	if e.downlinks == nil {
		e.downlinks = make(map[Session]*sessionDownlink)
	}
	e.downlinks[session] = dl
	go e.sessionDownlinkWorker(dl)
	return dl
}

func putDownlinkPacket(item *downlinkPacket) {
	item.len = 0
	if cap(item.buf) > downlinkPooledBufferSize {
		return
	}
	downlinkPacketPool.Put(item)
}

func (e *ServerEngine) sessionDownlinkWorker(dl *sessionDownlink) {
	var (
		batch   [downlinkBatchSize]*downlinkPacket
		packets [downlinkBatchSize][]byte
		count   int
	)
	release := func() {
		for i := 0; i < count; i++ {
			putDownlinkPacket(batch[i])
			batch[i] = nil
			packets[i] = nil
		}
		count = 0
	}
	defer func() {
		release()
		for {
			select {
			case item := <-dl.ch:
				putDownlinkPacket(item)
			default:
				return
			}
		}
	}()

	for {
		select {
		case <-dl.done:
			return
		case <-e.closeChan:
			return
		case first := <-dl.ch:
			batch[0] = first
			count = 1

		drainLoop:
			for count < len(batch) {
				select {
				case next := <-dl.ch:
					batch[count] = next
					count++
				default:
					break drainLoop
				}
			}

			if dl.session.IsClosed() {
				return
			}
			for i := 0; i < count; i++ {
				packets[i] = batch[i].buf[:batch[i].len]
			}
			err := writeFramedPackets(dl.session, nil, packets[:count])
			release()
			if err != nil && dl.session.IsClosed() {
				return
			}
		}
	}
}

func (e *ServerEngine) HandleDownlink(packet []byte) error {
	if e.closed.Load() || len(packet) == 0 {
		return nil
	}

	dstIP := PacketDestinationIP(packet)
	if !dstIP.IsValid() {
		e.tracer.Trace("pseudovpn [server]: dropped downlink packet from tun (invalid destination IP)")
		return nil
	}

	// Level 1: 查逻辑路由获取 ClientID
	clientID, found := e.routes.Lookup(dstIP)
	if !found || clientID == 0 {
		return nil
	}

	// Level 2: 查物理出接口 Session
	e.sessionsMu.RLock()
	session := e.activeSessions[clientID]
	var dl *sessionDownlink
	if session != nil && !session.IsClosed() {
		dl = e.downlinks[session]
	}
	e.sessionsMu.RUnlock()
	if session == nil || session.IsClosed() {
		return nil
	}

	if e.tcpMSSClamping {
		clampTCPMSS(packet, e.mtu)
	}

	if dl == nil {
		e.sessionsMu.Lock()
		if !e.closed.Load() {
			session = e.activeSessions[clientID]
			if session != nil && !session.IsClosed() {
				var ok bool
				dl, ok = e.downlinks[session]
				if !ok {
					dl = e.startDownlinkLocked(session)
				}
			}
		}
		e.sessionsMu.Unlock()
	}
	if dl == nil {
		return nil
	}

	item := downlinkPacketPool.Get().(*downlinkPacket)
	if len(packet) > cap(item.buf) {
		item.buf = make([]byte, len(packet))
	}
	item.buf = item.buf[:cap(item.buf)]
	copy(item.buf, packet)
	item.len = len(packet)

	select {
	case <-dl.done:
		putDownlinkPacket(item)
	case dl.ch <- item:
	default:
		putDownlinkPacket(item)
		e.tracer.Trace("pseudovpn [server]: downlink queue full, dropping packet for dst ", dstIP)
	}
	return nil
}

func (e *ServerEngine) Close() error {
	if e.closed.CompareAndSwap(false, true) {
		if e.closeChan != nil {
			close(e.closeChan)
		}
		if e.tunIf != nil {
			_ = e.tunIf.Close()
		}
		e.sessionsMu.Lock()
		for _, dl := range e.downlinks {
			dl.close()
		}
		e.downlinks = nil
		clear(e.sessionClients)
		clear(e.activeSessions)
		clear(e.clients)
		e.routes.Clear()
		e.sessionsMu.Unlock()
		e.nackAccess.Lock()
		clear(e.nackAt)
		e.nackAccess.Unlock()
	}
	return nil
}

func PacketSourceIP(packet []byte) netip.Addr {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		if len(packet) >= header.IPv4MinimumSize {
			return header.IPv4(packet).SourceAddr()
		}
	case header.IPv6Version:
		if len(packet) >= header.IPv6MinimumSize {
			return header.IPv6(packet).SourceAddr()
		}
	}
	return netip.Addr{}
}

func PacketDestinationIP(packet []byte) netip.Addr {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		if len(packet) >= header.IPv4MinimumSize {
			return header.IPv4(packet).DestinationAddr()
		}
	case header.IPv6Version:
		if len(packet) >= header.IPv6MinimumSize {
			return header.IPv6(packet).DestinationAddr()
		}
	}
	return netip.Addr{}
}

// maxIPv6ExtensionHeaders 限制扩展头链长度，畸形报文不能让解析无限循环或耗费大量 CPU。
const maxIPv6ExtensionHeaders = 16

func findIPv6L4Header(packet []byte) (proto uint8, l4Offset int, isFragNonFirst bool) {
	if len(packet) < header.IPv6MinimumSize {
		return 0, 0, false
	}
	currProto := packet[6]
	offset := header.IPv6MinimumSize

	for range maxIPv6ExtensionHeaders {
		switch currProto {
		case 44: // Fragment
			if len(packet) < offset+8 {
				return 0, 0, false
			}
			fragOffset := binary.BigEndian.Uint16(packet[offset+2:offset+4]) & 0xfff8
			if fragOffset > 0 {
				return 0, 0, true
			}
			currProto = packet[offset]
			offset += 8
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if len(packet) < offset+8 {
				return 0, 0, false
			}
			// 长度字段为 uint8，必须先转 int 再加 1：255+1 在 uint8 上回绕为 0，扩展头长度
			// 变成 0，offset 不再前进，恶意报文即可让解析死循环。
			extLen := (int(packet[offset+1]) + 1) * 8
			if len(packet) < offset+extLen {
				return 0, 0, false
			}
			currProto = packet[offset]
			offset += extLen
		case 51: // Authentication Header, 长度单位为 4 字节且不含前 2 个单位
			if len(packet) < offset+8 {
				return 0, 0, false
			}
			extLen := (int(packet[offset+1]) + 2) * 4
			if len(packet) < offset+extLen {
				return 0, 0, false
			}
			currProto = packet[offset]
			offset += extLen
		default:
			return currProto, offset, false
		}
	}
	return 0, 0, false
}

func clampTCPMSS(packet []byte, mtu uint32) {
	if len(packet) == 0 || mtu == 0 {
		return
	}
	version := header.IPVersion(packet)
	var ipHdrLen int
	var safeMSS uint16

	switch version {
	case header.IPv4Version:
		if len(packet) < header.IPv4MinimumSize {
			return
		}
		ipHdr := header.IPv4(packet)
		if ipHdr.Protocol() != uint8(header.TCPProtocolNumber) {
			return
		}
		fragOffset := binary.BigEndian.Uint16(packet[6:8]) & 0x1fff
		if fragOffset > 0 {
			return
		}
		ipHdrLen = int(ipHdr.HeaderLength())
		if ipHdrLen < header.IPv4MinimumSize || len(packet) < ipHdrLen+header.TCPMinimumSize {
			return
		}
		if mtu <= 40 {
			return
		}
		safeMSS = uint16(mtu - 40)

	case header.IPv6Version:
		if len(packet) < header.IPv6MinimumSize {
			return
		}
		proto, l4Offset, isFragNonFirst := findIPv6L4Header(packet)
		if isFragNonFirst || proto != uint8(header.TCPProtocolNumber) {
			return
		}
		ipHdrLen = l4Offset
		if len(packet) < ipHdrLen+header.TCPMinimumSize {
			return
		}
		if mtu <= 60 {
			return
		}
		safeMSS = uint16(mtu - 60)

	default:
		return
	}

	tcpHdr := packet[ipHdrLen:]
	flags := tcpHdr[13]
	if (flags & 0x02) == 0 {
		return
	}

	dataOffset := int(tcpHdr[12]>>4) * 4
	if dataOffset <= header.TCPMinimumSize || len(tcpHdr) < dataOffset {
		return
	}

	optOffset := header.TCPMinimumSize
	for optOffset < dataOffset {
		kind := tcpHdr[optOffset]
		if kind == 0 {
			break
		}
		if kind == 1 {
			optOffset++
			continue
		}
		if optOffset+1 >= dataOffset {
			break
		}
		length := int(tcpHdr[optOffset+1])
		if length < 2 || optOffset+length > dataOffset {
			break
		}

		if kind == 2 && length == 4 {
			oldMSS := binary.BigEndian.Uint16(tcpHdr[optOffset+2 : optOffset+4])
			if oldMSS > safeMSS {
				binary.BigEndian.PutUint16(tcpHdr[optOffset+2:optOffset+4], safeMSS)
				csum := binary.BigEndian.Uint16(tcpHdr[16:18])
				newCsum := updateChecksumRFC1624(csum, oldMSS, safeMSS)
				binary.BigEndian.PutUint16(tcpHdr[16:18], newCsum)
			}
			break
		}
		optOffset += length
	}
}

// updateChecksumRFC1624 采用 RFC 1624 Eqn 3 算法精确更新单个 16 位字变化。
func updateChecksumRFC1624(csum uint16, oldVal, newVal uint16) uint16 {
	if oldVal == newVal {
		return csum
	}
	sum := uint32(^csum) + uint32(^oldVal) + uint32(newVal)
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	res := ^uint16(sum)
	if res == 0 {
		return 0xffff
	}
	return res
}

func updateChecksumRFC1624Multi(csum uint16, oldWords, newWords []uint16) uint16 {
	for i := 0; i < len(oldWords) && i < len(newWords); i++ {
		if oldWords[i] != newWords[i] {
			csum = updateChecksumRFC1624(csum, oldWords[i], newWords[i])
		}
	}
	return csum
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
