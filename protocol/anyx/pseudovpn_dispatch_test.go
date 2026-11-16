package anyx

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/anyx/pseudovpn/pvtest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// injectTUN 是服务端的内存 TUN：Inject 的报文从 Read 读出（内核发往虚拟子网的回包），
// Write 写入的报文被记录（交给内核转发的上行包）。
type injectTUN struct {
	tun.Tun
	inbound chan []byte
	closed  chan struct{}
	once    sync.Once
	mu      sync.Mutex
	written [][]byte
}

func newInjectTUN() *injectTUN {
	return &injectTUN{inbound: make(chan []byte, 64), closed: make(chan struct{})}
}

func (t *injectTUN) Inject(packet []byte) {
	t.inbound <- append(make([]byte, tun.PacketOffset), packet...)
}

func (t *injectTUN) Read(p []byte) (int, error) {
	select {
	case packet := <-t.inbound:
		return copy(p, packet), nil
	case <-t.closed:
		return 0, net.ErrClosed
	}
}

func (t *injectTUN) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.written = append(t.written, append([]byte(nil), p[tun.PacketOffset:]...))
	return len(p), nil
}

func (t *injectTUN) Start() error { return nil }

func (t *injectTUN) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

func (t *injectTUN) take(tb testing.TB) []byte {
	tb.Helper()
	var packet []byte
	require.Eventually(tb, func() bool {
		t.mu.Lock()
		defer t.mu.Unlock()
		if len(t.written) == 0 {
			return false
		}
		packet, t.written = t.written[0], t.written[1:]
		return true
	}, 3*time.Second, 5*time.Millisecond)
	return packet
}

func (t *injectTUN) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.written)
}

// localWriteback 代表客户端本地 TUN：转发器把回程报文与它合成的拒绝报文写到这里。
type localWriteback struct {
	mu      sync.Mutex
	packets [][]byte
}

func (w *localWriteback) ReturnHeadroom() int { return 0 }

func (w *localWriteback) WriteReturnPackets(packets [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, packet := range packets {
		w.packets = append(w.packets, append([]byte(nil), packet...))
	}
	return nil
}

func (w *localWriteback) take(tb testing.TB) []byte {
	tb.Helper()
	var packet []byte
	require.Eventually(tb, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		if len(w.packets) == 0 {
			return false
		}
		packet, w.packets = w.packets[0], w.packets[1:]
		return true
	}, 3*time.Second, 5*time.Millisecond)
	return packet
}

func (w *localWriteback) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.packets)
}

// preMatchHandler 按 route 预匹配的语义判定流（route 侧的判定见 route 包的测试）：
// 出站的 PreMatchFlow 结果经 adapter.JudgeFlow 同样的映射转为转发器裁决。
type preMatchHandler struct {
	outbound *Outbound
}

func (h *preMatchHandler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	var name string
	switch network {
	case pvtest.ProtocolTCP:
		name = N.NetworkTCP
	case pvtest.ProtocolUDP:
		name = N.NetworkUDP
	default:
		name = N.NetworkICMP
	}
	switch h.outbound.PreMatchFlow(name, destination.Addr()) {
	case adapter.PreMatchFlow:
		return tun.FlowVerdict{Action: tun.ActionFlow, Port: h.outbound}
	case adapter.PreMatchReject:
		return tun.FlowVerdict{Action: tun.ActionReject}
	case adapter.PreMatchDrop:
		return tun.FlowVerdict{Action: tun.ActionDrop}
	default:
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
}

func (h *preMatchHandler) NewDNSPacket([]byte, M.Socksaddr, M.Socksaddr, N.PacketWriter) {}

func (h *preMatchHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	_ = conn.Close()
}

func (h *preMatchHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	_ = conn.Close()
}

// dispatchDriver 在单个协程上驱动转发阶段：投递报文、等裁决、刷出。
type dispatchDriver struct {
	stage     *tun.ForwardStage
	resumed   chan struct{}
	unhandled [][]byte
}

func newDispatchDriver(t *testing.T, outbound *Outbound, writeback *localWriteback) *dispatchDriver {
	dispatcher := tun.NewForwardDispatcher(&preMatchHandler{outbound: outbound}, writeback, logger.NOP(), tun.UDPNatOptions{}, 0)
	t.Cleanup(dispatcher.Close)
	driver := &dispatchDriver{resumed: make(chan struct{}, 64)}
	driver.stage = dispatcher.NewStage(nil, func() { driver.resumed <- struct{}{} })
	return driver
}

// newFlow 投递流的首包，等待裁决生效后刷出。
func (d *dispatchDriver) newFlow(t *testing.T, packet []byte) {
	t.Helper()
	require.True(t, d.stage.Dispatch(packet), "新流首包必须被转发器接管")
	select {
	case <-d.resumed:
	case <-time.After(3 * time.Second):
		t.Fatal("flow judgement timed out")
	}
	d.stage.ResumeJudged(func(packet []byte, _ tun.ForwardFrameMeta) {
		d.unhandled = append(d.unhandled, append([]byte(nil), packet...))
	})
	d.stage.Flush()
}

// hit 投递已建立流的后续报文。
func (d *dispatchDriver) hit(t *testing.T, packet []byte) {
	t.Helper()
	require.True(t, d.stage.Dispatch(packet), "已建立流的报文必须走三层直通")
	d.stage.Flush()
}

func startPseudoVPNPair(t *testing.T, udpMode string) (*Inbound, *Outbound, *injectTUN) {
	t.Helper()
	certPath, keyPath := generateTestCert(t)
	port := getFreePort(t)
	rawInbound, err := NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "anyx-in", option.AnyXInboundOptions{
		ListenOptions: option.ListenOptions{ListenPort: port},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{Enabled: true, CertificatePath: certPath, KeyPath: keyPath},
		},
		Users: []option.AnyXUser{{Name: "user", Password: "pseudovpn-password"}},
		PseudoVPN: &option.AnyXPseudoVPNInboundOptions{
			Enabled: true,
			MTU:     1400,
			Address: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("100.64.0.1/24"), netip.MustParsePrefix("fd00::1/64")},
		},
	})
	require.NoError(t, err)
	inbound := rawInbound.(*Inbound)
	serverTUN := newInjectTUN()
	setEngineTun(inbound.pseudoVPNEngine, serverTUN)
	inboundScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = inboundScope.Close() })
	require.NoError(t, inbound.Start(adapter.StartStateStart, inboundScope))

	rawOutbound, err := NewOutbound(t.Context(), nil, logger.NOP(), "anyx-out", option.AnyXOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "127.0.0.1", Insecure: true},
		},
		Password:  "pseudovpn-password",
		PseudoVPN: &option.AnyXPseudoVPNOutboundOptions{Enabled: true, UDP: udpMode},
	})
	require.NoError(t, err)
	outbound := rawOutbound.(*Outbound)
	outboundScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = outboundScope.Close() })
	require.NoError(t, outbound.Start(adapter.StartStateInitialize, outboundScope))
	require.NoError(t, outbound.Start(adapter.StartStateStart, outboundScope))
	require.Eventually(t, outbound.pseudoVPNEngine.IsReady, 5*time.Second, 20*time.Millisecond)
	return inbound, outbound, serverTUN
}

// 本地 TUN 三层包 → sing-tun 转发器（预匹配裁决为 Flow）→ AnyX 出站 → AnyX 会话 → 服务端引擎 → 服务端 TUN，
// 以及服务端 TUN 回包沿原路经转发器反向 NAT 回到本地 TUN。
func TestPseudoVPNThroughForwardDispatcher(t *testing.T) {
	_, outbound, serverTUN := startPseudoVPNPair(t, "")
	assignedV4 := outbound.pseudoVPNEngine.AssignedIPv4()
	assignedV6 := outbound.pseudoVPNEngine.AssignedIPv6()
	require.True(t, assignedV4.IsValid())
	require.True(t, assignedV6.IsValid())

	writeback := &localWriteback{}
	driver := newDispatchDriver(t, outbound, writeback)

	for _, family := range []struct {
		name     string
		client   netip.Addr
		remote   netip.Addr
		assigned netip.Addr
		mss      uint16
	}{
		{"ipv4", netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("93.184.216.34"), assignedV4, 1400 - 40},
		{"ipv6", netip.MustParseAddr("fdfe:dcba:9876::2"), netip.MustParseAddr("2606:2800:220:1::1"), assignedV6, 1400 - 60},
	} {
		t.Run(family.name, func(t *testing.T) {
			client := netip.AddrPortFrom(family.client, 40000)
			remote := netip.AddrPortFrom(family.remote, 443)

			driver.newFlow(t, pvtest.TCP(client, remote, 1, 0, pvtest.TCPFlagSyn, 1460, nil))
			syn := serverTUN.take(t)
			require.Equal(t, family.assigned, pvtest.Source(syn), "服务端看到的源地址必须是虚拟地址")
			require.Equal(t, family.remote, pvtest.Destination(syn))
			require.Equal(t, pvtest.TCPFlagSyn, pvtest.TCPFlags(syn)&(pvtest.TCPFlagSyn|pvtest.TCPFlagAck))
			require.Equal(t, family.mss, pvtest.MSS(syn), "MSS 必须按隧道 MTU 钳制")
			require.True(t, pvtest.ChecksumsValid(syn))
			virtualPort, _ := pvtest.Ports(syn)

			serverTUN.Inject(pvtest.TCP(remote, netip.AddrPortFrom(family.assigned, virtualPort), 100, 2, pvtest.TCPFlagSyn|pvtest.TCPFlagAck, 1460, nil))
			synAck := writeback.take(t)
			require.Equal(t, family.client, pvtest.Destination(synAck), "回包必须反向 NAT 回本地客户端地址")
			require.Equal(t, family.remote, pvtest.Source(synAck))
			_, clientPort := pvtest.Ports(synAck)
			require.Equal(t, client.Port(), clientPort)
			require.Equal(t, family.mss, pvtest.MSS(synAck))
			require.True(t, pvtest.ChecksumsValid(synAck))

			driver.hit(t, pvtest.TCP(client, remote, 2, 101, pvtest.TCPFlagAck|pvtest.TCPFlagPsh, 0, []byte("GET / HTTP/1.1\r\n\r\n")))
			data := serverTUN.take(t)
			require.Equal(t, family.assigned, pvtest.Source(data))
			require.True(t, pvtest.ChecksumsValid(data))

			driver.newFlow(t, pvtest.Echo(family.client, family.remote, 9, 1, false, []byte("ping")))
			echo := serverTUN.take(t)
			require.Equal(t, family.assigned, pvtest.Source(echo))
			require.True(t, pvtest.ChecksumsValid(echo))
			echoID := pvtest.EchoID(echo)
			serverTUN.Inject(pvtest.Echo(family.remote, family.assigned, echoID, 1, true, []byte("ping")))
			reply := writeback.take(t)
			require.Equal(t, family.client, pvtest.Destination(reply))
			replyID := pvtest.EchoID(reply)
			require.Equal(t, uint16(9), replyID)
			require.True(t, pvtest.ChecksumsValid(reply))
		})
	}
	require.Empty(t, driver.unhandled, "TCP 与 ICMP 不得回落到本地 L4 栈")
}

// UDP 三种策略在转发器上的效果：drop 丢弃、reject 由转发器回 ICMP 端口不可达、transparent 交还 L4。
func TestPseudoVPNUDPModesThroughForwardDispatcher(t *testing.T) {
	for _, mode := range []string{"drop", "reject", "transparent"} {
		t.Run(mode, func(t *testing.T) {
			rawOutbound, err := NewOutbound(t.Context(), nil, logger.NOP(), "anyx-out", option.AnyXOutboundOptions{
				ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1},
				Password:      "pseudovpn-password",
				PseudoVPN:     &option.AnyXPseudoVPNOutboundOptions{Enabled: true, UDP: mode},
			})
			require.NoError(t, err)
			outbound := rawOutbound.(*Outbound)
			writeback := &localWriteback{}
			driver := newDispatchDriver(t, outbound, writeback)

			client := netip.MustParseAddrPort("172.19.0.2:5353")
			driver.newFlow(t, pvtest.UDP(client, netip.MustParseAddrPort("1.1.1.1:53"), []byte("query")))
			switch mode {
			case "drop":
				require.Zero(t, writeback.count())
				require.Empty(t, driver.unhandled)
			case "reject":
				reject := writeback.take(t)
				icmpType, icmpCode := pvtest.ICMPType(reject)
				require.Equal(t, [2]uint8{3, 3}, [2]uint8{icmpType, icmpCode})
				require.Equal(t, client.Addr(), pvtest.Destination(reject))
				require.True(t, pvtest.ChecksumsValid(reject))
				require.Empty(t, driver.unhandled)
			case "transparent":
				require.Len(t, driver.unhandled, 1, "transparent 模式下 UDP 交还 L4 栈处理")
			}
		})
	}
}

// 物理会话丢失后，转发器上已建立的流继续工作：首包重建会话，服务端漫游到新会话。
func TestPseudoVPNDispatcherFlowSurvivesSessionLoss(t *testing.T) {
	_, outbound, serverTUN := startPseudoVPNPair(t, "")
	assigned := outbound.pseudoVPNEngine.AssignedIPv4()
	writeback := &localWriteback{}
	driver := newDispatchDriver(t, outbound, writeback)

	client := netip.MustParseAddrPort("172.19.0.2:41000")
	remote := netip.MustParseAddrPort("93.184.216.34:80")
	driver.newFlow(t, pvtest.TCP(client, remote, 1, 0, pvtest.TCPFlagSyn, 0, nil))
	virtualPort, _ := pvtest.Ports(serverTUN.take(t))

	session := outbound.pseudoVPNEngine.CurrentSession()
	require.NotNil(t, session)
	require.NoError(t, session.Close())
	outbound.InterfaceUpdated(t.Context())

	driver.hit(t, pvtest.TCP(client, remote, 2, 101, pvtest.TCPFlagAck, 0, []byte("after-reconnect")))
	data := serverTUN.take(t)
	require.Equal(t, assigned, pvtest.Source(data), "重连后虚拟地址不变")
	require.True(t, outbound.pseudoVPNEngine.CurrentSession() != session, "必须换用新的物理会话")

	serverTUN.Inject(pvtest.TCP(remote, netip.AddrPortFrom(assigned, virtualPort), 101, 3, pvtest.TCPFlagAck, 0, []byte("ok")))
	reply := writeback.take(t)
	require.Equal(t, client.Addr(), pvtest.Destination(reply))
	require.True(t, pvtest.ChecksumsValid(reply))
	require.Zero(t, serverTUN.count())
}
