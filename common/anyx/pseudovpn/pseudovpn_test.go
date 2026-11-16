package pseudovpn

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/stretchr/testify/require"
)

var _ tun.Return = (*mockTunReturn)(nil)

type mockTunReturn struct {
	mu      sync.Mutex
	packets [][]byte
}

func (r *mockTunReturn) ReturnHeadroom() int { return 0 }

func (r *mockTunReturn) ReturnPackets(packets [][]byte) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range packets {
		cp := make([]byte, len(p))
		copy(cp, p)
		r.packets = append(r.packets, cp)
	}
	return nil
}

var _ Session = (*mockDirectSession)(nil)

type mockDirectSession struct {
	mu        sync.Mutex
	written   [][]byte
	isClosed  bool
	failWrite error
}

func (s *mockDirectSession) WriteFramePacket(cmd byte, packet []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return net.ErrClosed
	}
	if s.failWrite != nil {
		return s.failWrite
	}
	cp := make([]byte, len(packet))
	copy(cp, packet)
	s.written = append(s.written, cp)
	return nil
}

func (s *mockDirectSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isClosed = true
	return nil
}

func (s *mockDirectSession) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isClosed
}

func (s *mockDirectSession) popPacket() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.written) == 0 {
		return nil
	}
	pkt := s.written[0]
	s.written = s.written[1:]
	return pkt
}

func (s *mockDirectSession) packetCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.written)
}

func (s *mockDirectSession) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.written = nil
}

type mockConcurrentSession struct {
	onPacket func(cmd byte, packet []byte)
	isClosed atomic.Bool
}

func (s *mockConcurrentSession) WriteFramePacket(cmd byte, packet []byte) error {
	if s.isClosed.Load() {
		return net.ErrClosed
	}
	s.onPacket(cmd, packet)
	return nil
}

func (s *mockConcurrentSession) Close() error {
	s.isClosed.Store(true)
	return nil
}

func (s *mockConcurrentSession) IsClosed() bool {
	return s.isClosed.Load()
}

// performInBandNegotiation 驱动双端完成标准的带内 IP 协商握手
func performInBandNegotiation(t *testing.T, clientEngine *ClientEngine, serverEngine *ServerEngine, session *mockDirectSession) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				req := session.popPacket()
				if req != nil {
					_ = serverEngine.HandleUplink(session, req)
					goto waitResp
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
	waitResp:
		for {
			select {
			case <-ctx.Done():
				return
			default:
				resp := session.popPacket()
				if resp != nil {
					clientEngine.HandleDownlink(resp)
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

	err := clientEngine.Initialize(ctx)
	require.NoError(t, err)
	<-done
	require.True(t, clientEngine.IsReady())
}

// ---------------------------------------------------------------------------
// 1. Radix Table: 完整 LPM、边界默认路由与并发安全测试
// ---------------------------------------------------------------------------

func TestRadixTable_BasicAndLPM(t *testing.T) {
	table := NewTable[string]()

	table.Insert(netip.MustParsePrefix("0.0.0.0/0"), "default-v4")
	table.Insert(netip.MustParsePrefix("100.64.0.0/24"), "subnet-v4")
	table.Insert(netip.MustParsePrefix("100.64.0.5/32"), "host-5")
	table.Insert(netip.MustParsePrefix("::/0"), "default-v6")
	table.Insert(netip.MustParsePrefix("fd00::/64"), "subnet-v6")
	table.Insert(netip.MustParsePrefix("fd00::1/128"), "host-v6-1")

	val, ok := table.Lookup(netip.MustParseAddr("100.64.0.5"))
	require.True(t, ok)
	require.Equal(t, "host-5", val)

	val, ok = table.Lookup(netip.MustParseAddr("100.64.0.6"))
	require.True(t, ok)
	require.Equal(t, "subnet-v4", val)

	val, ok = table.Lookup(netip.MustParseAddr("8.8.8.8"))
	require.True(t, ok)
	require.Equal(t, "default-v4", val)

	val, ok = table.Lookup(netip.MustParseAddr("fd00::1"))
	require.True(t, ok)
	require.Equal(t, "host-v6-1", val)

	val, ok = table.Lookup(netip.MustParseAddr("fd00::2"))
	require.True(t, ok)
	require.Equal(t, "subnet-v6", val)

	val, ok = table.Lookup(netip.MustParseAddr("2001:4860:4860::8888"))
	require.True(t, ok)
	require.Equal(t, "default-v6", val)

	table.Remove(netip.MustParsePrefix("100.64.0.5/32"))
	val, ok = table.Lookup(netip.MustParseAddr("100.64.0.5"))
	require.True(t, ok)
	require.Equal(t, "subnet-v4", val)

	table.RemoveByValue(func(v string) bool { return v == "subnet-v4" })
	val, ok = table.Lookup(netip.MustParseAddr("100.64.0.5"))
	require.True(t, ok)
	require.Equal(t, "default-v4", val)

	table.Remove(netip.MustParsePrefix("0.0.0.0/0"))
	_, ok = table.Lookup(netip.MustParseAddr("8.8.8.8"))
	require.False(t, ok)

	table.Clear()
	_, ok = table.Lookup(netip.MustParseAddr("fd00::2"))
	require.False(t, ok)
}

func TestRadixTable_Concurrency(t *testing.T) {
	table := NewTable[int]()
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, byte(workerID), byte(j)}), 32)
				table.Insert(prefix, workerID*1000+j)
				table.Lookup(prefix.Addr())
				if j%2 == 0 {
					table.Remove(prefix)
				}
			}
		}(i)
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				table.Lookup(netip.MustParseAddr("100.64.0.1"))
			}
		}()
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// 2. IPAM: 配置校验、点对点子网 (/127)、双栈协同、CAS 滑动续约与粘性映射清理
// ---------------------------------------------------------------------------

func TestIPAM_AddressValidation(t *testing.T) {
	_, err := NewIPAM(nil)
	require.ErrorIs(t, err, ErrAddressEmpty)
	_, err = NewIPAM([]netip.Prefix{})
	require.ErrorIs(t, err, ErrAddressEmpty)

	_, err = NewIPAM([]netip.Prefix{
		netip.MustParsePrefix("100.64.0.1/24"),
		netip.MustParsePrefix("100.65.0.1/24"),
	})
	require.ErrorIs(t, err, ErrTooManyIPv4Subnets)

	_, err = NewIPAM([]netip.Prefix{
		netip.MustParsePrefix("fd00::1/64"),
		netip.MustParsePrefix("fd01::1/64"),
	})
	require.ErrorIs(t, err, ErrTooManyIPv6Subnets)

	ipam4, err := NewIPAM([]netip.Prefix{netip.MustParsePrefix("100.64.0.1/24")})
	require.NoError(t, err)
	require.True(t, ipam4.HasV4())
	require.False(t, ipam4.HasV6())

	ipam6, err := NewIPAM([]netip.Prefix{netip.MustParsePrefix("fd00::1/64")})
	require.NoError(t, err)
	require.False(t, ipam4.HasV6())
	require.True(t, ipam6.HasV6())

	ipamDual, err := NewIPAM([]netip.Prefix{
		netip.MustParsePrefix("100.64.0.1/24"),
		netip.MustParsePrefix("fd00::1/64"),
	})
	require.NoError(t, err)
	require.True(t, ipamDual.HasV4())
	require.True(t, ipamDual.HasV6())
}

func TestIPAM_IPv6PointToPoint127(t *testing.T) {
	ipam127, err := NewIPAM([]netip.Prefix{netip.MustParsePrefix("fd00::/127")})
	require.NoError(t, err)
	require.True(t, ipam127.HasV6())

	_, addr, flags, _, err := ipam127.AllocateDualStackForSession(1001, 5*time.Minute, false, netip.Addr{}, true, netip.Addr{})
	require.NoError(t, err)
	require.Equal(t, byte(0x02), flags)
	require.Equal(t, netip.MustParseAddr("fd00::"), addr)

	_, _, _, _, err = ipam127.AllocateDualStackForSession(1002, 5*time.Minute, false, netip.Addr{}, true, netip.Addr{})
	require.ErrorIs(t, err, ErrSubnetExhausted)

	ipam127.Release(addr)
	_, reAlloc, _, _, err := ipam127.AllocateDualStackForSession(1003, 5*time.Minute, false, netip.Addr{}, true, netip.Addr{})
	require.NoError(t, err)
	require.Equal(t, addr, reAlloc)
}

func TestIPAM_DualStackAllocationAndReclaim(t *testing.T) {
	ipam, err := NewIPAM([]netip.Prefix{
		netip.MustParsePrefix("100.64.0.1/24"),
		netip.MustParsePrefix("fd00::1/64"),
	})
	require.NoError(t, err)

	clientID := uint64(987654321)
	v4, v6, flags, token, err := ipam.AllocateDualStackForSession(clientID, 5*time.Minute, true, netip.Addr{}, true, netip.Addr{})
	require.NoError(t, err)
	require.Equal(t, byte(0x03), flags)
	require.NotZero(t, token)
	require.True(t, v4.Is4())
	require.Equal(t, netip.MustParseAddr("100.64.0.2"), v4)
	require.True(t, v6.Is6())
	require.NotEqual(t, netip.MustParseAddr("fd00::1"), v6)

	require.True(t, ipam.TouchWithDuration(v4, 5*time.Minute))
	require.True(t, ipam.TouchWithDuration(v6, 5*time.Minute))

	reclaimed := ipam.ReclaimLease(v4, clientID, token, 10*time.Minute)
	require.True(t, reclaimed)

	require.True(t, ipam.ValidateClientAndTouch(v4, clientID, 5*time.Minute))
	require.False(t, ipam.ValidateClientAndTouch(v4, clientID+1, 5*time.Minute), "非持有人 ClientID 必须校验失败")
	require.False(t, ipam.ValidateClientAndTouch(v4, 0, 5*time.Minute), "非法 ClientID=0 必须校验失败")

	require.False(t, ipam.ReclaimLease(v4, clientID, token+1, 10*time.Minute))
	require.False(t, ipam.ReclaimLease(v4, clientID+1, token, 10*time.Minute))

	ipam.Release(v4)
	ipam.Release(v6)
	require.False(t, ipam.TouchWithDuration(v4, 5*time.Minute))
	require.False(t, ipam.TouchWithDuration(v6, 5*time.Minute))
}

func TestIPAM_StickyMapCleanupOnPurge(t *testing.T) {
	ipam, err := NewIPAM([]netip.Prefix{netip.MustParsePrefix("100.64.0.1/24")})
	require.NoError(t, err)

	clientID := uint64(123456)
	v4, _, _, _, err := ipam.AllocateDualStackForSession(clientID, 5*time.Minute, true, netip.Addr{}, false, netip.Addr{})
	require.NoError(t, err)

	ipam.mu.RLock()
	require.Equal(t, v4, ipam.v4Pool.stickyMap[clientID])
	ipam.mu.RUnlock()

	ipam.mu.Lock()
	ipam.v4Pool.leases[v4].SetExpireAt(time.Now().Add(-1 * time.Second))
	ipam.mu.Unlock()

	purged := ipam.PurgeExpired()
	require.Contains(t, purged, v4)

	ipam.mu.RLock()
	_, exists := ipam.v4Pool.stickyMap[clientID]
	ipam.mu.RUnlock()
	require.False(t, exists, "租约过期 Purge 后 stickyMap 中的映射必须被同步清理以防内存泄漏")
}

func TestIPAM_LeaseDurationClamping(t *testing.T) {
	require.Equal(t, DefaultLeaseDuration, ClampLeaseDuration(0))
	require.Equal(t, DefaultLeaseDuration, ClampLeaseDuration(-1*time.Minute))
	require.Equal(t, MinLeaseDuration, ClampLeaseDuration(1*time.Minute))
	require.Equal(t, MinLeaseDuration, ClampLeaseDuration(4*time.Minute+59*time.Second))
	require.Equal(t, 5*time.Minute, ClampLeaseDuration(5*time.Minute))
	require.Equal(t, 2*time.Hour, ClampLeaseDuration(2*time.Hour))
	require.Equal(t, 7*24*time.Hour, ClampLeaseDuration(7*24*time.Hour))
	require.Equal(t, MaxLeaseDuration, ClampLeaseDuration(8*24*time.Hour))
}

func TestIPAM_Touch_ThrottleAndCAS(t *testing.T) {
	ipam, err := NewIPAM([]netip.Prefix{netip.MustParsePrefix("100.64.0.1/24")})
	require.NoError(t, err)

	clientID := uint64(112233)
	v4, _, _, _, err := ipam.AllocateDualStackForSession(clientID, 5*time.Minute, true, netip.Addr{}, false, netip.Addr{})
	require.NoError(t, err)

	require.True(t, ipam.TouchWithDuration(v4, 5*time.Minute))
	require.False(t, ipam.TouchWithDuration(netip.MustParseAddr("100.64.0.99"), 5*time.Minute))

	ipam.mu.RLock()
	lease := ipam.v4Pool.leases[v4]
	ipam.mu.RUnlock()
	require.NotNil(t, lease)
	oldExpire := lease.ExpireAt()

	require.True(t, ipam.TouchWithDuration(v4, 10*time.Minute))
	require.Equal(t, oldExpire, lease.ExpireAt(), "15秒节流窗口内时间戳应受保护不发生写入")

	lease.lastTouch.Store(time.Now().Unix() - 20)
	require.True(t, ipam.TouchWithDuration(v4, 10*time.Minute))
	newExpire := lease.ExpireAt()
	require.True(t, newExpire.After(oldExpire), "节流窗口过后应原子顺延租约时间戳")
}

// ---------------------------------------------------------------------------
// 3. 纯三层无状态转发验证与上行 8 字节 ClientID 字段验证 (TCP / ICMP)
// ---------------------------------------------------------------------------

func TestStatelessForwarding_TCP_ICMP_And_8ByteClientID(t *testing.T) {
	var tunWritten [][]byte
	var tunMu sync.Mutex

	serverEngine, err := NewServerEngine(ServerEngineOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/24")},
		MTU:     1400,
		WriteTUN: func(packet []byte) error {
			tunMu.Lock()
			defer tunMu.Unlock()
			cp := make([]byte, len(packet))
			copy(cp, packet)
			tunWritten = append(tunWritten, cp)
			return nil
		},
	})
	require.NoError(t, err)
	defer serverEngine.Close()

	session := &mockDirectSession{}
	clientEngine := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return session, nil
		},
	})

	performInBandNegotiation(t, clientEngine, serverEngine, session)
	assignedIP := clientEngine.AssignedIPv4()
	require.True(t, assignedIP.IsValid())
	clientID := clientEngine.ClientID()

	tunReturn := &mockTunReturn{}
	require.NoError(t, clientEngine.AttachReturn(tunReturn))
	defer clientEngine.DetachReturn(tunReturn)

	targetDst := netip.MustParseAddrPort("8.8.8.8:80")

	// 1. TCP 无状态转发验证及上行 8 字节 ClientID 校验
	tcpSrc := netip.AddrPortFrom(assignedIP, 12345)
	tcpPkt := buildTestIPv4TCP(tcpSrc, targetDst, 1000, 0, header.TCPFlagSyn, nil)
	require.NoError(t, clientEngine.WritePackets([][]byte{tcpPkt}))

	fromClient := session.popPacket()
	require.NotNil(t, fromClient)
	require.Equal(t, 8+len(tcpPkt), len(fromClient), "上行数据包必须为 8 字节 ClientID + IP 报文")
	require.Equal(t, clientID, binary.BigEndian.Uint64(fromClient[:8]), "前置 8 字节必须为当前 ClientID")
	require.Equal(t, tcpPkt, fromClient[8:], "8 字节之后必须为原始 IP 报文")

	require.NoError(t, serverEngine.HandleUplink(session, fromClient))

	tunMu.Lock()
	require.Len(t, tunWritten, 1)
	require.Equal(t, tcpPkt, tunWritten[0])
	tunWritten = nil
	tunMu.Unlock()

	// 2. ICMP Echo Request / Reply 无状态透传验证 (保留原始 ID 与 Seq)
	const icmpID uint16 = 0xABCD
	const icmpSeq uint16 = 42
	icmpReq := buildTestIPv4ICMPEcho(assignedIP, targetDst.Addr(), 8, 0, icmpID, icmpSeq, []byte("ping-req"))
	require.NoError(t, clientEngine.WritePackets([][]byte{icmpReq}))

	fromClient = session.popPacket()
	require.NotNil(t, fromClient)
	require.Equal(t, clientID, binary.BigEndian.Uint64(fromClient[:8]), "ICMP 报文必须同样自包含 8 字节 ClientID")
	require.Equal(t, icmpReq, fromClient[8:])

	require.NoError(t, serverEngine.HandleUplink(session, fromClient))

	tunMu.Lock()
	require.Len(t, tunWritten, 1)
	receivedICMP := tunWritten[0]
	tunWritten = nil
	tunMu.Unlock()

	require.Equal(t, uint8(header.ICMPv4ProtocolNumber), header.IPv4(receivedICMP).Protocol())
	require.Equal(t, uint8(8), receivedICMP[20])
	require.Equal(t, icmpID, binary.BigEndian.Uint16(receivedICMP[24:26]), "ICMP ID 必须完整保留")
	require.Equal(t, icmpSeq, binary.BigEndian.Uint16(receivedICMP[26:28]), "ICMP Seq 必须完整保留")

	// 3. 下行 ICMP Echo Reply 透传 (下行是纯 IP 报文，无需前缀)
	icmpReply := buildTestIPv4ICMPEcho(targetDst.Addr(), assignedIP, 0, 0, icmpID, icmpSeq, []byte("ping-reply"))
	require.NoError(t, serverEngine.HandleDownlink(icmpReply))

	require.Eventually(t, func() bool {
		return session.packetCount() == 1
	}, 500*time.Millisecond, 5*time.Millisecond)

	toClient := session.popPacket()
	clientEngine.HandleDownlink(toClient)

	tunReturn.mu.Lock()
	require.Len(t, tunReturn.packets, 1)
	clientICMP := tunReturn.packets[0]
	tunReturn.packets = nil
	tunReturn.mu.Unlock()

	require.Equal(t, uint8(0), clientICMP[20])
	require.Equal(t, icmpID, binary.BigEndian.Uint16(clientICMP[24:26]))
	require.Equal(t, icmpSeq, binary.BigEndian.Uint16(clientICMP[26:28]))
}

// ---------------------------------------------------------------------------
// 4. 物理连接中断后，同步屏障自动重绑与 0-RTT 首包直发自愈测试
// ---------------------------------------------------------------------------

func TestLevel2Routing_RoamingAndDownlinkSelfHealing(t *testing.T) {
	var tunWritten [][]byte
	var tunMu sync.Mutex

	serverEngine, err := NewServerEngine(ServerEngineOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/24")},
		MTU:     1400,
		WriteTUN: func(packet []byte) error {
			tunMu.Lock()
			defer tunMu.Unlock()
			cp := make([]byte, len(packet))
			copy(cp, packet)
			tunWritten = append(tunWritten, cp)
			return nil
		},
	})
	require.NoError(t, err)
	defer serverEngine.Close()

	session1 := &mockDirectSession{}
	clientEngine := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return session1, nil
		},
	})

	performInBandNegotiation(t, clientEngine, serverEngine, session1)
	assignedIP := clientEngine.AssignedIPv4()
	require.True(t, assignedIP.IsValid())
	clientID := clientEngine.ClientID()

	tunReturn := &mockTunReturn{}
	require.NoError(t, clientEngine.AttachReturn(tunReturn))
	defer clientEngine.DetachReturn(tunReturn)

	targetDst := netip.MustParseAddrPort("8.8.8.8:80")

	// 1. 在 session1 上发送第一个数据包并验证出接口绑定
	tcpPkt1 := buildTestIPv4TCP(netip.AddrPortFrom(assignedIP, 10001), targetDst, 100, 0, header.TCPFlagSyn, nil)
	require.NoError(t, clientEngine.WritePackets([][]byte{tcpPkt1}))
	frame1 := session1.popPacket()
	require.NotNil(t, frame1)
	require.NoError(t, serverEngine.HandleUplink(session1, frame1))

	serverEngine.sessionsMu.RLock()
	require.Equal(t, session1, serverEngine.activeSessions[clientID], "初始状态 Level 2 路由应绑定 session1")
	serverEngine.sessionsMu.RUnlock()

	// 2. 模拟物理会话 session1 异常中断并注销
	_ = session1.Close()
	serverEngine.UnregisterSession(session1)

	// 验证 Level 1 逻辑路由依然保留，未随物理会话注销而删除
	lookupCID, ok := serverEngine.routes.Lookup(assignedIP)
	require.True(t, ok, "物理连接断开后 Level 1 路由必须持久保留")
	require.Equal(t, clientID, lookupCID)

	// 3. 客户端切换会话提供器为 session2；此时客户端持有的 currentSession 依然是已关闭的 session1
	session2 := &mockDirectSession{}
	clientEngine.SetSessionProvider(func(ctx context.Context) (Session, error) {
		return session2, nil
	})

	tcpPkt2 := buildTestIPv4TCP(netip.AddrPortFrom(assignedIP, 10002), targetDst, 200, 0, header.TCPFlagSyn, nil)
	// 发包触发同步屏障：自动检测 session1 关闭，同步拨号拿到 session2 并直接发射首包（不丢弃！）
	require.NoError(t, clientEngine.WritePackets([][]byte{tcpPkt2}))

	require.Equal(t, session2, clientEngine.CurrentSession(), "发包后当前锁存会话必须自动同步换乘为 session2")
	frame2 := session2.popPacket()
	require.NotNil(t, frame2, "触发换乘的业务首包必须直接送出，绝不能被异步微观丢弃")
	require.Equal(t, clientID, binary.BigEndian.Uint64(frame2[:8]), "新连接直发报文仍自包含 ClientID")

	// 服务端收到新连接直发报文，触发 Level 2 自动漫游自愈
	require.NoError(t, serverEngine.HandleUplink(session2, frame2))

	serverEngine.sessionsMu.RLock()
	require.Equal(t, session2, serverEngine.activeSessions[clientID], "Level 2 路由应自愈重定向至 session2")
	serverEngine.sessionsMu.RUnlock()

	// 4. 验证下行流量通过 Level 2 路由平滑送往 session2
	downlinkPkt := buildTestIPv4TCP(targetDst, netip.AddrPortFrom(assignedIP, 10002), 0, 201, header.TCPFlagSyn|header.TCPFlagAck, nil)
	require.NoError(t, serverEngine.HandleDownlink(downlinkPkt))

	require.Eventually(t, func() bool {
		return session2.packetCount() == 1
	}, 500*time.Millisecond, 5*time.Millisecond)

	toClient := session2.popPacket()
	clientEngine.HandleDownlink(toClient)

	tunReturn.mu.Lock()
	require.Len(t, tunReturn.packets, 1)
	expectedDownlink := buildTestIPv4TCP(targetDst, netip.AddrPortFrom(LocalPortIPv4, 10002), 0, 201, header.TCPFlagSyn|header.TCPFlagAck, nil)
	require.Equal(t, expectedDownlink, tunReturn.packets[0], "下行回包应成功穿透自愈后的 session2 交付本地网卡（目的地址经 1:1 NAT 还原为本地端口地址）")
	tunReturn.packets = nil
	tunReturn.mu.Unlock()
}

// ---------------------------------------------------------------------------
// 5. 验证 UDP drop / reject / transparent 三模式行为测试
// ---------------------------------------------------------------------------

func TestUDP_ModeHandling(t *testing.T) {
	// A. drop 模式验证（默认）：完全不触发 GetSession，零通信拦截
	var getSessionCalled atomic.Int32
	session := &mockDirectSession{}

	clientDrop := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		UDP:     "drop",
		GetSession: func(ctx context.Context) (Session, error) {
			getSessionCalled.Add(1)
			return session, nil
		},
	})

	tunReturn := &mockTunReturn{}
	require.NoError(t, clientDrop.AttachReturn(tunReturn))
	defer clientDrop.DetachReturn(tunReturn)

	udpPkt := buildTestIPv4UDP(netip.MustParseAddrPort("100.64.0.2:12345"), netip.MustParseAddrPort("8.8.8.8:53"), []byte("dns-query"))
	err := clientDrop.WritePackets([][]byte{udpPkt})
	require.NoError(t, err)

	require.Equal(t, int32(0), getSessionCalled.Load(), "UDP drop 模式下绝对不得调用 GetSession")
	require.Equal(t, 0, session.packetCount(), "UDP drop 模式下不得产生任何物理帧")
	tunReturn.mu.Lock()
	require.Empty(t, tunReturn.packets, "UDP drop 模式下本地网卡不得收到反弹包")
	tunReturn.mu.Unlock()

	// B. reject 模式验证：就地构造 ICMP Port Unreachable 回注本地网卡，零网络通信
	clientReject := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		UDP:     "reject",
		GetSession: func(ctx context.Context) (Session, error) {
			getSessionCalled.Add(1)
			return session, nil
		},
	})
	tunReturnReject := &mockTunReturn{}
	require.NoError(t, clientReject.AttachReturn(tunReturnReject))
	defer clientReject.DetachReturn(tunReturnReject)

	err = clientReject.WritePackets([][]byte{udpPkt})
	require.NoError(t, err)

	require.Equal(t, int32(0), getSessionCalled.Load(), "UDP reject 模式下绝对不得调用 GetSession")
	require.Equal(t, 0, session.packetCount(), "UDP reject 模式下不得产生任何物理帧")

	tunReturnReject.mu.Lock()
	require.Len(t, tunReturnReject.packets, 1, "UDP reject 模式下必须向本地网卡回注 ICMP 差错")
	icmpReply := tunReturnReject.packets[0]
	tunReturnReject.mu.Unlock()

	require.Equal(t, uint8(header.ICMPv4ProtocolNumber), header.IPv4(icmpReply).Protocol())
	require.Equal(t, uint8(3), icmpReply[20], "ICMP Type 必须为 3 (Destination Unreachable)")
	require.Equal(t, uint8(3), icmpReply[21], "ICMP Code 必须为 3 (Port Unreachable)")

	// C. transparent 模式验证：PreMatchFlow 旁路放行
	clientTrans := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		UDP:     "transparent",
	})
	require.False(t, clientTrans.PreMatchFlow("udp"), "transparent 模式下 UDP 必须返回 false 放行给上层 UoT")
	require.True(t, clientTrans.PreMatchFlow("tcp"), "transparent 模式下 TCP 必须由 PseudoVPN 接管")
	require.True(t, clientTrans.PreMatchFlow("icmp"), "transparent 模式下 ICMP 必须由 PseudoVPN 接管")
}

// ---------------------------------------------------------------------------
// 6. 按需单飞节流与初始冷启动握手测试 (Cold Start Demand-Driven Negotiation)
// ---------------------------------------------------------------------------

func TestSingleflight_CooldownAndDemandDriven(t *testing.T) {
	session := &mockDirectSession{}
	clientEngine := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return session, nil
		},
	})
	require.False(t, clientEngine.IsReady())

	targetDst := netip.MustParseAddrPort("8.8.8.8:80")
	tcpPkt := buildTestIPv4TCP(netip.MustParseAddrPort("100.64.0.2:12345"), targetDst, 100, 0, header.TCPFlagSyn, nil)

	// 1. 冷启动未就绪态下高频发包，仅允许触发 1 次握手请求 (Singleflight 保护)
	for i := 0; i < 10; i++ {
		_ = clientEngine.WritePackets([][]byte{tcpPkt})
	}

	require.Eventually(t, func() bool {
		return session.packetCount() == 1
	}, 500*time.Millisecond, 10*time.Millisecond)

	req := session.popPacket()
	require.NotNil(t, req)
	require.Equal(t, PacketTypeIPRequest, req[0])

	// 2. 在 2 秒冷却期内再次发包，严禁触发多余握手 (Cooldown 保护)
	for i := 0; i < 10; i++ {
		_ = clientEngine.WritePackets([][]byte{tcpPkt})
	}
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 0, session.packetCount(), "冷却期内高频发包绝对不产生新的出站握手请求")

	// 3. 服务端返回响应，客户端转为可用状态
	resp := make([]byte, 83)
	resp[0] = PacketTypeIPResponse
	resp[1] = 0 // Success
	resp[2] = 0x01
	v4 := netip.MustParseAddr("100.64.0.2")
	v4Bytes := v4.As16()
	copy(resp[3:19], v4Bytes[:])
	binary.BigEndian.PutUint32(resp[67:71], 1400)
	clientEngine.HandleDownlink(resp)

	require.True(t, clientEngine.IsReady())

	// 4. 可用状态下发包正常流出并前置 8 字节 ClientID
	require.NoError(t, clientEngine.WritePackets([][]byte{tcpPkt}))
	require.Equal(t, 1, session.packetCount())
	forwarded := session.popPacket()
	require.Equal(t, clientEngine.ClientID(), binary.BigEndian.Uint64(forwarded[:8]))
}

// ---------------------------------------------------------------------------
// 7. 三层状态单向就绪测试 (Plan A 核心：初次握手后永久 Ready)
// ---------------------------------------------------------------------------

func TestClientEngine_IsReady_Persistent(t *testing.T) {
	clientEngine := NewClientEngine(ClientEngineOptions{Enabled: true, MTU: 1400})
	require.False(t, clientEngine.IsReady())

	v4 := netip.MustParseAddr("100.64.0.2")
	clientEngine.OnNegotiatedDualStack(v4, netip.MustParseAddr("100.64.0.1"), netip.Addr{}, netip.Addr{}, 1400)
	require.True(t, clientEngine.IsReady())

	// Plan A 单向可用准则：只要曾经协商成功分配了 IP，客户端绝不主动降级为未就绪态
	require.True(t, clientEngine.IsReady(), "协商分配 IP 后 IsReady 必须持久返回 true")
}

// ---------------------------------------------------------------------------
// 8. 下行 IPResponse 重复应答防抖测试
// ---------------------------------------------------------------------------

func TestClientEngine_HandleDownlink_ResponseDedup(t *testing.T) {
	clientEngine := NewClientEngine(ClientEngineOptions{Enabled: true, MTU: 1400})
	v4 := netip.MustParseAddr("100.64.0.2")
	clientEngine.OnNegotiatedDualStack(v4, netip.MustParseAddr("100.64.0.1"), netip.Addr{}, netip.Addr{}, 1400)
	require.True(t, clientEngine.IsReady())

	oldToken := uint64(12345)
	clientEngine.SetLeaseToken(oldToken)

	// 构造相同 IP 但新 Token 的 IPResponse 回包
	resp := make([]byte, 83)
	resp[0] = PacketTypeIPResponse
	resp[1] = 0
	resp[2] = 0x01
	v4Bytes := v4.As16()
	copy(resp[3:19], v4Bytes[:])
	binary.BigEndian.PutUint32(resp[67:71], 1400)
	newToken := uint64(67890)
	binary.BigEndian.PutUint64(resp[75:83], newToken)

	clientEngine.HandleDownlink(resp)

	// 状态机平稳未发生震荡，Token 被平滑刷新
	require.True(t, clientEngine.IsReady())
	require.Equal(t, newToken, clientEngine.LeaseToken(), "重复应答防抖分支应平滑更新 Token")
}

// ---------------------------------------------------------------------------
// 9. NACK 精准状态降级与自愈测试
// ---------------------------------------------------------------------------

func TestNACK_DegradeAndAutoRecover(t *testing.T) {
	session := &mockDirectSession{}
	clientEngine := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return session, nil
		},
	})

	v4 := netip.MustParseAddr("100.64.0.2")
	clientEngine.OnNegotiatedDualStack(v4, netip.MustParseAddr("100.64.0.1"), netip.Addr{}, netip.Addr{}, 1400)
	clientEngine.SetCurrentSession(session)
	require.True(t, clientEngine.IsReady())

	// 1. 模拟收到与当前 IP 不符的 NACK（如其他客户端冲突报文），必须被静默忽略
	otherNack := make([]byte, 18)
	otherNack[0] = PacketTypeIPExpired
	otherV4 := netip.MustParseAddr("100.64.0.99").As16()
	copy(otherNack[2:18], otherV4[:])
	clientEngine.HandleDownlink(otherNack)
	require.True(t, clientEngine.IsReady(), "不匹配自身虚拟 IP 的 NACK 必须直接忽略")

	// 2. 模拟收到服务端针对当前虚拟 IP 的 IPExpired NACK
	nack := make([]byte, 18)
	nack[0] = PacketTypeIPExpired
	v4Bytes := v4.As16()
	copy(nack[2:18], v4Bytes[:])
	clientEngine.HandleDownlink(nack)

	require.False(t, clientEngine.IsReady(), "收到匹配的 IPExpired NACK 后必须精准降级为未就绪状态")
	// 租约失效不代表物理会话失效，保留会话直接在其上重新协商，避免无谓地新建连接。
	require.True(t, clientEngine.CurrentSession() == Session(session), "租约失效时应保留仍然健康的物理会话")

	// 3. 校验 HandleDownlink 自动触发后台重连协商
	require.Eventually(t, func() bool {
		return session.packetCount() == 1
	}, 1*time.Second, 10*time.Millisecond)

	req := session.popPacket()
	require.NotNil(t, req)
	require.Equal(t, PacketTypeIPRequest, req[0], "降级后后台协程应自动发出新的协商请求帧")
}

// ---------------------------------------------------------------------------
// 10. 物理重绑同步屏障测试 (0-RTT 首包同步发射与刚性超时熔断)
// ---------------------------------------------------------------------------

func TestClientEngine_SyncRecoveryBarrier(t *testing.T) {
	// A. 成功分支：物理会话失效时，发包同步触发 GetSession 并在当前调用内直接将数据包发出（0-RTT 首包零丢失）
	sessionNew := &mockDirectSession{}
	clientEngine := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			time.Sleep(15 * time.Millisecond)
			return sessionNew, nil
		},
	})
	v4 := netip.MustParseAddr("100.64.0.2")
	clientEngine.OnNegotiatedDualStack(v4, netip.MustParseAddr("100.64.0.1"), netip.Addr{}, netip.Addr{}, 1400)
	require.True(t, clientEngine.IsReady())

	require.Nil(t, clientEngine.CurrentSession())

	pkt := buildTestIPv4TCP(netip.AddrPortFrom(v4, 12345), netip.MustParseAddrPort("8.8.8.8:80"), 1000, 0, header.TCPFlagSyn, nil)
	err := clientEngine.WritePackets([][]byte{pkt})
	require.NoError(t, err)

	require.Equal(t, sessionNew, clientEngine.CurrentSession(), "同步屏障必须就地原子更新 CurrentSession")
	require.Equal(t, 1, sessionNew.packetCount(), "首包必须在当次发包中直接推入新物理通道，严禁被微观丢弃")

	// B. 超时熔断保护：底层拨号长时间卡死时，2秒刚性超时熔断生效，安全返回 nil，严禁发生永久死锁
	clientEngineTimeout := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(10 * time.Second):
				return &mockDirectSession{}, nil
			}
		},
	})
	clientEngineTimeout.OnNegotiatedDualStack(v4, netip.MustParseAddr("100.64.0.1"), netip.Addr{}, netip.Addr{}, 1400)
	require.True(t, clientEngineTimeout.IsReady())

	start := time.Now()
	err = clientEngineTimeout.WritePackets([][]byte{pkt})
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.GreaterOrEqual(t, elapsed, 1800*time.Millisecond, "网络阻塞时同步屏障必须在约 2 秒时熔断退出")
	require.Less(t, elapsed, 3000*time.Millisecond, "严禁发生死锁无限制挂起网卡读循环")
}

// 写失败但会话仍存活（例如抢写锁超时）时只丢弃报文：复用会话上可能还承载着其他代理流，
// 不能因一个三层报文写不出去就关闭它。会话因写错误已关闭时才清空锁存指针以便重建。
func TestClientEngine_WriteFailureKeepsLiveSession(t *testing.T) {
	session := &mockDirectSession{
		failWrite: errors.New("write deadline exceeded"),
	}
	clientEngine := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return session, nil
		},
	})
	v4 := netip.MustParseAddr("100.64.0.2")
	clientEngine.OnNegotiatedDualStack(v4, netip.MustParseAddr("100.64.0.1"), netip.Addr{}, netip.Addr{}, 1400)
	clientEngine.SetCurrentSession(session)
	require.True(t, clientEngine.IsReady())

	pkt := buildTestIPv4TCP(netip.AddrPortFrom(v4, 12345), netip.MustParseAddrPort("8.8.8.8:80"), 1000, 0, header.TCPFlagSyn, nil)
	err := clientEngine.WritePackets([][]byte{pkt})
	require.NoError(t, err)
	require.False(t, session.IsClosed(), "会话仍存活时写失败不得关闭复用会话")
	require.True(t, clientEngine.CurrentSession() == Session(session), "会话仍存活时应保留锁存指针")

	require.NoError(t, session.Close())
	session.failWrite = nil
	replacement := &mockDirectSession{}
	clientEngine.SetSessionProvider(func(ctx context.Context) (Session, error) {
		return replacement, nil
	})
	pkt = buildTestIPv4TCP(netip.AddrPortFrom(v4, 12345), netip.MustParseAddrPort("8.8.8.8:80"), 1000, 0, header.TCPFlagSyn, nil)
	require.NoError(t, clientEngine.WritePackets([][]byte{pkt}))
	require.True(t, clientEngine.CurrentSession() == Session(replacement), "会话关闭后必须换用新会话")
	require.Equal(t, 1, replacement.packetCount())
}

// ---------------------------------------------------------------------------
// 11. RFC 5508 / RFC 4443 ICMP & ICMPv6 差错报文深度反向 NAT 改写验证
// ---------------------------------------------------------------------------

func TestRFC5508_ICMPErrorPacketRewrite(t *testing.T) {
	virtualIP := netip.MustParseAddr("100.64.0.2")
	localIP := netip.MustParseAddr("172.19.0.1")
	remoteDst := netip.MustParseAddr("8.8.8.8")

	innerTCP := buildTestIPv4TCP(netip.AddrPortFrom(virtualIP, 12345), netip.AddrPortFrom(remoteDst, 80), 1000, 0, header.TCPFlagSyn, nil)

	totalLen := 20 + 8 + len(innerTCP)
	outerPkt := make([]byte, totalLen)
	outerPkt[0] = 0x45
	binary.BigEndian.PutUint16(outerPkt[2:4], uint16(totalLen))
	outerPkt[8] = 64
	outerPkt[9] = uint8(header.ICMPv4ProtocolNumber)

	remoteDst4 := remoteDst.As4()
	virtualIP4 := virtualIP.As4()
	copy(outerPkt[12:16], remoteDst4[:])
	copy(outerPkt[16:20], virtualIP4[:])
	binary.BigEndian.PutUint16(outerPkt[10:12], checksum(outerPkt[:20]))

	icmpPayload := outerPkt[20:]
	icmpPayload[0] = 3 // Destination Unreachable
	icmpPayload[1] = 4 // Fragmentation Needed
	copy(icmpPayload[8:], innerTCP)
	binary.BigEndian.PutUint16(icmpPayload[2:4], checksum(icmpPayload))

	rewritePacketDstIPv4(outerPkt, localIP)

	require.Equal(t, localIP, PacketDestinationIP(outerPkt))
	require.Equal(t, uint16(0), checksum(outerPkt[:20]))

	innerProcessed := outerPkt[28:]
	require.Equal(t, localIP, PacketSourceIP(innerProcessed))
	require.Equal(t, uint16(0), checksum(innerProcessed[:20]), "内嵌 IP 首部校验和必须重新计算且有效")
	require.Equal(t, uint16(0), checksum(outerPkt[20:]), "外层 ICMP 校验和必须重新计算且有效")
}

func TestRFC4443_ICMPv6PacketTooBigRewrite(t *testing.T) {
	virtualIPv6 := netip.MustParseAddr("fd00::2")
	localIPv6 := netip.MustParseAddr("fe80::1")
	remoteDst6 := netip.MustParseAddr("2001:4860:4860::8888")

	innerTCP := buildTestIPv6TCP(netip.AddrPortFrom(virtualIPv6, 12345), netip.AddrPortFrom(remoteDst6, 80), 1000, 0, header.TCPFlagSyn, nil)

	outerPkt := buildTestIPv6ICMP(remoteDst6, virtualIPv6, 2, 0, innerTCP)
	binary.BigEndian.PutUint32(outerPkt[44:48], 1280)
	outerPkt[42] = 0
	outerPkt[43] = 0
	csum := checksumWithIPv6Pseudo(remoteDst6, virtualIPv6, uint8(header.ICMPv6ProtocolNumber), outerPkt[40:])
	binary.BigEndian.PutUint16(outerPkt[42:44], csum)

	rewritePacketDstIPv6(outerPkt, localIPv6)

	require.Equal(t, localIPv6, PacketDestinationIP(outerPkt))
	require.Equal(t, uint16(0), checksumWithIPv6Pseudo(remoteDst6, localIPv6, uint8(header.ICMPv6ProtocolNumber), outerPkt[40:]))

	innerProcessed := outerPkt[48:]
	require.Equal(t, localIPv6, PacketSourceIP(innerProcessed), "内嵌 IPv6 首部的源地址必须改写为本地真实 IPv6 以解决 PMTUD 黑洞")
}

// ---------------------------------------------------------------------------
// 12. 大并发穿透测试 (80,000+ 流并发透传验证)
// ---------------------------------------------------------------------------

func TestHighConcurrency_80000_Flows(t *testing.T) {
	var tunReceived atomic.Int64

	serverEngine, err := NewServerEngine(ServerEngineOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/24")},
		MTU:     1400,
		WriteTUN: func(packet []byte) error {
			tunReceived.Add(1)
			return nil
		},
	})
	require.NoError(t, err)
	defer serverEngine.Close()

	var clientEngine *ClientEngine
	var session *mockConcurrentSession
	session = &mockConcurrentSession{
		onPacket: func(cmd byte, packet []byte) {
			if isControlPacket(packet) {
				switch packet[0] {
				case PacketTypeIPRequest:
					_ = serverEngine.HandleUplink(session, packet)
				case PacketTypeIPResponse, PacketTypeIPExpired:
					clientEngine.HandleDownlink(packet)
				}
				return
			}
			_ = serverEngine.HandleUplink(session, packet)
		},
	}

	clientEngine = NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return session, nil
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = clientEngine.Initialize(ctx)
	require.NoError(t, err)
	require.True(t, clientEngine.IsReady())

	assignedIP := clientEngine.AssignedIPv4()
	require.True(t, assignedIP.IsValid())

	const totalFlows = 80000
	const numGoroutines = 8
	const flowsPerGoroutine = totalFlows / numGoroutines
	const batchSize = 100

	targetDst := netip.MustParseAddrPort("8.8.8.8:443")

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(workerID int) {
			defer wg.Done()
			basePort := uint32(workerID * flowsPerGoroutine)

			for i := 0; i < flowsPerGoroutine; i += batchSize {
				batch := make([][]byte, batchSize)
				for j := 0; j < batchSize; j++ {
					port := uint16(1024 + (basePort+uint32(i+j))%60000)
					src := netip.AddrPortFrom(assignedIP, port)
					batch[j] = buildTestIPv4TCP(src, targetDst, 1000, 0, header.TCPFlagSyn, []byte("flow-payload"))
				}
				_ = clientEngine.WritePackets(batch)
			}
		}(g)
	}

	wg.Wait()

	require.Equal(t, int64(totalFlows), tunReceived.Load(), "80,000+ 并发 TCP 流必须全部无状态穿透交付给服务端的 TUN 网卡")
}

// ---------------------------------------------------------------------------
// 13. 长连接被动滑动续约与空闲自然超时测试
// ---------------------------------------------------------------------------

func TestLongConnection_PassiveLeaseRenewal(t *testing.T) {
	serverEngine, err := NewServerEngine(ServerEngineOptions{
		Address:       []netip.Prefix{netip.MustParsePrefix("100.64.0.1/24")},
		MTU:           1400,
		LeaseDuration: 5 * time.Minute,
	})
	require.NoError(t, err)
	defer serverEngine.Close()

	session := &mockDirectSession{}
	clientEngine := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return session, nil
		},
	})

	performInBandNegotiation(t, clientEngine, serverEngine, session)
	assignedIP := clientEngine.AssignedIPv4()
	require.True(t, assignedIP.IsValid())
	clientID := clientEngine.ClientID()
	session.clear()

	serverEngine.ipam.mu.RLock()
	lease := serverEngine.ipam.v4Pool.leases[assignedIP]
	serverEngine.ipam.mu.RUnlock()
	require.NotNil(t, lease)
	initialServerExpire := lease.ExpireAt()

	lease.lastTouch.Store(time.Now().Unix() - 20)

	dataPkt := buildTestIPv4TCP(netip.AddrPortFrom(assignedIP, 12345), netip.MustParseAddrPort("8.8.8.8:80"), 1000, 0, header.TCPFlagSyn, []byte("active-data"))
	require.NoError(t, clientEngine.WritePackets([][]byte{dataPkt}))

	fromClient := session.popPacket()
	require.NotNil(t, fromClient)
	require.Equal(t, clientID, binary.BigEndian.Uint64(fromClient[:8]))
	require.NoError(t, serverEngine.HandleUplink(session, fromClient))

	newServerExpire := lease.ExpireAt()

	require.True(t, newServerExpire.After(initialServerExpire), "服务端收包通过 Strict RPF 被动刷新服务端 IPAM 租约")
	require.True(t, serverEngine.ipam.ValidateClientAndTouch(assignedIP, clientID, 5*time.Minute))
}

func TestIdle_NaturalLeaseExpiration(t *testing.T) {
	serverEngine, err := NewServerEngine(ServerEngineOptions{
		Address:       []netip.Prefix{netip.MustParsePrefix("100.64.0.1/24")},
		MTU:           1400,
		LeaseDuration: 5 * time.Minute,
	})
	require.NoError(t, err)
	defer serverEngine.Close()

	session := &mockDirectSession{}
	clientEngine := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return session, nil
		},
	})

	performInBandNegotiation(t, clientEngine, serverEngine, session)
	assignedIP := clientEngine.AssignedIPv4()
	require.True(t, assignedIP.IsValid())
	clientID := clientEngine.ClientID()
	session.clear()

	time.Sleep(100 * time.Millisecond)
	require.Equal(t, 0, session.packetCount(), "空闲期必须保持绝对静默，严禁引入心跳协程")

	serverEngine.ipam.mu.RLock()
	lease := serverEngine.ipam.v4Pool.leases[assignedIP]
	serverEngine.ipam.mu.RUnlock()
	require.NotNil(t, lease)

	lease.SetExpireAt(time.Now().Add(-1 * time.Second))

	purged := serverEngine.ipam.PurgeExpired()
	require.Contains(t, purged, assignedIP, "自然超时的虚拟 IP 必须被 IPAM GC 成功回收")

	dataPkt := buildTestIPv4TCP(netip.AddrPortFrom(assignedIP, 12345), netip.MustParseAddrPort("8.8.8.8:80"), 1000, 0, header.TCPFlagSyn, []byte("after-idle-data"))
	framed := make([]byte, 8+len(dataPkt))
	binary.BigEndian.PutUint64(framed[:8], clientID)
	copy(framed[8:], dataPkt)

	err = serverEngine.HandleUplink(session, framed)
	require.NoError(t, err)

	require.Equal(t, 1, session.packetCount())
	nack := session.popPacket()
	require.Equal(t, PacketTypeIPExpired, nack[0], "超时后发包服务端必须返回 IPExpired NACK")

	clientEngine.HandleDownlink(nack)
	require.False(t, clientEngine.IsReady())

	// 校验 HandleDownlink 自动启动重协商，服务端处理后重新就绪
	require.Eventually(t, func() bool {
		return session.packetCount() == 1
	}, 1*time.Second, 10*time.Millisecond)

	req := session.popPacket()
	require.NotNil(t, req)
	require.Equal(t, PacketTypeIPRequest, req[0])
	require.NoError(t, serverEngine.HandleUplink(session, req))

	resp := session.popPacket()
	require.NotNil(t, resp)
	clientEngine.HandleDownlink(resp)

	require.True(t, clientEngine.IsReady())
	require.Equal(t, assignedIP, clientEngine.AssignedIPv4(), "重新协商后凭借 ClientID 粘性池原位复用分配同一虚拟 IP")
}

// ---------------------------------------------------------------------------
// 14. ClientEngine: CSPRNG 随机 ClientID、带内协商、单栈独立 Fail-Closed 与 MSS
// ---------------------------------------------------------------------------

func TestClientEngine_RandomClientID(t *testing.T) {
	c1 := NewClientEngine(ClientEngineOptions{Enabled: true})
	c2 := NewClientEngine(ClientEngineOptions{Enabled: true})

	require.NotZero(t, c1.ClientID())
	require.NotZero(t, c2.ClientID())
	require.NotEqual(t, c1.ClientID(), c2.ClientID(), "每个 ClientEngine 必须由 CSPRNG 独立生成全局唯一 ClientID")
}

func TestClientEngine_InBandNegotiationDualStack(t *testing.T) {
	serverEngine, err := NewServerEngine(ServerEngineOptions{
		Address: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.1/24"),
			netip.MustParsePrefix("fd00::1/64"),
		},
		MTU:           1400,
		LeaseDuration: 5 * time.Minute,
	})
	require.NoError(t, err)
	defer serverEngine.Close()

	session := &mockDirectSession{}
	clientEngine := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return session, nil
		},
	})

	performInBandNegotiation(t, clientEngine, serverEngine, session)

	require.Equal(t, netip.MustParseAddr("100.64.0.2"), clientEngine.AssignedIPv4())
	require.True(t, clientEngine.AssignedIPv6().Is6())
	require.Equal(t, netip.MustParseAddr("100.64.0.1"), clientEngine.ServerIPv4())
	require.Equal(t, netip.MustParseAddr("fd00::1"), clientEngine.ServerIPv6())
	require.NotZero(t, clientEngine.LeaseToken())

	oldCID := clientEngine.ClientID()
	oldToken := clientEngine.LeaseToken()
	clientEngine.Reset()

	require.False(t, clientEngine.IsReady())
	require.False(t, clientEngine.AssignedIPv4().IsValid())
	require.Equal(t, oldCID, clientEngine.ClientID())
	require.Equal(t, oldToken, clientEngine.LeaseToken())
}

func TestClientEngine_FailClosedUnsupportedStack_SilentDrop(t *testing.T) {
	clientEngine := NewClientEngine(ClientEngineOptions{Enabled: true, MTU: 1400})
	clientEngine.OnNegotiatedDualStack(
		netip.MustParseAddr("100.64.0.2"),
		netip.MustParseAddr("100.64.0.1"),
		netip.Addr{},
		netip.Addr{},
		1400,
	)
	require.True(t, clientEngine.IsReady())

	session := &mockDirectSession{}
	clientEngine.SetSessionProvider(func(ctx context.Context) (Session, error) {
		return session, nil
	})
	clientEngine.SetCurrentSession(session)

	p4, p6 := clientEngine.PortAddresses()
	require.Equal(t, LocalPortIPv4, p4)
	require.Equal(t, LocalPortIPv6, p6)

	v4Pkt := buildTestIPv4TCP(netip.MustParseAddrPort("100.64.0.2:12345"), netip.MustParseAddrPort("8.8.8.8:80"), 1000, 0, header.TCPFlagSyn, []byte("v4-ok"))
	require.NoError(t, clientEngine.WritePackets([][]byte{v4Pkt}))
	require.Equal(t, 1, session.packetCount())
	session.popPacket()

	v6Pkt := buildTestIPv6TCP(netip.MustParseAddrPort("[fd00::2]:12345"), netip.MustParseAddrPort("[2001:4860:4860::8888]:80"), 1000, 0, header.TCPFlagSyn, []byte("v6-drop"))
	err := clientEngine.WritePackets([][]byte{v6Pkt})
	require.NoError(t, err)
	require.Equal(t, 0, session.packetCount())

	mcastPkt := buildTestIPv4TCP(netip.MustParseAddrPort("100.64.0.2:12345"), netip.MustParseAddrPort("224.0.0.1:80"), 1000, 0, header.TCPFlagSyn, []byte("multicast-drop"))
	require.NoError(t, clientEngine.WritePackets([][]byte{mcastPkt}))
	require.Equal(t, 0, session.packetCount())
}

func TestClientEngine_TCPMSSClampingSwitch(t *testing.T) {
	src := netip.MustParseAddrPort("100.64.0.2:12345")
	dst := netip.MustParseAddrPort("8.8.8.8:80")

	sessClamped := &mockDirectSession{}
	cClamped := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return sessClamped, nil
		},
	})
	cClamped.OnNegotiatedDualStack(src.Addr(), netip.MustParseAddr("100.64.0.1"), netip.Addr{}, netip.Addr{}, 1400)
	cClamped.SetCurrentSession(sessClamped)

	synPkt := buildTestIPv4TCPSYNWithMSS(src, dst, 1460)
	require.NoError(t, cClamped.WritePackets([][]byte{synPkt}))
	sentClamped := sessClamped.popPacket()
	require.NotNil(t, sentClamped)

	require.Equal(t, cClamped.ClientID(), binary.BigEndian.Uint64(sentClamped[:8]))
	clampedIPPkt := sentClamped[8:]
	clampedMSS := binary.BigEndian.Uint16(clampedIPPkt[42:44])
	require.Equal(t, uint16(1360), clampedMSS)
	require.Equal(t, uint16(0), checksum(clampedIPPkt[:20]))

	sessUnclamped := &mockDirectSession{}
	cUnclamped := NewClientEngine(ClientEngineOptions{
		Enabled:        true,
		MTU:            1400,
		TCPMSSClamping: common.Ptr(false),
		GetSession: func(ctx context.Context) (Session, error) {
			return sessUnclamped, nil
		},
	})
	cUnclamped.OnNegotiatedDualStack(src.Addr(), netip.MustParseAddr("100.64.0.1"), netip.Addr{}, netip.Addr{}, 1400)
	cUnclamped.SetCurrentSession(sessUnclamped)

	synPkt2 := buildTestIPv4TCPSYNWithMSS(src, dst, 1460)
	require.NoError(t, cUnclamped.WritePackets([][]byte{synPkt2}))
	sentUnclamped := sessUnclamped.popPacket()
	require.NotNil(t, sentUnclamped)

	unclampedIPPkt := sentUnclamped[8:]
	unclampedMSS := binary.BigEndian.Uint16(unclampedIPPkt[42:44])
	require.Equal(t, uint16(1460), unclampedMSS, "关闭钳制后 MSS 应保持原始值 1460")
}

// ---------------------------------------------------------------------------
// 15. 严格 RPF 校验、IPExpired NACK 回送测试
// ---------------------------------------------------------------------------

func TestServerEngine_StrictRPFAndExpiredNACK(t *testing.T) {
	serverEngine, err := NewServerEngine(ServerEngineOptions{
		Address:       []netip.Prefix{netip.MustParsePrefix("100.64.0.1/24")},
		MTU:           1400,
		LeaseDuration: 5 * time.Minute,
	})
	require.NoError(t, err)
	defer serverEngine.Close()

	sessionA := &mockDirectSession{}
	sessionB := &mockDirectSession{}

	clientEngineA := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return sessionA, nil
		},
	})
	performInBandNegotiation(t, clientEngineA, serverEngine, sessionA)
	assignedIP_A := clientEngineA.AssignedIPv4()
	require.True(t, assignedIP_A.IsValid())

	clientEngineB := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return sessionB, nil
		},
	})
	performInBandNegotiation(t, clientEngineB, serverEngine, sessionB)
	require.True(t, clientEngineB.IsReady())
	sessionB.clear()

	spoofedTCP := buildTestIPv4TCP(netip.AddrPortFrom(assignedIP_A, 12345), netip.MustParseAddrPort("8.8.8.8:80"), 1000, 0, header.TCPFlagSyn, []byte("spoof"))
	spoofedFrame1 := make([]byte, 8+len(spoofedTCP))
	binary.BigEndian.PutUint64(spoofedFrame1[:8], uint64(99999999)) // 非法 ClientID
	copy(spoofedFrame1[8:], spoofedTCP)

	err = serverEngine.HandleUplink(sessionB, spoofedFrame1)
	require.NoError(t, err)

	require.Equal(t, 1, sessionB.packetCount(), "冒用他人 IP 的上行必须被拦截并回发 NACK")
	nack1 := sessionB.popPacket()
	require.Equal(t, PacketTypeIPExpired, nack1[0])
	require.Equal(t, assignedIP_A.As16(), [16]byte(nack1[2:18]))

	spoofedFrame2 := make([]byte, 8+len(spoofedTCP))
	binary.BigEndian.PutUint64(spoofedFrame2[:8], clientEngineB.ClientID())
	copy(spoofedFrame2[8:], spoofedTCP)

	err = serverEngine.HandleUplink(sessionB, spoofedFrame2)
	require.NoError(t, err)

	require.Equal(t, 1, sessionB.packetCount(), "已认证客户端冒用他人 IP 必须被 Strict RPF 拦截并回送 NACK")
	nack2 := sessionB.popPacket()
	require.Equal(t, PacketTypeIPExpired, nack2[0])
	require.Equal(t, assignedIP_A.As16(), [16]byte(nack2[2:18]))
}

// ---------------------------------------------------------------------------
// 16. Fail-Closed 静默丢弃验证
// ---------------------------------------------------------------------------

func TestClientEngine_FailClosedDropOnUnreadyOrBlocked(t *testing.T) {
	src := netip.MustParseAddrPort("100.64.0.2:12345")
	dst := netip.MustParseAddrPort("8.8.8.8:80")
	synPkt := buildTestIPv4TCP(src, dst, 1000, 0, header.TCPFlagSyn, nil)

	// A. 未就绪态 (Unready)
	clientEngineUnready := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return nil, net.ErrClosed
		},
	})

	tunReturn := &mockTunReturn{}
	require.NoError(t, clientEngineUnready.AttachReturn(tunReturn))
	err := clientEngineUnready.WritePackets([][]byte{synPkt})
	require.NoError(t, err)

	tunReturn.mu.Lock()
	require.Empty(t, tunReturn.packets, "Fail-Closed: 物理通道未就绪时必须纯静默丢弃，严禁向本地 TUN 注入 RST 报文")
	tunReturn.mu.Unlock()
	require.NoError(t, clientEngineUnready.DetachReturn(tunReturn))

	// B. 已就绪态但借出会话立即返回错误
	clientEngineReady := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return nil, net.ErrClosed
		},
	})
	clientEngineReady.OnNegotiatedDualStack(src.Addr(), netip.MustParseAddr("100.64.0.1"), netip.Addr{}, netip.Addr{}, 1400)
	require.True(t, clientEngineReady.IsReady())

	tunReturnReady := &mockTunReturn{}
	require.NoError(t, clientEngineReady.AttachReturn(tunReturnReady))
	err = clientEngineReady.WritePackets([][]byte{synPkt})
	require.NoError(t, err)

	tunReturnReady.mu.Lock()
	require.Empty(t, tunReturnReady.packets, "Fail-Closed: 借出会话失败时必须静默丢弃，严禁向本地注入 RST")
	tunReturnReady.mu.Unlock()
	require.NoError(t, clientEngineReady.DetachReturn(tunReturnReady))
}

// ---------------------------------------------------------------------------
// 17. 下行 Worker 批量抽取与 sync.Pool 对象池复用测试
// ---------------------------------------------------------------------------

func TestServerEngine_DownlinkBatchingAndPool(t *testing.T) {
	serverEngine, err := NewServerEngine(ServerEngineOptions{
		Address:       []netip.Prefix{netip.MustParsePrefix("100.64.0.1/24")},
		MTU:           1400,
		LeaseDuration: 5 * time.Minute,
	})
	require.NoError(t, err)
	defer serverEngine.Close()

	session := &mockDirectSession{}
	clientEngine := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		MTU:     1400,
		GetSession: func(ctx context.Context) (Session, error) {
			return session, nil
		},
	})
	performInBandNegotiation(t, clientEngine, serverEngine, session)
	assignedIP := clientEngine.AssignedIPv4()
	require.True(t, assignedIP.IsValid())
	session.clear()

	const burstCount = 64
	src := netip.MustParseAddrPort("8.8.8.8:80")
	dst := netip.AddrPortFrom(assignedIP, 12345)

	for i := 0; i < burstCount; i++ {
		pkt := buildTestIPv4TCP(src, dst, uint32(1000+i), 0, header.TCPFlagAck, []byte("burst-data"))
		err := serverEngine.HandleDownlink(pkt)
		require.NoError(t, err)
	}

	require.Eventually(t, func() bool {
		return session.packetCount() == burstCount
	}, 2*time.Second, 10*time.Millisecond)

	for i := 0; i < burstCount; i++ {
		recv := session.popPacket()
		require.NotNil(t, recv)
		require.Equal(t, assignedIP, PacketDestinationIP(recv))
	}
	require.Equal(t, 0, session.packetCount())
}

// ---------------------------------------------------------------------------
// 18. RFC 1624 增量校验和数学精度验证
// ---------------------------------------------------------------------------

func TestChecksumAndPacketRewrite(t *testing.T) {
	src := netip.MustParseAddrPort("10.0.0.2:1234")
	dst := netip.MustParseAddrPort("1.1.1.1:80")
	tcpPkt := buildTestIPv4TCP(src, dst, 100, 200, header.TCPFlagAck, []byte("checksum-payload"))

	require.Equal(t, uint16(0), checksum(tcpPkt[:20]))

	newSrc := netip.MustParseAddr("100.64.0.99")
	rewritePacketSrcIPv4(tcpPkt, newSrc)
	require.Equal(t, newSrc, PacketSourceIP(tcpPkt))
	require.Equal(t, uint16(0), checksum(tcpPkt[:20]))

	newDst := netip.MustParseAddr("8.8.4.4")
	rewritePacketDstIPv4(tcpPkt, newDst)
	require.Equal(t, newDst, PacketDestinationIP(tcpPkt))
	require.Equal(t, uint16(0), checksum(tcpPkt[:20]))
}

func TestRFC1624IncrementalChecksumAndIPv6(t *testing.T) {
	src6 := netip.MustParseAddrPort("[fd00::10]:1234")
	dst6 := netip.MustParseAddrPort("[2001:4860:4860::8888]:80")
	newSrc6 := netip.MustParseAddr("fd00::99")

	// 1. IPv6 TCP
	tcpPkt := buildTestIPv6TCP(src6, dst6, 100, 200, header.TCPFlagAck, []byte("tcp-payload"))
	rewritePacketSrcIPv6(tcpPkt, newSrc6)
	require.Equal(t, newSrc6, PacketSourceIP(tcpPkt))

	tcpPayloadZeroed := make([]byte, len(tcpPkt)-40)
	copy(tcpPayloadZeroed, tcpPkt[40:])
	tcpPayloadZeroed[16] = 0
	tcpPayloadZeroed[17] = 0
	csumExpectedTCP := checksumWithIPv6Pseudo(newSrc6, dst6.Addr(), uint8(header.TCPProtocolNumber), tcpPayloadZeroed)
	require.Equal(t, csumExpectedTCP, binary.BigEndian.Uint16(tcpPkt[56:58]))
	require.Equal(t, uint16(0), checksumWithIPv6Pseudo(newSrc6, dst6.Addr(), uint8(header.TCPProtocolNumber), tcpPkt[40:]))

	// 2. IPv6 ICMPv6 (RFC 4443 伪首部验证)
	icmpPkt := buildTestIPv6ICMP(src6.Addr(), dst6.Addr(), 128, 0, []byte("icmpv6-echo"))
	rewritePacketSrcIPv6(icmpPkt, newSrc6)
	require.Equal(t, newSrc6, PacketSourceIP(icmpPkt))

	icmpPayloadZeroed := make([]byte, len(icmpPkt)-40)
	copy(icmpPayloadZeroed, icmpPkt[40:])
	icmpPayloadZeroed[2] = 0
	icmpPayloadZeroed[3] = 0
	csumExpectedICMP := checksumWithIPv6Pseudo(newSrc6, dst6.Addr(), uint8(header.ICMPv6ProtocolNumber), icmpPayloadZeroed)
	require.Equal(t, csumExpectedICMP, binary.BigEndian.Uint16(icmpPkt[42:44]))
	require.Equal(t, uint16(0), checksumWithIPv6Pseudo(newSrc6, dst6.Addr(), uint8(header.ICMPv6ProtocolNumber), icmpPkt[40:]))
}

func TestIPv4FragmentationProtection(t *testing.T) {
	src := netip.MustParseAddrPort("10.0.0.2:1234")
	dst := netip.MustParseAddrPort("1.1.1.1:80")
	udpPkt := buildTestIPv4UDP(src, dst, []byte("fragment-payload-12345678"))

	binary.BigEndian.PutUint16(udpPkt[6:8], 0x0001)
	udpPkt[10] = 0
	udpPkt[11] = 0
	binary.BigEndian.PutUint16(udpPkt[10:12], checksum(udpPkt[:20]))

	payloadBefore := make([]byte, len(udpPkt)-20)
	copy(payloadBefore, udpPkt[20:])

	newSrc := netip.MustParseAddr("100.64.0.99")
	rewritePacketSrcIPv4(udpPkt, newSrc)

	require.Equal(t, newSrc, PacketSourceIP(udpPkt))
	require.Equal(t, uint16(0), checksum(udpPkt[:20]))
	require.Equal(t, payloadBefore, udpPkt[20:])
}

// ---------------------------------------------------------------------------
// 辅助封包与校验和函数
// ---------------------------------------------------------------------------

func buildTestIPv4ICMPEcho(src, dst netip.Addr, icmpType, icmpCode uint8, id, seq uint16, payload []byte) []byte {
	totalLen := 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = uint8(header.ICMPv4ProtocolNumber)

	src4 := src.As4()
	dst4 := dst.As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))

	icmp := pkt[20:]
	icmp[0] = icmpType
	icmp[1] = icmpCode
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	return pkt
}

func checksumWithPseudo(pseudo []byte, payload []byte) uint16 {
	var sum uint32
	for i := 0; i < len(pseudo)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func checksumWithIPv6Pseudo(src, dst netip.Addr, nextHdr uint8, payload []byte) uint16 {
	var pseudo [40]byte
	src16 := src.As16()
	dst16 := dst.As16()
	copy(pseudo[0:16], src16[:])
	copy(pseudo[16:32], dst16[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(payload)))
	pseudo[39] = nextHdr

	var sum uint32
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildTestIPv4UDP(src, dst netip.AddrPort, payload []byte) []byte {
	totalLen := 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = uint8(header.UDPProtocolNumber)

	src4 := src.Addr().As4()
	dst4 := dst.Addr().As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], src.Port())
	binary.BigEndian.PutUint16(udp[2:4], dst.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)
	return pkt
}

func buildTestIPv4TCP(src, dst netip.AddrPort, seq, ack uint32, flags header.TCPFlags, payload []byte) []byte {
	totalLen := 20 + 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = uint8(header.TCPProtocolNumber)

	src4 := src.Addr().As4()
	dst4 := dst.Addr().As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	binary.BigEndian.PutUint16(tcp[12:14], 0x5000|uint16(flags))
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)

	var pseudo [12]byte
	copy(pseudo[0:4], src4[:])
	copy(pseudo[4:8], dst4[:])
	pseudo[9] = uint8(header.TCPProtocolNumber)
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(tcp[16:18], checksumWithPseudo(pseudo[:], tcp))
	return pkt
}

func buildTestIPv4TCPSYNWithMSS(src, dst netip.AddrPort, mss uint16) []byte {
	totalLen := 20 + 24
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = uint8(header.TCPProtocolNumber)

	src4 := src.Addr().As4()
	dst4 := dst.Addr().As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], 1000)
	binary.BigEndian.PutUint32(tcp[8:12], 0)
	binary.BigEndian.PutUint16(tcp[12:14], 0x6000|uint16(header.TCPFlagSyn))
	binary.BigEndian.PutUint16(tcp[14:16], 65535)

	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], mss)

	var pseudo [12]byte
	copy(pseudo[0:4], src4[:])
	copy(pseudo[4:8], dst4[:])
	pseudo[9] = uint8(header.TCPProtocolNumber)
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(24))
	binary.BigEndian.PutUint16(tcp[16:18], checksumWithPseudo(pseudo[:], tcp))
	return pkt
}

func buildTestIPv6TCP(src, dst netip.AddrPort, seq, ack uint32, flags header.TCPFlags, payload []byte) []byte {
	totalLen := 40 + 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(20+len(payload)))
	pkt[6] = uint8(header.TCPProtocolNumber)
	pkt[7] = 64

	src16 := src.Addr().As16()
	dst16 := dst.Addr().As16()
	copy(pkt[8:24], src16[:])
	copy(pkt[24:40], dst16[:])

	tcp := pkt[40:]
	binary.BigEndian.PutUint16(tcp[0:2], src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	binary.BigEndian.PutUint16(tcp[12:14], 0x5000|uint16(flags))
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)

	csum := checksumWithIPv6Pseudo(src.Addr(), dst.Addr(), uint8(header.TCPProtocolNumber), tcp)
	binary.BigEndian.PutUint16(tcp[16:18], csum)
	return pkt
}

func buildTestIPv6ICMP(src, dst netip.Addr, icmpType, icmpCode uint8, payload []byte) []byte {
	totalLen := 40 + 8 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(8+len(payload)))
	pkt[6] = uint8(header.ICMPv6ProtocolNumber)
	pkt[7] = 64

	src16 := src.As16()
	dst16 := dst.As16()
	copy(pkt[8:24], src16[:])
	copy(pkt[24:40], dst16[:])

	icmp := pkt[40:]
	icmp[0] = icmpType
	icmp[1] = icmpCode
	copy(icmp[8:], payload)

	csum := checksumWithIPv6Pseudo(src, dst, uint8(header.ICMPv6ProtocolNumber), icmp)
	binary.BigEndian.PutUint16(icmp[2:4], csum)
	return pkt
}
