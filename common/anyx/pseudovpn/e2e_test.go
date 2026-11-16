package pseudovpn

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/anyx/pseudovpn/pvtest"
	tun "github.com/sagernet/sing-tun"

	"github.com/stretchr/testify/require"
)

// fakeTUN 是内存中的服务端 TUN：Inject 的报文从 Read 读出（模拟内核发往虚拟子网的回包），
// Write 写入的报文被记录（模拟交给内核转发的上行包）。
type fakeTUN struct {
	inbound chan []byte
	closed  chan struct{}
	once    sync.Once
	mu      sync.Mutex
	written [][]byte
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{inbound: make(chan []byte, 64), closed: make(chan struct{})}
}

func (t *fakeTUN) Inject(packet []byte) {
	t.inbound <- append(make([]byte, tun.PacketOffset), packet...)
}

func (t *fakeTUN) Read(p []byte) (int, error) {
	select {
	case packet := <-t.inbound:
		return copy(p, packet), nil
	case <-t.closed:
		return 0, net.ErrClosed
	}
}

func (t *fakeTUN) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.written = append(t.written, append([]byte(nil), p[tun.PacketOffset:]...))
	return len(p), nil
}

func (t *fakeTUN) Name() (string, error)                  { return "fake-anyx", nil }
func (t *fakeTUN) Start() error                           { return nil }
func (t *fakeTUN) UpdateRouteOptions(_ tun.Options) error { return nil }
func (t *fakeTUN) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

func (t *fakeTUN) take(tb testing.TB) []byte {
	tb.Helper()
	var packet []byte
	require.Eventually(tb, func() bool {
		t.mu.Lock()
		defer t.mu.Unlock()
		if len(t.written) == 0 {
			return false
		}
		packet = t.written[0]
		t.written = t.written[1:]
		return true
	}, 2*time.Second, 5*time.Millisecond)
	return packet
}

func (t *fakeTUN) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.written)
}

// pipeSession 把客户端与服务端引擎接在一起：客户端侧写出的帧交给服务端 HandleUplink，
// 服务端侧写出的帧交给客户端 HandleDownlink。
type pipeSession struct {
	peer     *pipeSession
	deliver  func(self *pipeSession, packet []byte)
	user     string
	closed   atomic.Bool
	isClient bool
}

func newPipe(user string, server *ServerEngine, client func() *ClientEngine) *pipeSession {
	clientSide := &pipeSession{user: user, isClient: true}
	serverSide := &pipeSession{user: user}
	clientSide.peer, serverSide.peer = serverSide, clientSide
	clientSide.deliver = func(self *pipeSession, packet []byte) {
		_ = server.HandleUplink(self.peer, packet)
	}
	serverSide.deliver = func(self *pipeSession, packet []byte) {
		client().HandleDownlink(packet)
	}
	return clientSide
}

func (s *pipeSession) WriteFramePacket(cmd byte, packet []byte) error {
	if s.closed.Load() {
		return net.ErrClosed
	}
	s.deliver(s, append([]byte(nil), packet...))
	return nil
}

func (s *pipeSession) Close() error {
	s.closed.Store(true)
	s.peer.closed.Store(true)
	return nil
}

func (s *pipeSession) IsClosed() bool { return s.closed.Load() }

type e2eFixture struct {
	server   *ServerEngine
	tun      *fakeTUN
	client   *ClientEngine
	returned *mockTunReturn
	sessions atomic.Int64
	current  atomic.Pointer[pipeSession]
}

func newE2E(t *testing.T, user string, clientOptions ClientEngineOptions, addresses ...string) *e2eFixture {
	t.Helper()
	fixture := &e2eFixture{tun: newFakeTUN(), returned: &mockTunReturn{}}
	var prefixes []netip.Prefix
	for _, address := range addresses {
		prefixes = append(prefixes, netip.MustParsePrefix(address))
	}
	server, err := NewServerEngine(ServerEngineOptions{
		Address: prefixes,
		MTU:     1400,
		Tun:     fixture.tun,
		UserOf: func(session Session) string {
			return session.(*pipeSession).user
		},
	})
	require.NoError(t, err)
	require.NoError(t, server.Start())
	t.Cleanup(func() { _ = server.Close() })
	fixture.server = server
	fixture.client = fixture.newClient(t, user, clientOptions)
	return fixture
}

func (f *e2eFixture) newClient(t *testing.T, user string, options ClientEngineOptions) *ClientEngine {
	var client *ClientEngine
	options.Enabled = true
	options.GetSession = func(ctx context.Context) (Session, error) {
		if current := f.current.Load(); current != nil && !current.IsClosed() {
			return current, nil
		}
		session := newPipe(user, f.server, func() *ClientEngine { return client })
		f.sessions.Add(1)
		f.current.Store(session)
		return session, nil
	}
	client = NewClientEngine(options)
	require.NoError(t, client.AttachReturn(f.returned))
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, client.Initialize(ctx))
	return client
}

func (f *e2eFixture) takeReturned(tb testing.TB) []byte {
	tb.Helper()
	var packet []byte
	require.Eventually(tb, func() bool {
		f.returned.mu.Lock()
		defer f.returned.mu.Unlock()
		if len(f.returned.packets) == 0 {
			return false
		}
		packet = f.returned.packets[0]
		f.returned.packets = f.returned.packets[1:]
		return true
	}, 2*time.Second, 5*time.Millisecond)
	return packet
}

func (f *e2eFixture) returnedCount() int {
	f.returned.mu.Lock()
	defer f.returned.mu.Unlock()
	return len(f.returned.packets)
}

var (
	remoteV4 = netip.MustParseAddr("93.184.216.34")
	remoteV6 = netip.MustParseAddr("2606:2800:220:1::1")
)

// 客户端三层包 → 会话 → 服务端引擎 → TUN，以及 TUN → 服务端引擎 → 会话 → 客户端返回路径，
// 覆盖 TCP 三次握手报文、MSS 双向钳制、ICMP / ICMPv6 回显与双栈 1:1 NAT。
func TestEndToEnd_DualStackTCPAndICMP(t *testing.T) {
	f := newE2E(t, "alice", ClientEngineOptions{MTU: 1400}, "100.64.0.1/24", "fd00::1/64")
	v4, v6 := f.client.AssignedIPv4(), f.client.AssignedIPv6()
	require.Equal(t, netip.MustParseAddr("100.64.0.2"), v4)
	require.True(t, v6.Is6())

	for _, family := range []struct {
		name     string
		local    netip.Addr
		assigned netip.Addr
		remote   netip.Addr
		mss      uint16
	}{
		{"ipv4", LocalPortIPv4, v4, remoteV4, 1400 - 40},
		{"ipv6", LocalPortIPv6, v6, remoteV6, 1400 - 60},
	} {
		t.Run(family.name, func(t *testing.T) {
			local := netip.AddrPortFrom(family.local, 40000)
			remote := netip.AddrPortFrom(family.remote, 443)
			virtual := netip.AddrPortFrom(family.assigned, 40000)

			// SYN 上行：源地址 NAT 为虚拟地址，MSS 被钳制。
			require.NoError(t, f.client.WritePackets([][]byte{pvtest.TCP(local, remote, 1, 0, pvtest.TCPFlagSyn, 1460, nil)}))
			syn := f.tun.take(t)
			require.Equal(t, family.assigned, pvtest.Source(syn))
			require.Equal(t, family.remote, pvtest.Destination(syn))
			require.Equal(t, family.mss, pvtest.MSS(syn))
			require.True(t, pvtest.ChecksumsValid(syn))

			// SYN-ACK 经 TUN 下行：目的地址还原为本地端口地址，MSS 同样被钳制。
			f.tun.Inject(pvtest.TCP(remote, virtual, 100, 2, pvtest.TCPFlagSyn|pvtest.TCPFlagAck, 1460, nil))
			synAck := f.takeReturned(t)
			require.Equal(t, family.local, pvtest.Destination(synAck))
			require.Equal(t, family.remote, pvtest.Source(synAck))
			_, dstPort := pvtest.Ports(synAck)
			require.Equal(t, uint16(40000), dstPort)
			require.Equal(t, family.mss, pvtest.MSS(synAck))
			require.True(t, pvtest.ChecksumsValid(synAck))

			// ACK 与数据上行。
			require.NoError(t, f.client.WritePackets([][]byte{pvtest.TCP(local, remote, 2, 101, pvtest.TCPFlagAck|pvtest.TCPFlagPsh, 0, []byte("hello"))}))
			data := f.tun.take(t)
			require.Equal(t, family.assigned, pvtest.Source(data))
			require.True(t, pvtest.ChecksumsValid(data))

			// ICMP 回显往返。
			require.NoError(t, f.client.WritePackets([][]byte{pvtest.Echo(family.local, family.remote, 7, 1, false, []byte("ping"))}))
			echo := f.tun.take(t)
			require.Equal(t, family.assigned, pvtest.Source(echo))
			require.True(t, pvtest.ChecksumsValid(echo))
			f.tun.Inject(pvtest.Echo(family.remote, family.assigned, 7, 1, true, []byte("ping")))
			reply := f.takeReturned(t)
			require.Equal(t, family.local, pvtest.Destination(reply))
			require.True(t, pvtest.ChecksumsValid(reply))
		})
	}

	// 发往未分配地址的下行报文不得送达。
	f.tun.Inject(pvtest.Echo(remoteV4, netip.MustParseAddr("100.64.0.99"), 1, 1, true, nil))
	time.Sleep(50 * time.Millisecond)
	require.Zero(t, f.returnedCount())
}

// UDP 三种策略：drop 静默丢弃；reject 在本地回 ICMP / ICMPv6 端口不可达（校验和正确）；
// transparent 交给 L4，引擎本身从不把 UDP 送进隧道。
func TestEndToEnd_UDPModes(t *testing.T) {
	for _, mode := range []UDPMode{UDPModeDrop, UDPModeReject, UDPModeTransparent} {
		t.Run(string(mode), func(t *testing.T) {
			f := newE2E(t, "alice", ClientEngineOptions{MTU: 1400, UDP: string(mode)}, "100.64.0.1/24", "fd00::1/64")
			v4Packet := pvtest.UDP(netip.AddrPortFrom(LocalPortIPv4, 5353), netip.AddrPortFrom(remoteV4, 53), []byte("query"))
			v6Packet := pvtest.UDP(netip.AddrPortFrom(LocalPortIPv6, 5353), netip.AddrPortFrom(remoteV6, 53), []byte("query"))
			require.NoError(t, f.client.WritePackets([][]byte{v4Packet, v6Packet}))
			time.Sleep(30 * time.Millisecond)
			require.Zero(t, f.tun.count(), "UDP 不得进入隧道")

			switch mode {
			case UDPModeReject:
				reject4 := f.takeReturned(t)
				icmpType, icmpCode := pvtest.ICMPType(reject4)
				require.Equal(t, [2]uint8{3, 3}, [2]uint8{icmpType, icmpCode})
				require.Equal(t, LocalPortIPv4, pvtest.Destination(reject4))
				require.True(t, pvtest.ChecksumsValid(reject4))
				reject6 := f.takeReturned(t)
				icmpType, icmpCode = pvtest.ICMPType(reject6)
				require.Equal(t, [2]uint8{1, 4}, [2]uint8{icmpType, icmpCode})
				require.Equal(t, LocalPortIPv6, pvtest.Destination(reject6))
				require.True(t, pvtest.ChecksumsValid(reject6))
			default:
				require.Zero(t, f.returnedCount())
			}
			expected := map[UDPMode]adapter.PreMatchAction{
				UDPModeDrop:        adapter.PreMatchDrop,
				UDPModeReject:      adapter.PreMatchReject,
				UDPModeTransparent: adapter.PreMatchContinue,
			}[mode]
			require.Equal(t, expected, f.client.PreMatchAction("udp"))
			require.Equal(t, adapter.PreMatchFlow, f.client.PreMatchAction("tcp"))
			require.Equal(t, adapter.PreMatchFlow, f.client.PreMatchAction("icmp"))
		})
	}
}

// 会话断开后自动重建：上行首包触发新会话，服务端漫游到新会话，下行也随之切换。
func TestEndToEnd_ReconnectAfterSessionLoss(t *testing.T) {
	f := newE2E(t, "alice", ClientEngineOptions{MTU: 1400}, "100.64.0.1/24")
	v4 := f.client.AssignedIPv4()
	require.NoError(t, f.current.Load().Close())
	f.server.UnregisterSession(f.current.Load().peer)

	local := netip.AddrPortFrom(LocalPortIPv4, 40001)
	remote := netip.AddrPortFrom(remoteV4, 80)
	require.NoError(t, f.client.WritePackets([][]byte{pvtest.TCP(local, remote, 1, 0, pvtest.TCPFlagSyn, 0, nil)}))
	require.Equal(t, int64(2), f.sessions.Load(), "必须重建物理会话")
	require.Equal(t, v4, pvtest.Source(f.tun.take(t)), "重连后虚拟地址保持不变")

	f.tun.Inject(pvtest.TCP(remote, netip.AddrPortFrom(v4, 40001), 1, 2, pvtest.TCPFlagSyn|pvtest.TCPFlagAck, 0, nil))
	require.Equal(t, LocalPortIPv4, pvtest.Destination(f.takeReturned(t)), "下行必须经新会话送达")
}

// 租约过期：GC 回收路由，下行不再送达；客户端再发包收到 NACK，重协商后拿回原地址。
func TestEndToEnd_LeaseExpiryAndRecovery(t *testing.T) {
	f := newE2E(t, "alice", ClientEngineOptions{MTU: 1400}, "100.64.0.1/24")
	v4 := f.client.AssignedIPv4()

	f.server.ipam.mu.Lock()
	f.server.ipam.v4Pool.leases[v4].SetExpireAt(time.Now().Add(-time.Second))
	f.server.ipam.mu.Unlock()
	f.server.collectGarbage()
	_, routed := f.server.routes.Lookup(v4)
	require.False(t, routed, "过期租约的路由必须被回收")

	f.tun.Inject(pvtest.Echo(remoteV4, v4, 1, 1, true, nil))
	time.Sleep(50 * time.Millisecond)
	require.Zero(t, f.returnedCount())

	local := netip.AddrPortFrom(LocalPortIPv4, 40002)
	require.NoError(t, f.client.WritePackets([][]byte{pvtest.TCP(local, netip.AddrPortFrom(remoteV4, 80), 1, 0, pvtest.TCPFlagSyn, 0, nil)}))
	require.Eventually(t, f.client.IsReady, 2*time.Second, 5*time.Millisecond)
	require.Equal(t, v4, f.client.AssignedIPv4(), "重协商应拿回原地址")
	_, routed = f.server.routes.Lookup(v4)
	require.True(t, routed)
}

// 同一用户的新客户端（客户端重启，ClientID 变化）在原客户端离线时拿回同一地址；
// 原客户端在线时不能抢占，其他用户也不能接管。
func TestEndToEnd_UserStickyAcrossClientRestart(t *testing.T) {
	f := newE2E(t, "alice", ClientEngineOptions{MTU: 1400}, "100.64.0.1/24", "fd00::1/64")
	v4, v6 := f.client.AssignedIPv4(), f.client.AssignedIPv6()
	firstSession := f.current.Load()

	// 原客户端在线：同一用户的另一台设备拿到不同地址。
	f.current.Store(nil)
	second := f.newClient(t, "alice", ClientEngineOptions{MTU: 1400})
	require.NotEqual(t, v4, second.AssignedIPv4())

	// 原客户端离线后，同一用户重启的客户端拿回原地址。
	require.NoError(t, firstSession.Close())
	f.server.UnregisterSession(firstSession.peer)
	f.current.Store(nil)
	restarted := f.newClient(t, "alice", ClientEngineOptions{MTU: 1400})
	require.Equal(t, v4, restarted.AssignedIPv4())
	require.Equal(t, v6, restarted.AssignedIPv6())
	routed, _ := f.server.routes.Lookup(v4)
	require.Equal(t, restarted.ClientID(), routed)
	f.server.sessionsMu.RLock()
	_, staleState := f.server.clients[f.client.ClientID()]
	f.server.sessionsMu.RUnlock()
	require.False(t, staleState, "被接管客户端的状态必须被清理")

	// 其他用户不能接管 alice 的地址。
	f.current.Store(nil)
	bob := f.newClient(t, "bob", ClientEngineOptions{MTU: 1400})
	require.NotEqual(t, v4, bob.AssignedIPv4())
}

func TestServerEngine_InterfaceAddresses(t *testing.T) {
	server, err := NewServerEngine(ServerEngineOptions{
		Address:  []netip.Prefix{netip.MustParsePrefix("100.64.0.0/24"), netip.MustParsePrefix("fd00::1/64")},
		WriteTUN: func([]byte) error { return nil },
	})
	require.NoError(t, err)
	defer server.Close()
	inet4, inet6 := server.InterfaceAddresses()
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.64.0.1/24")}, inet4, "网络地址自动顺延为网关地址")
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("fd00::1/64")}, inet6)
	require.Equal(t, DefaultMTU, server.MTU())
	require.Equal(t, DefaultLeaseDuration, server.LeaseDuration())

	_, err = NewServerEngine(ServerEngineOptions{Address: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/24"), netip.MustParsePrefix("10.0.0.1/24")}})
	require.ErrorIs(t, err, ErrTooManyIPv4Subnets)
	_, err = NewServerEngine(ServerEngineOptions{})
	require.ErrorIs(t, err, ErrAddressEmpty)
}
