package pseudovpn

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"

	"github.com/stretchr/testify/require"
)

func buildIPRequest(clientID, token uint64, flags byte, reqV4, reqV6 netip.Addr) []byte {
	req := make([]byte, 52)
	req[0] = PacketTypeIPRequest
	req[1] = flags
	if reqV4.IsValid() {
		b := reqV4.As16()
		copy(req[2:18], b[:])
	}
	if reqV6.IsValid() {
		b := reqV6.As16()
		copy(req[18:34], b[:])
	}
	binary.BigEndian.PutUint16(req[34:36], 2)
	binary.BigEndian.PutUint64(req[36:44], clientID)
	binary.BigEndian.PutUint64(req[44:52], token)
	return req
}

func grantedIPv4(t *testing.T, resp []byte) netip.Addr {
	t.Helper()
	require.GreaterOrEqual(t, len(resp), 83)
	require.Equal(t, PacketTypeIPResponse, resp[0])
	if resp[1] != 0 {
		return netip.Addr{}
	}
	return netip.AddrFrom16([16]byte(resp[3:19])).Unmap()
}

func frameData(clientID uint64, packet []byte) []byte {
	framed := make([]byte, 8+len(packet))
	binary.BigEndian.PutUint64(framed[:8], clientID)
	copy(framed[8:], packet)
	return framed
}

func newTestServer(t *testing.T, prefix string, writeTUN func([]byte) error) *ServerEngine {
	t.Helper()
	if writeTUN == nil {
		writeTUN = func([]byte) error { return nil }
	}
	engine, err := NewServerEngine(ServerEngineOptions{
		Address:  []netip.Prefix{netip.MustParsePrefix(prefix)},
		MTU:      1400,
		WriteTUN: writeTUN,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = engine.Close() })
	return engine
}

// 扩展头长度字段为 255 时，uint8 加 1 回绕为 0 曾让解析死循环；现在必须有限步内返回。
func TestFindIPv6L4Header_MalformedExtensionHeadersTerminate(t *testing.T) {
	packet := make([]byte, header.IPv6MinimumSize+8)
	packet[0] = 0x60
	packet[6] = 0 // Hop-by-Hop
	packet[header.IPv6MinimumSize] = 0
	packet[header.IPv6MinimumSize+1] = 255

	done := make(chan struct{})
	go func() {
		defer close(done)
		proto, offset, _ := findIPv6L4Header(packet)
		require.Zero(t, proto)
		require.Zero(t, offset)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("findIPv6L4Header did not terminate on a malformed extension header")
	}

	// 自指的 0 长度链（每个扩展头声明 8 字节并指向下一个 Hop-by-Hop）超过上限后放弃。
	chain := make([]byte, header.IPv6MinimumSize+8*(maxIPv6ExtensionHeaders+4))
	chain[0] = 0x60
	chain[6] = 60
	for offset := header.IPv6MinimumSize; offset+8 <= len(chain); offset += 8 {
		chain[offset] = 60
	}
	proto, offset, _ := findIPv6L4Header(chain)
	require.Zero(t, proto)
	require.Zero(t, offset)

	// AH 的长度单位是 4 字节。
	ah := make([]byte, header.IPv6MinimumSize+12+header.TCPMinimumSize)
	ah[0] = 0x60
	ah[6] = 51
	ah[header.IPv6MinimumSize] = uint8(header.TCPProtocolNumber)
	ah[header.IPv6MinimumSize+1] = 1 // (1+2)*4 = 12
	proto, offset, _ = findIPv6L4Header(ah)
	require.Equal(t, uint8(header.TCPProtocolNumber), proto)
	require.Equal(t, header.IPv6MinimumSize+12, offset)
}

func TestTable_IPv4MappedPrefix(t *testing.T) {
	table := NewTable[uint64]()
	mapped := netip.PrefixFrom(netip.MustParseAddr("::ffff:100.64.0.2"), 128)
	require.NotPanics(t, func() { table.Insert(mapped, 7) })
	value, found := table.Lookup(netip.MustParseAddr("100.64.0.2"))
	require.True(t, found)
	require.Equal(t, uint64(7), value)

	require.False(t, table.RemoveIf(mapped, func(v uint64) bool { return v == 8 }), "归属不符时不得删除")
	require.True(t, table.RemoveIf(mapped, func(v uint64) bool { return v == 7 }))
	_, found = table.Lookup(netip.MustParseAddr("100.64.0.2"))
	require.False(t, found)
	require.Zero(t, table.Count())
}

func TestGenerateClientID_AvoidsControlTypes(t *testing.T) {
	for range 4096 {
		first := byte(generateClientID() >> 56)
		require.False(t, first >= PacketTypeIPRequest && first <= PacketTypeIPExpired, "ClientID 首字节不得与控制报文类型冲突")
	}
}

// ClientID 首字节为 0x02 的数据帧曾被当成 IPResponse 控制帧丢弃。
func TestServerEngine_DataFrameWithControlLikeClientID(t *testing.T) {
	var forwarded atomic.Int64
	server := newTestServer(t, "100.64.0.1/24", func([]byte) error {
		forwarded.Add(1)
		return nil
	})
	session := &mockDirectSession{}
	clientID := uint64(0x02)<<56 | 0x1234
	require.NoError(t, server.HandleUplink(session, buildIPRequest(clientID, 0, 0x01, netip.Addr{}, netip.Addr{})))
	v4 := grantedIPv4(t, session.popPacket())
	require.True(t, v4.IsValid())

	packet := buildTestIPv4TCP(netip.AddrPortFrom(v4, 40000), netip.MustParseAddrPort("8.8.8.8:443"), 1, 0, header.TCPFlagAck, make([]byte, 200))
	require.NoError(t, server.HandleUplink(session, frameData(clientID, packet)))
	require.Equal(t, int64(1), forwarded.Load(), "数据帧必须被转发，而不是被当作控制帧丢弃")
}

func TestServerEngine_RejectsZeroClientID(t *testing.T) {
	server := newTestServer(t, "100.64.0.1/24", nil)
	session := &mockDirectSession{}
	require.NoError(t, server.HandleUplink(session, buildIPRequest(0, 0, 0x01, netip.Addr{}, netip.Addr{})))
	resp := session.popPacket()
	require.Equal(t, PacketTypeIPResponse, resp[0])
	require.Equal(t, byte(1), resp[1], "缺少 ClientID 的申请必须被拒绝")
	require.Zero(t, server.ipam.LeaseCount(), "被拒绝的申请不得占用租约")
}

// 地址被回收并重新分配给他人后，旧客户端重新申请不得删掉新主人的路由与租约。
func TestServerEngine_ReassignedAddressKeepsNewOwner(t *testing.T) {
	server := newTestServer(t, "100.64.0.1/30", nil) // 只有 1 个可分配地址
	sessionA := &mockDirectSession{}
	sessionB := &mockDirectSession{}
	const clientA, clientB = uint64(0x10) << 56, uint64(0x20) << 56

	require.NoError(t, server.HandleUplink(sessionA, buildIPRequest(clientA, 0, 0x01, netip.Addr{}, netip.Addr{})))
	addr := grantedIPv4(t, sessionA.popPacket())
	require.True(t, addr.IsValid())

	// A 的租约过期，A 离线；B 拿到同一地址。
	server.ipam.mu.Lock()
	server.ipam.v4Pool.leases[addr].SetExpireAt(time.Now().Add(-time.Second))
	server.ipam.mu.Unlock()
	server.UnregisterSession(sessionA)
	require.NoError(t, server.HandleUplink(sessionB, buildIPRequest(clientB, 0, 0x01, netip.Addr{}, netip.Addr{})))
	require.Equal(t, addr, grantedIPv4(t, sessionB.popPacket()))

	// A 回来重新申请：池已满且 B 在线，A 必须被拒绝，B 的路由与租约必须完好。
	sessionA2 := &mockDirectSession{}
	require.NoError(t, server.HandleUplink(sessionA2, buildIPRequest(clientA, 0, 0x01, addr, netip.Addr{})))
	require.False(t, grantedIPv4(t, sessionA2.popPacket()).IsValid())

	owner, owned := server.ipam.Owner(addr)
	require.True(t, owned)
	require.Equal(t, clientB, owner)
	routed, found := server.routes.Lookup(addr)
	require.True(t, found)
	require.Equal(t, clientB, routed)

	server.sessionsMu.RLock()
	_, stale := server.clients[clientA]
	server.sessionsMu.RUnlock()
	require.False(t, stale, "失去地址的旧客户端状态必须被清理")
}

// 同一物理会话不断更换 ClientID 申请地址曾能耗尽地址池。
func TestServerEngine_SessionClientIDChurnDoesNotExhaustPool(t *testing.T) {
	server := newTestServer(t, "100.64.0.1/29", nil) // 5 个可分配地址
	session := &mockDirectSession{}
	for i := range 32 {
		clientID := uint64(0x40)<<56 | uint64(i+1)
		require.NoError(t, server.HandleUplink(session, buildIPRequest(clientID, 0, 0x01, netip.Addr{}, netip.Addr{})))
		require.True(t, grantedIPv4(t, session.popPacket()).IsValid(), "第 %d 次申请不应因地址池耗尽失败", i)
	}
	require.Equal(t, 1, server.ipam.LeaseCount(), "一个会话只应持有一个客户端的租约")
	require.Equal(t, 1, server.routes.Count())
}

// 地址池被离线客户端的长租约占满时，新客户端驱逐最久未活动的离线租约。
func TestServerEngine_EvictsIdleLeaseWhenExhausted(t *testing.T) {
	server := newTestServer(t, "100.64.0.1/30", nil)
	sessionA := &mockDirectSession{}
	const clientA, clientB = uint64(0x10) << 56, uint64(0x20) << 56
	require.NoError(t, server.HandleUplink(sessionA, buildIPRequest(clientA, 0, 0x01, netip.Addr{}, netip.Addr{})))
	addr := grantedIPv4(t, sessionA.popPacket())
	require.True(t, addr.IsValid())

	// A 在线时 B 无法抢占。
	sessionB := &mockDirectSession{}
	require.NoError(t, server.HandleUplink(sessionB, buildIPRequest(clientB, 0, 0x01, netip.Addr{}, netip.Addr{})))
	require.False(t, grantedIPv4(t, sessionB.popPacket()).IsValid(), "在线客户端的租约不得被驱逐")

	require.NoError(t, sessionA.Close())
	server.UnregisterSession(sessionA)
	require.NoError(t, server.HandleUplink(sessionB, buildIPRequest(clientB, 0, 0x01, netip.Addr{}, netip.Addr{})))
	require.Equal(t, addr, grantedIPv4(t, sessionB.popPacket()))
	routed, _ := server.routes.Lookup(addr)
	require.Equal(t, clientB, routed)
}

// 失效客户端的突发流量只触发一次 NACK 与一次重协商。
func TestNACKStorm_SingleRenegotiation(t *testing.T) {
	server := newTestServer(t, "100.64.0.1/24", nil)
	session := &mockDirectSession{}
	client := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		GetSession: func(ctx context.Context) (Session, error) {
			return session, nil
		},
	})
	defer client.Close()
	performInBandNegotiation(t, client, server, session)
	v4 := client.AssignedIPv4()

	server.ipam.mu.Lock()
	server.ipam.v4Pool.leases[v4].SetExpireAt(time.Now().Add(-time.Second))
	server.ipam.mu.Unlock()
	session.clear()

	packet := buildTestIPv4TCP(netip.AddrPortFrom(v4, 40000), netip.MustParseAddrPort("8.8.8.8:443"), 1, 0, header.TCPFlagAck, nil)
	for range 100 {
		require.NoError(t, server.HandleUplink(session, frameData(client.ClientID(), packet)))
	}
	require.Equal(t, 1, session.packetCount(), "同一会话同一地址的 NACK 必须限速")

	nack := session.popPacket()
	for range 100 {
		client.HandleDownlink(nack)
	}
	require.Eventually(t, func() bool { return session.packetCount() >= 1 }, time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, session.packetCount(), "重复的 NACK 只能触发一次重协商")
}

// 重协商只拿到单栈时，另一族的旧地址必须清空。
func TestClientEngine_RenegotiationClearsStaleFamily(t *testing.T) {
	client := NewClientEngine(ClientEngineOptions{Enabled: true, MTU: 1400})
	defer client.Close()
	client.OnNegotiatedDualStack(netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.1"),
		netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::1"), 1400)
	require.True(t, client.AssignedIPv6().IsValid())
	client.OnNegotiatedDualStack(netip.MustParseAddr("100.64.0.3"), netip.MustParseAddr("100.64.0.1"),
		netip.Addr{}, netip.Addr{}, 9000)
	require.False(t, client.AssignedIPv6().IsValid())
	require.False(t, client.ServerIPv6().IsValid())
	require.Equal(t, uint32(1400), client.MTU(), "隧道 MTU 取本端配置与服务端通告的较小值")
}

// 服务端拒绝时 Initialize 立即返回，而不是等到超时。
func TestClientEngine_InitializeFailsFastOnRejection(t *testing.T) {
	var client *ClientEngine
	session := &mockConcurrentSession{}
	session.onPacket = func(cmd byte, packet []byte) {
		resp := make([]byte, 83)
		resp[0] = PacketTypeIPResponse
		resp[1] = 1
		go client.HandleDownlink(resp)
	}
	client = NewClientEngine(ClientEngineOptions{
		Enabled: true,
		GetSession: func(ctx context.Context) (Session, error) {
			return session, nil
		},
	})
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	err := client.Initialize(ctx)
	require.ErrorIs(t, err, errNegotiationRejected)
	require.Less(t, time.Since(start), time.Second)
}

// 并发的 Initialize 共享同一次协商，只发出一个请求。
func TestClientEngine_ConcurrentInitializeSingleRequest(t *testing.T) {
	server := newTestServer(t, "100.64.0.1/24", nil)
	var (
		client   *ClientEngine
		requests atomic.Int64
	)
	session := &mockConcurrentSession{}
	session.onPacket = func(cmd byte, packet []byte) {
		if packet[0] == PacketTypeIPRequest {
			requests.Add(1)
			go func() {
				time.Sleep(20 * time.Millisecond)
				_ = server.HandleUplink(session, packet)
			}()
			return
		}
		client.HandleDownlink(packet)
	}
	client = NewClientEngine(ClientEngineOptions{
		Enabled: true,
		GetSession: func(ctx context.Context) (Session, error) {
			return session, nil
		},
	})
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			require.NoError(t, client.Initialize(ctx))
		}()
	}
	wg.Wait()
	require.True(t, client.IsReady())
	require.Equal(t, int64(1), requests.Load())
}

type mockBatchSession struct {
	mockDirectSession
	batches atomic.Int64
}

func (s *mockBatchSession) WriteFramePackets(cmd byte, prefix []byte, packets [][]byte) error {
	s.batches.Add(1)
	for _, packet := range packets {
		framed := append(append([]byte(nil), prefix...), packet...)
		if err := s.WriteFramePacket(cmd, framed); err != nil {
			return err
		}
	}
	return nil
}

func TestClientEngine_UsesBatchWrites(t *testing.T) {
	session := &mockBatchSession{}
	client := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		GetSession: func(ctx context.Context) (Session, error) {
			return session, nil
		},
	})
	defer client.Close()
	v4 := netip.MustParseAddr("100.64.0.2")
	client.OnNegotiatedDualStack(v4, netip.MustParseAddr("100.64.0.1"), netip.Addr{}, netip.Addr{}, 1400)
	client.SetCurrentSession(session)

	var packets [][]byte
	for i := range 8 {
		packets = append(packets, buildTestIPv4TCP(netip.AddrPortFrom(v4, uint16(40000+i)), netip.MustParseAddrPort("8.8.8.8:443"), 1, 0, header.TCPFlagAck, nil))
	}
	require.NoError(t, client.WritePackets(packets))
	require.Equal(t, int64(1), session.batches.Load(), "一批数据报只应写一次")
	require.Equal(t, 8, session.packetCount())
	frame := session.popPacket()
	require.Equal(t, client.ClientID(), binary.BigEndian.Uint64(frame[:8]))
}

// 会话不可用时，拨号失败后进入退避，后续批次不再同步阻塞。
func TestClientEngine_SessionDialBackoff(t *testing.T) {
	var dials atomic.Int64
	client := NewClientEngine(ClientEngineOptions{
		Enabled: true,
		GetSession: func(ctx context.Context) (Session, error) {
			dials.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	defer client.Close()
	v4 := netip.MustParseAddr("100.64.0.2")
	client.OnNegotiatedDualStack(v4, netip.MustParseAddr("100.64.0.1"), netip.Addr{}, netip.Addr{}, 1400)
	packet := buildTestIPv4TCP(netip.AddrPortFrom(v4, 40000), netip.MustParseAddrPort("8.8.8.8:443"), 1, 0, header.TCPFlagSyn, nil)

	require.NoError(t, client.WritePackets([][]byte{packet}))
	require.Equal(t, int64(1), dials.Load())
	start := time.Now()
	for range 10 {
		require.NoError(t, client.WritePackets([][]byte{packet}))
	}
	require.Less(t, time.Since(start), 100*time.Millisecond, "退避期内不得再阻塞拨号")
	require.Equal(t, int64(1), dials.Load())
}

// ICMP 差错回包中内嵌报文的源地址只有等于虚拟地址时才改写。
func TestRewriteDstIPv4_ICMPErrorInnerOnlyWhenMatching(t *testing.T) {
	assigned := netip.MustParseAddr("100.64.0.2")
	local := netip.MustParseAddr("172.19.0.1")
	other := netip.MustParseAddr("10.9.9.9")
	inner := buildTestIPv4TCP(netip.AddrPortFrom(other, 40000), netip.MustParseAddrPort("8.8.8.8:443"), 1, 0, header.TCPFlagSyn, nil)
	icmp := buildTestIPv4ICMPEcho(netip.MustParseAddr("8.8.8.8"), assigned, 3, 3, 0, 0, inner[:28])
	rewritePacketDstIPv4(icmp, local)
	ihl := int(icmp[0]&0x0f) * 4
	innerSrc := netip.AddrFrom4([4]byte(icmp[ihl+8+12 : ihl+8+16]))
	require.Equal(t, other, innerSrc, "内嵌报文源地址不是虚拟地址时不得改写")
	require.Equal(t, local, PacketDestinationIP(icmp))
}

func TestNormalizeMTUAndValidation(t *testing.T) {
	require.Equal(t, DefaultMTU, NormalizeMTU(0))
	require.Equal(t, MinMTU, NormalizeMTU(100))
	require.Equal(t, MaxMTU, NormalizeMTU(70000))

	_, err := NewServerEngine(ServerEngineOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/64")},
		MTU:     1000,
	})
	require.Error(t, err, "配置 IPv6 子网时 MTU 不得低于 1280")
	_, err = NewServerEngine(ServerEngineOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/24")},
		MTU:     70000,
	})
	require.Error(t, err)

	require.NoError(t, ValidateUDPMode(""))
	require.NoError(t, ValidateUDPMode("Reject"))
	require.Error(t, ValidateUDPMode("rejcet"))
}

// /64 等超大子网的租约数有上限，不能被无限撑大。
func TestIPAM_LargePoolIsCapped(t *testing.T) {
	ipam, err := NewIPAM([]netip.Prefix{netip.MustParsePrefix("fd00::1/64")})
	require.NoError(t, err)
	require.Equal(t, uint64(MaxLeasesPerPool), ipam.v6Pool.capacity)
}
