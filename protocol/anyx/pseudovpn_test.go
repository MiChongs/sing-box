package anyx

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/anyx/pseudovpn"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

var _ tun.Return = (*testClientReturn)(nil)

type testClientReturn struct {
	mu      sync.Mutex
	packets [][]byte
}

func (r *testClientReturn) ReturnHeadroom() int { return 0 }

func (r *testClientReturn) ReturnPackets(packets [][]byte) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range packets {
		cp := make([]byte, len(p))
		copy(cp, p)
		r.packets = append(r.packets, cp)
	}
	return nil
}

type testInterceptTun struct {
	tun.Tun
	mu         sync.Mutex
	tunPackets [][]byte
	closed     chan struct{}
}

func newTestInterceptTun() *testInterceptTun {
	return &testInterceptTun{closed: make(chan struct{})}
}

func (t *testInterceptTun) Start() error { return nil }

func (t *testInterceptTun) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}

func (t *testInterceptTun) Read(p []byte) (int, error) {
	<-t.closed
	return 0, net.ErrClosed
}

func (t *testInterceptTun) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(p) >= tun.PacketOffset {
		packet := p[tun.PacketOffset:]
		cp := make([]byte, len(packet))
		copy(cp, packet)
		t.tunPackets = append(t.tunPackets, cp)
	}
	return len(p), nil
}

func setEngineTun(engine *pseudovpn.ServerEngine, tunDev tun.Tun) {
	field := reflect.ValueOf(engine).Elem().FieldByName("tunIf")
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(tunDev))
}

// 显式为 testEchoRouter 实现 PreMatch 方法，避免调用未初始化的内嵌 adapter.Router 接口
func (r *testEchoRouter) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	return adapter.PreMatchResult{
		Action: adapter.PreMatchContinue,
	}
}

// ---------------------------------------------------------------------------
// 1. 配置反序列化兼容性测试与参数强校验测试
// ---------------------------------------------------------------------------

func TestPseudoVPNOptionsJSON(t *testing.T) {
	// 客户端选项结构体解析 (含 TCPMSSClamping)
	var outObj option.AnyXOutboundOptions
	require.NoError(t, json.Unmarshal([]byte(`{"server":"127.0.0.1","password":"test","pseudo_vpn":{"enabled":true,"mtu":1400,"tcp_mss_clamping":false,"udp":"transparent"}}`), &outObj))
	require.NotNil(t, outObj.PseudoVPN)
	require.True(t, outObj.PseudoVPN.Enabled)
	require.Equal(t, uint32(1400), outObj.PseudoVPN.MTU)
	require.NotNil(t, outObj.PseudoVPN.TCPMSSClamping)
	require.False(t, *outObj.PseudoVPN.TCPMSSClamping)
	require.Equal(t, "transparent", outObj.PseudoVPN.UDP)

	// 服务端双栈配置解析 (包含 lease_duration 与 tcp_mss_clamping)
	var inObj option.AnyXInboundOptions
	inJSON := `{"pseudo_vpn":{"enabled":true,"interface_name":"anyx-test","mtu":1400,"address":["100.64.0.1/24","fd00::1/64"],"lease_duration":"3d","tcp_mss_clamping":true}}`
	require.NoError(t, json.Unmarshal([]byte(inJSON), &inObj))
	require.NotNil(t, inObj.PseudoVPN)
	require.True(t, inObj.PseudoVPN.Enabled)
	require.Equal(t, "anyx-test", inObj.PseudoVPN.InterfaceName)
	require.Equal(t, uint32(1400), inObj.PseudoVPN.MTU)
	require.Len(t, inObj.PseudoVPN.Address, 2)
	require.Equal(t, netip.MustParsePrefix("100.64.0.1/24"), inObj.PseudoVPN.Address[0])
	require.Equal(t, netip.MustParsePrefix("fd00::1/64"), inObj.PseudoVPN.Address[1])
	require.Equal(t, 3*24*time.Hour, inObj.PseudoVPN.LeaseDuration.Build())
	require.NotNil(t, inObj.PseudoVPN.TCPMSSClamping)
	require.True(t, *inObj.PseudoVPN.TCPMSSClamping)
}

func TestPseudoVPNInboundAddressValidation(t *testing.T) {
	certPath, keyPath := generateTestCert(t)
	port := getFreePort(t)

	baseOpt := func(addrs []string) option.AnyXInboundOptions {
		prefixes := make([]netip.Prefix, 0, len(addrs))
		for _, a := range addrs {
			prefixes = append(prefixes, netip.MustParsePrefix(a))
		}
		return option.AnyXInboundOptions{
			ListenOptions: option.ListenOptions{ListenPort: port},
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &option.InboundTLSOptions{
					Enabled:         true,
					CertificatePath: certPath,
					KeyPath:         keyPath,
				},
			},
			Users: []option.AnyXUser{{Name: "user", Password: "test-password"}},
			PseudoVPN: &option.AnyXPseudoVPNInboundOptions{
				Enabled:       true,
				InterfaceName: "anyx-test-tun",
				MTU:           1400,
				Address:       badoption.Listable[netip.Prefix](prefixes),
			},
		}
	}

	// 1. 空地址列表 -> 由引擎 NewIPAM 拒绝
	_, err := NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "inb-empty", baseOpt(nil))
	require.ErrorIs(t, err, pseudovpn.ErrAddressEmpty)

	// 2. 多个 IPv4 子网 -> 由引擎 NewIPAM 拒绝
	_, err = NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "inb-multi-v4", baseOpt([]string{"100.64.0.1/24", "100.65.0.1/24"}))
	require.ErrorIs(t, err, pseudovpn.ErrTooManyIPv4Subnets)

	// 3. 多个 IPv6 子网 -> 由引擎 NewIPAM 拒绝
	_, err = NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "inb-multi-v6", baseOpt([]string{"fd00::1/64", "fd01::1/64"}))
	require.ErrorIs(t, err, pseudovpn.ErrTooManyIPv6Subnets)

	// 4. 双栈（1个 IPv4 + 1个 IPv6） -> 正常通过
	inb, err := NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "inb-dual-ok", baseOpt([]string{"100.64.0.1/24", "fd00::1/64"}))
	require.NoError(t, err)
	require.NotNil(t, inb)
}

// ---------------------------------------------------------------------------
// 2. 接口合规性测试 (adapter.FlowOutbound & tun.Port)
// ---------------------------------------------------------------------------

func TestPseudoVPNOutboundInterfaceContract(t *testing.T) {
	// 开启状态 (默认 UDP drop)
	outbEnabled, err := NewOutbound(t.Context(), nil, logger.NOP(), "outb-enabled", option.AnyXOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		Password:      "test",
		PseudoVPN:     &option.AnyXPseudoVPNOutboundOptions{Enabled: true},
	})
	require.NoError(t, err)
	flowOutb := outbEnabled.(adapter.FlowOutbound)
	portOutb := outbEnabled.(tun.Port)
	require.Equal(t, adapter.PreMatchFlow, flowOutb.PreMatchFlow("tcp", netip.MustParseAddr("1.1.1.1")))
	require.Equal(t, adapter.PreMatchFlow, flowOutb.PreMatchFlow("tcp", netip.MustParseAddr("2001:db8::1")))
	require.Equal(t, adapter.PreMatchDrop, flowOutb.PreMatchFlow("udp", netip.MustParseAddr("1.1.1.1")), "默认 drop 模式下由网卡边界直接丢弃 (PreMatchDrop)")
	require.Equal(t, uint32(1400), portOutb.PortMTU())

	// 验证未协商时仍通告占位 IP 以锁定 ActionFlow
	v4, v6 := portOutb.PortAddresses()
	require.True(t, v4.IsValid())
	require.True(t, v6.IsValid())

	// 开启状态 (UDP reject)
	outbReject, err := NewOutbound(t.Context(), nil, logger.NOP(), "outb-reject", option.AnyXOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		Password:      "test",
		PseudoVPN:     &option.AnyXPseudoVPNOutboundOptions{Enabled: true, UDP: "reject"},
	})
	require.NoError(t, err)
	flowOutbReject := outbReject.(adapter.FlowOutbound)
	require.Equal(t, adapter.PreMatchReject, flowOutbReject.PreMatchFlow("udp", netip.MustParseAddr("1.1.1.1")), "reject 模式下由网卡边界直接拒绝 (PreMatchReject)")

	// 开启状态 (UDP transparent)
	outbTransparent, err := NewOutbound(t.Context(), nil, logger.NOP(), "outb-trans", option.AnyXOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		Password:      "test",
		PseudoVPN:     &option.AnyXPseudoVPNOutboundOptions{Enabled: true, UDP: "transparent"},
	})
	require.NoError(t, err)
	flowOutbTrans := outbTransparent.(adapter.FlowOutbound)
	require.Equal(t, adapter.PreMatchFlow, flowOutbTrans.PreMatchFlow("tcp", netip.MustParseAddr("1.1.1.1")))
	require.Equal(t, adapter.PreMatchContinue, flowOutbTrans.PreMatchFlow("udp", netip.MustParseAddr("1.1.1.1")), "transparent 模式下 UDP 旁路放行")

	// 关闭状态：验证空指针守卫有效性，调用 tun.Port 方法绝对不发生 panic
	outbDisabled, err := NewOutbound(t.Context(), nil, logger.NOP(), "outb-disabled", option.AnyXOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		Password:      "test",
	})
	require.NoError(t, err)
	flowOutbDis := outbDisabled.(adapter.FlowOutbound)
	portOutbDis := outbDisabled.(tun.Port)
	require.Equal(t, adapter.PreMatchContinue, flowOutbDis.PreMatchFlow("tcp", netip.MustParseAddr("1.1.1.1")))
	require.Equal(t, adapter.PreMatchContinue, flowOutbDis.PreMatchFlow("tcp", netip.MustParseAddr("2001:db8::1")))
	require.Equal(t, adapter.PreMatchContinue, flowOutbDis.PreMatchFlow("udp", netip.MustParseAddr("1.1.1.1")))

	require.NotPanics(t, func() {
		dv4, dv6 := portOutbDis.PortAddresses()
		require.False(t, dv4.IsValid())
		require.False(t, dv6.IsValid())
		require.Equal(t, uint32(0), portOutbDis.PortMTU())
		require.Nil(t, outbDisabled.(*Outbound).UpstreamPort())
		require.NoError(t, portOutbDis.AttachReturn(nil))
		require.NoError(t, portOutbDis.DetachReturn(nil))
		require.ErrorIs(t, portOutbDis.WritePackets(nil), os.ErrInvalid)
	}, "未开启 PseudoVPN 时显式代理实现必须安全防御，严禁触发空指针 panic")
}

// ---------------------------------------------------------------------------
// 3. 端到端多场景综合测试：双栈直通、L3/L4混流、ICMPv4/v6、网络漫游快速重连
// ---------------------------------------------------------------------------

func TestPseudoVPNEndToEndComprehensive(t *testing.T) {
	certPath, keyPath := generateTestCert(t)
	port := getFreePort(t)

	// 服务端配置 (开启 PseudoVPN 双栈)
	inbOpt := option.AnyXInboundOptions{
		ListenOptions: option.ListenOptions{ListenPort: port},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
		Users: []option.AnyXUser{{Name: "user", Password: "pseudovpn-password"}},
		PseudoVPN: &option.AnyXPseudoVPNInboundOptions{
			Enabled:       true,
			InterfaceName: "anyx-test-tun",
			MTU:           1400,
			Address: badoption.Listable[netip.Prefix]{
				netip.MustParsePrefix("100.64.0.1/24"),
				netip.MustParsePrefix("fd00::1/64"),
			},
		},
	}

	rawInb, err := NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "inbound-pvpn", inbOpt)
	require.NoError(t, err)
	inb := rawInb.(*Inbound)

	interceptTun := newTestInterceptTun()
	setEngineTun(inb.pseudoVPNEngine, interceptTun)

	inbScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = inbScope.Close() })
	require.NoError(t, inb.Start(adapter.StartStateStart, inbScope))

	// 客户端配置 (开启 PseudoVPN)
	outbOpt := option.AnyXOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "127.0.0.1",
				Insecure:   true,
			},
		},
		Password:  "pseudovpn-password",
		PseudoVPN: &option.AnyXPseudoVPNOutboundOptions{Enabled: true},
	}

	rawOutb, err := NewOutbound(t.Context(), nil, logger.NOP(), "outbound-pvpn", outbOpt)
	require.NoError(t, err)
	outb := rawOutb.(*Outbound)

	outbScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = outbScope.Close() })
	require.NoError(t, outb.Start(adapter.StartStateInitialize, outbScope))
	require.NoError(t, outb.Start(adapter.StartStateStart, outbScope))

	clientReturn := &testClientReturn{}
	require.NoError(t, outb.AttachReturn(clientReturn))

	// =========================================================================
	// 场景 A: 原生 L4 流量验证
	// =========================================================================
	l4Conn, err := outb.DialContext(t.Context(), "tcp", M.ParseSocksaddr("127.0.0.1:80"))
	require.NoError(t, err)

	_, err = l4Conn.Write([]byte("l4-echo-request"))
	require.NoError(t, err)

	l4Recv := make([]byte, 15)
	_, err = io.ReadFull(l4Conn, l4Recv)
	require.NoError(t, err)
	require.Equal(t, "l4-echo-request", string(l4Recv))

	// =========================================================================
	// 场景 B: PseudoVPN L3 IPv4 流量进出与双向透传 (TCP)
	// =========================================================================
	require.Eventually(t, func() bool {
		return outb.pseudoVPNEngine.IsReady()
	}, 5*time.Second, 50*time.Millisecond)

	assignedIPv4 := outb.pseudoVPNEngine.AssignedIPv4()
	require.True(t, assignedIPv4.IsValid())
	require.Equal(t, netip.MustParseAddr("100.64.0.2"), assignedIPv4)

	clientSrc := netip.AddrPortFrom(assignedIPv4, 34567)
	// TUN 转发器把流的源地址改写为端口地址，引擎再在端口地址与虚拟地址之间做 1:1 NAT。
	clientLocal := netip.AddrPortFrom(pseudovpn.LocalPortIPv4, 34567)
	targetDst := netip.MustParseAddrPort("1.1.1.1:80")
	l3Payload := []byte("l3-packet-payload")
	l3UplinkPacket := buildTestIPv4TCP(clientLocal, targetDst, 1000, 0, header.TCPFlagSyn, l3Payload)
	l3UplinkPacketExpected := buildTestIPv4TCP(clientSrc, targetDst, 1000, 0, header.TCPFlagSyn, l3Payload)

	err = outb.WritePackets([][]byte{l3UplinkPacket})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		interceptTun.mu.Lock()
		defer interceptTun.mu.Unlock()
		return len(interceptTun.tunPackets) > 0
	}, 3*time.Second, 50*time.Millisecond)

	interceptTun.mu.Lock()
	receivedAtServer := interceptTun.tunPackets[0]
	interceptTun.tunPackets = nil
	interceptTun.mu.Unlock()
	require.Equal(t, l3UplinkPacketExpected, receivedAtServer)

	// 服务端下行回包 (通过 HandleDownlink 注入)
	l3DownlinkPacket := buildTestIPv4TCP(targetDst, clientSrc, 2000, 1001, header.TCPFlagSyn|header.TCPFlagAck, []byte("l3-packet-response"))
	l3DownlinkPacketExpected := buildTestIPv4TCP(targetDst, clientLocal, 2000, 1001, header.TCPFlagSyn|header.TCPFlagAck, []byte("l3-packet-response"))
	err = inb.pseudoVPNEngine.HandleDownlink(l3DownlinkPacket)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		clientReturn.mu.Lock()
		defer clientReturn.mu.Unlock()
		return len(clientReturn.packets) > 0
	}, 3*time.Second, 50*time.Millisecond)

	clientReturn.mu.Lock()
	receivedAtClient := clientReturn.packets[0]
	clientReturn.packets = nil
	clientReturn.mu.Unlock()
	require.Equal(t, l3DownlinkPacketExpected, receivedAtClient)

	// =========================================================================
	// 场景 C: ICMPv4 Ping 报文透传
	// =========================================================================
	icmpPkt := buildTestIPv4ICMPPacket(pseudovpn.LocalPortIPv4, netip.MustParseAddr("8.8.8.8"), 8, 0, []byte("ping-test"))
	icmpPktExpected := buildTestIPv4ICMPPacket(assignedIPv4, netip.MustParseAddr("8.8.8.8"), 8, 0, []byte("ping-test"))
	err = outb.WritePackets([][]byte{icmpPkt})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		interceptTun.mu.Lock()
		defer interceptTun.mu.Unlock()
		return len(interceptTun.tunPackets) > 0
	}, 3*time.Second, 50*time.Millisecond)

	interceptTun.mu.Lock()
	require.Equal(t, icmpPktExpected, interceptTun.tunPackets[0])
	interceptTun.tunPackets = nil
	interceptTun.mu.Unlock()

	// =========================================================================
	// 场景 D: L3 与 L4 单物理连接并发混流与生命周期验证
	// =========================================================================
	_, err = l4Conn.Write([]byte("l4-concurrent-1"))
	require.NoError(t, err)

	l3Interleaved := buildTestIPv4TCP(clientLocal, targetDst, 1001, 0, header.TCPFlagAck, []byte("interleaved-l3"))
	l3InterleavedExpected := buildTestIPv4TCP(clientSrc, targetDst, 1001, 0, header.TCPFlagAck, []byte("interleaved-l3"))
	err = outb.WritePackets([][]byte{l3Interleaved})
	require.NoError(t, err)

	l4ConcurrentRecv := make([]byte, 15)
	_, err = io.ReadFull(l4Conn, l4ConcurrentRecv)
	require.NoError(t, err)
	require.Equal(t, "l4-concurrent-1", string(l4ConcurrentRecv))

	require.Eventually(t, func() bool {
		interceptTun.mu.Lock()
		defer interceptTun.mu.Unlock()
		return len(interceptTun.tunPackets) > 0
	}, 3*time.Second, 50*time.Millisecond)

	interceptTun.mu.Lock()
	require.Equal(t, l3InterleavedExpected, interceptTun.tunPackets[0])
	interceptTun.tunPackets = nil
	interceptTun.mu.Unlock()

	// 关闭 L4 连接，验证 L3 会话稳定且持续正常收发
	require.NoError(t, l4Conn.Close())

	l3AfterClose := buildTestIPv4TCP(clientLocal, targetDst, 1002, 0, header.TCPFlagAck, []byte("after-l4-close"))
	l3AfterCloseExpected := buildTestIPv4TCP(clientSrc, targetDst, 1002, 0, header.TCPFlagAck, []byte("after-l4-close"))
	err = outb.WritePackets([][]byte{l3AfterClose})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		interceptTun.mu.Lock()
		defer interceptTun.mu.Unlock()
		return len(interceptTun.tunPackets) > 0
	}, 3*time.Second, 50*time.Millisecond)

	interceptTun.mu.Lock()
	require.Equal(t, l3AfterCloseExpected, interceptTun.tunPackets[0])
	interceptTun.tunPackets = nil
	interceptTun.mu.Unlock()

	// =========================================================================
	// 场景 E: PseudoVPN L3 IPv6 流量进出与 ICMPv6 透传
	// =========================================================================
	assignedIPv6 := outb.pseudoVPNEngine.AssignedIPv6()
	require.True(t, assignedIPv6.IsValid())
	require.Equal(t, netip.MustParseAddr("fd00::2"), assignedIPv6)

	clientSrc6 := netip.AddrPortFrom(assignedIPv6, 34567)
	clientLocal6 := netip.AddrPortFrom(pseudovpn.LocalPortIPv6, 34567)
	targetDst6 := netip.MustParseAddrPort("[2001:4860:4860::8888]:80")
	l3Payload6 := []byte("l3-v6-packet-payload")
	l3UplinkPacket6 := buildTestIPv6TCP(clientLocal6, targetDst6, 1000, 0, header.TCPFlagSyn, l3Payload6)
	l3UplinkPacket6Expected := buildTestIPv6TCP(clientSrc6, targetDst6, 1000, 0, header.TCPFlagSyn, l3Payload6)

	err = outb.WritePackets([][]byte{l3UplinkPacket6})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		interceptTun.mu.Lock()
		defer interceptTun.mu.Unlock()
		return len(interceptTun.tunPackets) > 0
	}, 3*time.Second, 50*time.Millisecond)

	interceptTun.mu.Lock()
	receivedAtServer6 := interceptTun.tunPackets[0]
	interceptTun.tunPackets = nil
	interceptTun.mu.Unlock()
	require.Equal(t, l3UplinkPacket6Expected, receivedAtServer6)

	// 服务端下行 IPv6 回包
	l3DownlinkPacket6 := buildTestIPv6TCP(targetDst6, clientSrc6, 2000, 1001, header.TCPFlagSyn|header.TCPFlagAck, []byte("l3-v6-packet-response"))
	l3DownlinkPacket6Expected := buildTestIPv6TCP(targetDst6, clientLocal6, 2000, 1001, header.TCPFlagSyn|header.TCPFlagAck, []byte("l3-v6-packet-response"))
	err = inb.pseudoVPNEngine.HandleDownlink(l3DownlinkPacket6)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		clientReturn.mu.Lock()
		defer clientReturn.mu.Unlock()
		return len(clientReturn.packets) > 0
	}, 3*time.Second, 50*time.Millisecond)

	clientReturn.mu.Lock()
	receivedAtClient6 := clientReturn.packets[0]
	clientReturn.packets = nil
	clientReturn.mu.Unlock()
	require.Equal(t, l3DownlinkPacket6Expected, receivedAtClient6)

	// ICMPv6 Ping
	icmp6Pkt := buildTestIPv6ICMPPacket(pseudovpn.LocalPortIPv6, netip.MustParseAddr("2001:4860:4860::8888"), 128, 0, []byte("ping6-test"))
	icmp6PktExpected := buildTestIPv6ICMPPacket(assignedIPv6, netip.MustParseAddr("2001:4860:4860::8888"), 128, 0, []byte("ping6-test"))
	err = outb.WritePackets([][]byte{icmp6Pkt})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		interceptTun.mu.Lock()
		defer interceptTun.mu.Unlock()
		return len(interceptTun.tunPackets) > 0
	}, 3*time.Second, 50*time.Millisecond)

	interceptTun.mu.Lock()
	require.Equal(t, icmp6PktExpected, interceptTun.tunPackets[0])
	interceptTun.tunPackets = nil
	interceptTun.mu.Unlock()

	// =========================================================================
	// 场景 F: 网络漫游测试 (触发 InterfaceUpdated 与 Session Pinning 自动切换)
	// =========================================================================
	outb.InterfaceUpdated(t.Context())

	// 漫游后旧物理会话必须立即原子脱落置空（消除并发重绑竞态）
	require.Nil(t, outb.pseudoVPNEngine.CurrentSession(), "漫游后物理会话必须立即置空脱落")

	// 验证漫游后 IP 保持绝对一致 (无感换乘)
	require.Equal(t, assignedIPv4, outb.pseudoVPNEngine.AssignedIPv4())
	require.Equal(t, assignedIPv6, outb.pseudoVPNEngine.AssignedIPv6())

	// 验证漫游后能够在新物理通道上持续正常收发数据报 (首包同步拉起物理连接并直发)
	roamUplinkPkt := buildTestIPv4TCP(clientLocal, targetDst, 1003, 0, header.TCPFlagAck, []byte("roamed-uplink"))
	roamUplinkPktExpected := buildTestIPv4TCP(clientSrc, targetDst, 1003, 0, header.TCPFlagAck, []byte("roamed-uplink"))
	require.NoError(t, outb.WritePackets([][]byte{roamUplinkPkt}))

	// 发包后，首包触发了同步建连，CurrentSession 必须已就绪
	require.NotNil(t, outb.pseudoVPNEngine.CurrentSession(), "首包发出后物理连接必须已同步完成锁存")

	require.Eventually(t, func() bool {
		interceptTun.mu.Lock()
		defer interceptTun.mu.Unlock()
		return len(interceptTun.tunPackets) > 0
	}, 3*time.Second, 50*time.Millisecond)

	interceptTun.mu.Lock()
	require.Equal(t, roamUplinkPktExpected, interceptTun.tunPackets[0])
	interceptTun.tunPackets = nil
	interceptTun.mu.Unlock()
}

// ---------------------------------------------------------------------------
// 4. 单栈不支持时的 Fail-Closed 阻断测试 (就地静默丢弃，不崩客户端 TUN)
// ---------------------------------------------------------------------------

func TestPseudoVPNIPv6FailClosed(t *testing.T) {
	certPath, keyPath := generateTestCert(t)
	port := getFreePort(t)

	// 服务端：只配置 IPv4 子网，不配置 IPv6 子网
	inbOpt := option.AnyXInboundOptions{
		ListenOptions: option.ListenOptions{ListenPort: port},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
		Users: []option.AnyXUser{{Name: "user", Password: "pseudovpn-password"}},
		PseudoVPN: &option.AnyXPseudoVPNInboundOptions{
			Enabled:       true,
			InterfaceName: "anyx-test-tun-v4only",
			MTU:           1400,
			Address:       badoption.Listable[netip.Prefix]{netip.MustParsePrefix("100.64.0.1/24")},
		},
	}

	rawInb, err := NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "inbound-v4only", inbOpt)
	require.NoError(t, err)
	inb := rawInb.(*Inbound)

	interceptTun := newTestInterceptTun()
	setEngineTun(inb.pseudoVPNEngine, interceptTun)

	inbScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = inbScope.Close() })
	require.NoError(t, inb.Start(adapter.StartStateStart, inbScope))

	// 客户端：开启 PseudoVPN
	outbOpt := option.AnyXOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "127.0.0.1",
				Insecure:   true,
			},
		},
		Password:  "pseudovpn-password",
		PseudoVPN: &option.AnyXPseudoVPNOutboundOptions{Enabled: true},
	}

	rawOutb, err := NewOutbound(t.Context(), nil, logger.NOP(), "outbound-v4only", outbOpt)
	require.NoError(t, err)
	outb := rawOutb.(*Outbound)

	outbScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = outbScope.Close() })
	require.NoError(t, outb.Start(adapter.StartStateInitialize, outbScope))
	require.NoError(t, outb.Start(adapter.StartStateStart, outbScope))

	require.Eventually(t, func() bool {
		return outb.pseudoVPNEngine.IsReady()
	}, 5*time.Second, 50*time.Millisecond)

	// 验证 IPv4 正常就绪，IPv6 未分配
	require.True(t, outb.pseudoVPNEngine.AssignedIPv4().IsValid())
	require.False(t, outb.pseudoVPNEngine.AssignedIPv6().IsValid())

	// 验证 PortAddresses 依然通告双栈本地端口地址以锁死 ActionFlow，杜绝 IPv6 降级到本地 gVisor
	p4, p6 := outb.PortAddresses()
	require.Equal(t, pseudovpn.LocalPortIPv4, p4)
	require.Equal(t, pseudovpn.LocalPortIPv6, p6)

	// 发送 IPv6 数据包 -> 触发 Fail-Closed，客户端就地静默丢弃，严格返回 nil 杜绝崩溃本地 TUN
	v6Pkt := buildTestIPv6TCP(
		netip.MustParseAddrPort("[fd00::2]:34567"),
		netip.MustParseAddrPort("[2001:4860:4860::8888]:80"),
		1000, 0, header.TCPFlagSyn,
		[]byte("v6-must-drop"),
	)
	err = outb.WritePackets([][]byte{v6Pkt})
	require.NoError(t, err)

	// 服务端 TUN 绝不能收到该报文
	interceptTun.mu.Lock()
	require.Empty(t, interceptTun.tunPackets)
	interceptTun.mu.Unlock()
}

// ---------------------------------------------------------------------------
// 5. 协商降级与单边开启兼容性验证
// ---------------------------------------------------------------------------

func TestPseudoVPNNegotiationMismatch(t *testing.T) {
	certPath, keyPath := generateTestCert(t)
	port := getFreePort(t)

	// 服务端：未开启 PseudoVPN
	inbOpt := option.AnyXInboundOptions{
		ListenOptions: option.ListenOptions{ListenPort: port},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
		Users: []option.AnyXUser{{Name: "user", Password: "test-password"}},
	}
	inb, err := NewInbound(t.Context(), &testEchoRouter{}, logger.NOP(), "inbound-nomatch", inbOpt)
	require.NoError(t, err)

	inbScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = inbScope.Close() })
	require.NoError(t, inb.Start(adapter.StartStateStart, inbScope))

	// 客户端：开启了 PseudoVPN
	outbOpt := option.AnyXOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "127.0.0.1",
				Insecure:   true,
			},
		},
		Password:  "test-password",
		PseudoVPN: &option.AnyXPseudoVPNOutboundOptions{Enabled: true},
	}
	rawOutb, err := NewOutbound(t.Context(), nil, logger.NOP(), "outbound-nomatch", outbOpt)
	require.NoError(t, err)
	outb := rawOutb.(*Outbound)

	outbScope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = outbScope.Close() })
	require.NoError(t, outb.Start(adapter.StartStateInitialize, outbScope))

	conn, err := outb.DialContext(t.Context(), "tcp", M.ParseSocksaddr("127.0.0.1:80"))
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("fallback-check"))
	require.NoError(t, err)
	recv := make([]byte, 14)
	_, err = io.ReadFull(conn, recv)
	require.NoError(t, err)
	require.Equal(t, "fallback-check", string(recv))

	require.False(t, outb.pseudoVPNEngine.IsReady())
}

// ---------------------------------------------------------------------------
// 辅助封包与校验和函数
// ---------------------------------------------------------------------------

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

func buildTestIPv4ICMPPacket(src, dst netip.Addr, icmpType, icmpCode uint8, payload []byte) []byte {
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

	var sum uint32
	for i := 0; i < 20; i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	icmp := pkt[20:]
	icmp[0] = icmpType
	icmp[1] = icmpCode
	copy(icmp[8:], payload)

	var icmpSum uint32
	for i := 0; i < len(icmp)-1; i += 2 {
		icmpSum += uint32(binary.BigEndian.Uint16(icmp[i : i+2]))
	}
	if len(icmp)%2 == 1 {
		icmpSum += uint32(icmp[len(icmp)-1]) << 8
	}
	for icmpSum > 0xffff {
		icmpSum = (icmpSum & 0xffff) + (icmpSum >> 16)
	}
	binary.BigEndian.PutUint16(icmp[2:4], ^uint16(icmpSum))
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

func buildTestIPv6ICMPPacket(src, dst netip.Addr, icmpType, icmpCode uint8, payload []byte) []byte {
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
