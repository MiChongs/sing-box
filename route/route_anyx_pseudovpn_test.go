package route

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/anyx/pseudovpn/pvtest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anyx"
	tun "github.com/sagernet/sing-tun"

	"github.com/stretchr/testify/require"
)

type testNoFakeIPTransportManager struct {
	adapter.DNSTransportManager
}

func (m *testNoFakeIPTransportManager) FakeIP() adapter.FakeIPTransport {
	return nil
}

// 启用 pseudo_vpn 的 AnyX 出站经真实的路由预匹配成为 TUN 的三层直通目标：TCP / ICMP 裁决为
// ActionFlow 且端口就是该出站；UDP 按 udp 策略裁决；未启用时交还常规 L4。
func TestPreMatchRoutesToAnyXPseudoVPN(t *testing.T) {
	newOutbound := func(pseudoVPN *option.AnyXPseudoVPNOutboundOptions) adapter.Outbound {
		outbound, err := anyx.NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "anyx", option.AnyXOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
			Password:      "password",
			PseudoVPN:     pseudoVPN,
		})
		require.NoError(t, err)
		return outbound
	}
	newRouter := func(outbound adapter.Outbound) *Router {
		return &Router{
			ctx:          context.Background(),
			logger:       log.NewNOPFactory().NewLogger("router"),
			outbound:     &testL3OutboundManager{defaultOutbound: outbound, outbounds: map[string]adapter.Outbound{outbound.Tag(): outbound}},
			dns:          new(testL3DNSRouter),
			dnsTransport: &testNoFakeIPTransportManager{},
		}
	}
	judge := func(router *Router, protocol uint8, destination string) tun.FlowVerdict {
		return adapter.JudgeFlow(router, adapter.InboundContext{Inbound: "tun-in", InboundType: C.TypeTun}, protocol,
			netip.MustParseAddrPort("172.19.0.2:40000"), netip.MustParseAddrPort(destination), nil)
	}

	for _, test := range []struct {
		udp    string
		action tun.FlowAction
	}{
		{"", tun.ActionDrop},
		{"drop", tun.ActionDrop},
		{"reject", tun.ActionReject},
		{"transparent", tun.ActionAccept},
	} {
		outbound := newOutbound(&option.AnyXPseudoVPNOutboundOptions{Enabled: true, UDP: test.udp})
		router := newRouter(outbound)
		for _, flow := range []struct {
			protocol    uint8
			destination string
		}{
			{pvtest.ProtocolTCP, "93.184.216.34:443"},
			{pvtest.ProtocolTCP, "[2606:2800:220:1::1]:443"},
			{pvtest.ProtocolICMP, "93.184.216.34:0"},
			{pvtest.ProtocolICMPv6, "[2606:2800:220:1::1]:0"},
		} {
			verdict := judge(router, flow.protocol, flow.destination)
			require.Equal(t, tun.ActionFlow, verdict.Action, "protocol %d to %s", flow.protocol, flow.destination)
			require.Same(t, outbound.(tun.Port), verdict.Port)
		}
		require.Equal(t, test.action, judge(router, pvtest.ProtocolUDP, "1.1.1.1:53").Action, "udp mode %q", test.udp)
	}

	plain := newRouter(newOutbound(nil))
	require.Equal(t, tun.ActionAccept, judge(plain, pvtest.ProtocolTCP, "93.184.216.34:443").Action, "未启用 pseudo_vpn 时走常规 L4")
}
