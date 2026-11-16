package parser

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestOverridePseudoVPN_OptionsJSON(t *testing.T) {
	var override option.OverrideAnyTLSOptions
	require.NoError(t, json.UnmarshalContext(context.Background(), []byte(`{"use_anyx":true,"pseudo_vpn":{"enabled":true,"mtu":1380,"tcp_mss_clamping":false,"udp":"reject"}}`), &override))
	require.NotNil(t, override.PseudoVPN)
	require.True(t, *override.PseudoVPN.Enabled)
	require.Equal(t, uint32(1380), *override.PseudoVPN.MTU)
	require.False(t, *override.PseudoVPN.TCPMSSClamping)
	require.Equal(t, "reject", *override.PseudoVPN.UDP)
}

// use_anyx 转换 anytls 节点时带上 pseudo_vpn 覆写。
func TestOverridePseudoVPN_UseAnyXConversion(t *testing.T) {
	anytls := option.Outbound{
		Type: C.TypeAnyTLS,
		Tag:  "node",
		Options: &option.AnyTLSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "1.1.1.1", ServerPort: 443},
			Password:      "password",
		},
	}
	override := &option.OverrideAnyTLSOptions{
		UseAnyX: common.Ptr(true),
		PseudoVPN: &option.OverridePseudoVPNOptions{
			Enabled:        common.Ptr(true),
			MTU:            common.Ptr(uint32(1380)),
			TCPMSSClamping: common.Ptr(false),
			UDP:            common.Ptr("transparent"),
		},
	}
	outbounds := overrideOutbounds([]option.Outbound{anytls}, nil, nil, override, nil, []string{"node"}, "provider")
	require.Len(t, outbounds, 1)
	require.Equal(t, C.TypeAnyX, outbounds[0].Type)
	anyxOptions := outbounds[0].Options.(*option.AnyXOutboundOptions)
	require.NotNil(t, anyxOptions.PseudoVPN)
	require.True(t, anyxOptions.PseudoVPN.Enabled)
	require.Equal(t, uint32(1380), anyxOptions.PseudoVPN.MTU)
	require.False(t, *anyxOptions.PseudoVPN.TCPMSSClamping)
	require.Equal(t, "transparent", anyxOptions.PseudoVPN.UDP)
}

// 覆写 AnyX 节点自带的 pseudo_vpn：逐字段覆写，不修改节点原有选项；节点没有 pseudo_vpn 时，
// 只有 enabled 为 true 才添加。
func TestOverridePseudoVPN_AnyXNodes(t *testing.T) {
	original := &option.AnyXPseudoVPNOutboundOptions{Enabled: true, MTU: 1300, UDP: "drop"}
	withPseudoVPN := option.Outbound{
		Type: C.TypeAnyX,
		Tag:  "with",
		Options: &option.AnyXOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "1.1.1.1", ServerPort: 443},
			Password:      "password",
			PseudoVPN:     original,
		},
	}
	withoutPseudoVPN := option.Outbound{
		Type: C.TypeAnyX,
		Tag:  "without",
		Options: &option.AnyXOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "1.1.1.2", ServerPort: 443},
			Password:      "password",
		},
	}

	mtuOnly := &option.OverrideAnyTLSOptions{PseudoVPN: &option.OverridePseudoVPNOptions{MTU: common.Ptr(uint32(1200))}}
	outbounds := overrideOutbounds([]option.Outbound{withPseudoVPN, withoutPseudoVPN}, nil, nil, mtuOnly, nil, []string{"with", "without"}, "provider")
	overridden := outbounds[0].Options.(*option.AnyXOutboundOptions).PseudoVPN
	require.Equal(t, uint32(1200), overridden.MTU)
	require.True(t, overridden.Enabled)
	require.Equal(t, "drop", overridden.UDP)
	require.Equal(t, uint32(1300), original.MTU, "不得修改订阅节点原有的选项")
	require.Nil(t, outbounds[1].Options.(*option.AnyXOutboundOptions).PseudoVPN, "未启用时不得凭空添加 pseudo_vpn")

	disable := &option.OverrideAnyTLSOptions{PseudoVPN: &option.OverridePseudoVPNOptions{Enabled: common.Ptr(false)}}
	withPseudoVPN.Options.(*option.AnyXOutboundOptions).PseudoVPN = original
	outbounds = overrideOutbounds([]option.Outbound{withPseudoVPN}, nil, nil, disable, nil, []string{"with"}, "provider")
	require.False(t, outbounds[0].Options.(*option.AnyXOutboundOptions).PseudoVPN.Enabled)
}
