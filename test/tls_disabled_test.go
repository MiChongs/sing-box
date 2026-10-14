package main

import (
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

// 订阅转换与客户端常给出站写上 "tls": {"enabled": false}，此时应按明文连接，
// 而不是拿着空的 TLS 配置握手。
func TestTLSDisabledOutboundSelf(t *testing.T) {
	disabledTLS := option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: false}}
	user, err := uuid.DefaultGenerator.NewV4()
	require.NoError(t, err)
	listen := option.ListenOptions{
		Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
		ListenPort: serverPort,
	}
	server := option.ServerOptions{Server: "127.0.0.1", ServerPort: serverPort}
	for _, testCase := range []struct {
		name     string
		inbound  option.Inbound
		outbound option.Outbound
	}{
		{
			name: "vless",
			inbound: option.Inbound{Type: C.TypeVLESS, Options: &option.VLESSInboundOptions{
				ListenOptions: listen,
				Users:         []option.VLESSUser{{Name: "sekai", UUID: user.String()}},
			}},
			outbound: option.Outbound{Type: C.TypeVLESS, Tag: "proxy-out", Options: &option.VLESSOutboundOptions{
				ServerOptions:               server,
				UUID:                        user.String(),
				OutboundTLSOptionsContainer: disabledTLS,
			}},
		},
		{
			name: "trojan",
			inbound: option.Inbound{Type: C.TypeTrojan, Options: &option.TrojanInboundOptions{
				ListenOptions: listen,
				Users:         []option.TrojanUser{{Name: "sekai", Password: "password"}},
			}},
			outbound: option.Outbound{Type: C.TypeTrojan, Tag: "proxy-out", Options: &option.TrojanOutboundOptions{
				ServerOptions:               server,
				Password:                    "password",
				OutboundTLSOptionsContainer: disabledTLS,
			}},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			startInstance(t, option.Options{
				Inbounds: []option.Inbound{
					{
						Type: C.TypeMixed,
						Tag:  "mixed-in",
						Options: &option.HTTPMixedInboundOptions{
							ListenOptions: option.ListenOptions{
								Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
								ListenPort: clientPort,
							},
						},
					},
					testCase.inbound,
				},
				Outbounds: []option.Outbound{
					{Type: C.TypeDirect},
					testCase.outbound,
				},
				Route: &option.RouteOptions{
					Rules: []option.Rule{
						{
							Type: C.RuleTypeDefault,
							DefaultOptions: option.DefaultRule{
								RawDefaultRule: option.RawDefaultRule{
									Inbound: []string{"mixed-in"},
								},
								RuleAction: option.RuleAction{
									Action:       C.RuleActionTypeRoute,
									RouteOptions: option.RouteActionOptions{Outbound: "proxy-out"},
								},
							},
						},
					},
				},
			})
			testSuit(t, clientPort, testPort)
		})
	}
}
