package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

// XHTTP 隧道靠取消请求、重置流或关闭连接来结束，路由层不应把这些记成
// "connection upload closed: H3_REQUEST_CANCELLED" 一类的 ERROR。
func TestXHTTPCloseLogSelf(t *testing.T) {
	caPem, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	user, err := uuid.DefaultGenerator.NewV4()
	require.NoError(t, err)
	for _, alpn := range []string{"h3", "h2"} {
		for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
			t.Run(alpn+"/"+mode, func(t *testing.T) {
				logPath := filepath.Join(t.TempDir(), "box.log")
				instance := startInstance(t, option.Options{
					Log: &option.LogOptions{Level: "error", Output: logPath},
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
						{
							Type: C.TypeVLESS,
							Options: &option.VLESSInboundOptions{
								ListenOptions: option.ListenOptions{
									Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
									ListenPort: serverPort,
								},
								Users: []option.VLESSUser{{Name: "sekai", UUID: user.String()}},
								InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
									TLS: &option.InboundTLSOptions{
										Enabled:         true,
										ServerName:      "example.org",
										ALPN:            []string{alpn},
										CertificatePath: certPem,
										KeyPath:         keyPem,
									},
								},
								Transport: &option.V2RayTransportOptions{
									Type:  C.V2RayTransportTypeXHTTP,
									Extra: &option.V2RayXHTTPOptions{Path: "/xhttp"},
								},
							},
						},
					},
					Outbounds: []option.Outbound{
						{Type: C.TypeDirect},
						{
							Type: C.TypeVLESS,
							Tag:  "vless-out",
							Options: &option.VLESSOutboundOptions{
								ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: serverPort},
								UUID:          user.String(),
								OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
									TLS: &option.OutboundTLSOptions{
										Enabled:         true,
										ServerName:      "example.org",
										ALPN:            []string{alpn},
										CertificatePath: caPem,
									},
								},
								Transport: &option.V2RayTransportOptions{
									Type:  C.V2RayTransportTypeXHTTP,
									Extra: &option.V2RayXHTTPOptions{Path: "/xhttp", Mode: mode},
								},
							},
						},
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
										RouteOptions: option.RouteActionOptions{Outbound: "vless-out"},
									},
								},
							},
						},
					},
				})
				testSuit(t, clientPort, testPort)
				// 关闭实例时仍在进行的连接也会被拆除，同样不应记 ERROR。
				require.NoError(t, instance.Close())
				content, err := os.ReadFile(logPath)
				require.NoError(t, err)
				for _, line := range strings.Split(string(content), "\n") {
					if strings.Contains(line, "connection upload closed") || strings.Contains(line, "connection download closed") {
						t.Error(line)
					}
				}
			})
		}
	}
}
