package main

import (
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/vless/encryption"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

// TestVLESSEncryptionVisionWebsocket runs XTLS Vision on a WebSocket transport,
// which Vision only supports on top of VLESS Encryption.
func TestVLESSEncryptionVisionWebsocket(t *testing.T) {
	for _, mode := range []string{"native", "xorpub", "random"} {
		t.Run(mode, func(t *testing.T) {
			testVLESSEncryptionVision(t, mode)
		})
	}
}

func testVLESSEncryptionVision(t *testing.T, mode string) {
	user, err := uuid.DefaultGenerator.NewV4()
	require.NoError(t, err)
	serverKey, clientKey, err := encryption.GenerateX25519("")
	require.NoError(t, err)
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	transport := &option.V2RayTransportOptions{
		Type: C.V2RayTransportTypeWebsocket,
	}
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
			{
				Type: C.TypeVLESS,
				Options: &option.VLESSInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: serverPort,
					},
					Users: []option.VLESSUser{
						{
							Name: "sekai",
							UUID: user.String(),
							Flow: "xtls-rprx-vision",
						},
					},
					Decryption: "mlkem768x25519plus." + mode + ".600s.100-111-1111.75-0-111.50-0-3333." + serverKey,
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
							KeyPath:         keyPem,
						},
					},
					Transport: transport,
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeDirect,
			},
			{
				Type: C.TypeVLESS,
				Tag:  "vless-out",
				Options: &option.VLESSOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: serverPort,
					},
					UUID:       user.String(),
					Flow:       "xtls-rprx-vision",
					Encryption: "mlkem768x25519plus." + mode + ".0rtt.100-111-1111.75-0-111.50-0-3333." + clientKey,
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:         true,
							ServerName:      "example.org",
							CertificatePath: certPem,
						},
					},
					Transport: transport,
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
							Action: C.RuleActionTypeRoute,

							RouteOptions: option.RouteActionOptions{
								Outbound: "vless-out",
							},
						},
					},
				},
			},
		},
	})
	testSuit(t, clientPort, testPort)
}
