package parser

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess"

	"github.com/stretchr/testify/require"
)

func expectedVMessAutoSecurity() string {
	if vmess.AutoSecurityType() == vmess.SecurityTypeAes128Gcm {
		return "aes-128-gcm"
	}
	return "chacha20-poly1305"
}

// Clash cipher: auto + tls must not reach the VMess outbound as "auto", which
// sing-box downgrades to "zero" under TLS (NetProxy-Magisk#255).
func TestParseClashVMessCipherAutoWithTLS(t *testing.T) {
	outbounds, _, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: vmess-grpc
    type: vmess
    server: example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 0
    cipher: auto
    tls: true
    network: grpc
    grpc-opts:
      grpc-service-name: svc
`)
	require.NoError(t, err)
	require.Len(t, outbounds, 1)
	vmessOptions := outbounds[0].Options.(*option.VMessOutboundOptions)
	require.Equal(t, expectedVMessAutoSecurity(), vmessOptions.Security)
	require.NotNil(t, vmessOptions.TLS)
	require.True(t, vmessOptions.TLS.Enabled)
}

func TestParseClashVMessExplicitCipherPreserved(t *testing.T) {
	for _, cipher := range []string{"aes-128-gcm", "chacha20-poly1305", "none", "zero"} {
		t.Run(cipher, func(t *testing.T) {
			outbounds, _, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: vmess
    type: vmess
    server: example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    cipher: `+cipher+`
    tls: true
`)
			require.NoError(t, err)
			require.Len(t, outbounds, 1)
			require.Equal(t, cipher, outbounds[0].Options.(*option.VMessOutboundOptions).Security)
		})
	}
}

func TestParseVMessLinkSecurityAuto(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		link     string
		security string
	}{
		{"auto", `{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"grpc","scy":"auto"}`, expectedVMessAutoSecurity()},
		{"missing", `{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls"}`, expectedVMessAutoSecurity()},
		{"explicit", `{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","scy":"none"}`, "none"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			outbound, err := ParseSubscriptionLink("vmess://" + base64.RawURLEncoding.EncodeToString([]byte(testCase.link)))
			require.NoError(t, err)
			require.Equal(t, testCase.security, outbound.Options.(*option.VMessOutboundOptions).Security)
		})
	}
}
