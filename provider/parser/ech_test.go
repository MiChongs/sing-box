package parser

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// Cloudflare ECHConfigList (public name cloudflare-ech.com); contains "+" and "/".
const testECHConfigList = "AEX+DQBBbAAgACBqSNPZ/yOc2Xt+OUllw2Ct9IiyYY0MLY5B7NzL/PioQQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

func requireECHConfigPEM(t *testing.T, lines []string) {
	t.Helper()
	block, rest := pem.Decode([]byte(strings.Join(lines, "\n")))
	require.NotNil(t, block)
	require.Empty(t, strings.TrimSpace(string(rest)))
	require.Equal(t, "ECH CONFIGS", block.Type)
	expected, err := base64.StdEncoding.DecodeString(testECHConfigList)
	require.NoError(t, err)
	require.Equal(t, expected, block.Bytes)
}

func TestParseClashECHQueryServerName(t *testing.T) {
	outbounds, _, err := ParseClashSubscription(context.Background(), `
proxies:
  - {"name":"vless-ech","server":"cf.example.com","port":8443,"type":"vless","uuid":"11111111-1111-1111-1111-111111111111","tls":true,"alpn":["h2"],"client-fingerprint":"firefox","network":"xhttp","xhttp-opts":{"path":"/xhttp","host":"sni.example.com","mode":"stream-one"},"udp":true,"ech-opts":{"enable":true,"query-server-name":"encryptedsni.com"},"servername":"sni.example.com"}
`)
	require.NoError(t, err)
	require.Len(t, outbounds, 1)
	vlessOptions := outbounds[0].Options.(*option.VLESSOutboundOptions)
	require.NotNil(t, vlessOptions.TLS)
	require.Equal(t, "sni.example.com", vlessOptions.TLS.ServerName)
	require.NotNil(t, vlessOptions.TLS.ECH)
	require.True(t, vlessOptions.TLS.ECH.Enabled)
	require.Equal(t, "encryptedsni.com", vlessOptions.TLS.ECH.QueryServerName)
	require.Empty(t, vlessOptions.TLS.ECH.Config)
}

func TestParseClashECHConfig(t *testing.T) {
	outbounds, _, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: trojan-ech
    type: trojan
    server: example.com
    port: 443
    password: password
    ech-opts:
      enable: true
      config: `+testECHConfigList+`
`)
	require.NoError(t, err)
	require.Len(t, outbounds, 1)
	trojanOptions := outbounds[0].Options.(*option.TrojanOutboundOptions)
	require.True(t, trojanOptions.TLS.ECH.Enabled)
	requireECHConfigPEM(t, trojanOptions.TLS.ECH.Config)
}

func TestParseClashECHDisabled(t *testing.T) {
	outbounds, _, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: trojan-no-ech
    type: trojan
    server: example.com
    port: 443
    password: password
    ech-opts:
      enable: false
      query-server-name: encryptedsni.com
`)
	require.NoError(t, err)
	trojanOptions := outbounds[0].Options.(*option.TrojanOutboundOptions)
	require.Nil(t, trojanOptions.TLS.ECH)
}

func TestParseLinkECH(t *testing.T) {
	testCases := []struct {
		name            string
		link            string
		queryServerName string
		hasConfig       bool
	}{
		{
			"vless query server name unescaped",
			"vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=sni.example.com&ech=encryptedsni.com+https://1.1.1.1/dns-query#vless",
			"encryptedsni.com",
			false,
		},
		{
			"vless query server name escaped",
			"vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&ech=encryptedsni.com%2Bhttps%3A%2F%2F1.1.1.1%2Fdns-query#vless",
			"encryptedsni.com",
			false,
		},
		{
			"vless dns server only",
			"vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&ech=https://1.1.1.1/dns-query#vless",
			"",
			false,
		},
		{
			"vless config unescaped",
			"vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&ech=" + testECHConfigList + "#vless",
			"",
			true,
		},
		{
			"trojan config escaped",
			"trojan://password@example.com:443?ech=" + strings.NewReplacer("+", "%2B", "/", "%2F", "=", "%3D").Replace(testECHConfigList) + "#trojan",
			"",
			true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			outbound, err := ParseSubscriptionLink(testCase.link)
			require.NoError(t, err)
			var tlsOptions *option.OutboundTLSOptions
			switch options := outbound.Options.(type) {
			case *option.VLESSOutboundOptions:
				tlsOptions = options.TLS
			case *option.TrojanOutboundOptions:
				tlsOptions = options.TLS
			}
			require.NotNil(t, tlsOptions)
			require.True(t, tlsOptions.ECH.Enabled)
			require.Equal(t, testCase.queryServerName, tlsOptions.ECH.QueryServerName)
			if testCase.hasConfig {
				requireECHConfigPEM(t, tlsOptions.ECH.Config)
			} else {
				require.Empty(t, tlsOptions.ECH.Config)
			}
		})
	}
}

func TestOverrideECHOption(t *testing.T) {
	queryServerName := "encryptedsni.com"
	configPath := "/etc/ech.pem"
	enabled := true
	options := overrideTLSOption(&option.OutboundTLSOptions{
		Enabled: true,
		ECH: &option.OutboundECHOptions{
			Config: badoption.Listable[string]{"node config"},
		},
	}, &option.OverrideTLSOptions{
		ECH: &option.OverrideECHOptions{
			Enabled:         &enabled,
			ConfigPath:      &configPath,
			QueryServerName: &queryServerName,
		},
	})
	require.True(t, options.ECH.Enabled)
	require.Empty(t, options.ECH.Config)
	require.Equal(t, configPath, options.ECH.ConfigPath)
	require.Equal(t, queryServerName, options.ECH.QueryServerName)

	options = overrideTLSOption(&option.OutboundTLSOptions{Enabled: true}, &option.OverrideTLSOptions{
		ECH: &option.OverrideECHOptions{QueryServerName: &queryServerName},
	})
	require.NotNil(t, options.ECH)
	require.False(t, options.ECH.Enabled)
	require.Equal(t, queryServerName, options.ECH.QueryServerName)
}
