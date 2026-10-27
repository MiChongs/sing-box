package parser

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// clashNetworkCases lists every proxy type the Clash parser accepts. The
// expected UDP support follows mihomo: QUIC based protocols and WireGuard
// always relay UDP, HTTP never does, SSH is TCP only, and the rest follow
// the `udp` flag.
var clashNetworkCases = []struct {
	clashType string
	fields    string
	udp       func(flag bool) bool
}{
	{"ss", "cipher: aes-128-gcm\n    password: x", followFlag},
	{"vmess", "uuid: bf000d23-0752-40b4-affe-68f7707a9661\n    cipher: auto", followFlag},
	{"vless", "uuid: bf000d23-0752-40b4-affe-68f7707a9661", followFlag},
	{"trojan", "password: x", followFlag},
	{"socks5", "", followFlag},
	{"snell", "psk: x\n    version: 3", followFlag},
	{"anytls", "password: x", followFlag},
	{"http", "", never},
	{"ssh", "username: root\n    password: x", never},
	{"tuic", "uuid: bf000d23-0752-40b4-affe-68f7707a9661\n    password: x", always},
	{"hysteria", "auth-str: x\n    up: 10\n    down: 10", always},
	{"hysteria2", "password: x", always},
	{"wireguard", "ip: 172.16.0.2\n    private-key: eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=\n    public-key: Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=", always},
}

func followFlag(flag bool) bool { return flag }
func always(bool) bool          { return true }
func never(bool) bool           { return false }

func memberNetworks(t *testing.T, outbounds []option.Outbound, endpoints []option.Endpoint) []string {
	t.Helper()
	if len(endpoints) == 1 {
		// WireGuard / Tailscale endpoints always carry TCP, UDP and ICMP.
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	require.Len(t, outbounds, 1)
	switch options := outbounds[0].Options.(type) {
	case *option.ShadowsocksOutboundOptions:
		return options.Network.Build()
	case *option.VMessOutboundOptions:
		return options.Network.Build()
	case *option.VLESSOutboundOptions:
		return options.Network.Build()
	case *option.TrojanOutboundOptions:
		return options.Network.Build()
	case *option.SOCKSOutboundOptions:
		return options.Network.Build()
	case *option.SnellOutboundOptions:
		return options.Network.Build()
	case *option.AnyTLSOutboundOptions:
		return options.Network.Build()
	case *option.HTTPOutboundOptions:
		return options.Network.Build()
	case *option.TUICOutboundOptions:
		return options.Network.Build()
	case *option.HysteriaOutboundOptions:
		return options.Network.Build()
	case *option.Hysteria2OutboundOptions:
		return options.Network.Build()
	case *option.SSHOutboundOptions:
		// The SSH outbound is TCP only regardless of its options.
		return []string{N.NetworkTCP}
	default:
		t.Fatalf("unhandled options type %T", options)
		return nil
	}
}

func TestParseClashNetworkForEveryType(t *testing.T) {
	for _, testCase := range clashNetworkCases {
		for _, flag := range []bool{true, false} {
			t.Run(fmt.Sprint(testCase.clashType, "/udp=", flag), func(t *testing.T) {
				content := fmt.Sprintf("proxies:\n  - name: node\n    type: %s\n    server: 127.0.0.1\n    port: 1080\n    udp: %t\n",
					testCase.clashType, flag)
				if testCase.fields != "" {
					content += "    " + testCase.fields + "\n"
				}
				outbounds, endpoints, err := ParseClashSubscription(context.Background(), content)
				require.NoError(t, err)
				networks := memberNetworks(t, outbounds, endpoints)
				require.Contains(t, networks, N.NetworkTCP)
				require.Equal(t, testCase.udp(flag), slices.Contains(networks, N.NetworkUDP))
			})
		}
	}
}

func TestClashSpeedUnits(t *testing.T) {
	testCases := []struct {
		speed string
		mbps  int
	}{
		{"", 0},
		{"10", 10},
		{" 10 ", 10},
		{"10 Mbps", 10},
		{"10Mbps", 10},
		{"100 mbps", 100},
		{"1 Gbps", 1000},
		{"invalid", 0},
	}
	for _, testCase := range testCases {
		require.Equal(t, testCase.mbps, clashSpeedToIntMbps(testCase.speed), testCase.speed)
		bytes := clashSpeedToNetworkBytes(testCase.speed)
		if testCase.mbps == 0 {
			require.Nil(t, bytes, testCase.speed)
		} else {
			require.NotNil(t, bytes, testCase.speed)
			require.Equal(t, uint64(testCase.mbps)*1_000_000/8, bytes.Value(), testCase.speed)
		}
	}
}

func TestParseClashHysteriaSpeed(t *testing.T) {
	outbounds, _, err := ParseClashSubscription(context.Background(), `
proxies:
  - {name: h1, type: hysteria, server: 127.0.0.1, port: 1, auth-str: x, up: "30 Mbps", down: 200}
  - {name: h2, type: hysteria2, server: 127.0.0.1, port: 1, password: x, up: "50 Mbps", down: "1 Gbps"}
`)
	require.NoError(t, err)
	hysteria := outbounds[0].Options.(*option.HysteriaOutboundOptions)
	require.Equal(t, uint64(30_000_000/8), hysteria.Up.Value())
	require.Equal(t, uint64(200_000_000/8), hysteria.Down.Value())
	hysteria2 := outbounds[1].Options.(*option.Hysteria2OutboundOptions)
	require.Equal(t, 50, hysteria2.UpMbps)
	require.Equal(t, 1000, hysteria2.DownMbps)
}
