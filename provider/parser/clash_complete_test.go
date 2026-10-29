package parser

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func parseClashWithWarnings(t *testing.T, content string) ([]option.Outbound, []option.Endpoint, []string) {
	t.Helper()
	var warnings []string
	ctx := ContextWithWarnHandler(context.Background(), func(args ...any) {
		warnings = append(warnings, fmt.Sprint(args...))
	})
	outbounds, endpoints, err := ParseClashSubscription(ctx, content)
	require.NoError(t, err)
	return outbounds, endpoints, warnings
}

func TestParseClashSkipsUnsupportedWithReason(t *testing.T) {
	testCases := []struct {
		name   string
		proxy  string
		reason string
	}{
		{"ssr", `{name: n, type: ssr, server: a, port: 1, cipher: aes-128-cfb, password: x, obfs: plain, protocol: origin}`, "ShadowsocksR"},
		{"mieru", `{name: n, type: mieru, server: a, port: 1}`, "mieru"},
		{"sudoku", `{name: n, type: sudoku, server: a, port: 1}`, "sudoku"},
		{"shadowquic", `{name: n, type: shadowquic, server: a, port: 1}`, "ShadowQUIC"},
		{"gost-relay", `{name: n, type: gost-relay, server: a, port: 1}`, "GOST"},
		{"trusttunnel", `{name: n, type: trusttunnel, server: a, port: 1}`, "TrustTunnel"},
		{"zerotier", `{name: n, type: zerotier}`, "ZeroTier"},
		{"masque", `{name: n, type: masque, server: a, port: 1}`, "WARP"},
		{"reject", `{name: n, type: reject}`, "reject route rule"},
		{"dns", `{name: n, type: dns}`, "hijack-dns"},
		{"rematch", `{name: n, type: rematch}`, "rematch"},
		{"unknown", `{name: n, type: foo, server: a, port: 1}`, "unknown proxy type: foo"},
		{"ss restls", `{name: n, type: ss, server: a, port: 1, cipher: aes-128-gcm, password: x, plugin: restls}`, "restls plugin"},
		{"ss kcptun", `{name: n, type: ss, server: a, port: 1, cipher: aes-128-gcm, password: x, plugin: kcptun}`, "kcptun"},
		{"ss gost", `{name: n, type: ss, server: a, port: 1, cipher: aes-128-gcm, password: x, plugin: gost-plugin}`, "gost"},
		{"v2ray-plugin skip-cert-verify", `{name: n, type: ss, server: a, port: 1, cipher: aes-128-gcm, password: x, plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, skip-cert-verify: true}}`, "skip-cert-verify"},
		{"v2ray-plugin quic", `{name: n, type: ss, server: a, port: 1, cipher: aes-128-gcm, password: x, plugin: v2ray-plugin, plugin-opts: {mode: quic}}`, "mode quic"},
		{"vmess kcp", `{name: n, type: vmess, server: a, port: 1, uuid: bf000d23-0752-40b4-affe-68f7707a9661, cipher: auto, network: kcp}`, "mKCP"},
		{"vmess mekya", `{name: n, type: vmess, server: a, port: 1, uuid: bf000d23-0752-40b4-affe-68f7707a9661, cipher: auto, network: mekya}`, "mekya"},
		{"vless restls", `{name: n, type: vless, server: a, port: 1, uuid: bf000d23-0752-40b4-affe-68f7707a9661, tls: true, restls-opts: {password: x}}`, "restls"},
		{"vless jls", `{name: n, type: vless, server: a, port: 1, uuid: bf000d23-0752-40b4-affe-68f7707a9661, tls: true, jls-opts: {password: x}}`, "JLS"},
		{"vmess tlsmirror", `{name: n, type: vmess, server: a, port: 1, uuid: bf000d23-0752-40b4-affe-68f7707a9661, cipher: auto, tlsmirror-opts: {primary-key: x}}`, "TLSMirror"},
		{"trojan ss-opts", `{name: n, type: trojan, server: a, port: 1, password: x, ss-opts: {enabled: true, password: y}}`, "ss-opts"},
		{"anytls shadow-tls", `{name: n, type: anytls, server: a, port: 1, password: x, shadow-tls-opts: {password: y, version: 3}}`, "shadow-tls"},
		{"socks5 tls", `{name: n, type: socks5, server: a, port: 1, tls: true}`, "SOCKS5 over TLS"},
		{"hysteria faketcp", `{name: n, type: hysteria, server: a, port: 1, auth-str: x, up: 10, down: 10, protocol: faketcp}`, "faketcp"},
		{"tuic v4", `{name: n, type: tuic, server: a, port: 1, token: x}`, "TUIC v4"},
		{"amnezia", `{name: n, type: wireguard, server: a, port: 1, ip: 172.16.0.2, private-key: x, public-key: y, amnezia-wg-option: {jc: 4}}`, "AmneziaWG"},
		{"openvpn tap", `{name: n, type: openvpn, server: a, port: 1, ca: x, dev: tap}`, "dev tap"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			outbounds, endpoints, warnings := parseClashWithWarnings(t, "proxies:\n  - "+testCase.proxy+"\n")
			require.Empty(t, outbounds)
			require.Empty(t, endpoints)
			require.Len(t, warnings, 1)
			require.Contains(t, warnings[0], "skip clash proxy n: ")
			require.Contains(t, warnings[0], testCase.reason)
		})
	}
}

func TestParseClashShadowTLSPlugin(t *testing.T) {
	outbounds, _, warnings := parseClashWithWarnings(t, `
proxies:
  - name: ss-stls
    type: ss
    server: 1.2.3.4
    port: 443
    cipher: 2022-blake3-aes-128-gcm
    password: x
    udp: true
    client-fingerprint: chrome
    plugin: shadow-tls
    plugin-opts: {host: cloud.tencent.com, password: stls, version: 3}
`)
	require.Empty(t, warnings)
	require.Len(t, outbounds, 2)
	ss := outbounds[0].Options.(*option.ShadowsocksOutboundOptions)
	require.Equal(t, "ss-stls (shadow-tls)", ss.Detour)
	require.Empty(t, ss.Plugin)
	require.Equal(t, option.NetworkList(N.NetworkTCP), ss.Network, "native UDP cannot pass the shadowtls detour")

	require.Equal(t, C.TypeShadowTLS, outbounds[1].Type)
	require.Equal(t, "ss-stls (shadow-tls)", outbounds[1].Tag)
	helper := outbounds[1].Options.(*option.ShadowTLSOutboundOptions)
	require.Equal(t, 3, helper.Version)
	require.Equal(t, "stls", helper.Password)
	require.Equal(t, "1.2.3.4", helper.Server)
	require.Equal(t, uint16(443), helper.ServerPort)
	require.Equal(t, "cloud.tencent.com", helper.TLS.ServerName)
	require.Equal(t, "chrome", helper.TLS.UTLS.Fingerprint)
	require.Equal(t, []string{"h2", "http/1.1"}, []string(helper.TLS.ALPN))
}

func TestParseClashShadowTLSOpts(t *testing.T) {
	outbounds, _, warnings := parseClashWithWarnings(t, `
proxies:
  - {name: v, type: vless, server: 1.2.3.4, port: 443, uuid: bf000d23-0752-40b4-affe-68f7707a9661, tls: true, servername: www.apple.com, client-fingerprint: safari, shadow-tls-opts: {password: p}}
  - {name: t, type: trojan, server: 1.2.3.4, port: 443, password: x, sni: www.apple.com, shadow-tls-opts: {password: p, version: 3}}
`)
	require.Empty(t, warnings)
	require.Len(t, outbounds, 4)
	vless := outbounds[0].Options.(*option.VLESSOutboundOptions)
	require.Nil(t, vless.TLS, "the proxy runs in plain text over shadow-tls")
	require.Equal(t, "v (shadow-tls)", vless.Detour)
	helper := outbounds[1].Options.(*option.ShadowTLSOutboundOptions)
	require.Equal(t, 2, helper.Version, "mihomo defaults to version 2")
	require.Equal(t, "www.apple.com", helper.TLS.ServerName)
	require.Equal(t, "safari", helper.TLS.UTLS.Fingerprint)
	require.Equal(t, []string{"http/1.1"}, []string(helper.TLS.ALPN))
	trojan := outbounds[2].Options.(*option.TrojanOutboundOptions)
	require.Nil(t, trojan.TLS)
	require.Equal(t, 3, outbounds[3].Options.(*option.ShadowTLSOutboundOptions).Version)
}

func TestParseClashShadowTLSWithProviderDetour(t *testing.T) {
	detour := "front"
	outbounds, _, err := ParseSubscription(context.Background(), `
proxies:
  - {name: ss, type: ss, server: 1.2.3.4, port: 443, cipher: aes-128-gcm, password: x, plugin: shadow-tls, plugin-opts: {host: a.com, password: p}}
`, &option.OverrideDialerOptions{Detour: &detour}, nil, nil, nil, "sub")
	require.NoError(t, err)
	require.Equal(t, "sub/ss (shadow-tls)", outbounds[0].Options.(*option.ShadowsocksOutboundOptions).Detour)
	require.Equal(t, "front", outbounds[1].Options.(*option.ShadowTLSOutboundOptions).Detour,
		"the provider detour applies to the outermost hop")
}

func TestParseClashV2RayPlugin(t *testing.T) {
	outbounds, _, warnings := parseClashWithWarnings(t, `
proxies:
  - {name: off, type: ss, server: a, port: 1, cipher: aes-128-gcm, password: x, plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: false, host: h.com, path: /p}}
  - {name: on, type: ss, server: a, port: 1, cipher: aes-128-gcm, password: x, plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, mux: true}}
`)
	require.Empty(t, warnings)
	off := strings.Split(outbounds[0].Options.(*option.ShadowsocksOutboundOptions).PluginOptions, ";")
	require.NotContains(t, off, "tls=false", "the plugin enables TLS whenever the key exists")
	require.NotContains(t, off, "tls=")
	require.Contains(t, off, "mux=0")
	on := strings.Split(outbounds[1].Options.(*option.ShadowsocksOutboundOptions).PluginOptions, ";")
	require.Contains(t, on, "tls=")
	require.Contains(t, on, "mux=1")
}

func TestParseClashTLSClientCertificate(t *testing.T) {
	outbounds, _, _ := parseClashWithWarnings(t, `
proxies:
  - name: t
    type: trojan
    server: a
    port: 1
    password: x
    name-cert-verify: real.example.com
    certificate: /etc/client.crt
    private-key: |
      -----BEGIN PRIVATE KEY-----
      AAAA
      -----END PRIVATE KEY-----
`)
	tls := outbounds[0].Options.(*option.TrojanOutboundOptions).TLS
	require.Equal(t, "real.example.com", tls.CertificateServerName)
	require.Equal(t, "/etc/client.crt", tls.ClientCertificatePath)
	require.Equal(t, []string{"-----BEGIN PRIVATE KEY-----", "AAAA", "-----END PRIVATE KEY-----"}, []string(tls.ClientKey))
}

func TestParseClashDurations(t *testing.T) {
	outbounds, _, warnings := parseClashWithWarnings(t, `
proxies:
  - {name: h1, type: hysteria, server: a, port: 1, auth-str: x, up: 10, down: 10, hop-interval: 30}
  - {name: h2, type: hysteria2, server: a, port: 1, password: x, hop-interval: "20-40"}
  - {name: h2s, type: hysteria2, server: a, port: 1, password: x, hop-interval: 15}
  - {name: tu, type: tuic, server: a, port: 1, uuid: bf000d23-0752-40b4-affe-68f7707a9661, password: x, heartbeat-interval: 10000}
  - {name: at, type: anytls, server: a, port: 1, password: x, idle-session-check-interval: 30, idle-session-timeout: 60}
  - {name: g, type: vless, server: a, port: 1, uuid: bf000d23-0752-40b4-affe-68f7707a9661, network: grpc, grpc-opts: {grpc-service-name: s, ping-interval: 15}}
`)
	require.Empty(t, warnings)
	require.Equal(t, 30*time.Second, time.Duration(outbounds[0].Options.(*option.HysteriaOutboundOptions).HopInterval))
	hy2 := outbounds[1].Options.(*option.Hysteria2OutboundOptions)
	require.Equal(t, 20*time.Second, time.Duration(hy2.HopInterval))
	require.Equal(t, 40*time.Second, time.Duration(hy2.HopIntervalMax))
	hy2Single := outbounds[2].Options.(*option.Hysteria2OutboundOptions)
	require.Equal(t, 15*time.Second, time.Duration(hy2Single.HopInterval))
	require.Zero(t, hy2Single.HopIntervalMax)
	require.Equal(t, 10*time.Second, time.Duration(outbounds[3].Options.(*option.TUICOutboundOptions).Heartbeat))
	anytls := outbounds[4].Options.(*option.AnyTLSOutboundOptions)
	require.Equal(t, 30*time.Second, time.Duration(anytls.IdleSessionCheckInterval))
	require.Equal(t, 60*time.Second, time.Duration(anytls.IdleSessionTimeout))
	require.Equal(t, 15*time.Second, time.Duration(outbounds[5].Options.(*option.VLESSOutboundOptions).Transport.GRPCOptions.IdleTimeout))
}

func TestParseClashHysteria2Extras(t *testing.T) {
	outbounds, _, _ := parseClashWithWarnings(t, `
proxies:
  - name: h2
    type: hysteria2
    server: a
    port: 1
    password: x
    bbr-profile: aggressive
    initial-stream-receive-window: 8388608
    max-stream-receive-window: 16777216
    initial-connection-receive-window: 20971520
    realm-opts: {enable: true, server-url: "https://realm.example.com", token: t, realm-id: r, stun-servers: [stun.l.google.com:19302], sni: realm.example.com}
`)
	hy2 := outbounds[0].Options.(*option.Hysteria2OutboundOptions)
	require.Equal(t, "aggressive", hy2.BBRProfile)
	require.Equal(t, uint64(16777216), hy2.StreamReceiveWindow.Value())
	require.Equal(t, uint64(20971520), hy2.ConnectionReceiveWindow.Value())
	require.Equal(t, "https://realm.example.com", hy2.Realm.ServerURL)
	require.Equal(t, "r", hy2.Realm.RealmID)
	require.Equal(t, []string{"stun.l.google.com:19302"}, []string(hy2.Realm.STUNServers))
	require.Equal(t, "realm.example.com", hy2.Realm.HTTPClient.TLS.ServerName)
}

func TestParseClashNewTypes(t *testing.T) {
	outbounds, endpoints, warnings := parseClashWithWarnings(t, `
proxies:
  - {name: d, type: direct, interface-name: eth0}
  - {name: anytls, type: anytls, server: a, port: 1, password: x, client-metadata: "mihomo/1.19"}
  - name: ovpn
    type: openvpn
    server: vpn.example.com
    port: 1194
    proto: tcp-client
    cipher: AES-256-GCM
    data-ciphers: [AES-256-GCM, CHACHA20-POLY1305]
    auth: SHA256
    comp-lzo: adaptive
    ca: /etc/ca.crt
    tls-auth: /etc/ta.key
    key-direction: "1"
    username: u
    password: p
    ping: 10
    ping-restart: 60
    mtu: 1400
  - name: et
    type: easytier
    network-name: n
    network-secret: s
    ipv4: 10.126.126.2
    peers: [tcp://public.easytier.top:11010]
    exit-nodes: [10.126.126.1]
    proxy-networks: [192.168.1.0/24, 10.0.0.0/24->10.1.0.0/24]
    enable-encryption: false
    secure-mode: true
    local-private-key: k
`)
	require.Empty(t, warnings)
	require.Len(t, outbounds, 2)
	require.Equal(t, C.TypeDirect, outbounds[0].Type)
	require.Equal(t, "eth0", outbounds[0].Options.(*option.DirectOutboundOptions).BindInterface)
	require.Equal(t, "mihomo/1.19", *outbounds[1].Options.(*option.AnyTLSOutboundOptions).ClientMetadata)

	require.Len(t, endpoints, 2)
	require.Equal(t, C.TypeOpenVPNClient, endpoints[0].Type)
	ovpn := endpoints[0].Options.(*option.OpenVPNClientEndpointOptions)
	require.Equal(t, "tcp", ovpn.Network)
	require.Equal(t, "yes", ovpn.CompressionLZO)
	require.Equal(t, "/etc/ca.crt", ovpn.TLS.CertificatePath)
	require.Equal(t, "tls_auth", ovpn.TLS.ControlWrap.Type)
	require.Equal(t, "/etc/ta.key", ovpn.TLS.ControlWrap.KeyPath)
	require.Equal(t, "client", ovpn.TLS.ControlWrap.Direction)
	require.Equal(t, 10*time.Second, time.Duration(ovpn.PingInterval))
	require.Equal(t, uint32(1400), ovpn.MTU)

	require.Equal(t, C.TypeEasyTier, endpoints[1].Type)
	easytier := endpoints[1].Options.(*option.EasyTierEndpointOptions)
	require.Equal(t, "10.126.126.2/24", easytier.Address[0].String())
	require.True(t, easytier.DisableEncryption)
	require.Len(t, easytier.ProxyNetworks, 2)
	require.Equal(t, "10.1.0.0/24", easytier.ProxyNetworks[1].MappedCIDR.Build(netip.Prefix{}).String())
	require.Equal(t, "k", easytier.SecureMode.PrivateKey)
}

func TestParseClashXHTTPDownloadSettings(t *testing.T) {
	outbounds, _, warnings := parseClashWithWarnings(t, `
proxies:
  - name: x
    type: vless
    server: up.example.com
    port: 443
    uuid: bf000d23-0752-40b4-affe-68f7707a9661
    tls: true
    network: xhttp
    certificate: /etc/up.crt
    xhttp-opts:
      path: /x
      download-settings: {server: down.example.com, name-cert-verify: down.example.com, private-key: /etc/down.key}
  - name: bad
    type: vless
    server: up.example.com
    port: 443
    uuid: bf000d23-0752-40b4-affe-68f7707a9661
    tls: true
    network: xhttp
    xhttp-opts:
      download-settings: {server: down.example.com, restls-opts: {password: p}}
`)
	require.Len(t, warnings, 1)
	require.Contains(t, warnings[0], "skip clash proxy bad: restls")
	download := xhttpTransport(t, outbounds[0].Options.(*option.VLESSOutboundOptions).Transport).DownloadSettings
	require.Equal(t, "down.example.com", download.Server)
	require.Equal(t, "/etc/up.crt", download.TLS.ClientCertificatePath, "inherited from the upload side")
	require.Equal(t, "/etc/down.key", download.TLS.ClientKeyPath)
	require.Equal(t, "down.example.com", download.TLS.CertificateServerName)
}
