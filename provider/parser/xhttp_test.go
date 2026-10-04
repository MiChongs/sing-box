package parser

import (
	"context"
	"encoding/base64"
	"net/url"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func xhttpTransport(t *testing.T, transport *option.V2RayTransportOptions) *option.V2RayXHTTPOptions {
	t.Helper()
	require.NotNil(t, transport)
	require.Equal(t, C.V2RayTransportTypeXHTTP, transport.Type)
	xhttpOptions, ok := transport.Extra.(*option.V2RayXHTTPOptions)
	require.True(t, ok, "extra=%T", transport.Extra)
	return xhttpOptions
}

func xhttpRangeOf(from, to int32) option.XHTTPRange {
	return option.XHTTPRange{From: from, To: to}
}

// Share links: VLESS / VMess / Trojan

func TestParseVLESSLinkXHTTP(t *testing.T) {
	outbound, err := ParseSubscriptionLink("vless://11111111-1111-1111-1111-111111111111@example.com:443?" +
		"encryption=none&security=tls&type=xhttp&path=%2Fxyz&host=a.com&mode=packet-up#mytag")
	require.NoError(t, err)
	require.Equal(t, C.TypeVLESS, outbound.Type)
	xhttpOptions := xhttpTransport(t, outbound.Options.(*option.VLESSOutboundOptions).Transport)
	require.Equal(t, "/xyz", xhttpOptions.Path)
	require.Equal(t, []string{"a.com"}, []string(xhttpOptions.Host))
	require.Equal(t, "packet-up", xhttpOptions.Mode)
}

func TestParseVMessLinkXHTTP(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"xhttp-test","add":"cdn.example.com","port":"443",` +
		`"id":"11111111-1111-1111-1111-111111111111","aid":"0","scy":"auto",` +
		`"net":"xhttp","path":"/top","host":"top.com","mode":"stream-up","tls":"tls"}`
	outbound, err := ParseSubscriptionLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON)))
	require.NoError(t, err)
	vmessOptions := outbound.Options.(*option.VMessOutboundOptions)
	xhttpOptions := xhttpTransport(t, vmessOptions.Transport)
	require.Equal(t, "/top", xhttpOptions.Path)
	require.Equal(t, "stream-up", xhttpOptions.Mode)
	require.Equal(t, []string{"top.com"}, []string(xhttpOptions.Host))
	require.Equal(t, expectedVMessAutoSecurity(), vmessOptions.Security)
}

func TestParseTrojanLinkXHTTP(t *testing.T) {
	outbound, err := ParseSubscriptionLink("trojan://password@example.com:443?security=tls&type=xhttp&path=%2Ft&mode=auto#tag")
	require.NoError(t, err)
	xhttpOptions := xhttpTransport(t, outbound.Options.(*option.TrojanOutboundOptions).Transport)
	require.Equal(t, "/t", xhttpOptions.Path)
	require.Equal(t, "auto", xhttpOptions.Mode)
}

// Xray share links put every xhttpSettings field except host/path/mode into a
// URL-encoded "extra" JSON; host/path/mode inside extra are ignored.
func TestParseVLESSLinkXHTTPExtra(t *testing.T) {
	extra := `{
		"host": "ignored.com", "path": "/ignored", "mode": "stream-one",
		"headers": {"User-Agent": "ua", "Host": "header-host.com"},
		"xPaddingBytes": "200-800",
		"xPaddingObfsMode": true,
		"xPaddingPlacement": "header",
		"uplinkHTTPMethod": "PUT",
		"sessionIDPlacement": "query",
		"sessionIDKey": "sid",
		"sessionIDLength": "8-16",
		"seqPlacement": "header",
		"uplinkChunkSize": 4096,
		"noGRPCHeader": true,
		"noSSEHeader": true,
		"scMaxEachPostBytes": 4096,
		"scMinPostsIntervalMs": "10-50",
		"scMaxBufferedPosts": 64,
		"xmux": {"maxConnections": "2-4", "hMaxRequestTimes": 500, "hKeepAlivePeriod": 30},
		"downloadSettings": {
			"address": "down.example.com",
			"port": 8443,
			"network": "xhttp",
			"security": "reality",
			"realitySettings": {"serverName": "www.example.com", "publicKey": "pbk", "shortId": "abcd", "fingerprint": "firefox"},
			"xhttpSettings": {"path": "/down", "host": "down-host.com", "xmux": {"maxConcurrency": "16-32"}}
		}
	}`
	outbound, err := ParseSubscriptionLink("vless://11111111-1111-1111-1111-111111111111@example.com:443?" +
		"encryption=none&security=tls&type=xhttp&path=%2Fxyz&mode=packet-up&extra=" + url.QueryEscape(extra) + "#tag")
	require.NoError(t, err)
	xhttpOptions := xhttpTransport(t, outbound.Options.(*option.VLESSOutboundOptions).Transport)

	require.Equal(t, "/xyz", xhttpOptions.Path)
	require.Equal(t, "packet-up", xhttpOptions.Mode)
	require.Equal(t, []string{"header-host.com"}, []string(xhttpOptions.Host))
	require.Equal(t, []string{"ua"}, []string(xhttpOptions.Headers["User-Agent"]))
	require.NotContains(t, xhttpOptions.Headers, "Host")
	require.Equal(t, xhttpRangeOf(200, 800), xhttpOptions.XPaddingBytes)
	require.True(t, xhttpOptions.XPaddingObfsMode)
	require.Equal(t, "header", xhttpOptions.XPaddingPlacement)
	require.Equal(t, "PUT", xhttpOptions.UplinkHTTPMethod)
	require.Equal(t, "query", xhttpOptions.SessionPlacement)
	require.Equal(t, "sid", xhttpOptions.SessionKey)
	require.Equal(t, xhttpRangeOf(8, 16), xhttpOptions.SessionIDLength)
	require.Equal(t, "header", xhttpOptions.SeqPlacement)
	require.Equal(t, xhttpRangeOf(4096, 4096), xhttpOptions.UplinkChunkSize)
	require.True(t, xhttpOptions.NoGRPCHeader)
	require.True(t, xhttpOptions.NoSSEHeader)
	require.Equal(t, xhttpRangeOf(4096, 4096), xhttpOptions.ScMaxEachPostBytes)
	require.Equal(t, xhttpRangeOf(10, 50), xhttpOptions.ScMinPostsIntervalMs)
	require.EqualValues(t, 64, xhttpOptions.ScMaxBufferedPosts)

	require.NotNil(t, xhttpOptions.Xmux)
	require.Equal(t, xhttpRangeOf(2, 4), xhttpOptions.Xmux.MaxConnections)
	require.Equal(t, xhttpRangeOf(500, 500), xhttpOptions.Xmux.HMaxRequestTimes)
	require.EqualValues(t, 30, xhttpOptions.Xmux.HKeepAlivePeriod)

	download := xhttpOptions.DownloadSettings
	require.NotNil(t, download)
	require.Equal(t, "down.example.com", download.Server)
	require.EqualValues(t, 8443, download.ServerPort)
	require.Equal(t, "/down", download.Path)
	require.Equal(t, []string{"down-host.com"}, []string(download.Host))
	require.NotNil(t, download.Xmux)
	require.Equal(t, xhttpRangeOf(16, 32), download.Xmux.MaxConcurrency)
	require.Nil(t, download.DownloadSettings)
	require.NotNil(t, download.TLS)
	require.True(t, download.TLS.Enabled)
	require.Equal(t, "www.example.com", download.TLS.ServerName)
	require.True(t, download.TLS.Reality.Enabled)
	require.Equal(t, "pbk", download.TLS.Reality.PublicKey)
	require.Equal(t, "abcd", download.TLS.Reality.ShortID)
	require.Equal(t, "firefox", download.TLS.UTLS.Fingerprint)
}

func TestParseVLESSLinkXHTTPInvalidExtraIgnored(t *testing.T) {
	outbound, err := ParseSubscriptionLink("vless://11111111-1111-1111-1111-111111111111@example.com:443?" +
		"security=tls&type=xhttp&path=%2Fxyz&extra=%7Bnot-json#tag")
	require.NoError(t, err)
	xhttpOptions := xhttpTransport(t, outbound.Options.(*option.VLESSOutboundOptions).Transport)
	require.Equal(t, "/xyz", xhttpOptions.Path)
}

// Clash / mihomo YAML

func parseSingleClashProxy(t *testing.T, content string) option.Outbound {
	t.Helper()
	outbounds, _, err := ParseClashSubscription(context.Background(), content)
	require.NoError(t, err)
	require.Len(t, outbounds, 1)
	return outbounds[0]
}

func TestParseClashVLESSXHTTP(t *testing.T) {
	outbound := parseSingleClashProxy(t, `
proxies:
  - name: xh
    type: vless
    server: s.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    network: xhttp
    xhttp-opts:
      path: /abc
      host: s.com
      mode: packet-up
      headers:
        User-Agent: test-agent
      no-grpc-header: true
      no-sse-header: true
      x-padding-bytes: "100-1000"
      x-padding-obfs-mode: true
      x-padding-key: pad
      x-padding-header: X-Pad
      x-padding-placement: cookie
      x-padding-method: tokenish
      uplink-http-method: PATCH
      session-placement: header
      session-key: X-Session
      session-table: abcdef
      session-length: "10-20"
      seq-placement: query
      seq-key: seq
      uplink-data-placement: body
      uplink-data-key: data
      uplink-chunk-size: "2048-4096"
      sc-max-each-post-bytes: 8192
      sc-min-posts-interval-ms: "20"
      sc-max-buffered-posts: 40
      reuse-settings:
        max-connections: "3"
        c-max-reuse-times: "8-16"
        h-max-request-times: "600-900"
        h-max-reusable-secs: "1800-3000"
        h-keep-alive-period: 15
`)
	xhttpOptions := xhttpTransport(t, outbound.Options.(*option.VLESSOutboundOptions).Transport)
	require.Equal(t, "/abc", xhttpOptions.Path)
	require.Equal(t, []string{"s.com"}, []string(xhttpOptions.Host))
	require.Equal(t, "packet-up", xhttpOptions.Mode)
	require.Equal(t, []string{"test-agent"}, []string(xhttpOptions.Headers["User-Agent"]))
	require.True(t, xhttpOptions.NoGRPCHeader)
	require.True(t, xhttpOptions.NoSSEHeader)
	require.Equal(t, xhttpRangeOf(100, 1000), xhttpOptions.XPaddingBytes)
	require.True(t, xhttpOptions.XPaddingObfsMode)
	require.Equal(t, "pad", xhttpOptions.XPaddingKey)
	require.Equal(t, "X-Pad", xhttpOptions.XPaddingHeader)
	require.Equal(t, "cookie", xhttpOptions.XPaddingPlacement)
	require.Equal(t, "tokenish", xhttpOptions.XPaddingMethod)
	require.Equal(t, "PATCH", xhttpOptions.UplinkHTTPMethod)
	require.Equal(t, "header", xhttpOptions.SessionPlacement)
	require.Equal(t, "X-Session", xhttpOptions.SessionKey)
	require.Equal(t, "abcdef", xhttpOptions.SessionIDTable)
	require.Equal(t, xhttpRangeOf(10, 20), xhttpOptions.SessionIDLength)
	require.Equal(t, "query", xhttpOptions.SeqPlacement)
	require.Equal(t, "seq", xhttpOptions.SeqKey)
	require.Equal(t, "body", xhttpOptions.UplinkDataPlacement)
	require.Equal(t, "data", xhttpOptions.UplinkDataKey)
	require.Equal(t, xhttpRangeOf(2048, 4096), xhttpOptions.UplinkChunkSize)
	require.Equal(t, xhttpRangeOf(8192, 8192), xhttpOptions.ScMaxEachPostBytes)
	require.Equal(t, xhttpRangeOf(20, 20), xhttpOptions.ScMinPostsIntervalMs)
	require.EqualValues(t, 40, xhttpOptions.ScMaxBufferedPosts)
	require.NotNil(t, xhttpOptions.Xmux)
	require.Equal(t, xhttpRangeOf(3, 3), xhttpOptions.Xmux.MaxConnections)
	require.Equal(t, xhttpRangeOf(8, 16), xhttpOptions.Xmux.CMaxReuseTimes)
	require.Equal(t, xhttpRangeOf(600, 900), xhttpOptions.Xmux.HMaxRequestTimes)
	require.Equal(t, xhttpRangeOf(1800, 3000), xhttpOptions.Xmux.HMaxReusableSecs)
	require.EqualValues(t, 15, xhttpOptions.Xmux.HKeepAlivePeriod)
	require.Nil(t, xhttpOptions.DownloadSettings)
}

// mihomo download-settings inherit every unset field from the upload side;
// the converted download_settings must spell that inheritance out.
func TestParseClashXHTTPDownloadSettingsInheritance(t *testing.T) {
	outbound := parseSingleClashProxy(t, `
proxies:
  - name: xh
    type: vless
    server: up.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    servername: sni.example.com
    skip-cert-verify: true
    client-fingerprint: chrome
    alpn: [h2]
    network: xhttp
    xhttp-opts:
      path: /up
      host: up-host.com
      mode: stream-up
      x-padding-bytes: "300-600"
      headers:
        User-Agent: up-agent
      reuse-settings:
        max-connections: "2"
      download-settings:
        server: down.example.com
        reuse-settings:
          max-concurrency: "8"
`)
	xhttpOptions := xhttpTransport(t, outbound.Options.(*option.VLESSOutboundOptions).Transport)
	download := xhttpOptions.DownloadSettings
	require.NotNil(t, download)
	require.Equal(t, "down.example.com", download.Server)
	require.EqualValues(t, 443, download.ServerPort)
	require.Equal(t, "/up", download.Path)
	require.Equal(t, []string{"up-host.com"}, []string(download.Host))
	require.Equal(t, []string{"up-agent"}, []string(download.Headers["User-Agent"]))
	require.Equal(t, "stream-up", download.Mode)
	require.Equal(t, xhttpRangeOf(300, 600), download.XPaddingBytes)
	require.NotNil(t, download.Xmux)
	require.Equal(t, xhttpRangeOf(8, 8), download.Xmux.MaxConcurrency)
	require.True(t, download.Xmux.MaxConnections.IsZero())
	require.Nil(t, download.DownloadSettings)

	require.NotNil(t, download.TLS)
	require.True(t, download.TLS.Enabled)
	require.Equal(t, "sni.example.com", download.TLS.ServerName)
	require.True(t, download.TLS.Insecure)
	require.Equal(t, []string{"h2"}, []string(download.TLS.ALPN))
	require.NotNil(t, download.TLS.UTLS)
	require.Equal(t, "chrome", download.TLS.UTLS.Fingerprint)
}

func TestParseClashXHTTPDownloadSettingsOverride(t *testing.T) {
	outbound := parseSingleClashProxy(t, `
proxies:
  - name: xh
    type: vless
    server: up.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    network: xhttp
    xhttp-opts:
      path: /up
      host: up-host.com
      download-settings:
        server: down.example.com
        port: 8443
        path: /down
        host: down-host.com
        headers:
          X-Down: "1"
        tls: true
        servername: down-sni.example.com
        skip-cert-verify: true
`)
	vlessOptions := outbound.Options.(*option.VLESSOutboundOptions)
	require.Equal(t, "up.example.com", vlessOptions.TLS.ServerName)
	download := xhttpTransport(t, vlessOptions.Transport).DownloadSettings
	require.NotNil(t, download)
	require.EqualValues(t, 8443, download.ServerPort)
	require.Equal(t, "/down", download.Path)
	require.Equal(t, []string{"down-host.com"}, []string(download.Host))
	require.Equal(t, []string{"1"}, []string(download.Headers["X-Down"]))
	require.Equal(t, "down-sni.example.com", download.TLS.ServerName)
	require.True(t, download.TLS.Insecure)
}

func TestParseClashXHTTPDownloadSNIFallsBackToDownloadServer(t *testing.T) {
	outbound := parseSingleClashProxy(t, `
proxies:
  - name: xh
    type: vless
    server: up.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    network: xhttp
    xhttp-opts:
      download-settings:
        server: down.example.com
`)
	vlessOptions := outbound.Options.(*option.VLESSOutboundOptions)
	require.Equal(t, "up.example.com", vlessOptions.TLS.ServerName)
	download := xhttpTransport(t, vlessOptions.Transport).DownloadSettings
	require.NotNil(t, download)
	require.Equal(t, "down.example.com", download.TLS.ServerName)
}

func TestParseClashTrojanAndVMessXHTTP(t *testing.T) {
	trojan := parseSingleClashProxy(t, `
proxies:
  - name: trojan-xh
    type: trojan
    server: t.example.com
    port: 443
    password: password
    network: xhttp
    xhttp-opts:
      path: /trojan
`)
	require.Equal(t, "/trojan", xhttpTransport(t, trojan.Options.(*option.TrojanOutboundOptions).Transport).Path)

	vmess := parseSingleClashProxy(t, `
proxies:
  - name: vmess-xh
    type: vmess
    server: v.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 0
    cipher: auto
    tls: true
    network: xhttp
    xhttp-opts:
      path: /vmess
      mode: stream-one
`)
	vmessOptions := vmess.Options.(*option.VMessOutboundOptions)
	xhttpOptions := xhttpTransport(t, vmessOptions.Transport)
	require.Equal(t, "/vmess", xhttpOptions.Path)
	require.Equal(t, "stream-one", xhttpOptions.Mode)
	require.Equal(t, expectedVMessAutoSecurity(), vmessOptions.Security)
}

// A Host header is rejected by XHTTP; it is moved into host when host is unset.
func TestParseClashXHTTPHostHeader(t *testing.T) {
	outbound := parseSingleClashProxy(t, `
proxies:
  - name: xh
    type: vless
    server: s.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    network: xhttp
    xhttp-opts:
      headers:
        Host: header-host.com
        User-Agent: ua
`)
	xhttpOptions := xhttpTransport(t, outbound.Options.(*option.VLESSOutboundOptions).Transport)
	require.Equal(t, []string{"header-host.com"}, []string(xhttpOptions.Host))
	require.NotContains(t, xhttpOptions.Headers, "Host")
	require.Equal(t, []string{"ua"}, []string(xhttpOptions.Headers["User-Agent"]))
}
