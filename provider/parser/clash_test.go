package parser

import (
	"context"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestParseClashSnellObfsOptions(t *testing.T) {
	outbounds, endpoints, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: snell-out
    type: snell
    server: 127.0.0.1
    port: 1080
    psk: password
    version: 5
    udp: true
    obfs-opts:
      mode: http
      host: example.com
`)
	require.NoError(t, err)
	require.Empty(t, endpoints)
	require.Len(t, outbounds, 1)

	snellOptions, ok := outbounds[0].Options.(*option.SnellOutboundOptions)
	require.True(t, ok)
	require.Equal(t, 5, snellOptions.Version)
	require.Equal(t, option.NetworkList("tcp\nudp"), snellOptions.Network)
	require.Equal(t, "http", snellOptions.ObfsOptions.ObfsMode)
	require.Equal(t, "example.com", snellOptions.ObfsOptions.ObfsHost)
}

func TestParseClashAnyTLSDisableReuse(t *testing.T) {
	outbounds, endpoints, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: anytls-out
    type: anytls
    server: 127.0.0.1
    port: 443
    password: password
    disable-reuse: true
`)
	require.NoError(t, err)
	require.Empty(t, endpoints)
	require.Len(t, outbounds, 1)

	anyTLSOptions, ok := outbounds[0].Options.(*option.AnyTLSOutboundOptions)
	require.True(t, ok)
	require.True(t, anyTLSOptions.DisableReuse)
}

func TestParseClashVLESSEncryption(t *testing.T) {
	encryption := "mlkem768x25519plus.native.0rtt.100-111-1111.75-0-111.50-0-3333." + strings.Repeat("A", 43)
	outbounds, endpoints, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: vless-encryption
    type: vless
    server: 192.0.2.1
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    servername: example.com
    flow: xtls-rprx-vision
    network: xhttp
    xhttp-opts:
      path: /zones
      mode: auto
    encryption: `+encryption+`
  - name: vless-none
    type: vless
    server: 192.0.2.1
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    encryption: none
`)
	require.NoError(t, err)
	require.Empty(t, endpoints)
	require.Len(t, outbounds, 2)

	vlessOptions, ok := outbounds[0].Options.(*option.VLESSOutboundOptions)
	require.True(t, ok)
	require.Equal(t, encryption, vlessOptions.Encryption)
	require.Equal(t, "xtls-rprx-vision", vlessOptions.Flow)
	require.Equal(t, C.V2RayTransportTypeXHTTP, vlessOptions.Transport.Type)

	vlessOptions, ok = outbounds[1].Options.(*option.VLESSOutboundOptions)
	require.True(t, ok)
	require.Empty(t, vlessOptions.Encryption)
}
