//go:build with_xhttp

package parser_test

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/provider/parser"
	"github.com/sagernet/sing-box/transport/v2rayxhttp"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// A parsed XHTTP node must survive the provider's JSON round trip, which only
// works once the plugin registered its option factory (with_xhttp builds).
func TestParsedXHTTPOptionRoundtrip(t *testing.T) {
	v2rayxhttp.RegisterPlugin()
	outbound, err := parser.ParseSubscriptionLink("vless://11111111-1111-1111-1111-111111111111@example.com:443?" +
		"security=tls&type=xhttp&path=%2Fr&mode=stream-up&extra=%7B%22xPaddingBytes%22%3A%2250-500%22%7D#tag")
	require.NoError(t, err)
	transport := outbound.Options.(*option.VLESSOutboundOptions).Transport
	content, err := json.Marshal(transport)
	require.NoError(t, err)

	var decoded option.V2RayTransportOptions
	require.NoError(t, json.Unmarshal(content, &decoded))
	require.Equal(t, C.V2RayTransportTypeXHTTP, decoded.Type)
	xhttpOptions, ok := decoded.Extra.(*option.V2RayXHTTPOptions)
	require.True(t, ok, "extra=%T", decoded.Extra)
	require.Equal(t, "/r", xhttpOptions.Path)
	require.Equal(t, "stream-up", xhttpOptions.Mode)
	require.Equal(t, option.XHTTPRange{From: 50, To: 500}, xhttpOptions.XPaddingBytes)
}
