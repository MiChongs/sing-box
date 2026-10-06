//go:build with_quic && with_utls

package tls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// TestUTLSClientQUICChromeParrotHandshake covers the standard-library config
// QUICClientConfig derives from a uTLS client config for QUIC: the same checks
// must reach the Chrome-parroting handshake in a form quic-go accepts.
func TestUTLSClientQUICChromeParrotHandshake(t *testing.T) {
	server := startChromeParrotTestServer(t)
	for _, testCase := range chromeParrotTestCases(server) {
		t.Run(testCase.name, func(t *testing.T) {
			options := testCase.options
			options.Enabled = true
			options.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}
			config, err := NewClient(context.Background(), logger.NOP(), "", options)
			require.NoError(t, err)
			_, isUTLS := config.(*UTLSClientConfig)
			require.True(t, isUTLS, "config is %T, want the uTLS client", config)
			config, err = QUICClientConfig(config)
			require.NoError(t, err)
			clientName, err := server.dial(t, config)
			if testCase.fails {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "not supported with ChromeParrot")
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.client, clientName)
		})
	}
}
