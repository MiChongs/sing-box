//go:build with_quic

package quic

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestBuildQUICConfigDefaults(t *testing.T) {
	config := BuildQUICConfig(option.QUICOptions{})
	require.True(t, config.EnableDatagrams)
	require.False(t, config.Allow0RTT)
	require.Equal(t, defaultHandshakeIdleTimeout, config.HandshakeIdleTimeout)
	require.Equal(t, defaultIdleTimeout, config.MaxIdleTimeout)
	require.Zero(t, config.KeepAlivePeriod)
	require.Equal(t, defaultStreamReceiveWindow, config.InitialStreamReceiveWindow)
	require.Equal(t, defaultStreamReceiveWindow, config.MaxStreamReceiveWindow)
	require.Equal(t, defaultInitialConnWindow, config.InitialConnectionReceiveWindow)
	require.Equal(t, defaultMaxConnWindow, config.MaxConnectionReceiveWindow)
	require.Equal(t, defaultMaxIncomingStreams, config.MaxIncomingStreams)
	require.EqualValues(t, -1, config.MaxIncomingUniStreams)
	require.False(t, config.DisablePathMTUDiscovery)
}

func TestBuildQUICConfigSharedOverrides(t *testing.T) {
	var options option.QUICOptions
	require.NoError(t, json.Unmarshal([]byte(`{
		"idle_timeout":"45s",
		"keep_alive_period":"7s",
		"stream_receive_window":2097152,
		"connection_receive_window":8388608,
		"max_concurrent_streams":77,
		"initial_packet_size":1300,
		"disable_path_mtu_discovery":true
	}`), &options))
	config := BuildQUICConfig(options)
	require.Equal(t, 45*time.Second, config.MaxIdleTimeout)
	require.Equal(t, 7*time.Second, config.KeepAlivePeriod)
	require.EqualValues(t, 2*1024*1024, config.InitialStreamReceiveWindow)
	require.EqualValues(t, 2*1024*1024, config.MaxStreamReceiveWindow)
	require.EqualValues(t, 8*1024*1024, config.InitialConnectionReceiveWindow)
	require.EqualValues(t, 8*1024*1024, config.MaxConnectionReceiveWindow)
	require.EqualValues(t, 77, config.MaxIncomingStreams)
	require.EqualValues(t, 1300, config.InitialPacketSize)
	require.True(t, config.DisablePathMTUDiscovery)
}

func TestBuildQUICServerConfigUsesAdmissionLimitAndZeroUni(t *testing.T) {
	config := BuildQUICServerConfig(option.QUICOptions{})
	require.True(t, config.EnableDatagrams)
	require.False(t, config.Allow0RTT)
	require.EqualValues(t, defaultMaxIncomingStreams, config.MaxIncomingStreams)
	// quic-go normalizes a negative value into a MAX_STREAMS(uni=0) transport
	// parameter. Literal zero means the library default, not zero.
	require.EqualValues(t, nowhereUniStreams, config.MaxIncomingUniStreams)
}
