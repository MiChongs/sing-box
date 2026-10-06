//go:build with_quic

package quic

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCongestionControl(t *testing.T) {
	t.Parallel()
	testCases := map[string]CongestionControl{
		"":             CongestionControlBBR,
		"bbr":          CongestionControlBBR,
		"bbr_standard": CongestionControlBBRStandard,
		"bbr2":         CongestionControlBBR2,
		"bbr2_variant": CongestionControlBBR2Variant,
		"cubic":        CongestionControlCubic,
		"reno":         CongestionControlReno,
	}
	for value, expected := range testCases {
		actual, err := ParseCongestionControl(value)
		require.NoError(t, err, value)
		require.Equal(t, expected, actual, value)
	}
}

func TestParseCongestionControlRejectsUnknown(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"BBR", "new_reno", "bbr-profile", "unknown"} {
		_, err := ParseCongestionControl(value)
		require.ErrorContains(t, err, "unknown quic congestion control", value)
	}
}
