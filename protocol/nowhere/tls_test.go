package nowhere

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

func TestNormalizeNowhereTLSEmptyALPNAndVersion(t *testing.T) {
	original := &option.InboundTLSOptions{Enabled: true, MinVersion: "1.2", MaxVersion: "1.2"}
	normalized, err := normalizeNowhereInboundTLS(original)
	require.NoError(t, err)
	require.Equal(t, []string{defaultALPN}, []string(normalized.ALPN))
	require.Equal(t, "1.3", normalized.MinVersion)
	require.Equal(t, "1.3", normalized.MaxVersion)
	require.Empty(t, original.ALPN)
	require.Equal(t, "1.2", original.MinVersion)
}

func TestNormalizeNowhereTLSPreservesSingleCustomALPN(t *testing.T) {
	original := &option.OutboundTLSOptions{
		Enabled: true,
		ALPN:    badoption.Listable[string]{"custom/1"},
	}
	normalized, err := normalizeNowhereOutboundTLS(original)
	require.NoError(t, err)
	require.Equal(t, []string{"custom/1"}, []string(normalized.ALPN))
	require.Equal(t, "1.3", normalized.MinVersion)
	require.Equal(t, "1.3", normalized.MaxVersion)
}

// TestApplyNowhereCertificatePinNoneDisables covers the Rust "none" sentinel:
// empty or "none" disables pinning (nil config is never touched), while a
// malformed pin is rejected.
func TestApplyNowhereCertificatePinNoneDisables(t *testing.T) {
	require.NoError(t, applyNowhereCertificatePin(nil, ""))
	require.NoError(t, applyNowhereCertificatePin(nil, "none"))
	require.Error(t, applyNowhereCertificatePin(nil, "not-hex"))
}

func TestNormalizeNowhereTLSRejectsMultipleALPN(t *testing.T) {
	_, err := normalizeNowhereOutboundTLS(&option.OutboundTLSOptions{
		Enabled: true,
		ALPN:    badoption.Listable[string]{"nw2", "h3"},
	})
	require.ErrorContains(t, err, "exactly one ALPN")
}

func TestNormalizeNowhereNextServerName(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		input string
		want  string
	}{
		{"empty disables verification", "", ""},
		{"none disables verification", "none", ""},
		{"dns name kept", "origin.example", "origin.example"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := normalizeNowhereNextServerName(testCase.input)
			require.NoError(t, err)
			require.Equal(t, testCase.want, got)
		})
	}
	for _, input := range []string{
		"127.0.0.1",
		"::1",
		"exa:mple.org",
		"ex[ample.org",
		"exa]mple.org",
		"münchen.example",
		strings.Repeat("a", 254),
	} {
		_, err := normalizeNowhereNextServerName(input)
		require.ErrorContains(t, err, "must be an ASCII DNS name", "input %q", input)
	}
}
