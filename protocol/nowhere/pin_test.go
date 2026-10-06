package nowhere

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"

	"github.com/stretchr/testify/require"
)

func TestNormalizeNowhereOutboundTLSKeepsPinFieldOnOptions(t *testing.T) {
	pin := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	parsed, err := wire.ParseCertificatePin(pin)
	require.NoError(t, err)
	require.Equal(t, pin, parsed)

	_, err = wire.ParseCertificatePin("AAAAAAAAAAAAAAAAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	require.ErrorIs(t, err, wire.ErrInvalidCertificatePin)

	opts := &option.NowhereOutboundOptions{Pin: pin}
	require.Equal(t, pin, opts.Pin)
}
