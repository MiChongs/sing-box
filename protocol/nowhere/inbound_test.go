package nowhere

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"

	"github.com/stretchr/testify/require"
)

func TestInboundImplementsInterfaceUpdateListener(t *testing.T) {
	t.Parallel()
	var _ adapter.InterfaceUpdateListener = (*Inbound)(nil)
}

func TestNewInboundRejectsUnknownQUICCongestionControlForTCPOnly(t *testing.T) {
	t.Parallel()
	logger := log.NewNOPFactory().Logger()
	_, err := NewInbound(context.Background(), nil, logger, "nw", option.NowhereInboundOptions{
		Password:              "secret",
		QUICCongestionControl: "BBR",
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{Enabled: true},
		},
	})
	require.ErrorContains(t, err, "unknown quic congestion control")
}

func TestInboundInterfaceUpdatedTCPOnlyIsNoop(t *testing.T) {
	t.Parallel()
	in := &Inbound{
		logger:    log.NewNOPFactory().Logger(),
		enableUDP: false,
	}
	require.NotPanics(t, func() { in.InterfaceUpdated(context.Background()) })
}

func TestResolveNextMorph(t *testing.T) {
	t.Parallel()
	// nil next and nil next.morph inherit the inbound's morph setting.
	require.False(t, resolveNextMorph(false, nil))
	require.True(t, resolveNextMorph(true, nil))
	require.False(t, resolveNextMorph(false, &option.NowhereNextOptions{}))
	require.True(t, resolveNextMorph(true, &option.NowhereNextOptions{}))
	// An explicit next.morph overrides the inbound setting in both directions.
	require.True(t, resolveNextMorph(false, &option.NowhereNextOptions{Morph: common.Ptr(true)}))
	require.False(t, resolveNextMorph(true, &option.NowhereNextOptions{Morph: common.Ptr(false)}))
}
