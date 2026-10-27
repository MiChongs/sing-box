package provider

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type stubOutbound struct {
	adapter.Outbound
	tag string
}

func (o *stubOutbound) Tag() string { return o.tag }

type stubOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *stubOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	detour, loaded := m.outbounds[tag]
	return detour, loaded
}

func (m *stubOutboundManager) Create(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ string, _ any) error {
	m.outbounds[tag] = &stubOutbound{tag: tag}
	return nil
}

func TestProviderInlineNotifiesGroupsOnStart(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[adapter.OutboundManager](context.Background(),
		&stubOutboundManager{outbounds: make(map[string]adapter.Outbound)})
	provider, err := NewProviderInline(ctx, nil, log.NewNOPFactory(), "inline", option.ProviderInlineOptions{
		Outbounds: []option.Outbound{{Type: "socks", Tag: "node", Options: &option.SOCKSOutboundOptions{}}},
	})
	require.NoError(t, err)

	// Groups register their callbacks after providers are constructed.
	var updated []string
	provider.RegisterCallback(func(tag string) error {
		updated = append(updated, tag)
		return nil
	})
	require.NoError(t, provider.(*ProviderLocal).StartContext(ctx, nil))
	require.Equal(t, []string{"inline"}, updated)
	require.Len(t, provider.Outbounds(), 1)
}
