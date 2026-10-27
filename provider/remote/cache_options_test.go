package remote

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	providerAdapter "github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing/common/json/badoption"
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

type stubEndpointManager struct {
	adapter.EndpointManager
}

func (m *stubEndpointManager) Get(string) (adapter.Endpoint, bool) { return nil, false }

const twoNodes = `{"outbounds":[
	{"type":"socks","tag":"keep","server":"127.0.0.1","server_port":1080},
	{"type":"socks","tag":"drop","server":"127.0.0.1","server_port":1081}
]}`

func newCachedProvider(t *testing.T, url string, options option.ProviderRemoteOptions, saved *adapter.SavedBinary) *ProviderRemote {
	t.Helper()
	registry := outbound.NewRegistry()
	socks.RegisterOutbound(registry)
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), registry)
	logFactory := log.NewNOPFactory()
	options.URL = url
	created, err := NewProviderRemote(ctx, nil, logFactory, "test", options)
	require.NoError(t, err)
	provider := created.(*ProviderRemote)
	provider.Adapter = providerAdapter.NewAdapter(
		ctx, nil,
		&stubOutboundManager{outbounds: make(map[string]adapter.Outbound)},
		&stubEndpointManager{},
		logFactory, logFactory.NewLogger("test"),
		"test", C.ProviderTypeRemote, option.ProviderHealthCheckOptions{},
	)
	provider.cacheFile = &subscriptionCacheStub{saved: saved}
	return provider
}

func excludeOptions(t *testing.T, pattern string) option.ProviderRemoteOptions {
	t.Helper()
	var exclude badoption.Regexp
	require.NoError(t, exclude.UnmarshalJSON([]byte(`"`+pattern+`"`)))
	return option.ProviderRemoteOptions{Exclude: &exclude}
}

func outboundTags(provider *ProviderRemote) []string {
	var tags []string
	for _, detour := range provider.Outbounds() {
		tags = append(tags, detour.Tag())
	}
	return tags
}

func TestProviderRemoteCacheKeyTracksOptions(t *testing.T) {
	t.Parallel()

	const url = "https://example.com/provider"
	plain := newCachedProvider(t, url, option.ProviderRemoteOptions{}, nil)
	samePlain := newCachedProvider(t, url, option.ProviderRemoteOptions{}, nil)
	excluded := newCachedProvider(t, url, excludeOptions(t, "drop"), nil)
	detour := "front"
	overridden := newCachedProvider(t, url, option.ProviderRemoteOptions{
		OverrideDialer: &option.OverrideDialerOptions{Detour: &detour},
	}, nil)

	urlHash := sha256.Sum256([]byte(url))
	for _, provider := range []*ProviderRemote{plain, excluded, overridden} {
		require.Equal(t, urlHash[:], provider.cacheKey()[:len(urlHash)])
	}
	require.Equal(t, plain.cacheKey(), samePlain.cacheKey())
	require.NotEqual(t, plain.cacheKey(), excluded.cacheKey())
	require.NotEqual(t, plain.cacheKey(), overridden.cacheKey())
}

func TestProviderRemoteCacheAppliesCurrentFilter(t *testing.T) {
	t.Parallel()

	const url = "https://example.com/provider"
	// The cache was written before "exclude" was added to the configuration.
	written := newCachedProvider(t, url, option.ProviderRemoteOptions{}, nil)
	provider := newCachedProvider(t, url, excludeOptions(t, "drop"), &adapter.SavedBinary{
		Content:  []byte(twoNodes),
		LastEtag: `"etag"`,
		URLHash:  written.cacheKey(),
	})

	loaded, err := provider.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, []string{"test/keep"}, outboundTags(provider))
	require.True(t, provider.optionsChanged)
	require.Empty(t, provider.lastEtag, "a 304 must not keep content processed with old options")
}

func TestProviderRemoteCacheUnchangedOptions(t *testing.T) {
	t.Parallel()

	const url = "https://example.com/provider"
	written := newCachedProvider(t, url, option.ProviderRemoteOptions{}, nil)
	provider := newCachedProvider(t, url, option.ProviderRemoteOptions{}, &adapter.SavedBinary{
		Content:  []byte(twoNodes),
		LastEtag: `"etag"`,
		URLHash:  written.cacheKey(),
	})

	loaded, err := provider.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, []string{"test/keep", "test/drop"}, outboundTags(provider))
	require.False(t, provider.optionsChanged)
	require.Equal(t, `"etag"`, provider.lastEtag)
}

func TestProviderRemoteCacheFromURLOnlyBuild(t *testing.T) {
	t.Parallel()

	const url = "https://example.com/provider"
	urlHash := sha256.Sum256([]byte(url))
	provider := newCachedProvider(t, url, option.ProviderRemoteOptions{}, &adapter.SavedBinary{
		Content: []byte(twoNodes),
		URLHash: urlHash[:],
	})

	loaded, err := provider.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded, "cache written by older builds is still served")
	require.True(t, provider.optionsChanged, "and refreshed once to record the options hash")
}
