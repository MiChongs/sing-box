package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type stubEndpointManager struct {
	adapter.EndpointManager
}

func (m *stubEndpointManager) Get(string) (adapter.Endpoint, bool) { return nil, false }

type removableOutboundManager struct {
	stubOutboundManager
}

func (m *removableOutboundManager) Remove(tag string) error {
	delete(m.outbounds, tag)
	return nil
}

func newOutboundManager() *removableOutboundManager {
	return &removableOutboundManager{stubOutboundManager{outbounds: make(map[string]adapter.Outbound)}}
}

const clashWithDNS = `
dns:
  proxy-server-nameserver: [223.5.5.5, "tls://1.1.1.1"]
proxies:
  - {name: node, type: socks5, server: node.example, port: 1080}
`

func TestProviderLocalDomainResolver(t *testing.T) {
	t.Parallel()
	dnsRegistry := dns.NewTransportRegistry()
	transport.RegisterUDP(dnsRegistry)
	transport.RegisterTLS(dnsRegistry)
	outboundRegistry := outbound.NewRegistry()
	socks.RegisterOutbound(outboundRegistry)
	dnsManager := dns.NewTransportManager(dnsRegistry, nil, "")
	ctx := context.Background()
	ctx = service.ContextWith[option.OutboundOptionsRegistry](ctx, outboundRegistry)
	ctx = service.ContextWith[option.DNSTransportOptionsRegistry](ctx, dnsRegistry)
	ctx = service.ContextWith[adapter.DNSTransportRegistry](ctx, dnsRegistry)
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, dnsManager)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, adapter.OutboundManager(newOutboundManager()))
	ctx = service.ContextWith[adapter.EndpointManager](ctx, &stubEndpointManager{})
	logFactory := log.NewNOPFactory()
	require.NoError(t, dnsManager.Create(ctx, logFactory.Logger(), "bootstrap", C.DNSTypeUDP, &option.RemoteDNSServerOptions{
		DNSServerAddressOptions: option.DNSServerAddressOptions{Server: "127.0.0.1", ServerPort: 53},
	}))

	path := filepath.Join(t.TempDir(), "sub.yaml")
	require.NoError(t, os.WriteFile(path, []byte(clashWithDNS), 0o644))
	instance, err := NewProviderLocal(ctx, nil, logFactory, "sub", option.ProviderLocalOptions{
		Path: path,
		OverrideDialer: &option.OverrideDialerOptions{
			ProviderDomainResolver: &option.ProviderDomainResolverOptions{
				Enabled:          common.Ptr(true),
				OutboundStrategy: option.DomainStrategy(C.DomainStrategyIPv4Only),
			},
		},
	})
	require.NoError(t, err)
	providerDNS, registered := dnsManager.Transport("sub-dns")
	require.True(t, registered)
	require.Equal(t, C.DNSTypeProvider, providerDNS.Type())

	scope := adapter.NewScope(ctx, logFactory.Logger())
	defer scope.Close()
	dnsManager.Initialize(func() (adapter.DNSTransport, error) { return nil, os.ErrInvalid })
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, dnsManager.Start(stage, scope))
	}
	local := instance.(*ProviderLocal)
	require.NoError(t, local.reloadFile(path))
	require.Len(t, local.lastOutOpts, 1)
	resolver := local.lastOutOpts[0].Options.(*option.SOCKSOutboundOptions).DomainResolver
	require.NotNil(t, resolver)
	require.Equal(t, "sub-dns", resolver.Server)
	require.Equal(t, option.DomainStrategy(C.DomainStrategyIPv4Only), resolver.Strategy)

	require.NoError(t, local.Close())
	_, registered = dnsManager.Transport("sub-dns")
	require.False(t, registered, "closing the provider removes its DNS server")
}

func TestProviderLocalDomainResolverDisabled(t *testing.T) {
	t.Parallel()
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), adapter.OutboundManager(newOutboundManager()))
	ctx = service.ContextWith[adapter.EndpointManager](ctx, &stubEndpointManager{})
	outboundRegistry := outbound.NewRegistry()
	socks.RegisterOutbound(outboundRegistry)
	ctx = service.ContextWith[option.OutboundOptionsRegistry](ctx, outboundRegistry)
	path := filepath.Join(t.TempDir(), "sub.yaml")
	require.NoError(t, os.WriteFile(path, []byte(clashWithDNS), 0o644))
	instance, err := NewProviderLocal(ctx, nil, log.NewNOPFactory(), "sub", option.ProviderLocalOptions{
		Path:           path,
		OverrideDialer: &option.OverrideDialerOptions{ProviderDomainResolver: &option.ProviderDomainResolverOptions{Enabled: common.Ptr(false)}},
	})
	require.NoError(t, err, "a disabled provider_domain_resolver needs no DNS manager")
	local := instance.(*ProviderLocal)
	require.NoError(t, local.reloadFile(path))
	require.Nil(t, local.lastOutOpts[0].Options.(*option.SOCKSOutboundOptions).DomainResolver)
	require.NoError(t, local.Close())
}
