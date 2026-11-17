package provider

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type fakeDNSTransport struct {
	tag      string
	dnsType  string
	rcode    int
	err      error
	closed   atomic.Bool
	queries  atomic.Int32
	keepIdle atomic.Bool
}

func (t *fakeDNSTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateStart {
		scope.Add(func() error {
			t.closed.Store(true)
			return nil
		})
	}
	return nil
}
func (t *fakeDNSTransport) Type() string                     { return t.dnsType }
func (t *fakeDNSTransport) Tag() string                      { return t.tag }
func (t *fakeDNSTransport) Dependencies() []string           { return nil }
func (t *fakeDNSTransport) Reset()                           {}
func (t *fakeDNSTransport) SetKeepIdleConnections(keep bool) { t.keepIdle.Store(keep) }
func (t *fakeDNSTransport) CloseIdleConnections()            {}

func (t *fakeDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries.Add(1)
	if t.err != nil {
		return nil, t.err
	}
	response := new(mDNS.Msg)
	response.SetRcode(message, t.rcode)
	return response, nil
}

func (t *fakeDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	callback(t.Exchange(ctx, message))
}

type fakeDNSManager struct {
	adapter.DNSTransportManager
	transports map[string]adapter.DNSTransport
	defaultTag string
}

func (m *fakeDNSManager) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, loaded := m.transports[tag]
	return transport, loaded
}

func (m *fakeDNSManager) Default() adapter.DNSTransport {
	return m.transports[m.defaultTag]
}

// fakeDNSRegistry creates members from RemoteDNSServerOptions whose server
// names the behavior: "ok", "fail", "servfail", or "invalid" (not created).
type fakeDNSRegistry struct {
	adapter.DNSTransportRegistry
	access  sync.Mutex
	created []*fakeDNSTransport
	options []any
}

func (r *fakeDNSRegistry) CreateDNSTransport(_ context.Context, _ log.ContextLogger, tag string, transportType string, options any) (adapter.DNSTransport, error) {
	r.access.Lock()
	defer r.access.Unlock()
	if options.(*option.RemoteDNSServerOptions).Server == "invalid.example" {
		return nil, errors.New("invalid server")
	}
	transport := &fakeDNSTransport{tag: tag, dnsType: transportType}
	switch options.(*option.RemoteDNSServerOptions).Server {
	case "fail.example":
		transport.err = errors.New("unreachable")
	case "servfail.example":
		transport.rcode = mDNS.RcodeServerFailure
	}
	r.created = append(r.created, transport)
	r.options = append(r.options, options)
	return transport, nil
}

func udpServer(server string) option.DNSServerOptions {
	return option.DNSServerOptions{
		Type: C.DNSTypeUDP,
		Options: &option.RemoteDNSServerOptions{
			RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: option.DialerOptions{Detour: "subscription-node"}},
			DNSServerAddressOptions:  option.DNSServerAddressOptions{Server: server, ServerPort: 53},
		},
	}
}

func newTestProviderDNS(t *testing.T, fallback *fakeDNSTransport) (*providerDNS, *fakeDNSRegistry, *adapter.Scope) {
	t.Helper()
	manager := &fakeDNSManager{transports: map[string]adapter.DNSTransport{fallback.tag: fallback}, defaultTag: fallback.tag}
	registry := &fakeDNSRegistry{}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	ctx = service.ContextWith[adapter.DNSTransportRegistry](ctx, registry)
	transport, err := newProviderDNS(ctx, log.NewNOPFactory(), "sub", &option.ProviderDomainResolverOptions{}, nil, option.DialerOptions{})
	require.NoError(t, err)
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, transport.Start(stage, scope))
	}
	t.Cleanup(func() { _ = scope.Close() })
	return transport, registry, scope
}

func query(t *testing.T, transport adapter.DNSTransport) *mDNS.Msg {
	t.Helper()
	message := new(mDNS.Msg)
	message.SetQuestion("node.example.", mDNS.TypeA)
	response, err := transport.Exchange(context.Background(), message)
	require.NoError(t, err)
	return response
}

func TestProviderDNSFallbackWithoutMembers(t *testing.T) {
	t.Parallel()
	fallback := &fakeDNSTransport{tag: "default", dnsType: C.DNSTypeUDP}
	transport, _, _ := newTestProviderDNS(t, fallback)
	require.Equal(t, "sub-dns", transport.Tag())
	require.Equal(t, mDNS.RcodeSuccess, query(t, transport).Rcode)
	require.EqualValues(t, 1, fallback.queries.Load())

	transport.Update(nil)
	require.Equal(t, mDNS.RcodeSuccess, query(t, transport).Rcode)
	require.EqualValues(t, 2, fallback.queries.Load())
}

func TestProviderDNSRaceAndFallback(t *testing.T) {
	t.Parallel()
	fallback := &fakeDNSTransport{tag: "default", dnsType: C.DNSTypeUDP}
	transport, registry, _ := newTestProviderDNS(t, fallback)

	transport.Update([]option.DNSServerOptions{udpServer("fail.example"), udpServer("ok.example")})
	require.Len(t, registry.created, 2)
	require.Equal(t, mDNS.RcodeSuccess, query(t, transport).Rcode)
	require.Zero(t, fallback.queries.Load(), "a member answered")

	// all members inconclusive: the fallback answers
	transport.Update([]option.DNSServerOptions{udpServer("fail.example"), udpServer("servfail.example")})
	require.Equal(t, mDNS.RcodeSuccess, query(t, transport).Rcode)
	require.EqualValues(t, 1, fallback.queries.Load())

	// fallback broken too: the SERVFAIL answer is returned rather than nothing
	fallback.err = errors.New("down")
	require.Equal(t, mDNS.RcodeServerFailure, query(t, transport).Rcode)

	// single member fast path
	transport.Update([]option.DNSServerOptions{udpServer("fail.example")})
	message := new(mDNS.Msg)
	message.SetQuestion("node.example.", mDNS.TypeA)
	_, err := transport.Exchange(context.Background(), message)
	require.Error(t, err)
}

func TestProviderDNSUpdateLifecycle(t *testing.T) {
	t.Parallel()
	fallback := &fakeDNSTransport{tag: "default", dnsType: C.DNSTypeUDP}
	transport, registry, _ := newTestProviderDNS(t, fallback)
	transport.SetKeepIdleConnections(true)

	servers := []option.DNSServerOptions{udpServer("ok.example"), udpServer("doh.example")}
	transport.Update(servers)
	require.Len(t, registry.created, 2)
	first := registry.created
	for _, member := range first {
		require.True(t, member.keepIdle.Load(), "new members follow keep-idle")
	}

	// the same list keeps members and their connections
	transport.Update([]option.DNSServerOptions{udpServer("ok.example"), udpServer("doh.example")})
	require.Len(t, registry.created, 2)

	transport.Update([]option.DNSServerOptions{udpServer("ok.example")})
	require.Len(t, registry.created, 3)
	for _, member := range first {
		require.True(t, member.closed.Load(), "replaced members are closed")
	}

	// subscription options are not mutated, members dial directly and resolve
	// server names through the fallback
	require.Equal(t, "subscription-node", servers[0].Options.(*option.RemoteDNSServerOptions).Detour)
	created := registry.options[2].(*option.RemoteDNSServerOptions)
	require.Empty(t, created.Detour)
	require.NotNil(t, created.DomainResolver)
	require.Equal(t, "default", created.DomainResolver.Server)

	last := registry.created[2]
	transport.close()
	require.True(t, last.closed.Load())
	require.Equal(t, mDNS.RcodeSuccess, query(t, transport).Rcode, "closed provider DNS still answers through the fallback")
}

func TestProviderDNSPendingBeforeStart(t *testing.T) {
	t.Parallel()
	fallback := &fakeDNSTransport{tag: "default", dnsType: C.DNSTypeUDP}
	manager := &fakeDNSManager{transports: map[string]adapter.DNSTransport{"default": fallback}, defaultTag: "default"}
	registry := &fakeDNSRegistry{}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	ctx = service.ContextWith[adapter.DNSTransportRegistry](ctx, registry)
	transport, err := newProviderDNS(ctx, log.NewNOPFactory(), "sub", &option.ProviderDomainResolverOptions{}, nil, option.DialerOptions{})
	require.NoError(t, err)
	transport.Update([]option.DNSServerOptions{udpServer("ok.example")})
	require.Empty(t, registry.created, "members wait for the transport to start")
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	defer scope.Close()
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, transport.Start(stage, scope))
	}
	require.Len(t, registry.created, 1)
}

func TestProviderDNSResolverValidation(t *testing.T) {
	t.Parallel()
	manager := &fakeDNSManager{transports: map[string]adapter.DNSTransport{}}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	ctx = service.ContextWith[adapter.DNSTransportRegistry](ctx, &fakeDNSRegistry{})
	_, err := newProviderDNS(ctx, log.NewNOPFactory(), "sub", &option.ProviderDomainResolverOptions{Resolver: "sub-dns"}, nil, option.DialerOptions{})
	require.Error(t, err)

	transport, err := newProviderDNS(ctx, log.NewNOPFactory(), "sub", &option.ProviderDomainResolverOptions{Resolver: "missing"}, nil, option.DialerOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"missing"}, transport.Dependencies())
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	defer scope.Close()
	require.Error(t, transport.Start(adapter.StartStateStart, scope))

	// override_dialer.domain_resolver becomes the fallback
	transport, err = newProviderDNS(ctx, log.NewNOPFactory(), "sub", &option.ProviderDomainResolverOptions{}, &option.DomainResolveOptions{Server: "bootstrap"}, option.DialerOptions{})
	require.NoError(t, err)
	require.Equal(t, "bootstrap", transport.fallbackTag())
}

func socksWithResolver(tag string, server string) option.Outbound {
	return option.Outbound{Type: C.TypeSOCKS, Tag: tag, Options: &option.SOCKSOutboundOptions{DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{DomainResolver: &option.DomainResolveOptions{Server: server}}}}}
}

func resolverOf(outbound option.Outbound) *option.DomainResolveOptions {
	return outbound.Options.(*option.SOCKSOutboundOptions).DomainResolver
}

func TestRepairDomainResolvers(t *testing.T) {
	t.Parallel()
	manager := &fakeDNSManager{transports: map[string]adapter.DNSTransport{"configured": &fakeDNSTransport{tag: "configured"}, "sub-dns": &fakeDNSTransport{tag: "sub-dns"}}}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)

	// provider_domain_resolver disabled, override_dialer.domain_resolver set:
	// a cached reference to the old provider DNS (or another provider tag)
	// is restored to the configured resolver
	a := &Adapter{ctx: ctx, providerTag: "renamed", logger: log.NewNOPFactory().Logger()}
	_, err := a.EnableProviderDNS(&option.OverrideDialerOptions{DomainResolver: &option.DomainResolveOptions{Server: "configured", Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only)}}, option.DialerOptions{})
	require.NoError(t, err)
	outbounds := []option.Outbound{socksWithResolver("a", "old-dns"), socksWithResolver("b", "configured"), socksWithResolver("c", "sub-dns")}
	a.repairDomainResolvers(outbounds, nil)
	require.Equal(t, "configured", resolverOf(outbounds[0]).Server)
	require.Equal(t, option.DomainStrategy(C.DomainStrategyIPv4Only), resolverOf(outbounds[0]).Strategy)
	require.Equal(t, "configured", resolverOf(outbounds[1]).Server)
	require.Equal(t, "sub-dns", resolverOf(outbounds[2]).Server, "existing servers are kept, whatever their name")

	// no override resolver: the dangling reference is dropped
	a = &Adapter{ctx: ctx, providerTag: "sub", logger: log.NewNOPFactory().Logger()}
	_, err = a.EnableProviderDNS(nil, option.DialerOptions{})
	require.NoError(t, err)
	outbounds = []option.Outbound{socksWithResolver("a", "missing")}
	a.repairDomainResolvers(outbounds, nil)
	require.Nil(t, resolverOf(outbounds[0]))

	// inline providers keep their configuration untouched
	a = &Adapter{ctx: ctx, providerTag: "inline"}
	outbounds = []option.Outbound{socksWithResolver("a", "missing")}
	a.repairDomainResolvers(outbounds, nil)
	require.Equal(t, "missing", resolverOf(outbounds[0]).Server)
}

// blockingDNSTransport never answers before the context ends.
type blockingDNSTransport struct {
	fakeDNSTransport
}

func (t *blockingDNSTransport) Exchange(ctx context.Context, _ *mDNS.Msg) (*mDNS.Msg, error) {
	t.queries.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestProviderDNSTimeoutFallsBack(t *testing.T) {
	t.Parallel()
	fallback := &fakeDNSTransport{tag: "default", dnsType: C.DNSTypeUDP}
	transport, _, _ := newTestProviderDNS(t, fallback)
	blocked := &blockingDNSTransport{fakeDNSTransport{tag: "blocked"}}
	members := []providerDNSMember{{transport: blocked, name: "blocked"}}
	transport.members.Store(&members)

	message := new(mDNS.Msg)
	message.SetQuestion("node.example.", mDNS.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	response, err := transport.Exchange(ctx, message)
	require.NoError(t, err, "a blocked subscription DNS leaves the fallback time to answer")
	require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
	require.EqualValues(t, 1, fallback.queries.Load())

	// the blocked members rest: the next query goes to the fallback directly
	response, err = transport.Exchange(context.Background(), message)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
	require.EqualValues(t, 1, blocked.queries.Load())
	require.EqualValues(t, 2, fallback.queries.Load())
}

func TestProviderDNSFallbackLoop(t *testing.T) {
	t.Parallel()
	manager := &fakeDNSManager{transports: map[string]adapter.DNSTransport{}}
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), manager)
	ctx = service.ContextWith[adapter.DNSTransportRegistry](ctx, &fakeDNSRegistry{})
	a, err := newProviderDNS(ctx, log.NewNOPFactory(), "a", &option.ProviderDomainResolverOptions{Resolver: "b-dns"}, nil, option.DialerOptions{})
	require.NoError(t, err)
	b, err := newProviderDNS(ctx, log.NewNOPFactory(), "b", &option.ProviderDomainResolverOptions{Resolver: "a-dns"}, nil, option.DialerOptions{})
	require.NoError(t, err)
	manager.transports["a-dns"] = a
	manager.transports["b-dns"] = b
	message := new(mDNS.Msg)
	message.SetQuestion("node.example.", mDNS.TypeA)
	_, err = a.Exchange(context.Background(), message)
	require.ErrorContains(t, err, "loop", "mutual fallback fails instead of overflowing the stack")
}

func TestProviderDNSEnvironmentAndDialer(t *testing.T) {
	t.Parallel()
	fallback := &fakeDNSTransport{tag: "default", dnsType: C.DNSTypeUDP}
	transport, registry, _ := newTestProviderDNS(t, fallback)
	transport.memberDialer = option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: "wan0"}}
	before := transport.Environment()
	server := udpServer("ok.example")
	server.Options.(*option.RemoteDNSServerOptions).BindInterface = "subscription-chosen"
	transport.Update([]option.DNSServerOptions{server})
	require.NotEqual(t, before, transport.Environment(), "new members invalidate cached answers")
	created := registry.options[0].(*option.RemoteDNSServerOptions)
	require.Equal(t, "wan0", created.BindInterface, "members dial with override_dialer, not the subscription")
	require.Empty(t, created.Detour)
	require.True(t, registry.created[0].keepIdle.Load(), "members keep idle connections by default")
}

// A subscription whose private DNS is the only source of usable node
// addresses disables the fallback: its failures are reported instead of
// answers from another resolver.
func TestProviderDNSWithoutFallback(t *testing.T) {
	t.Parallel()
	fallback := &fakeDNSTransport{tag: "default", dnsType: C.DNSTypeUDP}
	transport, _, _ := newTestProviderDNS(t, fallback)
	disabled := false
	transport.fallback = (&option.ProviderDomainResolverOptions{Fallback: &disabled}).FallbackEnabled()
	require.False(t, transport.fallback)
	message := new(mDNS.Msg)
	message.SetQuestion("node.example.", mDNS.TypeA)

	// No subscription DNS at all: the resolver is the nodes' only resolver.
	require.Equal(t, mDNS.RcodeSuccess, query(t, transport).Rcode)
	require.EqualValues(t, 1, fallback.queries.Load())

	transport.Update([]option.DNSServerOptions{udpServer("fail.example"), udpServer("servfail.example")})
	response, err := transport.Exchange(context.Background(), message)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeServerFailure, response.Rcode, "the subscription answer is returned as is")
	transport.Update([]option.DNSServerOptions{udpServer("fail.example")})
	_, err = transport.Exchange(context.Background(), message)
	require.Error(t, err)
	_, err = transport.Exchange(context.Background(), message)
	require.Error(t, err, "failed members are not rested in favor of the resolver")
	require.False(t, transport.membersAreDown())

	transport.Update([]option.DNSServerOptions{udpServer("invalid.example")})
	_, err = transport.Exchange(context.Background(), message)
	require.ErrorContains(t, err, "fallback is disabled")
	require.EqualValues(t, 1, fallback.queries.Load(), "the resolver never answered for the subscription")

	transport.Update([]option.DNSServerOptions{udpServer("ok.example")})
	require.Equal(t, mDNS.RcodeSuccess, query(t, transport).Rcode)
}

func TestProviderDomainResolverFallbackOption(t *testing.T) {
	t.Parallel()
	var options option.ProviderDomainResolverOptions
	require.NoError(t, options.UnmarshalJSON([]byte(`{"fallback": false}`)))
	require.True(t, options.IsEnabled())
	require.False(t, options.FallbackEnabled())
	content, err := options.MarshalJSON()
	require.NoError(t, err)
	require.JSONEq(t, `{"fallback": false}`, string(content))
	require.True(t, (*option.ProviderDomainResolverOptions)(nil).FallbackEnabled())
	require.True(t, (*option.ProviderDomainResolverOptions)(nil).NameserverEnabled())
	require.NoError(t, options.UnmarshalJSON([]byte(`{"use_nameserver": false}`)))
	require.False(t, options.NameserverEnabled())
	require.True(t, options.FallbackEnabled())
	content, err = options.MarshalJSON()
	require.NoError(t, err)
	require.JSONEq(t, `{"use_nameserver": false}`, string(content))
	require.NoError(t, options.UnmarshalJSON([]byte(`true`)))
	require.True(t, options.FallbackEnabled())
}
