package provider

import (
	"context"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

var (
	_ adapter.DNSTransport         = (*providerDNS)(nil)
	_ adapter.IdleConnectionKeeper = (*providerDNS)(nil)
)

// ProviderDNSTag is the DNS server the nodes of a provider with
// provider_domain_resolver resolve their server addresses through.
func ProviderDNSTag(providerTag string) string {
	return providerTag + "-dns"
}

type providerDNSMember struct {
	transport adapter.DNSTransport
	name      string
}

// providerDNS answers for the nodes of one provider through the DNS servers
// carried by its subscription. Its identity never changes while the provider
// lives: nodes and their resolve dialers hold it, and refreshing the
// subscription only swaps the members behind it. Without members, or when
// all of them fail, it answers through the fallback resolver.
type providerDNS struct {
	ctx              context.Context
	logger           log.ContextLogger
	logFactory       log.Factory
	tag              string
	providerTag      string
	resolver         string
	resolverStrategy option.DomainStrategy
	manager          adapter.DNSTransportManager
	registry         adapter.DNSTransportRegistry

	members  atomic.Pointer[[]providerDNSMember]
	keepIdle atomic.Bool

	access  sync.Mutex
	scope   *adapter.Scope
	started bool
	applied []option.DNSServerOptions
	pending []option.DNSServerOptions
}

func newProviderDNS(ctx context.Context, logFactory log.Factory, providerTag string, options *option.ProviderDomainResolverOptions, overrideResolver *option.DomainResolveOptions) (*providerDNS, error) {
	manager := service.FromContext[adapter.DNSTransportManager](ctx)
	if manager == nil {
		return nil, E.New("missing DNS transport manager")
	}
	registry := service.FromContext[adapter.DNSTransportRegistry](ctx)
	if registry == nil {
		return nil, E.New("missing DNS transport registry")
	}
	tag := ProviderDNSTag(providerTag)
	resolver := options.Resolver
	if resolver == "" && overrideResolver != nil {
		resolver = overrideResolver.Server
	}
	if resolver == tag {
		return nil, E.New("provider_domain_resolver.resolver cannot be the provider DNS server itself: ", tag)
	}
	return &providerDNS{
		ctx:              ctx,
		logger:           logFactory.NewLogger(F.ToString("dns/", C.DNSTypeProvider, "[", tag, "]")),
		logFactory:       logFactory,
		tag:              tag,
		providerTag:      providerTag,
		resolver:         resolver,
		resolverStrategy: options.ResolverStrategy,
		manager:          manager,
		registry:         registry,
	}, nil
}

func (t *providerDNS) Type() string {
	return C.DNSTypeProvider
}

func (t *providerDNS) Tag() string {
	return t.tag
}

func (t *providerDNS) Dependencies() []string {
	if t.resolver == "" {
		return nil
	}
	return []string{t.resolver}
}

func (t *providerDNS) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	t.access.Lock()
	defer t.access.Unlock()
	if t.scope == nil {
		t.scope = scope
	}
	if stage != adapter.StartStateStart {
		return nil
	}
	if t.resolver != "" {
		if _, loaded := t.manager.Transport(t.resolver); !loaded {
			return E.New("provider_domain_resolver: DNS server not found: ", t.resolver)
		}
	}
	t.started = true
	if t.pending != nil {
		servers := t.pending
		t.pending = nil
		t.applyLocked(servers)
	}
	return nil
}

// Update replaces the subscription DNS servers. Unchanged lists keep their
// members and connections.
func (t *providerDNS) Update(servers []option.DNSServerOptions) {
	t.access.Lock()
	defer t.access.Unlock()
	if !t.started {
		if servers == nil {
			servers = []option.DNSServerOptions{}
		}
		t.pending = servers
		return
	}
	t.applyLocked(servers)
}

func (t *providerDNS) applyLocked(servers []option.DNSServerOptions) {
	if t.applied != nil && (len(t.applied) == 0 && len(servers) == 0 || reflect.DeepEqual(t.applied, servers)) {
		return
	}
	if servers == nil {
		servers = []option.DNSServerOptions{}
	}
	if len(servers) == 0 {
		t.logger.Info("subscription carries no usable DNS server, nodes resolve through ", t.fallbackName())
	}
	resolver, strategy := t.memberResolver()
	members := make([]providerDNSMember, 0, len(servers))
	var names []string
	for i, server := range servers {
		name := describeDNSServer(server)
		memberTag := F.ToString(t.tag, "/", i)
		memberOptions, err := memberOptions(server, resolver, strategy)
		if err != nil {
			t.logger.Warn("skip subscription DNS server ", name, ": ", err)
			continue
		}
		logger := t.logFactory.NewLogger(F.ToString("dns/", server.Type, "[", memberTag, "]"))
		transport, err := t.registry.CreateDNSTransport(t.ctx, logger, memberTag, server.Type, memberOptions)
		if err != nil {
			t.logger.Warn("skip subscription DNS server ", name, ": ", err)
			continue
		}
		err = adapter.StartRuntimeComponent(t.scope, "dns/"+server.Type+"["+memberTag+"]", transport)
		if err != nil {
			t.logger.Warn("skip subscription DNS server ", name, ": ", err)
			continue
		}
		if keeper, isKeeper := transport.(adapter.IdleConnectionKeeper); isKeeper {
			keeper.SetKeepIdleConnections(t.keepIdle.Load())
		}
		members = append(members, providerDNSMember{transport: transport, name: name})
		names = append(names, name)
	}
	if len(servers) > 0 {
		if len(members) == 0 {
			t.logger.Error("no subscription DNS server is usable, nodes resolve through ", t.fallbackName())
		} else {
			t.logger.Info("resolve nodes through subscription DNS: [", strings.Join(names, ", "), "]")
		}
	}
	old := t.members.Swap(&members)
	t.applied = servers
	if old != nil {
		for _, member := range *old {
			// Exchanges still on the old member fail and fall back.
			_ = adapter.CloseRuntimeComponent(t.scope, member.transport)
		}
	}
}

// close drops the members; the provider removes the transport itself.
func (t *providerDNS) close() {
	t.access.Lock()
	defer t.access.Unlock()
	old := t.members.Swap(nil)
	t.applied = nil
	t.pending = nil
	if old != nil && t.scope != nil {
		for _, member := range *old {
			_ = adapter.CloseRuntimeComponent(t.scope, member.transport)
		}
	}
}

func (t *providerDNS) Reset() {
	for _, member := range t.loadMembers() {
		member.transport.Reset()
	}
}

func (t *providerDNS) SetKeepIdleConnections(keep bool) {
	t.keepIdle.Store(keep)
	for _, member := range t.loadMembers() {
		if keeper, isKeeper := member.transport.(adapter.IdleConnectionKeeper); isKeeper {
			keeper.SetKeepIdleConnections(keep)
		}
	}
}

func (t *providerDNS) CloseIdleConnections() {
	for _, member := range t.loadMembers() {
		if keeper, isKeeper := member.transport.(adapter.IdleConnectionKeeper); isKeeper {
			keeper.CloseIdleConnections()
		}
	}
}

func (t *providerDNS) loadMembers() []providerDNSMember {
	members := t.members.Load()
	if members == nil {
		return nil
	}
	return *members
}

func (t *providerDNS) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}

func (t *providerDNS) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	members := t.loadMembers()
	var (
		response *mDNS.Msg
		err      error
	)
	if len(members) > 0 {
		response, err = t.exchangeMembers(ctx, members, message)
		if err == nil {
			return response, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
	}
	fallback, fallbackErr := t.fallbackTransport()
	if fallbackErr != nil {
		if response != nil {
			return response, nil
		}
		if err != nil {
			return nil, E.Errors(err, fallbackErr)
		}
		return nil, fallbackErr
	}
	if err != nil {
		t.logger.DebugContext(ctx, "subscription DNS failed, fall back to ", fallback.Tag(), ": ", err)
	}
	fallbackResponse, fallbackExchangeErr := fallback.Exchange(ctx, message)
	if fallbackExchangeErr != nil {
		if response != nil {
			// a SERVFAIL / REFUSED answer is still better than nothing
			return response, nil
		}
		if err != nil {
			return nil, E.Errors(err, fallbackExchangeErr)
		}
		return nil, fallbackExchangeErr
	}
	return fallbackResponse, nil
}

// exchangeMembers races the members and returns the first conclusive answer
// (NOERROR or NXDOMAIN). With only inconclusive answers it returns one of
// them together with an error, so the caller can try the fallback first.
func (t *providerDNS) exchangeMembers(ctx context.Context, members []providerDNSMember, message *mDNS.Msg) (*mDNS.Msg, error) {
	if len(members) == 1 {
		response, err := members[0].transport.Exchange(ctx, message)
		if err != nil {
			return nil, E.Cause(err, members[0].name)
		}
		if !conclusiveResponse(response) {
			return response, E.New(members[0].name, ": ", mDNS.RcodeToString[response.Rcode])
		}
		return response, nil
	}
	type result struct {
		response *mDNS.Msg
		name     string
		err      error
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, len(members))
	for _, member := range members {
		go func(member providerDNSMember) {
			response, err := member.transport.Exchange(adapter.OverrideContext(ctx), message.Copy())
			results <- result{response, member.name, err}
		}(member)
	}
	var (
		inconclusive *mDNS.Msg
		errs         []error
	)
	for range members {
		var r result
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r = <-results:
		}
		if r.err != nil {
			errs = append(errs, E.Cause(r.err, r.name))
			continue
		}
		if conclusiveResponse(r.response) {
			t.logger.TraceContext(ctx, "fastest response from ", r.name)
			return r.response, nil
		}
		if inconclusive == nil {
			inconclusive = r.response
		}
		errs = append(errs, E.New(r.name, ": ", mDNS.RcodeToString[r.response.Rcode]))
	}
	return inconclusive, E.Errors(errs...)
}

func conclusiveResponse(response *mDNS.Msg) bool {
	return response != nil && (response.Rcode == mDNS.RcodeSuccess || response.Rcode == mDNS.RcodeNameError)
}

// fallbackTag selects the server resolving the subscription DNS server names
// and answering when the subscription DNS cannot.
func (t *providerDNS) fallbackTag() string {
	if t.resolver != "" {
		return t.resolver
	}
	if networkManager := service.FromContext[adapter.NetworkManager](t.ctx); networkManager != nil {
		if tag := networkManager.DefaultOptions().DomainResolver; tag != "" && tag != t.tag {
			return tag
		}
	}
	if defaultTransport := t.manager.Default(); defaultTransport != nil && defaultTransport.Tag() != t.tag {
		return defaultTransport.Tag()
	}
	return ""
}

func (t *providerDNS) fallbackName() string {
	tag := t.fallbackTag()
	if tag == "" {
		return "the default DNS server"
	}
	return tag
}

func (t *providerDNS) fallbackTransport() (adapter.DNSTransport, error) {
	tag := t.fallbackTag()
	if tag == "" {
		return nil, E.New("no fallback DNS server for ", t.tag)
	}
	transport, loaded := t.manager.Transport(tag)
	if !loaded {
		return nil, E.New("fallback DNS server not found: ", tag)
	}
	if transport.Type() == C.DNSTypeProvider {
		// another provider DNS falls back too, but never to this one
		if transport.Tag() == t.tag {
			return nil, E.New("provider DNS cannot fall back to itself: ", t.tag)
		}
	}
	return transport, nil
}

func (t *providerDNS) memberResolver() (string, option.DomainStrategy) {
	strategy := t.resolverStrategy
	tag := t.fallbackTag()
	if strategy == option.DomainStrategy(C.DomainStrategyAsIS) && t.resolver == "" {
		if networkManager := service.FromContext[adapter.NetworkManager](t.ctx); networkManager != nil {
			defaultOptions := networkManager.DefaultOptions()
			if defaultOptions.DomainResolver == tag {
				strategy = option.DomainStrategy(defaultOptions.DomainResolveOptions.Strategy)
			}
		}
	}
	return tag, strategy
}

// memberOptions copies the subscription server options for this box: they
// dial directly (a detour would name a subscription outbound, and resolving
// node addresses through a node loops), and server names resolve through
// the fallback resolver.
func memberOptions(server option.DNSServerOptions, resolver string, strategy option.DomainStrategy) (any, error) {
	rewrite := func(local *option.RawLocalDNSServerOptions, address option.DNSServerAddressOptions) error {
		local.Detour = ""
		local.DomainResolver = nil
		if address.ServerIsDomain() {
			if resolver == "" {
				return E.New("no DNS server to resolve ", address.Server)
			}
			local.DomainResolver = &option.DomainResolveOptions{Server: resolver, Strategy: strategy}
		}
		return nil
	}
	switch options := server.Options.(type) {
	case *option.RemoteDNSServerOptions:
		copied := *options
		return &copied, rewrite(&copied.RawLocalDNSServerOptions, copied.DNSServerAddressOptions)
	case *option.RemoteTLSDNSServerOptions:
		copied := *options
		return &copied, rewrite(&copied.RawLocalDNSServerOptions, copied.DNSServerAddressOptions)
	case *option.RemoteHTTPSDNSServerOptions:
		copied := *options
		return &copied, rewrite(&copied.RawLocalDNSServerOptions, copied.DNSServerAddressOptions)
	default:
		return nil, E.New("unsupported server type: ", server.Type)
	}
}

func describeDNSServer(server option.DNSServerOptions) string {
	var (
		address     option.DNSServerAddressOptions
		path        string
		defaultPort uint16
	)
	switch options := server.Options.(type) {
	case *option.RemoteDNSServerOptions:
		address = options.DNSServerAddressOptions
		defaultPort = 53
	case *option.RemoteTLSDNSServerOptions:
		address = options.DNSServerAddressOptions
		defaultPort = 853
	case *option.RemoteHTTPSDNSServerOptions:
		address = options.DNSServerAddressOptions
		defaultPort = 443
		path = options.Path
		if path == "" {
			path = "/dns-query"
		}
	default:
		return server.Type
	}
	host := address.Server
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
		host = "[" + host + "]"
	}
	if address.ServerPort != 0 && address.ServerPort != defaultPort {
		host += ":" + strconv.Itoa(int(address.ServerPort))
	}
	return server.Type + "://" + host + path
}
