package easytier

import (
	"context"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

var (
	_ adapter.DNSTransportWithPreferredDomain = (*DNSTransport)(nil)
	_ adapter.DNSTransportWithConfiguration   = (*DNSTransport)(nil)
)

func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.EasyTierDNSServerOptions](registry, C.DNSTypeEasyTier, NewDNSTransport)
}

// DNSTransport serves the Magic DNS names of an EasyTier endpoint: every
// node of its networks as "<hostname>.<zone>".
type DNSTransport struct {
	dns.TransportAdapter
	endpointTag        string
	acceptSearchDomain bool
	endpointManager    adapter.EndpointManager
	endpoint           *Endpoint
}

func NewDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.EasyTierDNSServerOptions) (adapter.DNSTransport, error) {
	if options.Endpoint == "" {
		return nil, E.New("missing EasyTier endpoint tag")
	}
	return &DNSTransport{
		TransportAdapter:   dns.NewTransportAdapter(C.DNSTypeEasyTier, tag, nil),
		endpointTag:        options.Endpoint,
		acceptSearchDomain: options.AcceptSearchDomain,
		endpointManager:    service.FromContext[adapter.EndpointManager](ctx),
	}, nil
}

func (t *DNSTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	rawEndpoint, loaded := t.endpointManager.Get(t.endpointTag)
	if !loaded {
		return E.New("endpoint not found: ", t.endpointTag)
	}
	ep, isEasyTier := rawEndpoint.(*Endpoint)
	if !isEasyTier {
		return E.New("endpoint is not EasyTier: ", t.endpointTag)
	}
	if !ep.dnsTransport.CompareAndSwap(nil, t) {
		return E.New("only one EasyTier DNS server is allowed for single endpoint")
	}
	t.endpoint = ep
	scope.Add(func() error {
		ep.dnsTransport.CompareAndSwap(t, nil)
		return nil
	})
	return nil
}

func (t *DNSTransport) Reset() {
}

func (t *DNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	return t.endpoint.dnsTable.Load().exchange(message, t.acceptSearchDomain)
}

func (t *DNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	callback(t.Exchange(ctx, message))
}

func (t *DNSTransport) PreferredDomain(domain string) bool {
	return t.endpoint.dnsTable.Load().preferred(domain, t.acceptSearchDomain)
}

// ServerAddresses reports no upstream servers: Magic DNS answers from the
// endpoint's records only.
func (t *DNSTransport) ServerAddresses() []netip.Addr {
	return nil
}

// SearchDomains reports the Magic DNS zones, which the daemon installs as
// search domains.
func (t *DNSTransport) SearchDomains() []string {
	zones := t.endpoint.dnsTable.Load().zones
	searchDomains := make([]string, 0, len(zones))
	for _, zone := range zones {
		searchDomains = append(searchDomains, strings.TrimSuffix(zone, "."))
	}
	return searchDomains
}
