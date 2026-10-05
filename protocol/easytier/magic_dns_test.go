package easytier

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	corehost "github.com/easytier/easytier/easytier-go"
	etcommon "github.com/easytier/easytier/easytier-go/proto/common"
	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestCanonicalDNSName(t *testing.T) {
	t.Parallel()
	for input, expected := range map[string]string{
		"DESKTOP-ABC":   "desktop-abc.",
		"nas.":          "nas.",
		" my_pc ":       "my_pc.",
		"MacBook.local": "macbook.local.",
		"中文":            "xn--fiq228c.",
		"Ｎａｓ":           "nas.",
	} {
		name, valid := canonicalDNSName(input)
		require.True(t, valid, input)
		require.Equal(t, expected, name, input)
	}
	for _, input := range []string{"", ".", "my pc", "a..b", "host/1", strings.Repeat("a", 64), strings.Repeat("a.", 128)} {
		_, valid := canonicalDNSName(input)
		require.False(t, valid, input)
	}
}

func TestParseDNSZone(t *testing.T) {
	t.Parallel()
	zone, err := parseDNSZone("")
	require.NoError(t, err)
	require.Equal(t, "et.net.", zone)
	zone, err = parseDNSZone("Home.Lan.")
	require.NoError(t, err)
	require.Equal(t, "home.lan.", zone)
	_, err = parseDNSZone("bad zone")
	require.Error(t, err)
}

func testRoute(hostname string, inet4 uint32, inet6Part4 uint32) *corehost.Route {
	route := &corehost.Route{Hostname: hostname}
	if inet4 != 0 {
		route.Ipv4Addr = &etcommon.Ipv4Inet{Address: &etcommon.Ipv4Addr{Addr: inet4}, NetworkLength: 24}
	}
	if inet6Part4 != 0 {
		route.Ipv6Addr = &etcommon.Ipv6Inet{Address: &etcommon.Ipv6Addr{Part1: 0xfd000000, Part4: inet6Part4}, NetworkLength: 64}
	}
	return route
}

// The daemon publishes this node and every peer with a hostname; peers
// sharing a hostname resolve to all of their addresses.
func TestMagicDNSHosts(t *testing.T) {
	t.Parallel()
	hosts := magicDNSHosts("et.net.", "Phone", []netip.Prefix{netip.MustParsePrefix("10.144.144.1/24")}, []*corehost.Route{
		testRoute("NAS", 0x0a909002, 2),
		testRoute("", 0x0a909003, 0),
		testRoute("bad name", 0x0a909004, 0),
		testRoute("nas", 0x0a909005, 0),
		testRoute("no-address", 0, 0),
	})
	require.Equal(t, []magicDNSHost{
		{name: "nas.et.net.", addresses: []netip.Addr{
			netip.MustParseAddr("10.144.144.2"),
			netip.MustParseAddr("10.144.144.5"),
			netip.MustParseAddr("fd00::2"),
		}},
		{name: "phone.et.net.", addresses: []netip.Addr{netip.MustParseAddr("10.144.144.1")}},
	}, hosts)
}

func testDNSTable() *magicDNSTable {
	return newMagicDNSTable([]string{"et.net.", "lab.et.net.", "et.net."},
		[]magicDNSHost{
			{name: "nas.et.net.", addresses: []netip.Addr{netip.MustParseAddr("10.144.144.2"), netip.MustParseAddr("fd00::2")}},
			{name: "printer.office.et.net.", addresses: []netip.Addr{netip.MustParseAddr("10.144.144.3")}},
			{name: "outside.example.", addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
		},
		[]magicDNSHost{
			{name: "nas.lab.et.net.", addresses: []netip.Addr{netip.MustParseAddr("10.200.0.2")}},
			{name: "nas.et.net.", addresses: []netip.Addr{netip.MustParseAddr("10.144.144.9")}},
		},
	)
}

func testQuery(name string, qType uint16) *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion(name, qType)
	return message
}

func answerAddresses(t *testing.T, response *mDNS.Msg) []netip.Addr {
	t.Helper()
	var addresses []netip.Addr
	for _, record := range response.Answer {
		require.Equal(t, uint32(magicDNSTTL), record.Header().Ttl)
		switch answer := record.(type) {
		case *mDNS.A:
			addresses = append(addresses, netip.AddrFrom4([4]byte(answer.A.To4())))
		case *mDNS.AAAA:
			addresses = append(addresses, netip.AddrFrom16([16]byte(answer.AAAA)))
		}
	}
	return addresses
}

func requireAuthority(t *testing.T, response *mDNS.Msg, zone string) {
	t.Helper()
	require.Len(t, response.Ns, 1)
	soa, isSOA := response.Ns[0].(*mDNS.SOA)
	require.True(t, isSOA)
	require.Equal(t, zone, soa.Hdr.Name)
	require.Equal(t, "ns."+zone, soa.Ns)
	// Negative answers expire with the records instead of being cached.
	require.Equal(t, uint32(magicDNSTTL), soa.Hdr.Ttl)
}

func TestMagicDNSExchange(t *testing.T) {
	t.Parallel()
	table := testDNSTable()
	require.Equal(t, []string{"lab.et.net.", "et.net."}, table.zones)

	response, err := table.exchange(testQuery("NAS.ET.NET.", mDNS.TypeA), false)
	require.NoError(t, err)
	require.True(t, response.Authoritative)
	require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
	require.Equal(t, "NAS.ET.NET.", response.Answer[0].Header().Name)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.144.144.2"), netip.MustParseAddr("10.144.144.9")}, answerAddresses(t, response))

	response, err = table.exchange(testQuery("nas.et.net.", mDNS.TypeAAAA), false)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("fd00::2")}, answerAddresses(t, response))

	response, err = table.exchange(testQuery("nas.et.net.", mDNS.TypeANY), false)
	require.NoError(t, err)
	require.Len(t, response.Answer, 3)

	// The most specific zone owns a name.
	response, err = table.exchange(testQuery("nas.lab.et.net.", mDNS.TypeA), false)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.200.0.2")}, answerAddresses(t, response))

	for _, query := range []*mDNS.Msg{
		testQuery("nas.et.net.", mDNS.TypeMX),
		testQuery("nas.lab.et.net.", mDNS.TypeAAAA),
		testQuery("printer.office.et.net.", mDNS.TypeHTTPS),
		// An empty non-terminal exists without records.
		testQuery("office.et.net.", mDNS.TypeA),
		testQuery("et.net.", mDNS.TypeNS),
	} {
		response, err = table.exchange(query, false)
		require.NoError(t, err, query.Question[0].String())
		require.Equal(t, mDNS.RcodeSuccess, response.Rcode, query.Question[0].String())
		require.Empty(t, response.Answer, query.Question[0].String())
		zone, _ := table.zone(mDNS.CanonicalName(query.Question[0].Name))
		requireAuthority(t, response, zone)
	}

	response, err = table.exchange(testQuery("missing.et.net.", mDNS.TypeA), false)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeNameError, response.Rcode)
	requireAuthority(t, response, "et.net.")

	response, err = table.exchange(testQuery("et.net.", mDNS.TypeSOA), false)
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	require.Equal(t, mDNS.TypeSOA, response.Answer[0].Header().Rrtype)

	query := testQuery("nas.et.net.", mDNS.TypeA)
	query.Question[0].Qclass = mDNS.ClassCHAOS
	response, err = table.exchange(query, false)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeRefused, response.Rcode)

	// Names outside every zone are not answered.
	_, err = table.exchange(testQuery("outside.example.", mDNS.TypeA), false)
	require.ErrorIs(t, err, dns.RcodeNameError)
	_, err = table.exchange(testQuery("nas.", mDNS.TypeA), false)
	require.ErrorIs(t, err, dns.RcodeNameError)
}

func TestMagicDNSSearchDomain(t *testing.T) {
	t.Parallel()
	table := testDNSTable()
	response, err := table.exchange(testQuery("NAS.", mDNS.TypeA), true)
	require.NoError(t, err)
	// The most specific zone is searched first, and the answer keeps the
	// asked name.
	require.Equal(t, "NAS.", response.Question[0].Name)
	require.Equal(t, "NAS.", response.Answer[0].Header().Name)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.200.0.2")}, answerAddresses(t, response))

	response, err = table.exchange(testQuery("office.", mDNS.TypeA), true)
	require.NoError(t, err)
	require.Equal(t, "office.", response.Question[0].Name)
	require.Empty(t, response.Answer)

	_, err = table.exchange(testQuery("missing.", mDNS.TypeA), true)
	require.ErrorIs(t, err, dns.RcodeNameError)
	_, err = table.exchange(testQuery("nas.example.", mDNS.TypeA), true)
	require.ErrorIs(t, err, dns.RcodeNameError)

	require.True(t, table.preferred("nas", true))
	require.False(t, table.preferred("nas", false))
	require.False(t, table.preferred("missing", true))
	require.True(t, table.preferred("missing.et.net", false))
	require.True(t, table.preferred("ET.NET", false))
	require.False(t, table.preferred("example.com", true))
}

func TestMagicDNSLookup(t *testing.T) {
	t.Parallel()
	table := testDNSTable()
	addresses, handled, err := table.lookup("Nas.Et.Net", false)
	require.True(t, handled)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.144.144.2"), netip.MustParseAddr("10.144.144.9"), netip.MustParseAddr("fd00::2")}, addresses)
	_, handled, err = table.lookup("missing.et.net", false)
	require.True(t, handled)
	require.Error(t, err)
	_, handled, _ = table.lookup("example.com", true)
	require.False(t, handled)
	_, handled, _ = table.lookup("nas", false)
	require.False(t, handled)
	addresses, handled, err = table.lookup("nas", true)
	require.True(t, handled)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.200.0.2")}, addresses)

	mixed := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::1"), netip.MustParseAddr("10.0.0.2")}
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("fd00::1")}, filterAddresses(mixed, C.DomainStrategyAsIS))
	require.Equal(t, []netip.Addr{netip.MustParseAddr("fd00::1"), netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}, filterAddresses(mixed, C.DomainStrategyPreferIPv6))
	require.Equal(t, []netip.Addr{netip.MustParseAddr("fd00::1")}, filterAddresses(mixed, C.DomainStrategyIPv6Only))
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}, filterAddresses(mixed, C.DomainStrategyIPv4Only))
}

// The zone of the local network is claimed before its instance reports any
// record, and Web instances contribute their own zones.
func TestEndpointDNSTable(t *testing.T) {
	t.Parallel()
	ep := &Endpoint{localConfig: "configured", localDNSZone: "et.net."}
	table := ep.newDNSTable(nil)
	require.Equal(t, []string{"et.net."}, table.zones)
	require.True(t, table.preferred("pending.et.net", false))

	local := &attachedInstance{name: "local"}
	local.state.Store(&instanceState{dnsZone: "et.net.", dnsHosts: []magicDNSHost{{name: "phone.et.net.", addresses: []netip.Addr{netip.MustParseAddr("10.144.144.1")}}}})
	web := &attachedInstance{name: "web", web: true}
	web.state.Store(&instanceState{dnsZone: "office.lan.", dnsHosts: []magicDNSHost{{name: "pc.office.lan.", addresses: []netip.Addr{netip.MustParseAddr("10.10.0.2")}}}})
	ep.dnsTable.Store(ep.newDNSTable([]*attachedInstance{local, web}))
	require.Equal(t, []string{"office.lan.", "et.net."}, ep.dnsTable.Load().zones)

	// Magic DNS names are only claimed with an EasyTier DNS server attached.
	require.False(t, ep.PreferredDomain(nil, "pc.office.lan"))
	ep.dnsTransport.Store(&DNSTransport{endpoint: ep})
	require.True(t, ep.PreferredDomain(nil, "pc.office.lan"))
	require.True(t, ep.PreferredDomain(nil, "missing.et.net"))
	require.False(t, ep.PreferredDomain(nil, "pc"))
	require.False(t, ep.PreferredDomain(nil, "example.com"))

	ep.innerDNSQueryOptions.Strategy = C.DomainStrategyIPv6Only
	_, err := ep.lookupDomain(context.Background(), "pc.office.lan")
	require.Error(t, err)
	ep.innerDNSQueryOptions.Strategy = C.DomainStrategyAsIS
	addresses, err := ep.lookupDomain(context.Background(), "PC.office.lan.")
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.10.0.2")}, addresses)
	ep.dnsTransport.Store(&DNSTransport{endpoint: ep, acceptSearchDomain: true})
	require.True(t, ep.PreferredDomain(nil, "pc"))
	addresses, err = ep.lookupDomain(context.Background(), "phone")
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.144.144.1")}, addresses)
}

type testEndpointManager struct {
	adapter.EndpointManager
	endpoints map[string]adapter.Endpoint
}

func (m *testEndpointManager) Get(tag string) (adapter.Endpoint, bool) {
	endpoint, loaded := m.endpoints[tag]
	return endpoint, loaded
}

type testOtherEndpoint struct {
	adapter.Endpoint
}

func TestDNSTransportStart(t *testing.T) {
	t.Parallel()
	ep := &Endpoint{localConfig: "configured", localDNSZone: "et.net."}
	ep.dnsTable.Store(ep.newDNSTable(nil))
	ctx := service.ContextWith[adapter.EndpointManager](context.Background(), &testEndpointManager{endpoints: map[string]adapter.Endpoint{
		"et":    ep,
		"other": &testOtherEndpoint{},
	}})
	logger := log.NewNOPFactory().NewLogger("dns")
	newTransport := func(endpointTag string) adapter.DNSTransport {
		transport, err := NewDNSTransport(ctx, logger, "et-dns", option.EasyTierDNSServerOptions{Endpoint: endpointTag, AcceptSearchDomain: true})
		require.NoError(t, err)
		return transport
	}
	_, err := NewDNSTransport(ctx, logger, "et-dns", option.EasyTierDNSServerOptions{})
	require.Error(t, err)
	require.Error(t, newTransport("missing").Start(adapter.StartStateInitialize, adapter.NewScope(ctx, logger)))
	require.Error(t, newTransport("other").Start(adapter.StartStateInitialize, adapter.NewScope(ctx, logger)))

	scope := adapter.NewScope(ctx, logger)
	transport := newTransport("et").(*DNSTransport)
	require.NoError(t, transport.Start(adapter.StartStateInitialize, scope))
	require.Same(t, transport, ep.dnsTransport.Load())
	require.Error(t, newTransport("et").Start(adapter.StartStateInitialize, adapter.NewScope(ctx, logger)))
	require.Equal(t, C.DNSTypeEasyTier, transport.Type())
	require.Empty(t, transport.ServerAddresses())
	require.Equal(t, []string{"et.net"}, transport.SearchDomains())
	require.True(t, transport.PreferredDomain("phone.et.net."))
	_, err = transport.Exchange(context.Background(), testQuery("example.com.", mDNS.TypeA))
	require.ErrorIs(t, err, dns.RcodeNameError)
	response, err := transport.Exchange(context.Background(), testQuery("phone.et.net.", mDNS.TypeA))
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeNameError, response.Rcode)

	require.NoError(t, scope.Close())
	require.Nil(t, ep.dnsTransport.Load())
}

func TestBuildConfigDNSZone(t *testing.T) {
	t.Parallel()
	options := option.EasyTierEndpointOptions{NetworkName: "office", TLDDNSZone: "Home.LAN"}
	config, err := buildConfig(options, addressConfig{inet4: netip.MustParsePrefix("10.144.0.1/24")}, defaultMTU)
	require.NoError(t, err)
	require.Equal(t, "home.lan.", tomlString(config, "flags", "tld_dns_zone"))
	options.TLDDNSZone = ""
	config, err = buildConfig(options, addressConfig{inet4: netip.MustParsePrefix("10.144.0.1/24")}, defaultMTU)
	require.NoError(t, err)
	require.NotContains(t, config, "tld_dns_zone")
	options.TLDDNSZone = "bad zone"
	_, err = buildConfig(options, addressConfig{inet4: netip.MustParsePrefix("10.144.0.1/24")}, defaultMTU)
	require.Error(t, err)

	_, err = NewEndpoint(context.Background(), nil, log.NewNOPFactory().NewLogger("easytier"), "et", option.EasyTierEndpointOptions{
		Web:        &option.EasyTierWebOptions{Server: "udp://127.0.0.1:22020/user"},
		TLDDNSZone: "et.net",
	})
	require.ErrorContains(t, err, "require network_name")
}
