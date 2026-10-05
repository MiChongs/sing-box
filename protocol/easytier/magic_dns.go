package easytier

import (
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	E "github.com/sagernet/sing/common/exceptions"

	corehost "github.com/easytier/easytier/easytier-go"
	mDNS "github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// Magic DNS follows the resolver of the EasyTier daemon
// (easytier/src/instance/dns_server): every node of a network is published
// as "<hostname>.<zone>" with the zone taken from the instance's
// tld_dns_zone, and the server is authoritative for each zone.
const (
	defaultDNSZone = "et.net."
	// magicDNSTTL matches the daemon's record TTL: names follow the peer
	// list, so neither positive nor negative answers are cached for long.
	magicDNSTTL = 1
)

// hostnameProfile maps internationalized names to punycode like the
// daemon's DNS name parser, and keeps underscores, which are common in
// machine names.
var hostnameProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(false))

// canonicalDNSName converts a hostname or zone to a lower-case ASCII FQDN.
// Names that cannot form a DNS name made of letters, digits, hyphens and
// underscores are rejected, as the daemon skips invalid record names.
func canonicalDNSName(name string) (string, bool) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return "", false
	}
	asciiName, err := hostnameProfile.ToASCII(name)
	if err != nil {
		return "", false
	}
	asciiName = strings.ToLower(asciiName)
	for label := range strings.SplitSeq(asciiName, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			char := label[i]
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
				return "", false
			}
		}
	}
	fqdn := asciiName + "."
	if len(fqdn) > 255 {
		return "", false
	}
	return fqdn, true
}

// parseDNSZone returns the canonical zone for a tld_dns_zone value; an empty
// value selects the daemon's default zone.
func parseDNSZone(zone string) (string, error) {
	if strings.TrimSpace(zone) == "" {
		return defaultDNSZone, nil
	}
	canonical, valid := canonicalDNSName(zone)
	if !valid {
		return "", E.New("invalid DNS zone: ", zone)
	}
	return canonical, nil
}

type magicDNSHost struct {
	name      string
	addresses []netip.Addr
}

func (h magicDNSHost) equal(other magicDNSHost) bool {
	return h.name == other.name && slices.Equal(h.addresses, other.addresses)
}

// magicDNSHosts builds the records an instance publishes in zone: this node,
// named by its own hostname and virtual addresses, and every peer route that
// carries a hostname. Hostnames shared by several nodes resolve to all of
// their addresses.
func magicDNSHosts(zone string, hostname string, localAddresses []netip.Prefix, routes []*corehost.Route) []magicDNSHost {
	hosts := make(map[string][]netip.Addr)
	addHost := func(hostname string, addresses ...netip.Addr) {
		if hostname == "" {
			return
		}
		name, valid := canonicalDNSName(hostname + "." + zone)
		if !valid {
			return
		}
		for _, address := range addresses {
			if address.IsValid() && !slices.Contains(hosts[name], address) {
				hosts[name] = append(hosts[name], address)
			}
		}
	}
	for _, localAddress := range localAddresses {
		addHost(hostname, localAddress.Addr())
	}
	for _, route := range routes {
		var addresses []netip.Addr
		if inet4Address := route.GetIpv4Addr().GetAddress(); inet4Address != nil {
			addresses = append(addresses, inet4AddrFrom(inet4Address))
		}
		if inet6Address := route.GetIpv6Addr().GetAddress(); inet6Address != nil {
			addresses = append(addresses, inet6AddrFrom(inet6Address))
		}
		addHost(route.GetHostname(), addresses...)
	}
	result := make([]magicDNSHost, 0, len(hosts))
	for name, addresses := range hosts {
		if len(addresses) == 0 {
			continue
		}
		slices.SortFunc(addresses, netip.Addr.Compare)
		result = append(result, magicDNSHost{name: name, addresses: addresses})
	}
	slices.SortFunc(result, func(a, b magicDNSHost) int {
		return strings.Compare(a.name, b.name)
	})
	return result
}

// magicDNSTable is the immutable view of the Magic DNS zones of all
// attached instances.
type magicDNSTable struct {
	// zones are sorted by descending length, so the first match is the most
	// specific zone.
	zones []string
	hosts map[string][]netip.Addr
	// nodes holds every owner name with its ancestors inside the zone, which
	// tells empty non-terminals (NODATA) from missing names (NXDOMAIN).
	nodes  map[string]bool
	serial uint32
}

func newMagicDNSTable(zones []string, hostLists ...[]magicDNSHost) *magicDNSTable {
	table := &magicDNSTable{
		hosts:  make(map[string][]netip.Addr),
		nodes:  make(map[string]bool),
		serial: uint32(time.Now().Unix()),
	}
	for _, zone := range zones {
		if !slices.Contains(table.zones, zone) {
			table.zones = append(table.zones, zone)
		}
	}
	slices.SortStableFunc(table.zones, func(a, b string) int {
		return len(b) - len(a)
	})
	for _, hosts := range hostLists {
		for _, host := range hosts {
			zone, inZone := table.zone(host.name)
			if !inZone {
				continue
			}
			for _, address := range host.addresses {
				if !slices.Contains(table.hosts[host.name], address) {
					table.hosts[host.name] = append(table.hosts[host.name], address)
				}
			}
			for name := host.name; name != zone; name = parentDNSName(name) {
				table.nodes[name] = true
			}
		}
	}
	for name := range table.hosts {
		slices.SortFunc(table.hosts[name], netip.Addr.Compare)
	}
	return table
}

func parentDNSName(name string) string {
	_, parent, _ := strings.Cut(name, ".")
	if parent == "" {
		return "."
	}
	return parent
}

// zone returns the most specific zone containing name, a canonical FQDN.
func (t *magicDNSTable) zone(name string) (string, bool) {
	for _, zone := range t.zones {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return zone, true
		}
	}
	return "", false
}

// exists reports whether name owns records or is an empty non-terminal.
func (t *magicDNSTable) exists(name string) bool {
	return t.nodes[name]
}

// expand resolves a single-label name against each zone, as the daemon's
// search domain does, and returns the first name that exists.
func (t *magicDNSTable) expand(name string) (string, bool) {
	if mDNS.CountLabel(name) != 1 {
		return "", false
	}
	for _, zone := range t.zones {
		expanded := name + zone
		if t.exists(expanded) {
			return expanded, true
		}
	}
	return "", false
}

// preferred reports whether domain belongs to Magic DNS: every name inside a
// zone does, as the zone is answered authoritatively, and with search domains
// a single-label name does when it exists in a zone.
func (t *magicDNSTable) preferred(domain string, acceptSearchDomain bool) bool {
	name := mDNS.CanonicalName(domain)
	if _, inZone := t.zone(name); inZone {
		return true
	}
	if acceptSearchDomain {
		_, expanded := t.expand(name)
		return expanded
	}
	return false
}

// lookup resolves domain for a connection. handled is false when domain is
// not a Magic DNS name and has to be resolved elsewhere.
func (t *magicDNSTable) lookup(domain string, acceptSearchDomain bool) (addresses []netip.Addr, handled bool, err error) {
	name := mDNS.CanonicalName(domain)
	if _, inZone := t.zone(name); !inZone {
		if !acceptSearchDomain {
			return nil, false, nil
		}
		expanded, loaded := t.expand(name)
		if !loaded {
			return nil, false, nil
		}
		name = expanded
	}
	addresses = t.hosts[name]
	if len(addresses) == 0 {
		return nil, true, E.New("EasyTier Magic DNS: no address for ", strings.TrimSuffix(name, "."))
	}
	return addresses, true, nil
}

// exchange answers a query for the Magic DNS zones. A name outside every zone
// is rejected with NXDOMAIN, as no default resolver is attached.
func (t *magicDNSTable) exchange(message *mDNS.Msg, acceptSearchDomain bool) (*mDNS.Msg, error) {
	if len(message.Question) != 1 {
		return nil, os.ErrInvalid
	}
	question := message.Question[0]
	name := mDNS.CanonicalName(question.Name)
	zone, inZone := t.zone(name)
	if !inZone {
		if !acceptSearchDomain {
			return nil, dns.RcodeNameError
		}
		expanded, loaded := t.expand(name)
		if !loaded {
			return nil, dns.RcodeNameError
		}
		response, err := t.exchange(expandedQuery(message, expanded), false)
		if err != nil {
			return nil, err
		}
		restoreQuestion(response, expanded, question)
		return response, nil
	}
	response := &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{
			Id:                 message.Id,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   message.RecursionDesired,
			RecursionAvailable: true,
			Rcode:              mDNS.RcodeSuccess,
		},
		Question: []mDNS.Question{question},
	}
	if question.Qclass != mDNS.ClassINET && question.Qclass != mDNS.ClassANY {
		response.Rcode = mDNS.RcodeRefused
		return response, nil
	}
	if name == zone {
		if question.Qtype == mDNS.TypeSOA || question.Qtype == mDNS.TypeANY {
			response.Answer = append(response.Answer, t.soa(zone))
		} else {
			response.Ns = append(response.Ns, t.soa(zone))
		}
		return response, nil
	}
	if !t.exists(name) {
		response.Rcode = mDNS.RcodeNameError
		response.Ns = append(response.Ns, t.soa(zone))
		return response, nil
	}
	for _, address := range t.hosts[name] {
		header := mDNS.RR_Header{Name: question.Name, Class: mDNS.ClassINET, Ttl: magicDNSTTL}
		switch {
		case address.Is4() && (question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeANY):
			header.Rrtype = mDNS.TypeA
			response.Answer = append(response.Answer, &mDNS.A{Hdr: header, A: address.AsSlice()})
		case address.Is6() && (question.Qtype == mDNS.TypeAAAA || question.Qtype == mDNS.TypeANY):
			header.Rrtype = mDNS.TypeAAAA
			response.Answer = append(response.Answer, &mDNS.AAAA{Hdr: header, AAAA: address.AsSlice()})
		}
	}
	if len(response.Answer) == 0 {
		response.Ns = append(response.Ns, t.soa(zone))
	}
	return response, nil
}

// soa returns the zone's SOA record in the daemon's format, with the record
// TTL lowered to magicDNSTTL so that negative answers expire with the names.
func (t *magicDNSTable) soa(zone string) *mDNS.SOA {
	return &mDNS.SOA{
		Hdr: mDNS.RR_Header{
			Name:   zone,
			Rrtype: mDNS.TypeSOA,
			Class:  mDNS.ClassINET,
			Ttl:    magicDNSTTL,
		},
		Ns:      "ns." + zone,
		Mbox:    "hostmaster." + zone,
		Serial:  t.serial,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  86400,
	}
}

func expandedQuery(message *mDNS.Msg, name string) *mDNS.Msg {
	query := *message
	question := message.Question[0]
	question.Name = name
	query.Question = []mDNS.Question{question}
	return &query
}

// restoreQuestion returns a search-domain answer under the name that was
// asked, since stub resolvers discard records whose owner differs from the
// question.
func restoreQuestion(response *mDNS.Msg, expandedName string, question mDNS.Question) {
	response.Question = []mDNS.Question{question}
	for _, record := range response.Answer {
		if strings.EqualFold(record.Header().Name, expandedName) {
			record.Header().Name = question.Name
		}
	}
}

// filterAddresses orders or filters Magic DNS addresses by a domain strategy.
func filterAddresses(addresses []netip.Addr, strategy C.DomainStrategy) []netip.Addr {
	var inet4Addresses, inet6Addresses []netip.Addr
	for _, address := range addresses {
		if address.Is4() {
			inet4Addresses = append(inet4Addresses, address)
		} else {
			inet6Addresses = append(inet6Addresses, address)
		}
	}
	switch strategy {
	case C.DomainStrategyIPv4Only:
		return inet4Addresses
	case C.DomainStrategyIPv6Only:
		return inet6Addresses
	case C.DomainStrategyPreferIPv6:
		return append(inet6Addresses, inet4Addresses...)
	default:
		return append(inet4Addresses, inet6Addresses...)
	}
}
