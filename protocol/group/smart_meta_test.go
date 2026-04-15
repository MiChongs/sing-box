package group

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// TestPickHostFromMetadata locks the host-source priority ladder so a
// future refactor can't silently downgrade us back to the
// "Destination.Fqdn-or-SniffHost only" behaviour that left
// recordStats with no key for huge classes of connections (TUN
// inbound + DNS-cached domains, route-action redirects, etc).
func TestPickHostFromMetadata(t *testing.T) {
	cases := []struct {
		name string
		in   adapter.InboundContext
		want string
	}{
		{"destination_fqdn_wins", adapter.InboundContext{
			Destination: M.Socksaddr{Fqdn: "a.example"},
			SniffHost:   "b.example",
			Domain:      "c.example",
		}, "a.example"},
		{"sniff_host_when_dst_blank", adapter.InboundContext{
			SniffHost: "sniff.example",
			Domain:    "domain.example",
		}, "sniff.example"},
		{"domain_when_no_sniff", adapter.InboundContext{
			Domain: "domain.example",
		}, "domain.example"},
		{"origin_destination_fallback", adapter.InboundContext{
			OriginDestination: M.Socksaddr{Fqdn: "origin.example"},
		}, "origin.example"},
		{"route_original_fallback", adapter.InboundContext{
			RouteOriginalDestination: M.Socksaddr{Fqdn: "rorig.example"},
		}, "rorig.example"},
		{"all_blank", adapter.InboundContext{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pickHostFromMetadata(c.in); got != c.want {
				t.Fatalf("pickHostFromMetadata = %q, want %q", got, c.want)
			}
		})
	}
}

// TestPickIPsFromMetadata covers the IP source aggregation: every
// candidate field contributes, duplicates collapse, ordering is
// stable so downstream lookups pick a deterministic primary IP.
func TestPickIPsFromMetadata(t *testing.T) {
	a := netip.MustParseAddr("1.1.1.1")
	b := netip.MustParseAddr("2.2.2.2")
	c := netip.MustParseAddr("3.3.3.3")
	d := netip.MustParseAddr("4.4.4.4")

	in := adapter.InboundContext{
		DestinationAddresses:     []netip.Addr{a, b},
		Destination:              M.Socksaddr{Addr: a}, // dup of DestinationAddresses[0]
		CacheIPs:                 []netip.Addr{c},
		OriginDestination:        M.Socksaddr{Addr: d},
		RouteOriginalDestination: M.Socksaddr{Addr: a}, // dup
	}
	got := pickIPsFromMetadata(in)
	want := []netip.Addr{a, b, c, d} // a (deduped from sources after the first)
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("idx %d: got %v want %v (full=%v)", i, got[i], want[i], got)
		}
	}
}

// TestPickIPsFromMetadata_AllEmpty: no IP sources → empty slice
// (caller must handle, can't fabricate one).
func TestPickIPsFromMetadata_AllEmpty(t *testing.T) {
	got := pickIPsFromMetadata(adapter.InboundContext{})
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %v", got)
	}
}

// TestNormaliseDialTarget covers the three-tier resolution:
// IP-literal-host short-circuit, normal wildcard normalisation, and
// the no-info fallback ladder ending at "_unbound_".
func TestNormaliseDialTarget(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		firstIP string
		want    string
	}{
		// publicsuffix: www.example.com → eTLD+1 example.com, sub=www,
		// single-label sub keeps "www" as-is → "www.example.com".
		// The exact value isn't important for this test — what matters
		// is that normalisation produces a non-empty deterministic key.
		{"plain_domain", "www.example.com", "1.2.3.4", "www.example.com"},
		{"ip_literal_host_v4", "1.2.3.4", "", "1.2.3.4"},
		{"ip_literal_host_v6", "2001:db8::1", "", "2001:db8::1"},
		{"only_ip_no_host", "", "5.5.5.5", "5.5.5.5"},
		// "example" is not a real TLD, publicsuffix falls back to the
		// last-2-labels heuristic → reg="raw.example", h==reg → "*.reg".
		{"only_host_no_ip", "raw.example", "", "*.raw.example"},
		{"all_blank_unbound", "", "", "_unbound_"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normaliseDialTarget(c.host, c.firstIP)
			if got != c.want {
				t.Fatalf("normaliseDialTarget(%q,%q) = %q, want %q",
					c.host, c.firstIP, got, c.want)
			}
		})
	}
}
