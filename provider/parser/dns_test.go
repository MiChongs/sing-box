package parser

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func dnsTestContext() context.Context {
	registry := dns.NewTransportRegistry()
	transport.RegisterUDP(registry)
	transport.RegisterTCP(registry)
	transport.RegisterTLS(registry)
	transport.RegisterHTTPS(registry)
	transport.RegisterGroup(registry)
	return service.ContextWith[option.DNSTransportOptionsRegistry](context.Background(), registry)
}

func TestParseClashNameserver(t *testing.T) {
	t.Parallel()
	type expect struct {
		dnsType  string
		server   string
		port     uint16
		path     string
		insecure bool
	}
	for _, testCase := range []struct {
		raw    string
		ok     bool
		expect expect
	}{
		{raw: "223.5.5.5", ok: true, expect: expect{dnsType: C.DNSTypeUDP, server: "223.5.5.5", port: 53}},
		{raw: "223.5.5.5:5353", ok: true, expect: expect{dnsType: C.DNSTypeUDP, server: "223.5.5.5", port: 5353}},
		{raw: "2400:3200::1", ok: true, expect: expect{dnsType: C.DNSTypeUDP, server: "2400:3200::1", port: 53}},
		{raw: "2001:4860:4860::8888", ok: true, expect: expect{dnsType: C.DNSTypeUDP, server: "2001:4860:4860::8888", port: 53}},
		{raw: "[2400:3200::1]:53", ok: true, expect: expect{dnsType: C.DNSTypeUDP, server: "2400:3200::1", port: 53}},
		{raw: "udp://8.8.8.8", ok: true, expect: expect{dnsType: C.DNSTypeUDP, server: "8.8.8.8", port: 53}},
		{raw: "tcp://8.8.8.8:5353", ok: true, expect: expect{dnsType: C.DNSTypeTCP, server: "8.8.8.8", port: 5353}},
		{raw: "tls://dns.alidns.com", ok: true, expect: expect{dnsType: C.DNSTypeTLS, server: "dns.alidns.com", port: 853}},
		{raw: "quic://dns.adguard.com:784", ok: true, expect: expect{dnsType: C.DNSTypeQUIC, server: "dns.adguard.com", port: 784}},
		{raw: "https://doh.pub/dns-query", ok: true, expect: expect{dnsType: C.DNSTypeHTTPS, server: "doh.pub", port: 443, path: "/dns-query"}},
		{raw: "https://1.12.12.12", ok: true, expect: expect{dnsType: C.DNSTypeHTTPS, server: "1.12.12.12", port: 443, path: "/dns-query"}},
		{raw: "https://dns.google/resolve#h3=true", ok: true, expect: expect{dnsType: C.DNSTypeHTTP3, server: "dns.google", port: 443, path: "/resolve"}},
		{raw: "https://1.1.1.1/dns-query#PROXY&skip-cert-verify=true", ok: true, expect: expect{dnsType: C.DNSTypeHTTPS, server: "1.1.1.1", port: 443, path: "/dns-query", insecure: true}},
		{raw: "h3://dns.alidns.com:8443/dns-query", ok: true, expect: expect{dnsType: C.DNSTypeHTTP3, server: "dns.alidns.com", port: 8443, path: "/dns-query"}},
		{raw: "system"},
		{raw: "system://"},
		{raw: "dhcp://en0"},
		{raw: "rcode://success"},
		{raw: "tls://1.1.1.1:0"},
		{raw: "  "},
	} {
		server, ok := ParseClashNameserver(testCase.raw)
		require.Equal(t, testCase.ok, ok, testCase.raw)
		if !ok {
			continue
		}
		require.Equal(t, testCase.expect.dnsType, server.Type, testCase.raw)
		var address option.DNSServerAddressOptions
		switch options := server.Options.(type) {
		case *option.RemoteDNSServerOptions:
			address = options.DNSServerAddressOptions
		case *option.RemoteTLSDNSServerOptions:
			address = options.DNSServerAddressOptions
			require.True(t, options.TLS.Enabled)
			require.Equal(t, testCase.expect.insecure, options.TLS.Insecure, testCase.raw)
		case *option.RemoteHTTPSDNSServerOptions:
			address = options.DNSServerAddressOptions
			require.Equal(t, testCase.expect.path, options.Path, testCase.raw)
			require.True(t, options.TLS.Enabled)
			require.Equal(t, testCase.expect.insecure, options.TLS.Insecure, testCase.raw)
		default:
			t.Fatalf("%s: unexpected options %T", testCase.raw, server.Options)
		}
		require.Equal(t, testCase.expect.server, address.Server, testCase.raw)
		require.Equal(t, testCase.expect.port, address.ServerPort, testCase.raw)
	}
}

func TestParseSubscriptionDNSClash(t *testing.T) {
	t.Parallel()
	ctx := dnsTestContext()
	servers := ParseSubscriptionDNS(ctx, `
dns:
  enable: true
  nameserver: [223.5.5.5]
  proxy-server-nameserver:
    - https://doh.pub/dns-query
    - https://doh.pub/dns-query
    - system
    - tls://1.1.1.1
proxies: []
`, true)
	require.Len(t, servers, 2, "duplicates and system are dropped")
	require.Equal(t, C.DNSTypeHTTPS, servers[0].Type)
	require.Equal(t, C.DNSTypeTLS, servers[1].Type)

	servers = ParseSubscriptionDNS(ctx, `
dns:
  nameserver: 119.29.29.29
`, true)
	require.Len(t, servers, 1, "nameserver as a scalar, used without proxy-server-nameserver")

	require.Empty(t, ParseSubscriptionDNS(ctx, `
dns:
  enable: false
  proxy-server-nameserver: [223.5.5.5]
`, true))
	require.Empty(t, ParseSubscriptionDNS(ctx, "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#node", true))
}

func TestParseSubscriptionDNSSingBox(t *testing.T) {
	t.Parallel()
	ctx := dnsTestContext()
	servers := ParseSubscriptionDNS(ctx, `{
		"dns": {
			"servers": [
				{"type": "local", "tag": "local"},
				{"type": "https", "tag": "doh", "server": "doh.pub", "detour": "proxy"},
				{"type": "udp", "tag": "udp", "server": "223.5.5.5"},
				{"type": "nonexistent", "tag": "broken"},
				{"type": "group", "tag": "bootstrap", "servers": ["doh", "local", "udp"]}
			],
			"final": "local"
		},
		"route": {"default_domain_resolver": {"server": "bootstrap", "strategy": "ipv4_only"}},
		"outbounds": [{"type": "socks", "tag": "a", "server": "1.2.3.4", "server_port": 1080}]
	}`, true)
	require.Len(t, servers, 2, "group members except local, broken server skipped")
	require.Equal(t, C.DNSTypeHTTPS, servers[0].Type)
	require.Equal(t, C.DNSTypeUDP, servers[1].Type)

	servers = ParseSubscriptionDNS(ctx, `{
		"dns": {"servers": [{"type": "udp", "tag": "a", "server": "1.1.1.1"}, {"type": "tls", "tag": "b", "server": "8.8.8.8"}], "final": "b"},
		"route": {"default_domain_resolver": "missing"}
	}`, true)
	require.Len(t, servers, 1, "unknown default_domain_resolver falls through to final")
	require.Equal(t, C.DNSTypeTLS, servers[0].Type)

	servers = ParseSubscriptionDNS(ctx, `{"dns": {"servers": [{"type": "local"}]}}`, true)
	require.Empty(t, servers, "local resolver has no subscription counterpart")
}

// The remote provider cache stores the servers as a group selected by
// dns.final; reading it back must return the same list.
func TestParseSubscriptionDNSCacheRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := dnsTestContext()
	original := ParseSubscriptionDNS(ctx, `
dns:
  proxy-server-nameserver: [https://doh.pub/dns-query, "tls://1.1.1.1#skip-cert-verify=true", 223.5.5.5, "tcp://[2400:3200::1]"]
`, true)
	require.Len(t, original, 4)
	var servers []option.DNSServerOptions
	var tags []string
	for i, server := range original {
		server.Tag = string(rune('a' + i))
		tags = append(tags, server.Tag)
		servers = append(servers, server)
	}
	servers = append(servers, option.DNSServerOptions{Type: C.DNSTypeGroup, Tag: "provider", Options: &option.GroupDNSServerOptions{Servers: tags}})
	content, err := json.Marshal(option.Options{
		DNS:   &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{Servers: servers, Final: "provider"}},
		Route: &option.RouteOptions{DefaultDomainResolver: &option.DomainResolveOptions{Server: "provider"}},
	})
	require.NoError(t, err)
	require.Equal(t, original, ParseSubscriptionDNS(ctx, string(content), true))
	require.Equal(t, original, ParseSubscriptionDNS(ctx, string(content), false), "the cache names the list as the nodes' resolver")
}

// Without use_nameserver only the DNS a subscription names for its nodes is
// taken; its general DNS is left to the client.
func TestParseSubscriptionDNSWithoutNameserver(t *testing.T) {
	t.Parallel()
	ctx := dnsTestContext()
	require.Empty(t, ParseSubscriptionDNS(ctx, `
dns:
  nameserver: [223.5.5.5, https://doh.pub/dns-query]
`, false))
	servers := ParseSubscriptionDNS(ctx, `
dns:
  nameserver: [223.5.5.5]
  proxy-server-nameserver: [tls://1.1.1.1]
`, false)
	require.Len(t, servers, 1)
	require.Equal(t, C.DNSTypeTLS, servers[0].Type)

	require.Empty(t, ParseSubscriptionDNS(ctx, `{
		"dns": {"servers": [{"type": "udp", "tag": "a", "server": "1.1.1.1"}, {"type": "tls", "tag": "b", "server": "8.8.8.8"}], "final": "b"}
	}`, false), "dns.final and the first server are general DNS")
	require.Empty(t, ParseSubscriptionDNS(ctx, `{
		"dns": {"servers": [{"type": "udp", "tag": "a", "server": "1.1.1.1"}], "final": "a"},
		"route": {"default_domain_resolver": "missing"}
	}`, false))
	servers = ParseSubscriptionDNS(ctx, `{
		"dns": {"servers": [{"type": "udp", "tag": "a", "server": "1.1.1.1"}, {"type": "tls", "tag": "b", "server": "8.8.8.8"}], "final": "a"},
		"route": {"default_domain_resolver": {"server": "b"}}
	}`, false)
	require.Len(t, servers, 1)
	require.Equal(t, C.DNSTypeTLS, servers[0].Type)
}
