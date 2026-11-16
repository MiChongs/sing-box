package parser

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"gopkg.in/yaml.v3"
)

// ParseSubscriptionDNS extracts the DNS servers a subscription wants its own
// server addresses resolved with: Clash dns.proxy-server-nameserver (else
// dns.nameserver), or the sing-box server selected by
// route.default_domain_resolver (else dns.final, else the first server), a
// group expanding to its members. Only plain remote servers are kept
// (udp / tcp / tls / quic / https / h3); a broken DNS section never fails
// the node import.
func ParseSubscriptionDNS(ctx context.Context, content string) []option.DNSServerOptions {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return nil
	}
	var servers []option.DNSServerOptions
	if trimmed[0] == '{' {
		servers = parseBoxDNS(ctx, trimmed)
	} else {
		servers = parseClashDNS(ctx, trimmed)
	}
	return dedupDNSServers(servers)
}

func isSubscriptionDNSType(dnsType string) bool {
	switch dnsType {
	case C.DNSTypeUDP, C.DNSTypeTCP, C.DNSTypeTLS, C.DNSTypeQUIC, C.DNSTypeHTTPS, C.DNSTypeHTTP3:
		return true
	default:
		return false
	}
}

func dedupDNSServers(servers []option.DNSServerOptions) []option.DNSServerOptions {
	var result []option.DNSServerOptions
	for _, server := range servers {
		server.Tag = ""
		duplicate := false
		for _, existing := range result {
			if existing.Type == server.Type && reflect.DeepEqual(existing.Options, server.Options) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, server)
		}
	}
	return result
}

type boxDNSDocument struct {
	DNS *struct {
		Servers []json.RawMessage `json:"servers"`
		Final   string            `json:"final"`
	} `json:"dns"`
	Route *struct {
		DefaultDomainResolver json.RawMessage `json:"default_domain_resolver"`
	} `json:"route"`
}

func parseBoxDNS(ctx context.Context, content string) []option.DNSServerOptions {
	document, err := json.UnmarshalExtendedContext[boxDNSDocument](ctx, []byte(content))
	if err != nil || document.DNS == nil || len(document.DNS.Servers) == 0 {
		return nil
	}
	var (
		servers []option.DNSServerOptions
		byTag   = make(map[string]int)
	)
	for i, raw := range document.DNS.Servers {
		var server option.DNSServerOptions
		err = json.UnmarshalContext(ctx, raw, &server)
		if err != nil {
			warn(ctx, "skip subscription DNS server[", i, "]: ", err)
			continue
		}
		if server.Tag != "" {
			byTag[server.Tag] = len(servers)
		}
		servers = append(servers, server)
	}
	if len(servers) == 0 {
		return nil
	}
	target := -1
	if document.Route != nil && len(document.Route.DefaultDomainResolver) > 0 {
		var resolver option.DomainResolveOptions
		if json.Unmarshal(document.Route.DefaultDomainResolver, &resolver) == nil && resolver.Server != "" {
			if index, loaded := byTag[resolver.Server]; loaded {
				target = index
			}
		}
	}
	if target < 0 && document.DNS.Final != "" {
		if index, loaded := byTag[document.DNS.Final]; loaded {
			target = index
		}
	}
	if target < 0 {
		target = 0
	}
	selected := servers[target]
	if selected.Type == C.DNSTypeGroup {
		group, isGroup := selected.Options.(*option.GroupDNSServerOptions)
		if !isGroup {
			return nil
		}
		var members []option.DNSServerOptions
		for _, tag := range group.Servers {
			if index, loaded := byTag[tag]; loaded && isSubscriptionDNSType(servers[index].Type) {
				members = append(members, servers[index])
			}
		}
		return members
	}
	if isSubscriptionDNSType(selected.Type) {
		return []option.DNSServerOptions{selected}
	}
	return nil
}

// clashNameserverList accepts a single string or a list.
type clashNameserverList []string

func (l *clashNameserverList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		if value.Tag == "!!null" || strings.TrimSpace(value.Value) == "" {
			*l = nil
		} else {
			*l = []string{value.Value}
		}
		return nil
	}
	var list []string
	err := value.Decode(&list)
	if err != nil {
		return err
	}
	*l = list
	return nil
}

type clashDNSDocument struct {
	DNS struct {
		Enable                *bool               `yaml:"enable"`
		ProxyServerNameserver clashNameserverList `yaml:"proxy-server-nameserver"`
		Nameserver            clashNameserverList `yaml:"nameserver"`
	} `yaml:"dns"`
}

func parseClashDNS(ctx context.Context, content string) []option.DNSServerOptions {
	var document clashDNSDocument
	if yaml.Unmarshal([]byte(content), &document) != nil {
		return nil
	}
	if document.DNS.Enable != nil && !*document.DNS.Enable {
		return nil
	}
	nameservers := document.DNS.ProxyServerNameserver
	if len(nameservers) == 0 {
		nameservers = document.DNS.Nameserver
	}
	var servers []option.DNSServerOptions
	for _, nameserver := range nameservers {
		server, ok := ParseClashNameserver(nameserver)
		if !ok {
			if strings.TrimSpace(nameserver) != "" {
				warn(ctx, "skip subscription DNS server ", nameserver)
			}
			continue
		}
		servers = append(servers, server)
	}
	return servers
}

// ParseClashNameserver converts one mihomo nameserver entry:
//
//	8.8.8.8  8.8.8.8:53  [2001:4860:4860::8888]:53
//	udp://  tcp://  tls:// (dot)  quic:// (doq)  https:// (doh)  h3:// http3://
//
// followed by an optional `#` fragment of `&` separated params: `h3=true`
// upgrades https to HTTP/3, `skip-cert-verify=true` disables certificate
// verification. A bare word in the fragment names a mihomo proxy or interface
// to dial through; subscription DNS always dials directly, so it is ignored.
// system / dhcp / rcode servers have no counterpart and are rejected.
func ParseClashNameserver(raw string) (option.DNSServerOptions, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return option.DNSServerOptions{}, false
	}
	var fragment string
	if index := strings.IndexByte(raw, '#'); index >= 0 {
		fragment = raw[index+1:]
		raw = raw[:index]
	}
	var (
		h3       bool
		insecure bool
	)
	for _, param := range strings.Split(fragment, "&") {
		key, value, hasValue := strings.Cut(strings.TrimSpace(param), "=")
		if !hasValue {
			continue
		}
		enabled, _ := strconv.ParseBool(strings.TrimSpace(value))
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "h3":
			h3 = enabled
		case "skip-cert-verify":
			insecure = enabled
		}
	}
	scheme := "udp"
	if index := strings.Index(raw, "://"); index >= 0 {
		scheme = strings.ToLower(raw[:index])
	} else {
		switch strings.ToLower(raw) {
		case "system", "dhcp":
			return option.DNSServerOptions{}, false
		}
		if address, err := netip.ParseAddr(raw); err == nil && address.Is6() {
			// mihomo accepts a bare IPv6 address; url.Parse would take its
			// last group for a port
			raw = "[" + raw + "]"
		}
		raw = "udp://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return option.DNSServerOptions{}, false
	}
	host := parsed.Hostname()
	if host == "" {
		return option.DNSServerOptions{}, false
	}
	var port uint16
	if portString := parsed.Port(); portString != "" {
		portValue, err := strconv.ParseUint(portString, 10, 16)
		if err != nil || portValue == 0 {
			return option.DNSServerOptions{}, false
		}
		port = uint16(portValue)
	}
	address := option.DNSServerAddressOptions{Server: host, ServerPort: port}
	tls := func(defaultPort uint16) option.RemoteTLSDNSServerOptions {
		if address.ServerPort == 0 {
			address.ServerPort = defaultPort
		}
		options := option.RemoteTLSDNSServerOptions{
			RemoteDNSServerOptions: option.RemoteDNSServerOptions{DNSServerAddressOptions: address},
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: insecure},
			},
		}
		if net.ParseIP(host) == nil {
			options.TLS.ServerName = host
		}
		return options
	}
	switch scheme {
	case "udp", "tcp":
		if address.ServerPort == 0 {
			address.ServerPort = 53
		}
		dnsType := C.DNSTypeUDP
		if scheme == "tcp" {
			dnsType = C.DNSTypeTCP
		}
		return option.DNSServerOptions{
			Type:    dnsType,
			Options: &option.RemoteDNSServerOptions{DNSServerAddressOptions: address},
		}, true
	case "tls", "dot":
		options := tls(853)
		return option.DNSServerOptions{Type: C.DNSTypeTLS, Options: &options}, true
	case "quic", "doq":
		options := tls(853)
		return option.DNSServerOptions{Type: C.DNSTypeQUIC, Options: &options}, true
	case "https", "doh", "h3", "http3":
		dnsType := C.DNSTypeHTTPS
		if h3 || scheme == "h3" || scheme == "http3" {
			dnsType = C.DNSTypeHTTP3
		}
		path := parsed.EscapedPath()
		if path == "" || path == "/" {
			path = "/dns-query"
		}
		return option.DNSServerOptions{
			Type: dnsType,
			Options: &option.RemoteHTTPSDNSServerOptions{
				RemoteTLSDNSServerOptions: tls(443),
				Path:                      path,
				Method:                    "POST",
			},
		}, true
	default:
		return option.DNSServerOptions{}, false
	}
}
