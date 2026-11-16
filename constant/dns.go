package constant

const (
	DefaultDNSTTL = 600
)

type DomainStrategy = uint8

const (
	DomainStrategyAsIS DomainStrategy = iota
	DomainStrategyPreferIPv4
	DomainStrategyPreferIPv6
	DomainStrategyIPv4Only
	DomainStrategyIPv6Only
)

const (
	DNSTypeLegacy      = "legacy"
	DNSTypeUDP         = "udp"
	DNSTypeTCP         = "tcp"
	DNSTypeTLS         = "tls"
	DNSTypeHTTPS       = "https"
	DNSTypeQUIC        = "quic"
	DNSTypeHTTP3       = "h3"
	DNSTypeLocal       = "local"
	DNSTypeHosts       = "hosts"
	DNSTypeFakeIP      = "fakeip"
	DNSTypeDHCP        = "dhcp"
	DNSTypeMDNS        = "mdns"
	DNSTypeTailscale   = "tailscale"
	DNSTypeEasyTier    = "easytier"
	DNSTypeOpenConnect = "openconnect"
	DNSTypeOpenVPN     = "openvpn"
	DNSTypeGroup       = "group"
	// DNSTypeProvider answers for the nodes of an outbound provider through the
	// DNS servers of its subscription; it is not configurable.
	DNSTypeProvider = "provider"
)

const (
	DNSProviderAliDNS     = "alidns"
	DNSProviderCloudflare = "cloudflare"
	DNSProviderACMEDNS    = "acmedns"
)
