package easytier

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

const (
	defaultMTU        = 1380
	maxHostnameLength = 32
)

type addressConfig struct {
	inet4 netip.Prefix
	inet6 netip.Prefix
}

func parseAddress(prefixes []netip.Prefix) (addressConfig, error) {
	var config addressConfig
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			if config.inet4.IsValid() {
				return addressConfig{}, E.New("only one IPv4 address is supported")
			}
			if prefix.Bits() == 32 {
				return addressConfig{}, E.New("IPv4 address must include a network prefix shorter than /32")
			}
			config.inet4 = prefix
		} else {
			if config.inet6.IsValid() {
				return addressConfig{}, E.New("only one IPv6 address is supported")
			}
			config.inet6 = prefix
		}
	}
	return config, nil
}

func (c addressConfig) prefixes() []netip.Prefix {
	var prefixes []netip.Prefix
	if c.inet4.IsValid() {
		prefixes = append(prefixes, c.inet4)
	}
	if c.inet6.IsValid() {
		prefixes = append(prefixes, c.inet6)
	}
	return prefixes
}

// proxyMapping translates destinations in a mapped proxy network, as
// advertised to peers, to the real network behind this node.
type proxyMapping struct {
	realPrefix   netip.Prefix
	mappedPrefix netip.Prefix
}

func (m proxyMapping) translate(address netip.Addr) (netip.Addr, bool) {
	if !m.mappedPrefix.Contains(address) {
		return netip.Addr{}, false
	}
	return replacePrefix(address, m.mappedPrefix.Bits(), m.realPrefix.Addr()), true
}

// replacePrefix keeps the host bits of address and takes the first bits from
// prefix.
func replacePrefix(address netip.Addr, bits int, prefix netip.Addr) netip.Addr {
	addressBytes := address.AsSlice()
	prefixBytes := prefix.AsSlice()
	for i := range addressBytes {
		remaining := bits - i*8
		switch {
		case remaining >= 8:
			addressBytes[i] = prefixBytes[i]
		case remaining > 0:
			mask := byte(0xff) << (8 - remaining)
			addressBytes[i] = prefixBytes[i]&mask | addressBytes[i]&^mask
		}
	}
	result, _ := netip.AddrFromSlice(addressBytes)
	return result
}

func parseProxyNetworks(options []option.EasyTierProxyNetworkOptions) ([]proxyMapping, error) {
	var mappings []proxyMapping
	seen := make(map[netip.Prefix]bool)
	for _, proxyNetwork := range options {
		cidr := proxyNetwork.CIDR
		if !cidr.IsValid() || !cidr.Addr().Is4() {
			return nil, E.New("proxy network ", cidr, ": only IPv4 networks can be proxied")
		}
		cidr = cidr.Masked()
		advertised := cidr
		if proxyNetwork.MappedCIDR != nil {
			mapped := proxyNetwork.MappedCIDR.Build(netip.Prefix{})
			if !mapped.Addr().Is4() || mapped.Bits() != cidr.Bits() {
				return nil, E.New("proxy network ", cidr, ": mapped_cidr must be an IPv4 network of the same size")
			}
			mapped = mapped.Masked()
			mappings = append(mappings, proxyMapping{realPrefix: cidr, mappedPrefix: mapped})
			advertised = mapped
		}
		if seen[advertised] {
			return nil, E.New("proxy network ", advertised, " is advertised twice")
		}
		seen[advertised] = true
	}
	return mappings, nil
}

// parseCoreCIDR parses a network as the core prints it, which omits the
// prefix length of a single-address network.
func parseCoreCIDR(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "/") {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(address, address.BitLen()), nil
	}
	return netip.ParsePrefix(value)
}

// parseNodeProxyCIDRs reads the proxy networks a node reports about itself,
// where a mapped network is written as "real->mapped".
func parseNodeProxyCIDRs(proxyCIDRs []string) []proxyMapping {
	var mappings []proxyMapping
	for _, proxyCIDR := range proxyCIDRs {
		realCIDR, mappedCIDR, isMapped := strings.Cut(proxyCIDR, "->")
		if !isMapped {
			continue
		}
		realPrefix, err := parseCoreCIDR(realCIDR)
		if err != nil {
			continue
		}
		mappedPrefix, err := parseCoreCIDR(mappedCIDR)
		if err != nil || mappedPrefix.Bits() != realPrefix.Bits() || mappedPrefix.Addr().Is4() != realPrefix.Addr().Is4() {
			continue
		}
		mappings = append(mappings, proxyMapping{realPrefix: realPrefix.Masked(), mappedPrefix: mappedPrefix.Masked()})
	}
	return mappings
}

type portForward struct {
	network     string
	listen      netip.AddrPort
	destination netip.AddrPort
}

func parsePortForwards(options []option.EasyTierPortForwardOptions) ([]portForward, error) {
	var forwards []portForward
	seen := make(map[string]bool)
	for _, forwardOptions := range options {
		if !forwardOptions.Listen.IsValid() || forwardOptions.Listen.Port() == 0 {
			return nil, E.New("port forward: invalid listen address ", forwardOptions.Listen)
		}
		if !forwardOptions.Destination.IsValid() || forwardOptions.Destination.Port() == 0 || forwardOptions.Destination.Addr().IsUnspecified() {
			return nil, E.New("port forward: invalid destination ", forwardOptions.Destination)
		}
		for _, network := range forwardOptions.Network.Build() {
			key := network + "/" + forwardOptions.Listen.String()
			if seen[key] {
				return nil, E.New("port forward: ", network, " listen address ", forwardOptions.Listen, " is used twice")
			}
			seen[key] = true
			forwards = append(forwards, portForward{
				network:     network,
				listen:      forwardOptions.Listen,
				destination: forwardOptions.Destination,
			})
		}
	}
	return forwards, nil
}

func defaultHostname() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return ""
	}
	if utf8.RuneCountInString(hostname) > maxHostnameLength {
		hostname = string([]rune(hostname)[:maxHostnameLength])
	}
	return hostname
}

// buildConfig renders the endpoint options as the native EasyTier TOML
// configuration of the local instance.
//
// Traffic from peers to proxy networks and to this node as an exit node is
// always handed to sing-box (proxy_forward_by_system) instead of the core's
// own proxy, so it is routed by sing-box rules with the peer as source.
func buildConfig(options option.EasyTierEndpointOptions, address addressConfig, mtu uint32) (string, error) {
	if options.NetworkName == "" {
		return "", E.New("missing network_name")
	}
	if _, err := parseProxyNetworks(options.ProxyNetworks); err != nil {
		return "", err
	}
	forwards, err := parsePortForwards(options.PortForwards)
	if err != nil {
		return "", err
	}
	hostname := options.Hostname
	if hostname == "" {
		hostname = defaultHostname()
	} else if utf8.RuneCountInString(hostname) > maxHostnameLength {
		return "", E.New("hostname must not exceed ", maxHostnameLength, " characters")
	}
	for _, peer := range options.Peers {
		if peer == "" || strings.TrimSpace(peer) != peer {
			return "", E.New("invalid peer: ", strconv.Quote(peer))
		}
	}
	for _, listener := range options.Listeners {
		if listener == "" || strings.TrimSpace(listener) != listener {
			return "", E.New("invalid listener: ", strconv.Quote(listener))
		}
	}
	var builder configBuilder
	if hostname != "" {
		builder.stringField("hostname", hostname)
	}
	if address.inet4.IsValid() {
		builder.stringField("ipv4", address.inet4.String())
	} else {
		builder.boolField("dhcp", true)
	}
	if address.inet6.IsValid() {
		builder.stringField("ipv6", address.inet6.String())
	}
	if len(options.Listeners) > 0 {
		builder.stringArrayField("listeners", options.Listeners)
	}
	if len(options.ExitNodes) > 0 {
		builder.stringArrayField("exit_nodes", common.Map(options.ExitNodes, netip.Addr.String))
	}
	if len(options.STUNServers) > 0 {
		builder.stringArrayField("stun_servers", options.STUNServers)
	}
	if len(options.STUNServersV6) > 0 {
		builder.stringArrayField("stun_servers_v6", options.STUNServersV6)
	}

	builder.table("network_identity")
	builder.stringField("network_name", options.NetworkName)
	builder.stringField("network_secret", options.NetworkSecret)

	for _, peer := range options.Peers {
		builder.arrayTable("peer")
		builder.stringField("uri", peer)
	}

	for _, proxyNetwork := range options.ProxyNetworks {
		builder.arrayTable("proxy_network")
		builder.stringField("cidr", proxyNetwork.CIDR.Masked().String())
		if proxyNetwork.MappedCIDR != nil {
			builder.stringField("mapped_cidr", proxyNetwork.MappedCIDR.Build(netip.Prefix{}).Masked().String())
		}
	}

	for _, forward := range forwards {
		builder.arrayTable("port_forward")
		builder.stringField("bind_addr", forward.listen.String())
		builder.stringField("dst_addr", forward.destination.String())
		builder.stringField("proto", forward.network)
	}

	builder.table("flags")
	builder.intField("mtu", uint64(mtu))
	builder.boolField("proxy_forward_by_system", true)
	builder.boolField("enable_exit_node", options.EnableExitNode)
	builder.boolField("enable_encryption", !options.DisableEncryption)
	if options.EncryptionAlgorithm != "" {
		builder.stringField("encryption_algorithm", options.EncryptionAlgorithm)
	}
	builder.boolField("disable_p2p", options.DisableP2P)
	builder.boolField("lazy_p2p", options.LazyP2P)
	builder.boolField("need_p2p", options.NeedP2P)
	builder.boolField("p2p_only", options.P2POnly)
	builder.boolField("disable_tcp_hole_punching", options.DisableTCPHolePunching)
	builder.boolField("disable_udp_hole_punching", options.DisableUDPHolePunching)
	builder.boolField("disable_sym_hole_punching", options.DisableSymHolePunching)
	builder.boolField("latency_first", options.LatencyFirst)
	builder.boolField("private_mode", options.PrivateMode)
	builder.boolField("relay_all_peer_rpc", options.RelayAllPeerRPC)
	if len(options.RelayNetworkWhitelist) > 0 {
		builder.stringField("relay_network_whitelist", strings.Join(options.RelayNetworkWhitelist, " "))
	}

	if options.SecureMode != nil && options.SecureMode.Enabled {
		if options.NetworkSecret == "" {
			return "", E.New("secure_mode requires network_secret")
		}
		privateKey, err := parseSecureModePrivateKey(options.SecureMode.PrivateKey)
		if err != nil {
			return "", E.Cause(err, "secure_mode.private_key")
		}
		builder.table("secure_mode")
		builder.boolField("enabled", true)
		builder.stringField("local_private_key", base64.StdEncoding.EncodeToString(privateKey.Bytes()))
		builder.stringField("local_public_key", base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()))
	}
	return builder.String(), nil
}

func parseSecureModePrivateKey(encoded string) (*ecdh.PrivateKey, error) {
	if encoded == "" {
		return ecdh.X25519().GenerateKey(rand.Reader)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(keyBytes)
}

type configBuilder struct {
	strings.Builder
}

func (b *configBuilder) table(name string) {
	b.header("[", name, "]")
}

func (b *configBuilder) arrayTable(name string) {
	b.header("[[", name, "]]")
}

func (b *configBuilder) header(open string, name string, close string) {
	if b.Len() > 0 {
		b.WriteByte('\n')
	}
	b.WriteString(open)
	b.WriteString(name)
	b.WriteString(close)
	b.WriteByte('\n')
}

func (b *configBuilder) field(name string, value string) {
	b.WriteString(name)
	b.WriteString(" = ")
	b.WriteString(value)
	b.WriteByte('\n')
}

func (b *configBuilder) stringField(name string, value string) {
	b.field(name, quoteString(value))
}

func (b *configBuilder) boolField(name string, value bool) {
	b.field(name, strconv.FormatBool(value))
}

func (b *configBuilder) intField(name string, value uint64) {
	b.field(name, strconv.FormatUint(value, 10))
}

func (b *configBuilder) stringArrayField(name string, values []string) {
	b.field(name, "["+strings.Join(common.Map(values, quoteString), ", ")+"]")
}

// quoteString encodes a Go string as a TOML basic string; JSON string escapes
// are a subset of TOML basic string escapes.
func quoteString(value string) string {
	return string(common.Must1(json.Marshal(value)))
}
