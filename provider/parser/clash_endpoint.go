package parser

import (
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type DirectOption struct {
	DialerOptions `yaml:",inline"`
}

func (d *DirectOption) Build() any {
	return &option.DirectOutboundOptions{
		DialerOptions: d.DialerOptions.Build(),
	}
}

type ClashOpenVPNOption struct {
	DialerOptions      `yaml:",inline"`
	ServerOptions      `yaml:",inline"`
	Proto              string   `yaml:"proto,omitempty"`
	Dev                string   `yaml:"dev,omitempty"`
	Cipher             string   `yaml:"cipher,omitempty"`
	DataCiphers        []string `yaml:"data-ciphers,omitempty"`
	DataCipherFallback string   `yaml:"data-ciphers-fallback,omitempty"`
	Auth               string   `yaml:"auth,omitempty"`
	CompLZO            string   `yaml:"comp-lzo,omitempty"`
	CA                 string   `yaml:"ca"`
	Cert               string   `yaml:"cert,omitempty"`
	Key                string   `yaml:"key,omitempty"`
	TLSAuth            string   `yaml:"tls-auth,omitempty"`
	KeyDirection       string   `yaml:"key-direction,omitempty"`
	TLSCrypt           string   `yaml:"tls-crypt,omitempty"`
	TLSCryptV2         string   `yaml:"tls-crypt-v2,omitempty"`
	Username           string   `yaml:"username,omitempty"`
	Password           string   `yaml:"password,omitempty"`
	// seconds
	Ping             int `yaml:"ping,omitempty"`
	PingRestart      int `yaml:"ping-restart,omitempty"`
	HandshakeTimeout int `yaml:"handshake-timeout,omitempty"`
	MTU              int `yaml:"mtu,omitempty"`
}

func (o *ClashOpenVPNOption) unsupported() string {
	if dev := strings.ToLower(strings.TrimSpace(o.Dev)); dev != "" && dev != "tun" {
		return "OpenVPN dev " + o.Dev + " is not supported, only tun"
	}
	if o.network() == "" {
		return "OpenVPN proto " + o.Proto + " is not supported"
	}
	switch o.KeyDirection {
	case "", "0", "1":
	default:
		return "OpenVPN key-direction " + o.KeyDirection + " is not supported"
	}
	return ""
}

func (o *ClashOpenVPNOption) network() string {
	switch strings.ToLower(strings.TrimSpace(o.Proto)) {
	case "", "udp", "udp4":
		return "udp"
	case "tcp", "tcp-client", "tcp4", "tcp4-client":
		return "tcp"
	}
	return ""
}

func (o *ClashOpenVPNOption) Build() any {
	tls := &option.OpenVPNOutboundTLSOptions{}
	tls.Certificate, tls.CertificatePath = clashPEMOrPath(o.CA)
	tls.ClientCertificate, tls.ClientCertificatePath = clashPEMOrPath(o.Cert)
	tls.ClientKey, tls.ClientKeyPath = clashPEMOrPath(o.Key)
	switch {
	case strings.TrimSpace(o.TLSCryptV2) != "":
		tls.ControlWrap = clashOpenVPNControlWrap("tls_crypt_v2", o.TLSCryptV2, "")
	case strings.TrimSpace(o.TLSCrypt) != "":
		tls.ControlWrap = clashOpenVPNControlWrap("tls_crypt", o.TLSCrypt, "")
	case strings.TrimSpace(o.TLSAuth) != "":
		tls.ControlWrap = clashOpenVPNControlWrap("tls_auth", o.TLSAuth, o.KeyDirection)
	}
	compression := strings.ToLower(strings.TrimSpace(o.CompLZO))
	if compression == "adaptive" {
		// mihomo treats adaptive as yes
		compression = "yes"
	}
	options := &option.OpenVPNClientEndpointOptions{
		DialerOptions:       o.DialerOptions.Build(),
		ServerOptions:       o.ServerOptions.Build(),
		Network:             o.network(),
		Username:            o.Username,
		Password:            o.Password,
		TLS:                 tls,
		Cipher:              o.Cipher,
		DataCiphers:         o.DataCiphers,
		DataCiphersFallback: o.DataCipherFallback,
		Auth:                o.Auth,
		CompressionLZO:      compression,
		PingInterval:        badoption.Duration(time.Duration(o.Ping) * time.Second),
		PingRestart:         badoption.Duration(time.Duration(o.PingRestart) * time.Second),
		HandshakeWindow:     badoption.Duration(time.Duration(o.HandshakeTimeout) * time.Second),
	}
	options.MTU = uint32(o.MTU)
	return options
}

func clashOpenVPNControlWrap(wrapType string, key string, keyDirection string) *option.OpenVPNControlWrapOptions {
	wrap := &option.OpenVPNControlWrapOptions{Type: wrapType}
	wrap.Key, wrap.KeyPath = clashPEMOrPath(key)
	switch keyDirection {
	case "0":
		wrap.Direction = "server"
	case "1":
		wrap.Direction = "client"
	}
	return wrap
}

type ClashEasyTierOption struct {
	DialerOptions       `yaml:",inline"`
	NetworkName         string   `yaml:"network-name,omitempty"`
	NetworkSecret       string   `yaml:"network-secret,omitempty"`
	Hostname            string   `yaml:"hostname,omitempty"`
	IPv4                string   `yaml:"ipv4,omitempty"`
	Peers               []string `yaml:"peers,omitempty"`
	Listeners           []string `yaml:"listeners,omitempty"`
	NoListener          *bool    `yaml:"no-listener,omitempty"`
	ExitNodes           []string `yaml:"exit-nodes,omitempty"`
	ProxyNetworks       []string `yaml:"proxy-networks,omitempty"`
	EnableExitNode      *bool    `yaml:"enable-exit-node,omitempty"`
	EnableEncryption    *bool    `yaml:"enable-encryption,omitempty"`
	EncryptionAlgorithm string   `yaml:"encryption-algorithm,omitempty"`
	PrivateMode         *bool    `yaml:"private-mode,omitempty"`
	LatencyFirst        *bool    `yaml:"latency-first,omitempty"`
	DisableP2P          *bool    `yaml:"disable-p2p,omitempty"`
	MTU                 int      `yaml:"mtu,omitempty"`
	TLDDNSZone          string   `yaml:"tld-dns-zone,omitempty"`
	SecureMode          *bool    `yaml:"secure-mode,omitempty"`
	LocalPrivateKey     string   `yaml:"local-private-key,omitempty"`
}

func (e *ClashEasyTierOption) unsupported() string {
	for _, network := range e.ProxyNetworks {
		if _, _, err := clashEasyTierProxyNetwork(network); err != nil {
			return "invalid EasyTier proxy network: " + network
		}
	}
	return ""
}

func (e *ClashEasyTierOption) Build() any {
	options := &option.EasyTierEndpointOptions{
		DialerOptions:       e.DialerOptions.Build(),
		NetworkName:         e.NetworkName,
		NetworkSecret:       e.NetworkSecret,
		Hostname:            e.Hostname,
		Peers:               e.Peers,
		Listeners:           e.Listeners,
		EncryptionAlgorithm: e.EncryptionAlgorithm,
		TLDDNSZone:          e.TLDDNSZone,
		EnableExitNode:      clashBool(e.EnableExitNode),
		DisableEncryption:   e.EnableEncryption != nil && !*e.EnableEncryption,
		PrivateMode:         clashBool(e.PrivateMode),
		LatencyFirst:        clashBool(e.LatencyFirst),
		DisableP2P:          clashBool(e.DisableP2P),
	}
	options.MTU = uint32(e.MTU)
	if clashBool(e.NoListener) {
		options.Listeners = nil
	}
	if address, ok := clashEasyTierAddress(e.IPv4); ok {
		options.Address = badoption.Listable[netip.Prefix]{address}
	}
	for _, node := range e.ExitNodes {
		if addr, err := netip.ParseAddr(strings.TrimSpace(node)); err == nil {
			options.ExitNodes = append(options.ExitNodes, addr)
		}
	}
	for _, network := range e.ProxyNetworks {
		cidr, mapped, err := clashEasyTierProxyNetwork(network)
		if err != nil {
			continue
		}
		proxyNetwork := option.EasyTierProxyNetworkOptions{CIDR: cidr}
		if mapped.IsValid() {
			mappedPrefix := badoption.Prefix(mapped)
			proxyNetwork.MappedCIDR = &mappedPrefix
		}
		options.ProxyNetworks = append(options.ProxyNetworks, proxyNetwork)
	}
	if clashBool(e.SecureMode) {
		options.SecureMode = &option.EasyTierSecureModeOptions{Enabled: true, PrivateKey: e.LocalPrivateKey}
	}
	return options
}

// clashEasyTierAddress accepts "10.0.0.1" or "10.0.0.1/24"; EasyTier
// defaults to a /24 network.
func clashEasyTierAddress(value string) (netip.Prefix, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, false
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix, true
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return netip.PrefixFrom(addr, 24), true
	}
	return netip.Prefix{}, false
}

// clashEasyTierProxyNetwork parses "cidr" or "cidr->mapped-cidr".
func clashEasyTierProxyNetwork(value string) (netip.Prefix, netip.Prefix, error) {
	cidr, mapped, hasMapped := strings.Cut(value, "->")
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !hasMapped {
		return prefix, netip.Prefix{}, err
	}
	mappedPrefix, err := netip.ParsePrefix(strings.TrimSpace(mapped))
	return prefix, mappedPrefix, err
}

func clashBool(value *bool) bool {
	return value != nil && *value
}
