package parser

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"net/netip"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"gopkg.in/yaml.v3"
)

type ClashConfig struct {
	Proxies []ClashProxy `yaml:"proxies"`
}

type _ClashProxy struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Options Proxy  `yaml:"-"`

	SingType string `yaml:"-"`
	// Unsupported explains why the proxy cannot be converted: its type or one
	// of its options has no counterpart in this build.
	Unsupported string `yaml:"-"`
}
type ClashProxy _ClashProxy

type Proxy interface {
	Build() any
}

// clashUnsupported is implemented by proxies whose options may need a feature
// this build does not have. A non-empty reason skips the proxy instead of
// creating a node that silently behaves differently from Clash.
type clashUnsupported interface {
	unsupported() string
}

// clashChained is implemented by proxies that need helper outbounds, such as
// the shadowtls outbound behind shadow-tls. chain may rewrite the built
// outbound to dial through them.
type clashChained interface {
	chain(tag string, outbound *option.Outbound) []option.Outbound
}

// Clash / mihomo proxy types without an implementation in this build.
var clashUnsupportedTypes = map[string]string{
	"ssr":         "ShadowsocksR is not implemented",
	"mieru":       "mieru is not implemented",
	"sudoku":      "sudoku is not implemented",
	"shadowquic":  "ShadowQUIC is not implemented",
	"gost-relay":  "GOST relay is not implemented",
	"rematch":     "rematch is a Clash routing construct",
	"trusttunnel": "TrustTunnel is not implemented",
	"zerotier":    "ZeroTier is not implemented",
	"masque":      "Clash masque is Cloudflare WARP authentication, the masque-client endpoint only supports RFC 9484 with username and password",
	"dns":         "Clash dns proxies map to the deprecated dns outbound, use a hijack-dns route rule",
	"reject":      "Clash reject proxies map to the deprecated block outbound, use a reject route rule",
}

func (c *ClashProxy) UnmarshalYAML(value *yaml.Node) error {
	err := value.Decode((*_ClashProxy)(c))
	if err != nil {
		return err
	}
	var options Proxy
	switch c.Type {
	case "ss":
		c.SingType = C.TypeShadowsocks
		options = &ShadowSocksOption{}
	case "tuic":
		c.SingType = C.TypeTUIC
		options = &TuicOption{}
	case "vmess":
		c.SingType = C.TypeVMess
		options = &VmessOption{}
	case "vless":
		c.SingType = C.TypeVLESS
		options = &VlessOption{}
	case "socks5":
		c.SingType = C.TypeSOCKS
		options = &Socks5Option{}
	case "http":
		c.SingType = C.TypeHTTP
		options = &HttpOption{}
	case "trojan":
		c.SingType = C.TypeTrojan
		options = &TrojanOption{}
	case "hysteria":
		c.SingType = C.TypeHysteria
		options = &HysteriaOption{}
	case "hysteria2":
		c.SingType = C.TypeHysteria2
		options = &Hysteria2Option{}
	case "ssh":
		c.SingType = C.TypeSSH
		options = &SSHOption{}
	case "snell":
		c.SingType = C.TypeSnell
		options = &SnellOption{}
	case "anytls":
		c.SingType = C.TypeAnyTLS
		options = &AnyTLSOption{}
	case "wireguard":
		c.SingType = C.TypeWireGuard
		options = &ClashWireGuardOption{}
	case "tailscale":
		c.SingType = C.TypeTailscale
		options = &ClashTailscaleOption{}
	case "direct":
		c.SingType = C.TypeDirect
		options = &DirectOption{}
	case "openvpn":
		c.SingType = C.TypeOpenVPNClient
		options = &ClashOpenVPNOption{}
	case "easytier":
		c.SingType = C.TypeEasyTier
		options = &ClashEasyTierOption{}
	default:
		if reason, loaded := clashUnsupportedTypes[c.Type]; loaded {
			c.Unsupported = reason
		} else {
			c.Unsupported = "unknown proxy type: " + c.Type
		}
		return nil
	}
	err = value.Decode(options)
	if err != nil {
		return err
	}
	c.Options = options
	if checker, isChecker := options.(clashUnsupported); isChecker {
		c.Unsupported = checker.unsupported()
	}
	return nil
}

func (c *ClashProxy) isEndpoint() bool {
	switch c.SingType {
	case C.TypeWireGuard, C.TypeTailscale, C.TypeOpenVPNClient, C.TypeEasyTier:
		return true
	}
	return false
}

func (c *ClashProxy) Build() option.Outbound {
	outbound := option.Outbound{
		Tag:  c.Name,
		Type: c.SingType,
	}
	if c.Options != nil {
		outbound.Options = c.Options.Build()
	}
	return outbound
}

func (c *ClashProxy) BuildEndpoint() option.Endpoint {
	endpoint := option.Endpoint{
		Tag:  c.Name,
		Type: c.SingType,
	}
	if c.Options != nil {
		endpoint.Options = c.Options.Build()
	}
	return endpoint
}

func ParseClashSubscription(ctx context.Context, content string) ([]option.Outbound, []option.Endpoint, error) {
	config := &ClashConfig{}
	err := yaml.Unmarshal([]byte(content), &config)
	if err != nil {
		return nil, nil, E.Cause(err, "parse clash config")
	}
	var (
		outbounds []option.Outbound
		endpoints []option.Endpoint
	)
	for _, proxy := range config.Proxies {
		if proxy.Unsupported != "" {
			warn(ctx, "skip clash proxy ", proxy.Name, ": ", proxy.Unsupported)
			continue
		}
		if proxy.SingType == "" {
			continue
		}
		if proxy.isEndpoint() {
			endpoints = append(endpoints, proxy.BuildEndpoint())
			continue
		}
		outbound := proxy.Build()
		outbounds = append(outbounds, outbound)
		if chained, isChained := proxy.Options.(clashChained); isChained {
			index := len(outbounds) - 1
			outbounds = append(outbounds, chained.chain(proxy.Name, &outbounds[index])...)
		}
	}
	return outbounds, endpoints, nil
}

type ShadowSocksOption struct {
	DialerOptions     `yaml:",inline"`
	ServerOptions     `yaml:",inline"`
	Password          string         `yaml:"password"`
	Cipher            string         `yaml:"cipher"`
	UDP               bool           `yaml:"udp,omitempty"`
	Plugin            string         `yaml:"plugin,omitempty"`
	PluginOpts        map[string]any `yaml:"plugin-opts,omitempty"`
	UDPOverTCP        bool           `yaml:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion int            `yaml:"udp-over-tcp-version,omitempty"`
	ClientFingerprint string         `yaml:"client-fingerprint,omitempty"`
	MuxOpts           *MuxOptions    `yaml:"smux,omitempty"`
}

func (s *ShadowSocksOption) unsupported() string {
	switch s.Plugin {
	case "", "obfs", "v2ray-plugin", "shadow-tls":
	case "restls":
		return "the restls plugin is not implemented"
	case "gost-plugin":
		return "the gost plugin is not implemented"
	case "kcptun":
		return "the kcptun plugin is not implemented"
	default:
		return "unknown shadowsocks plugin: " + s.Plugin
	}
	if s.Plugin == "v2ray-plugin" {
		return clashV2RayPluginUnsupported(s.PluginOpts)
	}
	return ""
}

// shadow-tls is not a SIP003 plugin in sing-box: the outbound dials through a
// shadowtls outbound instead.
func (s *ShadowSocksOption) chain(tag string, outbound *option.Outbound) []option.Outbound {
	if s.Plugin != "shadow-tls" {
		return nil
	}
	options := outbound.Options.(*option.ShadowsocksOutboundOptions)
	tls := &TLSOptions{
		TLS:               true,
		SNI:               clashStringOption(s.PluginOpts, "host"),
		SkipCertVerify:    clashBoolOption(s.PluginOpts, "skip-cert-verify"),
		Fingerprint:       clashStringOption(s.PluginOpts, "fingerprint"),
		ClientFingerprint: s.ClientFingerprint,
		Certificate:       clashStringOption(s.PluginOpts, "certificate"),
		PrivateKey:        clashStringOption(s.PluginOpts, "private-key"),
		NameCertVerify:    clashStringOption(s.PluginOpts, "name-cert-verify"),
		ALPN:              clashStringListOption(s.PluginOpts, "alpn"),
	}
	container := option.OutboundTLSOptionsContainer{TLS: tls.Build()}
	version, _ := strconv.Atoi(clashStringOption(s.PluginOpts, "version"))
	if !s.UDPOverTCP {
		// mihomo sends native UDP directly to the server, outside shadow-tls;
		// sing-box can only dial through the detour, which carries TCP alone.
		options.Network = N.NetworkTCP
	}
	return clashShadowTLSChain(tag, &options.DialerOptions, options.ServerOptions, &container,
		clashStringOption(s.PluginOpts, "password"), version, []string{"h2", "http/1.1"})
}

func (s *ShadowSocksOption) Build() any {
	return &option.ShadowsocksOutboundOptions{
		DialerOptions: s.DialerOptions.Build(),
		ServerOptions: s.ServerOptions.Build(),
		Password:      s.Password,
		Method:        clashShadowsocksCipher(s.Cipher),
		Plugin:        clashPluginName(s.Plugin),
		PluginOptions: clashPluginOptions(s.Plugin, s.PluginOpts),
		Network:       clashNetworks(s.UDP),
		UDPOverTCP: &option.UDPOverTCPOptions{
			Enabled: s.UDPOverTCP,
			Version: uint8(s.UDPOverTCPVersion),
		},
		Multiplex: s.MuxOpts.Build(),
	}
}

type TuicOption struct {
	DialerOptions        `yaml:",inline"`
	ServerOptions        `yaml:",inline"`
	TLSOptions           `yaml:",inline"`
	UUID                 string `yaml:"uuid,omitempty"`
	Password             string `yaml:"password,omitempty"`
	Ip                   string `yaml:"ip,omitempty"`
	HeartbeatInterval    int    `yaml:"heartbeat-interval,omitempty"`
	DisableSni           bool   `yaml:"disable-sni,omitempty"`
	ReduceRtt            bool   `yaml:"reduce-rtt,omitempty"`
	UdpRelayMode         string `yaml:"udp-relay-mode,omitempty"`
	CongestionController string `yaml:"congestion-controller,omitempty"`
	FastOpen             bool   `yaml:"fast-open,omitempty"`
	DisableMTUDiscovery  bool   `yaml:"disable-mtu-discovery,omitempty"`
	UDPOverStream        bool   `yaml:"udp-over-stream,omitempty"`
	Token                string `yaml:"token,omitempty"`
	ReceiveWindowConn    int    `yaml:"recv-window-conn,omitempty"`
	ReceiveWindow        int    `yaml:"recv-window,omitempty"`
}

func (t *TuicOption) unsupported() string {
	if t.Token != "" {
		return "TUIC v4 (token authentication) is not implemented"
	}
	return ""
}

func (t *TuicOption) Build() any {
	t.TLS = true
	t.TFO = t.FastOpen
	options := &option.TUICOutboundOptions{
		DialerOptions:               t.DialerOptions.Build(),
		ServerOptions:               t.ServerOptions.Build(),
		UUID:                        t.UUID,
		Password:                    t.Password,
		CongestionControl:           t.CongestionController,
		UDPRelayMode:                t.UdpRelayMode,
		UDPOverStream:               t.UDPOverStream,
		ZeroRTTHandshake:            t.ReduceRtt,
		Heartbeat:                   badoption.Duration(time.Duration(t.HeartbeatInterval) * time.Millisecond), // milliseconds in Clash
		OutboundTLSOptionsContainer: clashTLSOptions(t.Server, &t.TLSOptions),
		QUICOptions: option.QUICOptions{
			HTTP2Options: option.HTTP2Options{
				StreamReceiveWindow:     clashMemoryBytes(t.ReceiveWindow),
				ConnectionReceiveWindow: clashMemoryBytes(t.ReceiveWindowConn),
			},
			DisablePathMTUDiscovery: t.DisableMTUDiscovery,
		},
	}
	if t.Ip != "" {
		options.Server = t.Ip
	}
	if t.DisableSni {
		options.TLS.DisableSNI = true
	}
	return options
}

type VmessOption struct {
	DialerOptions       `yaml:",inline"`
	ServerOptions       `yaml:",inline"`
	*TLSOptions         `yaml:",inline"`
	UUID                string       `yaml:"uuid"`
	AlterID             int          `yaml:"alterId"`
	Cipher              string       `yaml:"cipher"`
	UDP                 bool         `yaml:"udp,omitempty"`
	Network             string       `yaml:"network,omitempty"`
	ServerName          string       `yaml:"servername,omitempty"`
	HTTPOpts            HTTPOptions  `yaml:"http-opts,omitempty"`
	HTTP2Opts           HTTP2Options `yaml:"h2-opts,omitempty"`
	GrpcOpts            GrpcOptions  `yaml:"grpc-opts,omitempty"`
	WSOpts              WSOptions    `yaml:"ws-opts,omitempty"`
	XHTTPOpts           XHTTPOptions `yaml:"xhttp-opts,omitempty"`
	PacketAddr          bool         `yaml:"packet-addr,omitempty"`
	XUDP                bool         `yaml:"xudp,omitempty"`
	PacketEncoding      string       `yaml:"packet-encoding,omitempty"`
	GlobalPadding       bool         `yaml:"global-padding,omitempty"`
	AuthenticatedLength bool         `yaml:"authenticated-length,omitempty"`
	MuxOpts             *MuxOptions  `yaml:"smux,omitempty"`
	clashTLSExtensions  `yaml:",inline"`
}

func (v *VmessOption) unsupported() string {
	if reason := clashTransportUnsupported(v.Network); reason != "" {
		return reason
	}
	if v.Network == "xhttp" {
		if reason := v.XHTTPOpts.DownloadSettings.unsupported(); reason != "" {
			return reason
		}
	}
	return v.clashTLSExtensions.unsupported()
}

func (v *VmessOption) chain(tag string, outbound *option.Outbound) []option.Outbound {
	options := outbound.Options.(*option.VMessOutboundOptions)
	if !v.ShadowTLSOpts.enabled() || options.TLS == nil {
		return nil
	}
	return clashShadowTLSChain(tag, &options.DialerOptions, options.ServerOptions, &options.OutboundTLSOptionsContainer,
		v.ShadowTLSOpts.Password, v.ShadowTLSOpts.Version, []string{"http/1.1"})
}

func (v *VmessOption) Build() any {
	if v.TLSOptions != nil {
		v.SNI = v.ServerName
	}
	xhttp := clashXHTTP{options: v.XHTTPOpts, server: v.Server, port: v.Port, serverName: v.ServerName, tls: v.TLSOptions}
	switch v.PacketEncoding {
	case "":
		if v.XUDP {
			v.PacketEncoding = "xudp"
		} else if v.PacketAddr {
			v.PacketEncoding = "packetaddr"
		}
	case "packet":
		v.PacketEncoding = "packetaddr"
	}
	return &option.VMessOutboundOptions{
		DialerOptions:               v.DialerOptions.Build(),
		ServerOptions:               v.ServerOptions.Build(),
		UUID:                        v.UUID,
		Security:                    resolveVMessAutoSecurity(v.Cipher),
		AlterId:                     v.AlterID,
		GlobalPadding:               v.GlobalPadding,
		AuthenticatedLength:         v.AuthenticatedLength,
		Network:                     clashNetworks(v.UDP),
		OutboundTLSOptionsContainer: clashTLSOptions(v.Server, v.TLSOptions),
		PacketEncoding:              v.PacketEncoding,
		Multiplex:                   v.MuxOpts.Build(),
		Transport:                   clashTransport(v.Network, v.HTTPOpts, v.HTTP2Opts, v.GrpcOpts, v.WSOpts, xhttp),
	}
}

type VlessOption struct {
	DialerOptions      `yaml:",inline"`
	ServerOptions      `yaml:",inline"`
	*TLSOptions        `yaml:",inline"`
	UUID               string       `yaml:"uuid"`
	Flow               string       `yaml:"flow,omitempty"`
	Encryption         string       `yaml:"encryption,omitempty"`
	UDP                bool         `yaml:"udp,omitempty"`
	PacketAddr         bool         `yaml:"packet-addr,omitempty"`
	XUDP               bool         `yaml:"xudp,omitempty"`
	PacketEncoding     string       `yaml:"packet-encoding,omitempty"`
	Network            string       `yaml:"network,omitempty"`
	ServerName         string       `yaml:"servername,omitempty"`
	HTTPOpts           HTTPOptions  `yaml:"http-opts,omitempty"`
	HTTP2Opts          HTTP2Options `yaml:"h2-opts,omitempty"`
	GrpcOpts           GrpcOptions  `yaml:"grpc-opts,omitempty"`
	WSOpts             WSOptions    `yaml:"ws-opts,omitempty"`
	XHTTPOpts          XHTTPOptions `yaml:"xhttp-opts,omitempty"`
	MuxOpts            *MuxOptions  `yaml:"smux,omitempty"`
	clashTLSExtensions `yaml:",inline"`
}

func (v *VlessOption) unsupported() string {
	if reason := clashTransportUnsupported(v.Network); reason != "" {
		return reason
	}
	if v.Network == "xhttp" {
		if reason := v.XHTTPOpts.DownloadSettings.unsupported(); reason != "" {
			return reason
		}
	}
	return v.clashTLSExtensions.unsupported()
}

func (v *VlessOption) chain(tag string, outbound *option.Outbound) []option.Outbound {
	options := outbound.Options.(*option.VLESSOutboundOptions)
	if !v.ShadowTLSOpts.enabled() || options.TLS == nil {
		return nil
	}
	return clashShadowTLSChain(tag, &options.DialerOptions, options.ServerOptions, &options.OutboundTLSOptionsContainer,
		v.ShadowTLSOpts.Password, v.ShadowTLSOpts.Version, []string{"http/1.1"})
}

func (v *VlessOption) Build() any {
	if v.TLSOptions != nil {
		v.SNI = v.ServerName
	}
	xhttp := clashXHTTP{options: v.XHTTPOpts, server: v.Server, port: v.Port, serverName: v.ServerName, tls: v.TLSOptions}
	switch v.PacketEncoding {
	case "":
		if v.PacketAddr {
			v.PacketEncoding = "packetaddr"
		} else {
			v.PacketEncoding = "xudp"
		}
	case "packet":
		v.PacketEncoding = "packetaddr"
	}
	if v.Encryption == "none" {
		v.Encryption = ""
	}
	return &option.VLESSOutboundOptions{
		DialerOptions:               v.DialerOptions.Build(),
		ServerOptions:               v.ServerOptions.Build(),
		UUID:                        v.UUID,
		Flow:                        v.Flow,
		Encryption:                  v.Encryption,
		Network:                     clashNetworks(v.UDP),
		OutboundTLSOptionsContainer: clashTLSOptions(v.Server, v.TLSOptions),
		Multiplex:                   v.MuxOpts.Build(),
		Transport:                   clashTransport(v.Network, v.HTTPOpts, v.HTTP2Opts, v.GrpcOpts, v.WSOpts, xhttp),
		PacketEncoding:              &v.PacketEncoding,
	}
}

type Socks5Option struct {
	DialerOptions `yaml:",inline"`
	ServerOptions `yaml:",inline"`
	UserName      string `yaml:"username,omitempty"`
	Password      string `yaml:"password,omitempty"`
	UDP           bool   `yaml:"udp,omitempty"`
	TLS           bool   `yaml:"tls,omitempty"`
}

func (s *Socks5Option) unsupported() string {
	if s.TLS {
		return "SOCKS5 over TLS is not implemented"
	}
	return ""
}

func (s *Socks5Option) Build() any {
	return &option.SOCKSOutboundOptions{
		DialerOptions: s.DialerOptions.Build(),
		ServerOptions: s.ServerOptions.Build(),
		Username:      s.UserName,
		Password:      s.Password,
		Network:       clashNetworks(s.UDP),
	}
}

type HttpOption struct {
	DialerOptions `yaml:",inline"`
	ServerOptions `yaml:",inline"`
	*TLSOptions   `yaml:",inline"`
	UserName      string            `yaml:"username,omitempty"`
	Password      string            `yaml:"password,omitempty"`
	Headers       map[string]string `yaml:"headers,omitempty"`
}

func (h *HttpOption) Build() any {
	return &option.HTTPOutboundOptions{
		DialerOptions:               h.DialerOptions.Build(),
		ServerOptions:               h.ServerOptions.Build(),
		Username:                    h.UserName,
		Password:                    h.Password,
		OutboundTLSOptionsContainer: clashTLSOptions(h.Server, h.TLSOptions),
		Headers:                     clashHeaders(h.Headers),
		// Clash HTTP proxies never relay UDP; CONNECT-UDP is a sing-box extension.
		Network: N.NetworkTCP,
	}
}

type TrojanOption struct {
	DialerOptions `yaml:",inline"`
	ServerOptions `yaml:",inline"`
	TLSOptions    `yaml:",inline"`
	Password      string       `yaml:"password"`
	UDP           bool         `yaml:"udp,omitempty"`
	Network       string       `yaml:"network,omitempty"`
	GrpcOpts      GrpcOptions  `yaml:"grpc-opts,omitempty"`
	WSOpts        WSOptions    `yaml:"ws-opts,omitempty"`
	XHTTPOpts     XHTTPOptions `yaml:"xhttp-opts,omitempty"`
	MuxOpts       *MuxOptions  `yaml:"smux,omitempty"`
	SSOpts        struct {
		Enabled bool `yaml:"enabled,omitempty"`
	} `yaml:"ss-opts,omitempty"`
	clashTLSExtensions `yaml:",inline"`
}

func (t *TrojanOption) unsupported() string {
	if t.SSOpts.Enabled {
		return "trojan-go shadowsocks encryption (ss-opts) is not implemented"
	}
	if reason := clashTransportUnsupported(t.Network); reason != "" {
		return reason
	}
	return t.clashTLSExtensions.unsupported()
}

func (t *TrojanOption) chain(tag string, outbound *option.Outbound) []option.Outbound {
	if !t.ShadowTLSOpts.enabled() {
		return nil
	}
	options := outbound.Options.(*option.TrojanOutboundOptions)
	return clashShadowTLSChain(tag, &options.DialerOptions, options.ServerOptions, &options.OutboundTLSOptionsContainer,
		t.ShadowTLSOpts.Password, t.ShadowTLSOpts.Version, []string{"http/1.1"})
}

func (t *TrojanOption) Build() any {
	t.TLS = true
	xhttp := clashXHTTP{options: t.XHTTPOpts, server: t.Server, port: t.Port, serverName: t.SNI, tls: &t.TLSOptions}
	return &option.TrojanOutboundOptions{
		DialerOptions:               t.DialerOptions.Build(),
		ServerOptions:               t.ServerOptions.Build(),
		Password:                    t.Password,
		Network:                     clashNetworks(t.UDP),
		OutboundTLSOptionsContainer: clashTLSOptions(t.Server, &t.TLSOptions),
		Multiplex:                   t.MuxOpts.Build(),
		Transport:                   clashTransport(t.Network, HTTPOptions{}, HTTP2Options{}, t.GrpcOpts, t.WSOpts, xhttp),
	}
}

type HysteriaOption struct {
	DialerOptions       `yaml:",inline"`
	ServerOptions       `yaml:",inline"`
	TLSOptions          `yaml:",inline"`
	Ports               string `yaml:"ports,omitempty"`
	Up                  string `yaml:"up"`
	UpSpeed             int    `yaml:"up-speed,omitempty"` // compatible with Stash
	Down                string `yaml:"down"`
	DownSpeed           int    `yaml:"down-speed,omitempty"` // compatible with Stash
	Auth                string `yaml:"auth,omitempty"`
	AuthString          string `yaml:"auth-str,omitempty"`
	Obfs                string `yaml:"obfs,omitempty"`
	ReceiveWindowConn   int    `yaml:"recv-window-conn,omitempty"`
	ReceiveWindow       int    `yaml:"recv-window,omitempty"`
	DisableMTUDiscovery bool   `yaml:"disable-mtu-discovery,omitempty"`
	FastOpen            bool   `yaml:"fast-open,omitempty"`
	HopInterval         int    `yaml:"hop-interval,omitempty"`
	Protocol            string `yaml:"protocol,omitempty"`
	ObfsProtocol        string `yaml:"obfs-protocol,omitempty"`
}

func (h *HysteriaOption) unsupported() string {
	for _, protocol := range []string{h.Protocol, h.ObfsProtocol} {
		switch protocol {
		case "", "udp":
		default:
			return "hysteria protocol " + protocol + " is not implemented"
		}
	}
	return ""
}

func (h *HysteriaOption) Build() any {
	h.TLS = true
	h.TFO = h.FastOpen
	outbound := &option.HysteriaOutboundOptions{
		DialerOptions: h.DialerOptions.Build(),
		ServerOptions: h.ServerOptions.Build(),
		ServerPorts:   option.LegacyListable[string](clashPorts(h.Ports)),
		HopInterval:   badoption.Duration(time.Duration(h.HopInterval) * time.Second),
		Up:            clashSpeedToNetworkBytes(h.Up),
		UpMbps:        h.UpSpeed,
		Down:          clashSpeedToNetworkBytes(h.Down),
		DownMbps:      h.DownSpeed,
		Obfs:          h.Obfs,
		Auth:          []byte(h.Auth),
		AuthString:    h.AuthString,
		QUICOptions: option.QUICOptions{
			HTTP2Options: option.HTTP2Options{
				ConnectionReceiveWindow: clashMemoryBytes(h.ReceiveWindowConn),
				StreamReceiveWindow:     clashMemoryBytes(h.ReceiveWindow),
			},
			DisablePathMTUDiscovery: h.DisableMTUDiscovery,
		},
		OutboundTLSOptionsContainer: clashTLSOptions(h.Server, &h.TLSOptions),
	}
	return outbound
}

func clashMemoryBytes(value int) *byteformats.MemoryBytes {
	if value == 0 {
		return nil
	}
	var result byteformats.MemoryBytes
	_ = result.UnmarshalJSON(strconv.AppendInt(nil, int64(value), 10))
	return &result
}

type Hysteria2Option struct {
	DialerOptions `yaml:",inline"`
	ServerOptions `yaml:",inline"`
	TLSOptions    `yaml:",inline"`
	Ports         string `yaml:"ports,omitempty"`
	// seconds, or a "min-max" range of seconds
	HopInterval                    string                   `yaml:"hop-interval,omitempty"`
	Up                             string                   `yaml:"up,omitempty"`
	Down                           string                   `yaml:"down,omitempty"`
	Password                       string                   `yaml:"password,omitempty"`
	Obfs                           string                   `yaml:"obfs,omitempty"`
	ObfsPassword                   string                   `yaml:"obfs-password,omitempty"`
	BBRProfile                     string                   `yaml:"bbr-profile,omitempty"`
	InitialStreamReceiveWindow     uint64                   `yaml:"initial-stream-receive-window,omitempty"`
	MaxStreamReceiveWindow         uint64                   `yaml:"max-stream-receive-window,omitempty"`
	InitialConnectionReceiveWindow uint64                   `yaml:"initial-connection-receive-window,omitempty"`
	MaxConnectionReceiveWindow     uint64                   `yaml:"max-connection-receive-window,omitempty"`
	RealmOpts                      *ClashHysteria2RealmOpts `yaml:"realm-opts,omitempty"`
}

type ClashHysteria2RealmOpts struct {
	Enable      bool     `yaml:"enable,omitempty"`
	ServerURL   string   `yaml:"server-url,omitempty"`
	Token       string   `yaml:"token,omitempty"`
	RealmID     string   `yaml:"realm-id,omitempty"`
	STUNServers []string `yaml:"stun-servers,omitempty"`
	// TLS of the server URL
	SNI            string   `yaml:"sni,omitempty"`
	SkipCertVerify bool     `yaml:"skip-cert-verify,omitempty"`
	NameCertVerify string   `yaml:"name-cert-verify,omitempty"`
	Fingerprint    string   `yaml:"fingerprint,omitempty"`
	Certificate    string   `yaml:"certificate,omitempty"`
	PrivateKey     string   `yaml:"private-key,omitempty"`
	ALPN           []string `yaml:"alpn,omitempty"`
}

func (r *ClashHysteria2RealmOpts) Build() *option.Hysteria2Realm {
	if r == nil || !r.Enable {
		return nil
	}
	realm := &option.Hysteria2Realm{
		ServerURL:   r.ServerURL,
		Token:       r.Token,
		RealmID:     r.RealmID,
		STUNServers: r.STUNServers,
	}
	tls := TLSOptions{
		TLS:            true,
		SNI:            r.SNI,
		SkipCertVerify: r.SkipCertVerify,
		NameCertVerify: r.NameCertVerify,
		Fingerprint:    r.Fingerprint,
		Certificate:    r.Certificate,
		PrivateKey:     r.PrivateKey,
		ALPN:           r.ALPN,
	}
	if r.SNI != "" || r.SkipCertVerify || r.NameCertVerify != "" || r.Fingerprint != "" || r.Certificate != "" || len(r.ALPN) > 0 {
		realm.HTTPClient = &option.HTTPClientOptions{
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls.Build()},
		}
	}
	return realm
}

// clashHopInterval parses the mihomo hysteria2 hop-interval: seconds or a
// "min-max" range, of which sing-box picks a random value per hop.
func clashHopInterval(value string) (badoption.Duration, badoption.Duration) {
	start, end, isRange := strings.Cut(strings.TrimSpace(value), "-")
	minimum, err := strconv.ParseUint(strings.TrimSpace(start), 10, 64)
	if err != nil {
		return 0, 0
	}
	if !isRange {
		return badoption.Duration(time.Duration(minimum) * time.Second), 0
	}
	maximum, err := strconv.ParseUint(strings.TrimSpace(end), 10, 64)
	if err != nil || maximum <= minimum {
		return badoption.Duration(time.Duration(minimum) * time.Second), 0
	}
	return badoption.Duration(time.Duration(minimum) * time.Second), badoption.Duration(time.Duration(maximum) * time.Second)
}

// clashReceiveWindow prefers the maximum window: sing-box has one value per
// window, which bounds auto-tuning like mihomo's maximum does.
func clashReceiveWindow(initial uint64, maximum uint64) *byteformats.MemoryBytes {
	if maximum == 0 {
		maximum = initial
	}
	return clashMemoryBytes(int(maximum))
}

func (h *Hysteria2Option) Build() any {
	h.TLS = true
	hopInterval, hopIntervalMax := clashHopInterval(h.HopInterval)
	return &option.Hysteria2OutboundOptions{
		DialerOptions:               h.DialerOptions.Build(),
		ServerOptions:               h.ServerOptions.Build(),
		ServerPorts:                 option.LegacyListable[string](clashPorts(h.Ports)),
		HopInterval:                 hopInterval,
		HopIntervalMax:              hopIntervalMax,
		UpMbps:                      clashSpeedToIntMbps(h.Up),
		DownMbps:                    clashSpeedToIntMbps(h.Down),
		Obfs:                        clashHysteria2Obfs(h.Obfs, h.ObfsPassword),
		Password:                    h.Password,
		OutboundTLSOptionsContainer: clashTLSOptions(h.Server, &h.TLSOptions),
		QUICOptions: option.QUICOptions{
			HTTP2Options: option.HTTP2Options{
				StreamReceiveWindow:     clashReceiveWindow(h.InitialStreamReceiveWindow, h.MaxStreamReceiveWindow),
				ConnectionReceiveWindow: clashReceiveWindow(h.InitialConnectionReceiveWindow, h.MaxConnectionReceiveWindow),
			},
		},
		BBRProfile: h.BBRProfile,
		Realm:      h.RealmOpts.Build(),
	}
}

type SSHOption struct {
	DialerOptions        `yaml:",inline"`
	ServerOptions        `yaml:",inline"`
	UserName             string   `yaml:"username"`
	Password             string   `yaml:"password,omitempty"`
	PrivateKey           string   `yaml:"private-key,omitempty"`
	PrivateKeyPassphrase string   `yaml:"private-key-passphrase,omitempty"`
	HostKey              []string `yaml:"host-key,omitempty"`
	HostKeyAlgorithms    []string `yaml:"host-key-algorithms,omitempty"`
}

func (s *SSHOption) Build() any {
	options := &option.SSHOutboundOptions{
		DialerOptions:        s.DialerOptions.Build(),
		ServerOptions:        s.ServerOptions.Build(),
		User:                 s.UserName,
		Password:             s.Password,
		PrivateKeyPassphrase: s.PrivateKeyPassphrase,
		HostKey:              s.HostKey,
		HostKeyAlgorithms:    s.HostKeyAlgorithms,
	}
	if strings.Contains(s.PrivateKey, "PRIVATE KEY") {
		options.PrivateKey = trimStringArray(strings.Split(s.PrivateKey, "\n"))
	} else {
		options.PrivateKeyPath = s.PrivateKey
	}
	return options
}

type SnellOption struct {
	DialerOptions `yaml:",inline"`
	ServerOptions `yaml:",inline"`
	PSK           string         `yaml:"psk"`
	UDP           bool           `yaml:"udp,omitempty"`
	Version       int            `yaml:"version,omitempty"`
	Reuse         bool           `yaml:"reuse,omitempty"`
	ObfsOpts      map[string]any `yaml:"obfs-opts,omitempty"`
}

func (s *SnellOption) Build() any {
	return &option.SnellOutboundOptions{
		Version: s.Version,
		AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
			DialerOptions: s.DialerOptions.Build(),
			ServerOptions: s.ServerOptions.Build(),
			PSK:           s.PSK,
			Reuse:         s.Reuse,
			Network:       clashSnellNetworks(s.UDP),
		},
		ObfsOptions: option.SnellObfsClientOptions{
			ObfsMode: clashStringOption(s.ObfsOpts, "mode"),
			ObfsHost: clashStringOption(s.ObfsOpts, "host"),
		},
	}
}

type AnyTLSOption struct {
	DialerOptions            `yaml:",inline"`
	ServerOptions            `yaml:",inline"`
	TLSOptions               `yaml:",inline"`
	Password                 string `yaml:"password"`
	UDP                      bool   `yaml:"udp,omitempty"`
	IdleSessionCheckInterval int    `yaml:"idle-session-check-interval,omitempty"`
	IdleSessionTimeout       int    `yaml:"idle-session-timeout,omitempty"`
	MinIdleSession           int    `yaml:"min-idle-session,omitempty"`
	DisableReuse             bool   `yaml:"disable-reuse,omitempty"`
	ClientMetadata           string `yaml:"client-metadata,omitempty"`
	clashTLSExtensions       `yaml:",inline"`
}

func (a *AnyTLSOption) unsupported() string {
	if a.ShadowTLSOpts.enabled() {
		// the anytls outbound always performs its own TLS handshake
		return "anytls over shadow-tls is not supported"
	}
	return a.clashTLSExtensions.unsupported()
}

func (a *AnyTLSOption) Build() any {
	a.TLS = true
	options := &option.AnyTLSOutboundOptions{
		DialerOptions:               a.DialerOptions.Build(),
		ServerOptions:               a.ServerOptions.Build(),
		OutboundTLSOptionsContainer: clashTLSOptions(a.Server, &a.TLSOptions),
		Password:                    a.Password,
		IdleSessionCheckInterval:    badoption.Duration(time.Duration(a.IdleSessionCheckInterval) * time.Second),
		IdleSessionTimeout:          badoption.Duration(time.Duration(a.IdleSessionTimeout) * time.Second),
		MinIdleSession:              a.MinIdleSession,
		DisableReuse:                a.DisableReuse,
		Network:                     clashNetworks(a.UDP),
	}
	if a.ClientMetadata != "" {
		options.ClientMetadata = &a.ClientMetadata
	}
	return options
}

type ClashTailscaleOption struct {
	DialerOptions          `yaml:",inline"`
	Hostname               string `yaml:"hostname,omitempty"`
	AuthKey                string `yaml:"auth-key,omitempty"`
	ControlURL             string `yaml:"control-url,omitempty"`
	StateDir               string `yaml:"state-dir,omitempty"`
	Ephemeral              bool   `yaml:"ephemeral,omitempty"`
	UDP                    bool   `yaml:"udp,omitempty"`
	AcceptRoutes           *bool  `yaml:"accept-routes,omitempty"`
	ExitNode               string `yaml:"exit-node,omitempty"`
	ExitNodeAllowLANAccess *bool  `yaml:"exit-node-allow-lan-access,omitempty"`
}

func (t *ClashTailscaleOption) Build() any {
	var acceptRoutes bool
	if t.AcceptRoutes != nil {
		acceptRoutes = *t.AcceptRoutes
	}
	var exitNodeAllowLANAccess bool
	if t.ExitNodeAllowLANAccess != nil {
		exitNodeAllowLANAccess = *t.ExitNodeAllowLANAccess
	}
	return &option.TailscaleEndpointOptions{
		DialerOptions:          t.DialerOptions.Build(),
		StateDirectory:         t.StateDir,
		AuthKey:                t.AuthKey,
		ControlURL:             t.ControlURL,
		Ephemeral:              t.Ephemeral,
		Hostname:               t.Hostname,
		AcceptRoutes:           acceptRoutes,
		ExitNode:               t.ExitNode,
		ExitNodeAllowLANAccess: exitNodeAllowLANAccess,
	}
}

type ClashWireGuardReserved []uint8

func (r *ClashWireGuardReserved) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		decoded, err := base64.StdEncoding.DecodeString(value.Value)
		if err != nil {
			return E.Cause(err, "decode reserved")
		}
		*r = decoded
		return nil
	}
	var reserved []uint8
	if err := value.Decode(&reserved); err != nil {
		return err
	}
	*r = reserved
	return nil
}

type ClashWireGuardPeerOption struct {
	Server       string                 `yaml:"server"`
	Port         int                    `yaml:"port"`
	PublicKey    string                 `yaml:"public-key,omitempty"`
	PreSharedKey string                 `yaml:"pre-shared-key,omitempty"`
	Reserved     ClashWireGuardReserved `yaml:"reserved,omitempty"`
	AllowedIPs   []string               `yaml:"allowed-ips,omitempty"`
}

type ClashWireGuardOption struct {
	DialerOptions            `yaml:",inline"`
	ClashWireGuardPeerOption `yaml:",inline"`
	Ip                       string                     `yaml:"ip,omitempty"`
	Ipv6                     string                     `yaml:"ipv6,omitempty"`
	PrivateKey               string                     `yaml:"private-key"`
	MTU                      int                        `yaml:"mtu,omitempty"`
	Workers                  int                        `yaml:"workers,omitempty"`
	PersistentKeepalive      int                        `yaml:"persistent-keepalive,omitempty"`
	Peers                    []ClashWireGuardPeerOption `yaml:"peers,omitempty"`
	AmneziaWGOption          map[string]any             `yaml:"amnezia-wg-option,omitempty"`
}

func (w *ClashWireGuardOption) unsupported() string {
	if len(w.AmneziaWGOption) > 0 {
		return "AmneziaWG is not implemented"
	}
	return ""
}

func (w *ClashWireGuardOption) Build() any {
	var address badoption.Listable[netip.Prefix]
	if w.Ip != "" {
		ip := w.Ip
		if !strings.Contains(ip, "/") {
			ip += "/32"
		}
		if prefix, err := netip.ParsePrefix(ip); err == nil {
			address = append(address, prefix)
		}
	}
	if w.Ipv6 != "" {
		ipv6 := w.Ipv6
		if !strings.Contains(ipv6, "/") {
			ipv6 += "/128"
		}
		if prefix, err := netip.ParsePrefix(ipv6); err == nil {
			address = append(address, prefix)
		}
	}
	var peers []option.WireGuardPeer
	if len(w.Peers) > 0 {
		for _, peer := range w.Peers {
			peers = append(peers, clashWireGuardPeer(peer, w.PersistentKeepalive))
		}
	} else {
		peers = append(peers, clashWireGuardPeer(w.ClashWireGuardPeerOption, w.PersistentKeepalive))
	}
	return &option.WireGuardEndpointOptions{
		Address:       address,
		PrivateKey:    w.PrivateKey,
		MTU:           uint32(w.MTU),
		Workers:       w.Workers,
		Peers:         peers,
		DialerOptions: w.DialerOptions.Build(),
	}
}

func clashWireGuardPeer(peer ClashWireGuardPeerOption, persistentKeepalive int) option.WireGuardPeer {
	var allowedIPs badoption.Listable[netip.Prefix]
	for _, ip := range peer.AllowedIPs {
		if prefix, err := netip.ParsePrefix(ip); err == nil {
			allowedIPs = append(allowedIPs, prefix)
		}
	}
	return option.WireGuardPeer{
		Address:                     peer.Server,
		Port:                        uint16(peer.Port),
		PublicKey:                   peer.PublicKey,
		PreSharedKey:                peer.PreSharedKey,
		AllowedIPs:                  option.LegacyListable[netip.Prefix](allowedIPs),
		PersistentKeepaliveInterval: uint16(persistentKeepalive),
		Reserved:                    []uint8(peer.Reserved),
	}
}

type HTTPOptions struct {
	Method  string               `yaml:"method,omitempty"`
	Path    []string             `yaml:"path,omitempty"`
	Headers badoption.HTTPHeader `yaml:"headers,omitempty"`
}

type HTTP2Options struct {
	Host []string `yaml:"host,omitempty"`
	Path string   `yaml:"path,omitempty"`
}

type GrpcOptions struct {
	GrpcServiceName string `yaml:"grpc-service-name,omitempty"`
	// seconds between keepalive pings
	PingInterval int `yaml:"ping-interval,omitempty"`
}

type WSOptions struct {
	Path                string            `yaml:"path,omitempty"`
	Headers             map[string]string `yaml:"headers,omitempty"`
	MaxEarlyData        int               `yaml:"max-early-data,omitempty"`
	EarlyDataHeaderName string            `yaml:"early-data-header-name,omitempty"`
	V2rayHttpUpgrade    bool              `yaml:"v2ray-http-upgrade,omitempty"`
}

type MuxOptions struct {
	Enabled        bool           `yaml:"enabled,omitempty"`
	Protocol       string         `yaml:"protocol,omitempty"`
	MaxConnections int            `yaml:"max-connections,omitempty"`
	MinStreams     int            `yaml:"min-streams,omitempty"`
	MaxStreams     int            `yaml:"max-streams,omitempty"`
	Padding        bool           `yaml:"padding,omitempty"`
	BrutalOpts     *BrutalOptions `yaml:"brutal-opts,omitempty"`
}

func (s *MuxOptions) Build() *option.OutboundMultiplexOptions {
	if s == nil {
		return nil
	}
	return &option.OutboundMultiplexOptions{
		Enabled:        s.Enabled,
		Protocol:       s.Protocol,
		MaxConnections: s.MaxConnections,
		MinStreams:     s.MinStreams,
		MaxStreams:     s.MaxStreams,
		Padding:        s.Padding,
		Brutal:         s.BrutalOpts.Build(),
	}
}

type BrutalOptions struct {
	Enabled bool   `yaml:"enabled,omitempty"`
	Up      string `yaml:"up,omitempty"`
	Down    string `yaml:"down,omitempty"`
}

func (b *BrutalOptions) Build() *option.BrutalOptions {
	if b == nil {
		return nil
	}
	return &option.BrutalOptions{
		Enabled:  b.Enabled,
		UpMbps:   clashSpeedToIntMbps(b.Up),
		DownMbps: clashSpeedToIntMbps(b.Down),
	}
}

type RealityOptions struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

func (r *RealityOptions) Build() *option.OutboundRealityOptions {
	if r == nil {
		return nil
	}
	return &option.OutboundRealityOptions{
		Enabled:   true,
		PublicKey: r.PublicKey,
		ShortID:   r.ShortID,
	}
}

type ECHOptions struct {
	Enable          bool   `yaml:"enable,omitempty"`
	Config          string `yaml:"config,omitempty"`
	QueryServerName string `yaml:"query-server-name,omitempty"`
}

func (e *ECHOptions) Build() *option.OutboundECHOptions {
	if e == nil || !e.Enable {
		return nil
	}
	return &option.OutboundECHOptions{
		Enabled:         true,
		Config:          echConfigPEM(e.Config),
		QueryServerName: e.QueryServerName,
	}
}

// echConfigPEM converts a mihomo/Xray style base64 ECHConfigList into the
// "ECH CONFIGS" PEM lines sing-box expects. An empty or undecodable value
// returns nil, which falls back to fetching the config from DNS HTTPS records.
func echConfigPEM(config string) []string {
	config = strings.TrimSpace(config)
	if config == "" {
		return nil
	}
	if strings.Contains(config, "-----BEGIN") {
		return trimStringArray(strings.Split(config, "\n"))
	}
	list, err := base64.StdEncoding.DecodeString(config)
	if err != nil || len(list) == 0 {
		return nil
	}
	return trimStringArray(strings.Split(string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: list})), "\n"))
}

type TLSOptions struct {
	TLS               bool            `yaml:"tls,omitempty"`
	SNI               string          `yaml:"sni,omitempty"`
	SkipCertVerify    bool            `yaml:"skip-cert-verify,omitempty"`
	Fingerprint       string          `yaml:"fingerprint,omitempty"`
	ALPN              []string        `yaml:"alpn,omitempty"`
	ClientFingerprint string          `yaml:"client-fingerprint,omitempty"`
	CustomCA          string          `yaml:"ca,omitempty"`
	CustomCAString    string          `yaml:"ca-str,omitempty"`
	ECHOpts           *ECHOptions     `yaml:"ech-opts,omitempty"`
	RealityOpts       *RealityOptions `yaml:"reality-opts,omitempty"`
	KernelTx          bool            `yaml:"kernel-tx,omitempty"`
	KernelRx          bool            `yaml:"kernel-rx,omitempty"`
	// client certificate for mutual TLS, PEM content or a file path
	Certificate    string `yaml:"certificate,omitempty"`
	PrivateKey     string `yaml:"private-key,omitempty"`
	NameCertVerify string `yaml:"name-cert-verify,omitempty"`
}

func (t *TLSOptions) Build() *option.OutboundTLSOptions {
	if t == nil || !t.TLS {
		return nil
	}
	options := &option.OutboundTLSOptions{
		Enabled:              t.TLS,
		ServerName:           t.SNI,
		Insecure:             t.SkipCertVerify,
		CertificatePinSHA256: t.Fingerprint,
		ALPN:                 t.ALPN,
		UTLS:                 clashClientFingerprint(t.ClientFingerprint),
		Certificate:          trimStringArray(strings.Split(t.CustomCAString, "\n")),
		CertificatePath:      t.CustomCA,
		ECH:                  t.ECHOpts.Build(),
		Reality:              t.RealityOpts.Build(),
		KernelTx:             t.KernelTx,
		KernelRx:             t.KernelRx,
	}
	options.CertificateServerName = t.NameCertVerify
	options.ClientCertificate, options.ClientCertificatePath = clashPEMOrPath(t.Certificate)
	options.ClientKey, options.ClientKeyPath = clashPEMOrPath(t.PrivateKey)
	return options
}

// clashPEMOrPath splits a Clash certificate / key value, which is either the
// PEM content itself or a path to it.
func clashPEMOrPath(value string) (badoption.Listable[string], string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, ""
	}
	if strings.Contains(value, "-----BEGIN") {
		return trimStringArray(strings.Split(value, "\n")), ""
	}
	return nil, value
}

type ClashShadowTLSOptions struct {
	Password string `yaml:"password,omitempty"`
	Version  int    `yaml:"version,omitempty"`
}

func (o *ClashShadowTLSOptions) enabled() bool {
	return o != nil && (o.Password != "" || o.Version != 0)
}

// clashTLSExtensions are the mihomo security layers that replace the TLS
// handshake of vmess / vless / trojan / anytls.
type clashTLSExtensions struct {
	ShadowTLSOpts *ClashShadowTLSOptions `yaml:"shadow-tls-opts,omitempty"`
	RestlsOpts    map[string]any         `yaml:"restls-opts,omitempty"`
	JLSOpts       map[string]any         `yaml:"jls-opts,omitempty"`
	TLSMirrorOpts map[string]any         `yaml:"tlsmirror-opts,omitempty"`
}

func (e *clashTLSExtensions) unsupported() string {
	// mihomo treats each layer as configured once any of these fields is set
	switch {
	case clashStringOption(e.RestlsOpts, "password") != "" || clashStringOption(e.RestlsOpts, "version-hint") != "" ||
		clashStringOption(e.RestlsOpts, "restls-script") != "":
		return "restls is not implemented"
	case clashStringOption(e.JLSOpts, "password") != "" || clashStringOption(e.JLSOpts, "username") != "":
		return "JLS is not implemented"
	case clashStringOption(e.TLSMirrorOpts, "primary-key") != "":
		return "TLSMirror is not implemented"
	}
	return ""
}

// clashShadowTLSChain moves the TLS handshake of the outbound into a shadowtls
// outbound and dials through it, which is what mihomo does for shadow-tls:
// the TLS parameters authenticate the shadow-tls handshake and the proxy
// protocol then runs in plain text over it.
func clashShadowTLSChain(tag string, dialer *option.DialerOptions, server option.ServerOptions, tls *option.OutboundTLSOptionsContainer, password string, version int, alpn []string) []option.Outbound {
	if version == 0 {
		// mihomo's default
		version = 2
	}
	shadowTLS := common.PtrValueOrDefault(tls.TLS)
	shadowTLS.Enabled = true
	if len(shadowTLS.ALPN) == 0 {
		shadowTLS.ALPN = alpn
	}
	helperTag := tag + " (shadow-tls)"
	helper := option.Outbound{
		Type: C.TypeShadowTLS,
		Tag:  helperTag,
		Options: &option.ShadowTLSOutboundOptions{
			DialerOptions:               *dialer,
			ServerOptions:               server,
			Version:                     version,
			Password:                    password,
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &shadowTLS},
		},
	}
	*dialer = option.DialerOptions{Detour: helperTag}
	tls.TLS = nil
	return []option.Outbound{helper}
}

type DialerOptions struct {
	TFO         bool   `yaml:"tfo,omitempty"`
	MPTCP       bool   `yaml:"mptcp,omitempty"`
	Interface   string `yaml:"interface-name,omitempty"`
	RoutingMark int    `yaml:"routing-mark,omitempty"`
	DialerProxy string `yaml:"dialer-proxy,omitempty"`
}

func (b *DialerOptions) Build() option.DialerOptions {
	return option.DialerOptions{
		Detour: b.DialerProxy,
		AbstractDialerOptions: option.AbstractDialerOptions{
			BindInterface: b.Interface,
			TCPFastOpen:   b.TFO,
			TCPMultiPath:  b.MPTCP,
			RoutingMark:   option.FwMark(b.RoutingMark),
		},
	}
}

type ServerOptions struct {
	Server string `yaml:"server"`
	Port   int    `yaml:"port"`
}

func (s *ServerOptions) Build() option.ServerOptions {
	return option.ServerOptions{
		Server:     s.Server,
		ServerPort: uint16(s.Port),
	}
}

type shadowsocksPluginOptionsBuilder map[string]any

func (o shadowsocksPluginOptionsBuilder) Build() string {
	var opts []string
	for key, value := range o {
		if value == nil {
			continue
		}
		opts = append(opts, F.ToString(key, "=", value))
	}
	return strings.Join(opts, ";")
}

func clashClientFingerprint(clientFingerprint string) *option.OutboundUTLSOptions {
	if clientFingerprint == "" {
		return nil
	}
	return &option.OutboundUTLSOptions{
		Enabled:     true,
		Fingerprint: clientFingerprint,
	}
}

func clashHeaders(headers map[string]string) map[string]badoption.Listable[string] {
	if headers == nil {
		return nil
	}
	result := make(map[string]badoption.Listable[string])
	for key, value := range headers {
		result[key] = []string{value}
	}
	return result
}

func clashHysteria2Obfs(obfs string, password string) *option.Hysteria2Obfs {
	if obfs == "" {
		return nil
	}
	return &option.Hysteria2Obfs{
		Type:     obfs,
		Password: password,
	}
}

func clashNetworks(udpEnabled bool) option.NetworkList {
	if !udpEnabled {
		return N.NetworkTCP
	}
	return ""
}

func clashSnellNetworks(udpEnabled bool) option.NetworkList {
	if !udpEnabled {
		return N.NetworkTCP
	}
	return option.NetworkList(strings.Join([]string{N.NetworkTCP, N.NetworkUDP}, "\n"))
}

func clashStringOption(options map[string]any, key string) string {
	if options == nil {
		return ""
	}
	value, loaded := options[key]
	if !loaded || value == nil {
		return ""
	}
	return F.ToString(value)
}

func clashPluginName(plugin string) string {
	switch plugin {
	case "obfs":
		return "obfs-local"
	case "shadow-tls":
		// handled by ShadowSocksOption.chain
		return ""
	}
	return plugin
}

// clashV2RayPluginUnsupported reports v2ray-plugin options the built-in
// SIP003 implementation cannot express.
func clashV2RayPluginUnsupported(opts map[string]any) string {
	if mode := clashStringOption(opts, "mode"); mode != "" && mode != "websocket" {
		return "v2ray-plugin mode " + mode + " is not supported"
	}
	for _, key := range []string{"skip-cert-verify", "v2ray-http-upgrade"} {
		if clashBoolOption(opts, key) {
			return "v2ray-plugin " + key + " is not supported"
		}
	}
	for _, key := range []string{"fingerprint", "certificate", "private-key"} {
		if clashStringOption(opts, key) != "" {
			return "v2ray-plugin " + key + " is not supported"
		}
	}
	if headers, loaded := opts["headers"].(map[string]any); loaded && len(headers) > 0 {
		return "v2ray-plugin headers are not supported"
	}
	if ech, loaded := opts["ech-opts"].(map[string]any); loaded && clashBoolOption(ech, "enable") {
		return "v2ray-plugin ECH is not supported"
	}
	return ""
}

func clashBoolOption(options map[string]any, key string) bool {
	value, _ := options[key].(bool)
	return value
}

func clashStringListOption(options map[string]any, key string) []string {
	values, _ := options[key].([]any)
	var result []string
	for _, value := range values {
		result = append(result, F.ToString(value))
	}
	return result
}

func clashPluginOptions(plugin string, opts map[string]any) string {
	options := make(shadowsocksPluginOptionsBuilder)
	switch plugin {
	case "obfs":
		options["obfs"] = opts["mode"]
		options["obfs-host"] = opts["host"]
	case "v2ray-plugin":
		options["mode"] = opts["mode"]
		// the plugin enables TLS when the key is present at all
		if clashBoolOption(opts, "tls") {
			options["tls"] = ""
		}
		options["host"] = opts["host"]
		options["path"] = opts["path"]
		// Clash mux is a switch defaulting to off, the plugin takes a
		// concurrency defaulting to 1.
		if clashBoolOption(opts, "mux") {
			options["mux"] = 1
		} else {
			options["mux"] = 0
		}
	}
	return options.Build()
}

func clashPorts(ports string) badoption.Listable[string] {
	if ports == "" {
		return nil
	}
	serverPorts := badoption.Listable[string]{}
	ports = strings.ReplaceAll(ports, "/", ",")
	for port := range strings.SplitSeq(ports, ",") {
		if port == "" {
			continue
		}
		port = strings.Replace(port, "-", ":", 1)
		serverPorts = append(serverPorts, port)
	}
	return serverPorts
}

func clashShadowsocksCipher(cipher string) string {
	switch cipher {
	case "dummy":
		return "none"
	}
	return cipher
}

func clashStringList(list []string) string {
	if len(list) > 0 {
		return list[0]
	}
	return ""
}

func clashSpeedToIntMbps(speed string) int {
	if speed == "" {
		return 0
	}
	if num, err := strconv.Atoi(speed); err == nil {
		return num
	}
	networkBytes := clashSpeedToNetworkBytes(speed)
	if networkBytes == nil {
		return 0
	}
	// Value is in bytes per second.
	return int(networkBytes.Value() * 8 / 1_000_000)
}

func clashSpeedToNetworkBytes(speed string) *byteformats.NetworkBytesCompat {
	if speed == "" {
		return nil
	}
	networkBytes := &byteformats.NetworkBytesCompat{}
	speed = strings.TrimSpace(speed)
	if num, err := strconv.Atoi(speed); err == nil {
		// Clash treats a bare number as Mbps.
		speed = F.ToString(num, "Mbps")
	} else if unitIndex := len(speed) - len("mbps"); unitIndex > 0 && speed[unitIndex:] == strings.ToLower(speed[unitIndex:]) &&
		strings.HasSuffix(speed, "bps") && strings.ContainsRune("kmgt", rune(speed[unitIndex])) {
		// An all lowercase unit such as "100 mbps" can only mean bits.
		speed = speed[:unitIndex] + strings.ToUpper(speed[unitIndex:unitIndex+1]) + "bps"
	}
	// UnmarshalJSON expects a JSON string, not the raw "10 Mbps" text.
	content, err := json.Marshal(speed)
	if err != nil {
		return nil
	}
	if err = networkBytes.UnmarshalJSON(content); err != nil {
		return nil
	}
	return networkBytes
}

// clashTransportUnsupported reports Clash networks without a transport here;
// building them would silently fall back to plain TCP.
func clashTransportUnsupported(network string) string {
	switch network {
	case "", "tcp", "ws", "http", "h2", "grpc", "xhttp":
		return ""
	case "kcp", "mkcp":
		return "the mKCP transport is not implemented"
	case "mekya":
		return "the mekya transport is not implemented"
	default:
		return "unknown network: " + network
	}
}

func clashTransport(network string, httpOpts HTTPOptions, h2Opts HTTP2Options, grpcOpts GrpcOptions, wsOpts WSOptions, xhttp clashXHTTP) *option.V2RayTransportOptions {
	switch network {
	case "xhttp":
		return xhttp.build()
	case "http":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Method:  httpOpts.Method,
				Path:    clashStringList(httpOpts.Path),
				Headers: httpOpts.Headers,
			},
		}
	case "h2":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Path: h2Opts.Path,
				Host: h2Opts.Host,
			},
		}
	case "grpc":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: grpcOpts.GrpcServiceName,
				IdleTimeout: badoption.Duration(time.Duration(grpcOpts.PingInterval) * time.Second),
			},
		}
	case "ws":
		headers := clashHeaders(wsOpts.Headers)
		if wsOpts.V2rayHttpUpgrade {
			var host string
			if headers != nil && headers["Host"] != nil {
				host = headers["Host"][0]
			}
			return &option.V2RayTransportOptions{
				Type: C.V2RayTransportTypeHTTPUpgrade,
				HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
					Host:    host,
					Path:    wsOpts.Path,
					Headers: headers,
				},
			}
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:                wsOpts.Path,
				Headers:             headers,
				MaxEarlyData:        uint32(wsOpts.MaxEarlyData),
				EarlyDataHeaderName: wsOpts.EarlyDataHeaderName,
			},
		}
	default:
		return nil
	}
}

func clashTLSOptions(server string, tlsOptions *TLSOptions) option.OutboundTLSOptionsContainer {
	if tlsOptions != nil && tlsOptions.SNI == "" {
		tlsOptions.SNI = server
	}
	return option.OutboundTLSOptionsContainer{
		TLS: tlsOptions.Build(),
	}
}

func trimStringArray(array []string) []string {
	return common.Filter(array, func(it string) bool {
		return strings.TrimSpace(it) != ""
	})
}
