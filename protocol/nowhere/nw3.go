package nowhere

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	singtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/morph"
	nw2wire "github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
	"github.com/sagernet/sing-box/protocol/nowhere/core/portal"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

// nowhereStack selects the Nowhere protocol stack of one endpoint. The stack is
// derived from the single configured TLS ALPN: an empty or nw3 ALPN selects
// Nowhere 3 (the default), any other single ALPN selects the legacy Nowhere 2
// stack kept for compatibility with pre-nw3 peers. The two stacks share no
// handshake: a single inbound/outbound runs exactly one stack, and the fields
// of the other stack are rejected.
type nowhereStack int

const (
	nowhereStackNw2 nowhereStack = iota
	nowhereStackNw3
)

// resolveNowhereStack maps the configured ALPN to a stack. An empty list (or a
// single empty value) means Nowhere 3, which keeps nw3 the default for every
// configuration that does not opt into the legacy stack. Exactly one ALPN is
// required; any single non-nw3 value selects Nowhere 2, which preserves
// existing nw2 configurations that use a custom ALPN.
func resolveNowhereStack(alpn badoption.Listable[string]) (nowhereStack, error) {
	switch len(alpn) {
	case 0:
		return nowhereStackNw3, nil
	case 1:
		if alpn[0] == "" || alpn[0] == wire.ALPN {
			return nowhereStackNw3, nil
		}
		return nowhereStackNw2, nil
	default:
		return 0, E.New("nowhere: exactly one ALPN is required")
	}
}

// nowhereOutboundALPN and nowhereInboundALPN return the configured ALPN list,
// tolerating a nil TLS container: an endpoint without TLS selects the default
// nw3 stack and fails the TLS requirement inside the Nowhere 3 constructors.
func nowhereOutboundALPN(options *option.NowhereOutboundOptions) badoption.Listable[string] {
	if options.TLS == nil {
		return nil
	}
	return options.TLS.ALPN
}

func nowhereInboundALPN(options *option.NowhereInboundOptions) badoption.Listable[string] {
	if options.TLS == nil {
		return nil
	}
	return options.TLS.ALPN
}

// resolveNowhereMorph applies the per-stack Morph default: Nowhere 2 leaves the
// transform off, Nowhere 3 turns it on. An explicit value always wins.
func resolveNowhereMorph(raw *bool, stack nowhereStack) bool {
	if raw != nil {
		return *raw
	}
	return stack == nowhereStackNw3
}

// nowhereV3NetTCP and nowhereV3NetUDP are the two Nowhere 3 transports. Nowhere
// 3 speaks exactly one of them per endpoint: tcp is TLS over TCP, udp is QUIC.
const (
	nowhereV3NetTCP = "tcp"
	nowhereV3NetUDP = "udp"
)

// nowhereV3Net resolves the single Nowhere 3 transport. Nowhere 3 uses exactly
// one: tcp (TLS over TCP) or udp (QUIC). Empty means tcp.
func nowhereV3Net(raw string) (string, error) {
	switch raw {
	case "", nowhereV3NetTCP:
		return nowhereV3NetTCP, nil
	case nowhereV3NetUDP:
		return nowhereV3NetUDP, nil
	default:
		return "", E.New("nowhere: net must be tcp or udp, got ", raw)
	}
}

// validateNowhereV3OutboundTLS rejects TLS container fields Nowhere 3 cannot
// honor: the vendored stack pins TLS 1.3 and ALPN nw3 and uses the standard
// library TLS implementation, so uTLS/ECH/REALITY and version overrides would
// silently do nothing. The ALPN itself already selected the nw3 stack, so
// only the empty list and ["nw3"] reach this check.
func validateNowhereV3OutboundTLS(options *option.OutboundTLSOptions) error {
	if options == nil || !options.Enabled {
		return E.New("nowhere: tls is required")
	}
	if options.MinVersion != "" || options.MaxVersion != "" {
		return E.New("nowhere: Nowhere 3 fixes TLS 1.3; remove tls.min_version and tls.max_version")
	}
	if options.UTLS != nil {
		return E.New("nowhere: Nowhere 3 uses the standard TLS stack; remove tls.utls")
	}
	if options.ECH != nil {
		return E.New("nowhere: Nowhere 3 uses the standard TLS stack; remove tls.ech")
	}
	if options.Reality != nil {
		return E.New("nowhere: Nowhere 3 does not support REALITY")
	}
	return nil
}

// validateNowhereV3InboundTLS is the inbound counterpart of
// validateNowhereV3OutboundTLS: certificates stay configurable, but the
// protocol pins version and ALPN and the vendored Portal owns the handshake,
// so ACME/ECH/REALITY and version overrides are rejected.
func validateNowhereV3InboundTLS(options *option.InboundTLSOptions) error {
	if options == nil || !options.Enabled {
		return E.New("nowhere: tls is required")
	}
	if options.MinVersion != "" || options.MaxVersion != "" {
		return E.New("nowhere: Nowhere 3 fixes TLS 1.3; remove tls.min_version and tls.max_version")
	}
	if options.ACME != nil || options.CertificateProvider != nil {
		return E.New("nowhere: Nowhere 3 requires a static certificate; remove tls.acme and tls.certificate_provider")
	}
	if options.ECH != nil {
		return E.New("nowhere: Nowhere 3 uses the standard TLS stack; remove tls.ech")
	}
	if options.Reality != nil {
		return E.New("nowhere: Nowhere 3 does not support REALITY")
	}
	return nil
}

// buildNowhereV3ClientTLS produces the standard-library client config the
// vendored Vector uses for the TLS transport and for QUIC dials. Trust follows
// Nowhere 3: system roots plus the endpoint host name by default, pin overrides
// everything, and the explicit insecure escape hatch skips verification.
func buildNowhereV3ClientTLS(ctx context.Context, logger log.ContextLogger, server string, tlsOptions option.OutboundTLSOptions, pin string) (*tls.Config, error) {
	if err := validateNowhereV3OutboundTLS(&tlsOptions); err != nil {
		return nil, err
	}
	client, err := singtls.NewClient(ctx, logger, server, tlsOptions)
	if err != nil {
		return nil, err
	}
	std, err := client.STDConfig()
	if err != nil {
		return nil, E.Cause(err, "nowhere: read std TLS config")
	}
	cfg := std.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	cfg.NextProtos = []string{wire.ALPN}
	cfg.ClientSessionCache = nil
	// singtls seeds ServerName from the raw server address, which includes the
	// port. RFC 6066 forbids a port in the SNI host name and the Rust Portal's
	// rustls acceptor rejects such a ClientHello before TLS ever starts, so
	// normalize to the bare host for every verification mode.
	cfg.ServerName = nowhereV3ServerName(server, tlsOptions.ServerName, tlsOptions.DisableSNI)
	parsed, err := nw2wire.ParseCertificatePin(pin)
	if err != nil {
		return nil, err
	}
	switch {
	case parsed != "":
		verifier, err := nw2wire.PeerCertificatePinVerifier(parsed)
		if err != nil {
			return nil, err
		}
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = verifier
	case tlsOptions.Insecure || tlsOptions.DisableSNI:
		cfg.InsecureSkipVerify = true
	default:
		// System roots plus host name. The vendored stack performs the
		// handshake itself, so ServerName must already be set here.
		// cfg.RootCAs = nil
		if cfg.ServerName == "" {
			cfg.ServerName = nowhereV3ServerName(server, tlsOptions.ServerName, tlsOptions.DisableSNI)
		}
	}
	return cfg, nil
}

// buildNowhereV3ServerTLS produces the standard-library server config the
// vendored Portal uses for its own handshakes on both transports.
func buildNowhereV3ServerTLS(ctx context.Context, logger log.ContextLogger, tlsOptions option.InboundTLSOptions) (*tls.Config, error) {
	if err := validateNowhereV3InboundTLS(&tlsOptions); err != nil {
		return nil, err
	}
	server, err := singtls.NewServer(ctx, logger, tlsOptions)
	if err != nil {
		return nil, err
	}
	std, err := server.STDConfig()
	if err != nil {
		return nil, E.Cause(err, "nowhere: read std TLS config")
	}
	cfg := std.Clone()
	// The sing-box STD server config installs a GetConfigForClient callback
	// returning its internal config, which would bypass the pins below during
	// the handshake. Point the callback at the clone instead.
	cfg.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		return cfg, nil
	}
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	cfg.NextProtos = []string{wire.ALPN}
	cfg.SessionTicketsDisabled = true
	return cfg, nil
}

// nowhereV3ServerName resolves the verification name: an explicit server_name
// wins, disable_sni clears it, otherwise the endpoint host is used.
func nowhereV3ServerName(server, serverName string, disableSNI bool) string {
	if serverName != "" {
		return serverName
	}
	if disableSNI {
		return ""
	}
	if host, _, err := net.SplitHostPort(server); err == nil {
		return host
	}
	return server
}

// validateNowhereV3InboundOptions rejects the nw2-only inbound fields Nowhere 3
// cannot honor. The vendored Portal owns its own admission limits and speaks
// only nw3, and Nowhere 3 has no native Portal chaining.
func validateNowhereV3InboundOptions(options *option.NowhereInboundOptions) error {
	if options.Next != nil {
		return E.New("nowhere: Nowhere 3 does not support next chaining")
	}
	if options.MaxUnauthenticatedConnections != nil || options.MaxUnauthenticatedPerSource != nil {
		return E.New("nowhere: Nowhere 3 admission limits are fixed; remove max_unauthenticated_connections and max_unauthenticated_per_source")
	}
	return nil
}

// validateNowhereNw2InboundOptions rejects the Nowhere 3-only inbound fields on
// the legacy nw2 stack: net selects the single nw3 transport, and the egress
// bridge only exists on the nw3 Portal.
func validateNowhereNw2InboundOptions(options *option.NowhereInboundOptions) error {
	if options.Net != "" {
		return E.New("nowhere: net is a Nowhere 3 field; remove it or select the Nowhere 3 stack with tls.alpn [\"nw3\"]")
	}
	if options.Egress {
		return E.New("nowhere: egress is a Nowhere 3 field; remove it or select the Nowhere 3 stack with tls.alpn [\"nw3\"]")
	}
	return nil
}

// validateNowhereV3InboundNetworks keeps the network field consistent with the
// single Nowhere 3 transport: the net already decides TCP or UDP, so an
// explicit network list may only name that one transport.
func validateNowhereV3InboundNetworks(options *option.NowhereInboundOptions, net string) error {
	if options.Network == "" {
		return nil
	}
	expected := N.NetworkTCP
	if net == nowhereV3NetUDP {
		expected = N.NetworkUDP
	}
	networks := options.Network.Build()
	if len(networks) != 1 || networks[0] != expected {
		return E.New("nowhere: Nowhere 3 net ", net, " implies network ", expected, "; remove network or set it to ", expected)
	}
	return nil
}

// validateNowhereV3OutboundOptions rejects the nw2-only outbound fields: the
// vendored Vector speaks one transport with fixed pooling, so up/down/mux/pool
// and the warm-dial knobs have no Nowhere 3 meaning.
func validateNowhereV3OutboundOptions(options *option.NowhereOutboundOptions) error {
	if options.Up != "" || options.Down != "" {
		return E.New("nowhere: Nowhere 3 uses one transport; remove up and down")
	}
	if options.Mux != nil {
		return E.New("nowhere: Nowhere 3 has no multiplexing; remove mux")
	}
	if options.Pool != nil {
		return E.New("nowhere: Nowhere 3 has no connection pool; remove pool")
	}
	if options.PrewarmOnStart {
		return E.New("nowhere: Nowhere 3 has no prewarming; remove prewarm_on_start")
	}
	if options.MaxConcurrentDials != nil {
		return E.New("nowhere: Nowhere 3 has no max_concurrent_dials; remove it")
	}
	if options.WarmBackoffInitial > 0 || options.WarmBackoffMax > 0 {
		return E.New("nowhere: Nowhere 3 has no warm backoff; remove warm_backoff_initial and warm_backoff_max")
	}
	return nil
}

// validateNowhereNw2OutboundOptions rejects the Nowhere 3-only net field on the
// legacy nw2 stack, which selects its transports via up/down instead.
func validateNowhereNw2OutboundOptions(options *option.NowhereOutboundOptions) error {
	if options.Net != "" {
		return E.New("nowhere: net is a Nowhere 3 field; remove it or select the Nowhere 3 stack with tls.alpn [\"nw3\"]")
	}
	return nil
}

// logNowhereV3PortalFingerprint prints the leaf certificate SHA-256 so users
// can obtain a pin= value, matching the reference Portal's startup log.
func logNowhereV3PortalFingerprint(logger log.ContextLogger, tlsConfig *tls.Config) {
	if logger == nil || tlsConfig == nil || len(tlsConfig.Certificates) == 0 {
		return
	}
	leaf := tlsConfig.Certificates[0].Leaf
	if leaf == nil {
		return
	}
	logger.Info("nowhere TLS certificate SHA-256 fingerprint: ", nw2wire.LeafCertificateSHA256Hex(leaf.Raw))
}

// routerNw3Upstream adapts the SingBox router to the Nowhere 3 Upstream
// interface shared by the Portal (normal mode) and the Egress client. Both
// receive a target only, so the source address is left unspecified.
type routerNw3Upstream struct {
	tag    string
	typ    string
	detour string
	router adapter.ConnectionRouterEx
}

func newRouterNw3Upstream(tag, typ, detour string, router adapter.ConnectionRouterEx) *routerNw3Upstream {
	return &routerNw3Upstream{tag: tag, typ: typ, detour: detour, router: router}
}

func (u *routerNw3Upstream) DialTCP(ctx context.Context, target wire.Target) (net.Conn, error) {
	ctx = log.ContextWithNewID(ctx)
	local, remote := net.Pipe()
	u.router.RouteConnectionEx(ctx, remote, u.metadata(target), nil)
	return local, nil
}

func (u *routerNw3Upstream) DialUDP(ctx context.Context, target wire.Target) (net.Conn, error) {
	ctx = log.ContextWithNewID(ctx)
	packetConn := newPacketPipe()
	u.router.RoutePacketConnectionEx(ctx, packetConn, u.metadata(target), nil)
	return packetConn.netConn(), nil
}

func (u *routerNw3Upstream) metadata(target wire.Target) adapter.InboundContext {
	var metadata adapter.InboundContext
	metadata.Inbound = u.tag
	metadata.InboundType = u.typ
	metadata.InboundDetour = u.detour
	metadata.Source = M.SocksaddrFrom(netip.IPv4Unspecified(), 0)
	metadata.Destination = M.ParseSocksaddr(target.HostPort())
	return metadata
}

// nowhereV3MorphKeys derives the Nowhere 3 Morph keys for the QUIC transport.
// The TCP transport is wrapped inside the vendored Vector/Portal, so only QUIC
// dials and QUIC listeners need this host-side derivation.
func nowhereV3MorphKeys(password string) morph.Keys {
	return morph.Derive([]byte(password))
}

// packetPipe is an in-memory N.PacketConn pair: the router side reads and
// writes packets through the sing interface while the protocol side sees a
// datagram-oriented net.Conn. One Read/Write moves exactly one packet.
type packetPipe struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}

	closeOnce     sync.Once
	readDeadline  pipe.Deadline
	writeDeadline pipe.Deadline
}

func newPacketPipe() *packetPipe {
	return &packetPipe{
		in:            make(chan []byte, 64),
		out:           make(chan []byte, 64),
		closed:        make(chan struct{}),
		readDeadline:  pipe.MakeDeadline(),
		writeDeadline: pipe.MakeDeadline(),
	}
}

func (p *packetPipe) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case payload := <-p.in:
		n := copy(buffer.FreeBytes(), payload)
		buffer.Truncate(n)
		return M.Socksaddr{}, nil
	case <-p.closed:
		return M.Socksaddr{}, net.ErrClosed
	case <-p.readDeadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (p *packetPipe) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	payload := make([]byte, len(buffer.Bytes()))
	copy(payload, buffer.Bytes())
	buffer.Release()
	select {
	case p.out <- payload:
		return nil
	case <-p.closed:
		return net.ErrClosed
	case <-p.writeDeadline.Wait():
		return os.ErrDeadlineExceeded
	}
}

func (p *packetPipe) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *packetPipe) LocalAddr() net.Addr { return M.Socksaddr{} }

func (p *packetPipe) SetDeadline(t time.Time) error {
	p.readDeadline.Set(t)
	p.writeDeadline.Set(t)
	return nil
}

func (p *packetPipe) SetReadDeadline(t time.Time) error {
	p.readDeadline.Set(t)
	return nil
}

func (p *packetPipe) SetWriteDeadline(t time.Time) error {
	p.writeDeadline.Set(t)
	return nil
}

// packetPipeConn is the datagram-oriented net.Conn facade the Nowhere 3
// Portal/Egress upstream uses on the protocol side of a packetPipe. Its
// directions are opposite to the N.PacketConn methods: a Write hands a
// user-to-target packet to the router (it lands on the channel ReadPacket
// drains), and a Read takes a target-to-user packet the router wrote (from the
// channel WritePacket feeds).
type packetPipeConn struct {
	*packetPipe
}

func (p *packetPipe) netConn() net.Conn {
	return &packetPipeConn{packetPipe: p}
}

func (c *packetPipeConn) Read(b []byte) (int, error) {
	select {
	case payload := <-c.out:
		return copy(b, payload), nil
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.readDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *packetPipeConn) Write(b []byte) (int, error) {
	payload := make([]byte, len(b))
	copy(payload, b)
	select {
	case c.in <- payload:
		return len(b), nil
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *packetPipeConn) RemoteAddr() net.Addr { return M.Socksaddr{} }

var (
	_ portal.Upstream = (*routerNw3Upstream)(nil)
	_ N.PacketConn    = (*packetPipe)(nil)
	_ net.Conn        = (*packetPipeConn)(nil)
)
