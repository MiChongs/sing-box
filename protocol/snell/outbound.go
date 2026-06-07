package snellprotocol

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	snell "github.com/reF1nd/sing-snell"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	obfs "github.com/sagernet/sing-box/transport/simple-obfs"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SnellOutboundOptions](registry, C.TypeSnell, NewOutbound)
}

// quicDestCacheTTL is how long a destination is remembered as a QUIC proxy
// target. After a proxy-side connection drop (e.g. Clash API kill), the QUIC
// client stack may send 1-RTT short-header packets (0x40-0x7f) before learning
// of the disconnect. Those cannot be sniffed as QUIC ClientHello, so sniffQUIC
// would be false and the flow would fall through to UoT. The cache restores the
// QUIC proxy path without the false-positive risk of widening the byte check
// unconditionally.
//
// Aligned with the default sing-box UDP NAT timeout (5 minutes): beyond that
// window the NAT entry is gone and the cache entry is no longer useful.
const quicDestCacheTTL = 5 * time.Minute

type Outbound struct {
	outbound.Adapter
	logger     log.ContextLogger
	dialer     N.Dialer
	client     *snell.Client
	pool       *snell.Pool
	serverAddr M.Socksaddr
	obfsMode   string
	obfsHost   string
	serverPort string
	psk        []byte
	version    int
	// quicDestCache records 4-tuples that recently used the QUIC proxy path.
	// Keyed by quicDestCacheKey{source, destination}. Values are time.Time.
	// Using the full 4-tuple avoids misrouting when multiple source IPs reach
	// the same destination via different protocols.
	quicDestCache sync.Map
}

type quicDestCacheKey struct {
	source      M.Socksaddr
	destination M.Socksaddr
}

func (h *Outbound) isRecentQUICDest(source, destination M.Socksaddr) bool {
	key := quicDestCacheKey{source, destination}
	v, ok := h.quicDestCache.Load(key)
	if !ok {
		return false
	}
	if time.Since(v.(time.Time)) > quicDestCacheTTL {
		h.quicDestCache.Delete(key)
		return false
	}
	return true
}

func (h *Outbound) markQUICDest(source, destination M.Socksaddr) {
	h.quicDestCache.Store(quicDestCacheKey{source, destination}, time.Now())
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellOutboundOptions) (adapter.Outbound, error) {
	if options.PSK == "" {
		return nil, E.New("snell: psk is required")
	}

	switch options.ObfsMode {
	case "", "http":
	case "tls":
		ver := options.Version
		if ver == 0 {
			ver = snell.DefaultVersion
		}
		if ver >= snell.Version4 {
			return nil, E.New("snell: obfs_mode TLS is insecure and not supported for v4/v5; use ShadowTLS instead")
		}
	default:
		return nil, E.New("snell: unsupported obfs mode: ", options.ObfsMode)
	}

	serverAddr := options.ServerOptions.Build()

	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	version := options.Version
	if version == 0 {
		version = snell.DefaultVersion
	}

	// Build network list. If the user specified an explicit `network` field use
	// that; otherwise apply the protocol default: v3/v4/v5 enable TCP+UDP by
	// default, while v1/v2 default to TCP-only (no UDP support).
	var networks []string
	if string(options.Network) != "" {
		networks = options.Network.Build()
		for _, net := range networks {
			if net == N.NetworkUDP && version < snell.Version3 {
				return nil, E.New("snell: UDP requires version 3 or above")
			}
		}
	} else if version >= snell.Version3 {
		networks = []string{N.NetworkTCP, N.NetworkUDP}
	} else {
		networks = []string{N.NetworkTCP}
	}

	client, err := snell.NewClient([]byte(options.PSK), version)
	if err != nil {
		return nil, err
	}

	o := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeSnell, tag, networks, options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		client:     client,
		serverAddr: serverAddr,
		obfsMode:   options.ObfsMode,
		obfsHost:   options.ObfsHost,
		serverPort: fmt.Sprintf("%d", serverAddr.Port),
		psk:        []byte(options.PSK),
		version:    version,
	}

	// Connection reuse (v4+): build a pool whose factory dials + encrypts a
	// fresh stream.  The pool is only active when reuse is explicitly enabled.
	if options.Reuse && version >= snell.Version4 {
		o.pool = snell.NewPool(func(ctx context.Context) (net.Conn, error) {
			rawConn, err := outboundDialer.DialContext(ctx, N.NetworkTCP, serverAddr)
			if err != nil {
				return nil, err
			}
			return client.WrapStream(o.applyObfs(rawConn)), nil
		})
	}

	return o, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		if h.pool != nil {
			return h.client.DialContextWithPool(ctx, h.pool, destination)
		}
		rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, err
		}
		conn := h.applyObfs(rawConn)
		return h.client.DialContext(ctx, conn, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound UDP connection to ", destination)
		if h.version >= snell.Version5 {
			pc := newV5LazyPacketConn(ctx, h, metadata.Source, destination, metadata.Protocol == C.ProtocolQUIC)
			return &packetConnWrapper{PacketConn: pc, destination: destination}, nil
		}
		rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, err
		}
		conn := h.applyObfs(rawConn)
		udpStream, err := h.client.DialUDP(ctx, conn)
		if err != nil {
			return nil, err
		}
		pc := snell.NewClientPacketConn(udpStream)
		return &packetConnWrapper{PacketConn: pc, destination: destination}, nil
	}
	return nil, os.ErrInvalid
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination

	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)

	if h.version >= snell.Version5 {
		sniffQUIC := metadata.Protocol == C.ProtocolQUIC || h.isRecentQUICDest(metadata.Source, destination)
		return newV5LazyPacketConn(ctx, h, metadata.Source, destination, sniffQUIC), nil
	}

	rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	conn := h.applyObfs(rawConn)
	udpStream, err := h.client.DialUDP(ctx, conn)
	if err != nil {
		return nil, err
	}
	return snell.NewClientPacketConn(udpStream), nil
}

// dialUDPOverTCP creates a UDP-over-TCP tunnel (v3/v4/v5 fallback for non-QUIC UDP).
func (h *Outbound) dialUDPOverTCP(ctx context.Context) (net.PacketConn, error) {
	rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	conn := h.applyObfs(rawConn)
	udpStream, err := h.client.DialUDP(ctx, conn)
	if err != nil {
		return nil, err
	}
	return snell.NewClientPacketConn(udpStream), nil
}

// dialQUICProxy creates a QUIC proxy PacketConn (v5 only).
// initPayload is the first QUIC Initial packet; it is sent as part of the init frame.
func (h *Outbound) dialQUICProxy(ctx context.Context, destination M.Socksaddr, initPayload []byte) (net.PacketConn, error) {
	rawConn, err := h.dialer.DialContext(ctx, N.NetworkUDP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	return snell.NewQUICProxyPacketConn(rawConn, h.psk, destination, initPayload)
}

// v5LazyPacketConn defers connection establishment to the first WriteTo call,
// allowing mode selection between QUIC proxy and UDP-over-TCP.
//
// Mode selection priority:
//  1. sniffQUIC == true  (router sniff identified QUIC before reaching this outbound)
//  2. first payload byte >= 0xc0  (QUIC long-header, e.g. Initial / Handshake / 0-RTT)
//
// Using sniff as primary handles the 0-RTT resumption case where the first packet
// is a short-header (0x40-0x7f) and would otherwise be misclassified.
type v5LazyPacketConn struct {
	outbound    *Outbound
	ctx         context.Context
	source      M.Socksaddr
	destination M.Socksaddr
	// sniffQUIC is set when the router's sniff result identified this flow as QUIC.
	// It takes priority over the first-byte heuristic.
	sniffQUIC bool

	once           sync.Once
	initCh         chan struct{} // closed once conn is ready
	conn           net.PacketConn
	connErr        error
	firstWriteQUIC bool // true when dialQUICProxy consumed initPayload

	// closeRequested is set to 1 by Close(). If initConn is still in progress
	// when Close() is called, initConn will close the conn after it finishes.
	closeRequested atomic.Bool
	closeOnce      sync.Once // ensures conn.Close is called at most once

	// pendingReadDL stores a read (or combined) deadline set via
	// SetReadDeadline / SetDeadline before initConn completes.
	// Applied to conn inside ReadFrom after <-initCh unblocks.
	// Zero value means no pending deadline.
	pendingDLMu   sync.Mutex
	pendingReadDL time.Time
}

func newV5LazyPacketConn(ctx context.Context, ob *Outbound, src, dst M.Socksaddr, sniffQUIC bool) *v5LazyPacketConn {
	return &v5LazyPacketConn{
		outbound:    ob,
		ctx:         ctx,
		source:      src,
		destination: dst,
		sniffQUIC:   sniffQUIC,
		initCh:      make(chan struct{}),
	}
}

func (c *v5LazyPacketConn) initConn(p []byte, addr net.Addr) {
	useQUIC := c.sniffQUIC || (len(p) > 0 && snell.IsQUICInitial(p[0]))
	if useQUIC {
		// Always use c.destination (resolved at ListenPacket/DialContext time, after
		// FakeIP reverse-lookup and routing) as the QUIC proxy target.
		// Do NOT use addr here, which carries the fake IP in TUN+FakeIP scenarios.
		conn, err := c.outbound.dialQUICProxy(c.ctx, c.destination, p)
		c.conn = conn
		c.connErr = err
		c.firstWriteQUIC = (err == nil)
		// Record this destination so that subsequent connections (e.g. after a
		// Clash API kill) are also routed via QUIC proxy even when the first packet
		// is a 1-RTT short-header that cannot be sniffed as QUIC ClientHello.
		if err == nil {
			c.outbound.markQUICDest(c.source, c.destination)
		}
	} else {
		conn, err := c.outbound.dialUDPOverTCP(c.ctx)
		c.conn = conn
		c.connErr = err
	}
	close(c.initCh)
	// If Close() arrived while we were dialling, close the conn now so that
	// any blocked ReadFrom returns instead of hanging forever.
	if c.closeRequested.Load() {
		c.closeOnce.Do(func() {
			if c.conn != nil {
				c.conn.Close()
			}
		})
	}
}

func (c *v5LazyPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	var firstWriteQUIC bool
	c.once.Do(func() {
		c.initConn(p, addr)
		firstWriteQUIC = c.firstWriteQUIC
	})
	<-c.initCh
	if c.connErr != nil {
		return 0, c.connErr
	}
	// For QUIC proxy first write, the payload was already sent inside dialQUICProxy.
	if firstWriteQUIC {
		return len(p), nil
	}
	return c.conn.WriteTo(p, addr)
}

func (c *v5LazyPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	<-c.initCh
	if c.connErr != nil {
		return 0, nil, c.connErr
	}
	// Apply any read deadline that was stored before initConn completed.
	// Without this, a SetReadDeadline call that arrived during the dial window
	// would be silently dropped, leaving ReadFrom without a timeout.
	c.pendingDLMu.Lock()
	if !c.pendingReadDL.IsZero() {
		_ = c.conn.SetReadDeadline(c.pendingReadDL)
		c.pendingReadDL = time.Time{}
	}
	c.pendingDLMu.Unlock()
	return c.conn.ReadFrom(p)
}

// ReadPacket implements N.NetPacketConn, allowing bufio.NewPacketConn to use
// this type directly instead of wrapping it in ExtendedPacketConn. This
// preserves the FQDN source address through the relay chain.
func (c *v5LazyPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, addr, err := c.ReadFrom(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return M.SocksaddrFromNet(addr).Unwrap(), nil
}

// WritePacket implements N.NetPacketConn. Passing destination as M.Socksaddr
// directly (rather than converting to *net.UDPAddr first) ensures that FQDN
// destinations are forwarded correctly when the underlying conn is a
// ClientPacketConn (UoT fallback mode).
func (c *v5LazyPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	_, err := c.WriteTo(buffer.Bytes(), destination)
	return err
}

func (c *v5LazyPacketConn) Close() error {
	// Signal intent before the select so initConn's post-close check is
	// guaranteed to observe it if initCh is not yet closed.
	c.closeRequested.Store(true)
	select {
	case <-c.initCh:
		// initConn has finished; close the underlying conn exactly once.
		var err error
		c.closeOnce.Do(func() {
			if c.conn != nil {
				err = c.conn.Close()
			}
		})
		return err
	default:
		// initConn is still in progress; it will call closeOnce after finishing.
		return nil
	}
}

func (c *v5LazyPacketConn) LocalAddr() net.Addr {
	select {
	case <-c.initCh:
		if c.conn != nil {
			return c.conn.LocalAddr()
		}
	default:
	}
	return &net.UDPAddr{}
}

func (c *v5LazyPacketConn) SetDeadline(t time.Time) error {
	select {
	case <-c.initCh:
		// initConn finished; clear any stale pending deadline and apply directly.
		c.pendingDLMu.Lock()
		c.pendingReadDL = time.Time{}
		c.pendingDLMu.Unlock()
		if c.conn != nil {
			return c.conn.SetDeadline(t)
		}
		return nil
	default:
		// initConn still in progress; store for ReadFrom to apply after init.
		c.pendingDLMu.Lock()
		c.pendingReadDL = t
		c.pendingDLMu.Unlock()
		return nil
	}
}

func (c *v5LazyPacketConn) SetReadDeadline(t time.Time) error {
	select {
	case <-c.initCh:
		// initConn finished; clear any stale pending deadline and apply directly.
		c.pendingDLMu.Lock()
		c.pendingReadDL = time.Time{}
		c.pendingDLMu.Unlock()
		if c.conn != nil {
			return c.conn.SetReadDeadline(t)
		}
		return nil
	default:
		// initConn still in progress; store for ReadFrom to apply after init.
		c.pendingDLMu.Lock()
		c.pendingReadDL = t
		c.pendingDLMu.Unlock()
		return nil
	}
}

func (c *v5LazyPacketConn) SetWriteDeadline(t time.Time) error {
	select {
	case <-c.initCh:
		if c.conn != nil {
			return c.conn.SetWriteDeadline(t)
		}
	default:
	}
	return nil
}

func (h *Outbound) applyObfs(conn net.Conn) net.Conn {
	obfsHost := h.obfsHost
	if obfsHost == "" {
		obfsHost = "bing.com"
	}
	switch h.obfsMode {
	case "http":
		return obfs.NewHTTPObfs(conn, obfsHost, h.serverPort)
	case "tls":
		return obfs.NewTLSObfs(conn, obfsHost)
	}
	return conn
}

// packetConnWrapper wraps net.PacketConn as net.Conn so it can be used in DialContext for UDP networks.
type packetConnWrapper struct {
	net.PacketConn
	destination M.Socksaddr
}

func (w *packetConnWrapper) Read(p []byte) (int, error) {
	n, _, err := w.PacketConn.ReadFrom(p)
	return n, err
}

func (w *packetConnWrapper) Write(p []byte) (int, error) {
	return w.PacketConn.WriteTo(p, w.destination)
}

func (w *packetConnWrapper) RemoteAddr() net.Addr {
	return w.destination
}
