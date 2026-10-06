package nowhere

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/bundle"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/tcptls"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	"github.com/sagernet/sing-box/protocol/nowhere/internal/quicsettings"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.NowhereOutboundOptions](registry, C.TypeNowhere, NewOutbound)
}

var (
	_ adapter.Lifecycle               = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
)

type outboundCarrierOverrides struct {
	tcpDialer      tcptls.TCPDialer
	tlsDialer      tcptls.TLSDialer
	newQUICBackend func() carrier.QuicBackend
}

type outboundCarrierOverridesKey struct{}

func withOutboundCarrierOverrides(ctx context.Context, overrides outboundCarrierOverrides) context.Context {
	return context.WithValue(ctx, outboundCarrierOverridesKey{}, overrides)
}

func outboundOverridesFromContext(ctx context.Context) (outboundCarrierOverrides, bool) {
	overrides, loaded := ctx.Value(outboundCarrierOverridesKey{}).(outboundCarrierOverrides)
	return overrides, loaded
}

type Outbound struct {
	outbound.Adapter
	logger    log.ContextLogger
	observer  diagnostic.Observer
	server    M.Socksaddr
	matrix    Matrix
	mu        sync.Mutex
	bundle    *bundle.CarrierBundle
	newBundle func() (*bundle.CarrierBundle, error)
	closed    bool
	// prewarmOnStart defers the TLS/TCP pool prewarm to StartStateStarted:
	// dialing while the outbound is being constructed would run before the
	// DNS router and detour outbounds are started.
	prewarmOnStart bool
}

type quicBackendOptions struct {
	context           context.Context
	address           string
	serverName        string
	tlsConfig         tls.Config
	quicOptions       option.QUICOptions
	dialer            N.Dialer
	congestionControl quicsettings.CongestionControl
	morphSharedKey    []byte
	observer          diagnostic.Observer
}

// carrierDialOptions carries the resolved dial-side inputs shared by the
// outbound and the chained Portal upstream bundle construction.
type carrierDialOptions struct {
	matrix             Matrix
	credentials        *wire.Credentials
	server             option.ServerOptions
	alpn               string
	tlsOptions         option.OutboundTLSOptions
	pin                string
	dialerOptions      option.DialerOptions
	quicOptions        option.QUICOptions
	congestionControl  quicsettings.CongestionControl
	morphSharedKey     []byte
	maxConcurrentDials int
	warmBackoffInitial time.Duration
	warmBackoffMax     time.Duration
	prewarmOnStart     bool
	observer           diagnostic.Observer
}

// carrierDialPlan holds the dial-side pieces used to (re)build a CarrierBundle.
type carrierDialPlan struct {
	matrix         Matrix
	alpn           string
	credentials    *wire.Credentials
	observer       diagnostic.Observer
	prewarmOnStart bool
	tcpCfg         *tcptls.Config
	newQUICBackend func() carrier.QuicBackend
}

func newCarrierDialPlan(ctx context.Context, logger log.ContextLogger, options carrierDialOptions) (*carrierDialPlan, error) {
	tlsConfig, err := tls.NewClient(ctx, logger, options.server.Server, options.tlsOptions)
	if err != nil {
		return nil, err
	}
	if err := applyNowhereCertificatePin(tlsConfig, options.pin); err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.dialerOptions,
		RemoteIsDomain: options.server.ServerIsDomain(),
	})
	if err != nil {
		return nil, err
	}

	addr := options.server.Build().String()
	tcpDialer := tcptls.TCPDialer(&socksaddrDialer{dialer: outboundDialer})
	tlsDialer := tcptls.TLSDialer(&singTLSDialer{config: tlsConfig})
	overrides, hasOverrides := outboundOverridesFromContext(ctx)
	if hasOverrides {
		if overrides.tcpDialer != nil {
			tcpDialer = overrides.tcpDialer
		}
		if overrides.tlsDialer != nil {
			tlsDialer = overrides.tlsDialer
		}
	}
	plan := &carrierDialPlan{
		matrix:         options.matrix,
		alpn:           options.alpn,
		credentials:    options.credentials,
		observer:       options.observer,
		prewarmOnStart: options.prewarmOnStart,
	}
	if options.matrix.NeedsTCP {
		plan.tcpCfg, err = tcptls.NewConfig(tcptls.TCPOptions{
			Address:            addr,
			Dialer:             tcpDialer,
			TLSDialer:          tlsDialer,
			Observer:           options.observer,
			MaxConcurrentDials: options.maxConcurrentDials,
			WarmBackoffInitial: options.warmBackoffInitial,
			WarmBackoffMax:     options.warmBackoffMax,
			MorphSharedKey:     options.morphSharedKey,
		})
		if err != nil {
			return nil, err
		}
	}
	if options.matrix.NeedsQUIC {
		if hasOverrides && overrides.newQUICBackend != nil {
			plan.newQUICBackend = overrides.newQUICBackend
		} else {
			// QUIC handshakes run on crypto/tls: like the other QUIC
			// transports, the QUIC carrier ignores a uTLS fingerprint, which
			// the TLS/TCP carrier keeps.
			quicTLSConfig, err := tls.QUICClientConfig(tlsConfig)
			if err != nil {
				return nil, err
			}
			quicCfg := quicBackendOptions{
				context:           ctx,
				address:           addr,
				serverName:        options.server.Server,
				tlsConfig:         quicTLSConfig,
				quicOptions:       options.quicOptions,
				dialer:            outboundDialer,
				congestionControl: options.congestionControl,
				morphSharedKey:    options.morphSharedKey,
				observer:          options.observer,
			}
			plan.newQUICBackend = func() carrier.QuicBackend { return newQuicBackend(quicCfg) }
		}
	}
	return plan, nil
}

func (p *carrierDialPlan) newBundle() (*bundle.CarrierBundle, error) {
	return p.buildBundle(p.prewarmOnStart)
}

func (p *carrierDialPlan) buildBundle(prewarmOnStart bool) (*bundle.CarrierBundle, error) {
	bundleCfg := bundle.BundleOptions{
		TCP:                p.tcpCfg,
		Credentials:        p.credentials,
		ALPN:               p.alpn,
		Observer:           p.observer,
		PoolSize:           p.matrix.Pool,
		PrewarmOnStart:     prewarmOnStart,
		Up:                 p.matrix.UpCarrier(),
		Down:               p.matrix.DownCarrier(),
		MixUp:              p.matrix.MixUp,
		MixDown:            p.matrix.MixDown,
		MixFallbackTimeout: p.matrix.MixFallbackTimeout,
		Mux:                p.matrix.Mux,
	}
	if p.newQUICBackend != nil {
		bundleCfg.QUIC = p.newQUICBackend()
	}
	return bundle.NewCarrierBundle(bundleCfg)
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NowhereOutboundOptions) (adapter.Outbound, error) {
	if options.Password == "" {
		return nil, E.New("nowhere: missing password")
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsOptions, err := normalizeNowhereOutboundTLS(options.TLS)
	if err != nil {
		return nil, err
	}
	options.TLS = tlsOptions
	alpn := string(options.TLS.ALPN[0])
	congestionControl, err := quicsettings.ParseCongestionControl(options.QUICCongestionControl)
	if err != nil {
		return nil, err
	}

	matrix, err := ResolveMatrix(MatrixInputs{
		Up: options.Up, Down: options.Down, Pool: options.Pool, Mux: options.Mux,
		MixFallbackTimeout: options.MixFallbackTimeout.Build(),
	})
	if err != nil {
		return nil, err
	}
	for _, warning := range matrix.Warnings() {
		logger.Warn(warning)
	}
	if matrix.NeedsQUIC && !quicIncluded {
		return nil, C.ErrQUICNotIncluded
	}

	credentials, err := wire.NewCredentials(options.Password)
	if err != nil {
		return nil, err
	}
	observer := SingObserver{L: logger}

	maxConcurrentDials := 0
	if options.MaxConcurrentDials != nil {
		maxConcurrentDials = *options.MaxConcurrentDials
	}
	morphSharedKey := MorphSharedKey(options.Morph, options.Password)
	plan, err := newCarrierDialPlan(ctx, logger, carrierDialOptions{
		matrix:             matrix,
		credentials:        credentials,
		server:             options.ServerOptions,
		alpn:               alpn,
		tlsOptions:         common.PtrValueOrDefault(options.TLS),
		pin:                options.Pin,
		dialerOptions:      options.DialerOptions,
		quicOptions:        options.QUICOptions,
		congestionControl:  congestionControl,
		morphSharedKey:     morphSharedKey,
		maxConcurrentDials: maxConcurrentDials,
		warmBackoffInitial: options.WarmBackoffInitial.Build(),
		warmBackoffMax:     options.WarmBackoffMax.Build(),
		prewarmOnStart:     options.PrewarmOnStart,
		observer:           observer,
	})
	if err != nil {
		return nil, err
	}
	// Carriers are created lazily, so building the bundle here only validates
	// the configuration; the prewarm is started by Start.
	b, err := plan.buildBundle(false)
	if err != nil {
		return nil, err
	}

	networks := []string{N.NetworkTCP, N.NetworkUDP}
	return &Outbound{
		Adapter:        outbound.NewAdapterWithDialerOptions(C.TypeNowhere, tag, networks, options.DialerOptions),
		logger:         logger,
		observer:       observer,
		server:         options.ServerOptions.Build(),
		matrix:         matrix,
		bundle:         b,
		newBundle:      plan.newBundle,
		prewarmOnStart: options.PrewarmOnStart,
	}, nil
}

func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		scope.Add(o.Close)
	case adapter.StartStateStarted:
		if o.prewarmOnStart {
			b, err := o.getBundle()
			if err != nil {
				return err
			}
			return b.Prewarm()
		}
	}
	return nil
}

func (o *Outbound) getBundle() (*bundle.CarrierBundle, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, net.ErrClosed
	}
	if o.bundle != nil {
		return o.bundle, nil
	}
	if o.newBundle == nil {
		return nil, net.ErrClosed
	}
	b, err := o.newBundle()
	if err != nil {
		return nil, err
	}
	o.bundle = b
	return b, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		b, err := o.getBundle()
		if err != nil {
			return nil, err
		}
		target, err := targetFromSocksaddr(destination)
		if err != nil {
			return nil, err
		}
		return b.OpenTCP(ctx, target)
	case N.NetworkUDP:
		conn, err := o.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	b, err := o.getBundle()
	if err != nil {
		return nil, err
	}
	target, err := targetFromSocksaddr(destination)
	if err != nil {
		return nil, err
	}
	return b.OpenUDPAsync(ctx, target)
}

func (o *Outbound) InterfaceUpdated(ctx context.Context) {
	o.mu.Lock()
	bundle := o.bundle
	o.bundle = nil
	o.mu.Unlock()
	if bundle != nil {
		if err := bundle.Close(); err != nil {
			diagnostic.Emit(context.Background(), o.observer, diagnostic.Event{
				Level: diagnostic.LevelWarn, Code: "bundle_close_failed", Component: "sing-box",
				Carrier: diagnostic.CarrierQUIC, Err: err,
			})
		}
	}
}

func (o *Outbound) Close() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	bundle := o.bundle
	o.bundle = nil
	o.newBundle = nil
	o.mu.Unlock()
	if bundle != nil {
		return bundle.Close()
	}
	return nil
}

func (o *Outbound) MatrixForTest() Matrix { return o.matrix }

func (o *Outbound) bundleForTest() *bundle.CarrierBundle {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.bundle
}

// socksaddrDialer adapts SingBox N.Dialer (Socksaddr) to tcptls.TCPDialer (host:port string).
type socksaddrDialer struct {
	dialer N.Dialer
}

func (d *socksaddrDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
}

// singTLSDialer adapts sing-box TLS ClientHandshake to tcptls.TlsDialer.
type singTLSDialer struct {
	config tls.Config
}

func (d *singTLSDialer) DialTLSConn(ctx context.Context, c net.Conn) (wire.HandshakedConn, error) {
	conn, err := tls.ClientHandshake(ctx, c, d.config)
	if err != nil {
		return wire.HandshakedConn{}, err
	}
	state := conn.ConnectionState()
	material, err := state.ExportKeyingMaterial(wire.TLSExporterLabel, wire.EmptyTLSExporterContext(), wire.TLSExporterLen)
	if err != nil {
		_ = conn.Close()
		return wire.HandshakedConn{}, err
	}
	var value wire.TLSExporter
	copy(value[:], material)
	return wire.HandshakedConn{
		Conn: conn,
		TLSHandshakeInfo: wire.TLSHandshakeInfo{
			TLSVersion: state.Version, NegotiatedALPN: state.NegotiatedProtocol, Exporter: value,
		},
	}, nil
}

func targetFromSocksaddr(destination M.Socksaddr) (wire.Target, error) {
	if destination.Fqdn != "" {
		return wire.NewDomainTarget(destination.Fqdn, destination.Port)
	}
	return wire.NewIPTarget(destination.Addr, destination.Port)
}

var (
	_ tcptls.TCPDialer = (*socksaddrDialer)(nil)
	_ tcptls.TLSDialer = (*singTLSDialer)(nil)
)
