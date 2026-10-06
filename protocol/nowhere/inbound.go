package nowhere

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	"github.com/sagernet/sing-box/protocol/nowhere/internal/quicsettings"
	"github.com/sagernet/sing-box/protocol/nowhere/server"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.NowhereInboundOptions](registry, C.TypeNowhere, NewInbound)
}

var (
	_ adapter.Inbound                 = (*Inbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Inbound)(nil)
)

type inboundListener interface {
	Start() error
	ListenUDP() (net.PacketConn, error)
	Close() error
}

type inboundQUICServer interface {
	Start(net.PacketConn) error
	Restart(func() (net.PacketConn, error)) error
	Close() error
}

type inboundDrainStarter interface {
	BeginDrain()
}

const inboundHostCleanupReserve = 250 * time.Millisecond

type inboundStartFlight struct {
	done chan struct{}
	err  error
}

type Inbound struct {
	inbound.Adapter
	ctx          context.Context
	logger       log.ContextLogger
	listener     inboundListener
	tlsConfig    tls.ServerConfig
	config       *server.Config
	handler      *server.Handler
	nextUpstream *portalUpstreamManager
	quicServer   inboundQUICServer
	enableTCP    bool
	enableUDP    bool
	// morphKey is the endpoint password as a Morph shared key. Empty leaves
	// every carrier bare TLS/QUIC (morph disabled).
	morphKey []byte
	// nextMorph is the resolved Morph setting toward the chained next Portal:
	// next.morph when set, otherwise this inbound's morph.
	nextMorph   bool
	lifecycleMu sync.Mutex
	started     bool
	closed      bool
	startFlight *inboundStartFlight
	restartDone chan struct{}

	shutdownCoordinator inboundShutdownCoordinator
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NowhereInboundOptions) (adapter.Inbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsOptions, err := normalizeNowhereInboundTLS(options.TLS)
	if err != nil {
		return nil, err
	}
	options.TLS = tlsOptions
	congestionControl, err := quicsettings.ParseCongestionControl(options.QUICCongestionControl)
	if err != nil {
		return nil, err
	}
	cfg, err := server.NewConfig(options)
	if err != nil {
		return nil, err
	}
	if cfg.UDPEnabled() && !quicIncluded {
		return nil, C.ErrQUICNotIncluded
	}
	if !cfg.TCPEnabled() && !cfg.UDPEnabled() {
		return nil, E.New("nowhere: at least one of tcp/udp network required")
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}

	// TCP uses listener Network; UDP/QUIC is started manually (like TUIC) so
	// listener.Start does not consume the UDP socket via loopUDPIn.
	networks := make([]string, 0, 1)
	if cfg.TCPEnabled() {
		networks = append(networks, N.NetworkTCP)
	}

	observer := server.ObserverFromContext(ctx)
	if observer == nil {
		observer = server.AdaptObserver(logger)
	}
	in := &Inbound{
		Adapter:   inbound.NewAdapter(C.TypeNowhere, tag),
		ctx:       ctx,
		logger:    logger,
		tlsConfig: tlsConfig,
		config:    cfg,
		enableTCP: cfg.TCPEnabled(),
		enableUDP: cfg.UDPEnabled(),
		morphKey:  MorphSharedKey(options.Morph, options.Password),
	}
	if options.Next != nil {
		nextMorph := resolveNextMorph(options.Morph, options.Next)
		in.nextMorph = nextMorph
		in.nextUpstream, err = newPortalUpstream(ctx, logger, observer, string(tlsOptions.ALPN[0]), nextMorph, options.Next)
		if err != nil {
			return nil, err
		}
		// Chained mode forwards through the next native Portal and
		// intentionally bypasses the sing-box router (Rust no-fallback rule).
		in.handler, err = server.NewHandlerWithUpstream(cfg, in.nextUpstream, logger, observer)
		if err != nil {
			_ = in.nextUpstream.Close()
			return nil, err
		}
	} else {
		in.handler, err = server.NewHandler(tag, C.TypeNowhere, options.ListenOptions.Detour, cfg, router, logger, observer)
		if err != nil {
			return nil, err
		}
	}
	opts := listener.Options{
		Context: ctx,
		Logger:  logger,
		Network: networks,
		Listen:  options.ListenOptions,
	}
	if cfg.TCPEnabled() {
		opts.ConnectionHandler = in
	}
	in.listener = listener.New(opts)
	if cfg.UDPEnabled() {
		in.quicServer = server.NewQUICServer(
			ctx,
			in.handler,
			tlsConfig,
			options.QUICOptions,
			congestionControl,
			observer,
		)
	}
	return in, nil
}

// resolveNextMorph applies the next.morph override contract: nil inherits the
// inbound endpoint's morph setting, so both legs of a chained hop morph
// together unless the next hop explicitly opts out (or in).
func resolveNextMorph(inboundMorph bool, next *option.NowhereNextOptions) bool {
	if next == nil || next.Morph == nil {
		return inboundMorph
	}
	return *next.Morph
}

// newPortalUpstream builds the reloadable client upstream toward the next
// native Portal. The chained client shares the listener ALPN (Rust contract:
// the Portal's ALPN is shared by its listener and native upstream client) and
// the resolved next.morph, and next.server_name / next.pin mirror the
// outbound's tls.server_name and pin.
func newPortalUpstream(ctx context.Context, logger log.ContextLogger, observer diagnostic.Observer, alpn string, morph bool, next *option.NowhereNextOptions) (*portalUpstreamManager, error) {
	if next.Password == "" {
		return nil, E.New("nowhere: missing next password")
	}
	if next.Server == "" || next.ServerPort == 0 {
		return nil, E.New("nowhere: missing next server")
	}
	matrix, err := ResolveMatrix(MatrixInputs{
		Up: next.Up, Down: next.Down, Pool: next.Pool, Mux: next.Mux,
		MixFallbackTimeout: next.MixFallbackTimeout.Build(),
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
	credentials, err := wire.NewCredentials(next.Password)
	if err != nil {
		return nil, err
	}
	serverName, err := normalizeNowhereNextServerName(next.ServerName)
	if err != nil {
		return nil, err
	}
	// Empty and "none" disable pinning; a real pin overrides both SNI and chain
	// verification (Rust precedence).
	pin, err := wire.ParseCertificatePin(next.Pin)
	if err != nil {
		return nil, err
	}
	plan, err := newCarrierDialPlan(ctx, logger, carrierDialOptions{
		matrix:      matrix,
		credentials: credentials,
		server:      next.ServerOptions,
		alpn:        alpn,
		tlsOptions: option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: serverName,
			// Rust contract: an empty server_name disables certificate
			// verification; NewSTDClient still falls back to the endpoint host
			// for the ClientHello SNI.
			Insecure:   serverName == "",
			ALPN:       badoption.Listable[string]{alpn},
			MinVersion: "1.3",
			MaxVersion: "1.3",
		},
		pin:            pin,
		morphSharedKey: MorphSharedKey(morph, next.Password),
		observer:       observer,
	})
	if err != nil {
		return nil, err
	}
	return newPortalUpstreamManager(plan.newBundle, logger)
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	h.lifecycleMu.Lock()
	if h.closed {
		h.lifecycleMu.Unlock()
		return net.ErrClosed
	}
	if h.started {
		h.lifecycleMu.Unlock()
		return nil
	}
	if h.startFlight != nil {
		flight := h.startFlight
		h.lifecycleMu.Unlock()
		<-flight.done
		return flight.err
	}
	flight := &inboundStartFlight{done: make(chan struct{})}
	h.startFlight = flight
	// Registered before anything is started: Close is idempotent and releases
	// whatever a failed start already brought up (TLS, listener, QUIC).
	if scope != nil {
		scope.Add(h.Close)
	}
	tlsConfig := h.tlsConfig
	listener := h.listener
	quicServer := h.quicServer
	enableTCP := h.enableTCP
	enableUDP := h.enableUDP
	morphKey := h.morphKey
	h.lifecycleMu.Unlock()

	var err error
	if tlsConfig != nil {
		err = tlsConfig.Start()
	}
	if err == nil && enableTCP && listener != nil {
		err = listener.Start()
	}
	if err == nil && enableUDP && quicServer != nil && listener != nil {
		var packetConn net.PacketConn
		packetConn, err = listener.ListenUDP()
		if err == nil {
			// Morph seals the shared UDP socket below QUIC (server role);
			// wrap before the QUIC transport takes ownership, like the
			// mihomo Portal server reference does before quic.Listen.
			if len(morphKey) > 0 {
				packetConn = WrapMorphPacketConn(packetConn, string(morphKey), false)
			}
			err = quicServer.Start(packetConn)
		}
	}

	h.lifecycleMu.Lock()
	if err != nil {
		flight.err = err
	} else if h.closed {
		flight.err = net.ErrClosed
	} else {
		h.started = true
	}
	if h.startFlight == flight {
		h.startFlight = nil
	}
	close(flight.done)
	h.lifecycleMu.Unlock()
	return flight.err
}

func (h *Inbound) InterfaceUpdated(ctx context.Context) {
	if h == nil {
		return
	}
	h.lifecycleMu.Lock()
	if h.closed || !h.started {
		h.lifecycleMu.Unlock()
		return
	}
	restartQUIC := h.enableUDP && h.quicServer != nil && h.listener != nil
	replaceNext := h.nextUpstream != nil
	if !restartQUIC && !replaceNext {
		h.lifecycleMu.Unlock()
		return
	}
	if h.restartDone != nil {
		h.lifecycleMu.Unlock()
		return
	}
	restartDone := make(chan struct{})
	h.restartDone = restartDone
	quicServer := h.quicServer
	listener := h.listener
	nextUpstream := h.nextUpstream
	h.lifecycleMu.Unlock()

	var err error
	if replaceNext {
		err = nextUpstream.Replace()
	}
	if restartQUIC {
		morphKey := h.morphKey
		err = errors.Join(err, quicServer.Restart(func() (net.PacketConn, error) {
			packetConn, listenErr := listener.ListenUDP()
			if listenErr != nil {
				return nil, listenErr
			}
			// Re-apply the Morph seal on every rebound socket so the QUIC
			// transport keeps speaking the keyed transform below QUIC.
			if len(morphKey) > 0 {
				packetConn = WrapMorphPacketConn(packetConn, string(morphKey), false)
			}
			return packetConn, nil
		}))
	}

	h.lifecycleMu.Lock()
	closed := h.closed
	close(restartDone)
	h.restartDone = nil
	h.lifecycleMu.Unlock()
	if err != nil && !closed && h.logger != nil {
		h.logger.Error(E.Cause(err, "nowhere: refresh network-bound state after interface update"))
	}
}

func (h *Inbound) Close() error {
	if h == nil {
		return nil
	}
	h.shutdownCoordinator.start(func() (context.Context, context.CancelFunc) {
		timeout := h.config.Timeouts().Shutdown
		return context.WithTimeout(context.Background(), timeout)
	}, h.shutdownPhases)
	return h.shutdownCoordinator.wait(context.Background())
}

func (h *Inbound) shutdown(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	h.shutdownCoordinator.start(func() (context.Context, context.CancelFunc) {
		return ctx, nil
	}, h.shutdownPhases)
	return h.shutdownCoordinator.wait(ctx)
}

func (h *Inbound) shutdownPhases(ctx context.Context) []func() error {
	h.lifecycleMu.Lock()
	h.closed = true
	h.started = false
	startFlight := h.startFlight
	restartDone := h.restartDone
	quicServer := h.quicServer
	listener := h.listener
	handler := h.handler
	nextUpstream := h.nextUpstream
	tlsConfig := h.tlsConfig
	h.lifecycleMu.Unlock()

	waitLifecycle := func() {
		if startFlight != nil {
			<-startFlight.done
		}
		if restartDone != nil {
			<-restartDone
		}
	}
	phases := make([]func() error, 0, 5)
	var handlerDone chan struct{}
	if handler != nil {
		// Establish the core's synchronous admission barrier before host
		// transport cleanup when the Handler exposes BeginDrain.
		if drainer, ok := any(handler).(inboundDrainStarter); ok {
			drainer.BeginDrain()
		}
		handlerDone = make(chan struct{})
		phases = append(phases, func() error {
			waitLifecycle()
			defer close(handlerDone)
			handlerCtx, cancel := inboundHandlerShutdownContext(ctx)
			defer cancel()
			err := handler.Shutdown(handlerCtx)
			// The reserved tail belongs to host QUIC/listener/TLS cleanup.
			// Core reaching its earlier drain deadline is a normal forced
			// completion unless the outer host deadline also expired.
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				return nil
			}
			return err
		})
	}
	waitHandler := func() {
		if handlerDone != nil {
			<-handlerDone
		}
	}
	if quicServer != nil {
		phases = append(phases, func() error {
			waitLifecycle()
			waitHandler()
			return quicServer.Close()
		})
	}
	if listener != nil {
		phases = append(phases, func() error {
			waitLifecycle()
			waitHandler()
			return server.WithoutErrClosed(listener.Close())
		})
	}
	if nextUpstream != nil {
		// PortalUpstream borrows the next-hop bundle: close it only after the
		// handler has drained every forwarded flow.
		phases = append(phases, func() error {
			waitLifecycle()
			waitHandler()
			return nextUpstream.Close()
		})
	}
	if tlsConfig != nil {
		phases = append(phases, func() error {
			waitLifecycle()
			waitHandler()
			return tlsConfig.Close()
		})
	}
	return phases
}

func inboundHandlerShutdownContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return context.WithCancel(context.Background())
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return context.WithCancel(ctx)
	}
	reserve := inboundHostCleanupReserve
	if reserve >= remaining {
		reserve = remaining / 10
	}
	return context.WithDeadline(ctx, deadline.Add(-reserve))
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	// Morph seals accepted TCP below TLS. The sing-box listener does not use
	// core Server.serveTCP, which is the other place this wrap happens.
	if len(h.morphKey) > 0 {
		conn = WrapMorphTCPServer(conn, string(h.morphKey))
	}
	err := h.handler.ServeTCP(ctx, conn, metadata.Source, func(handshakeCtx context.Context, raw net.Conn) (wire.HandshakedConn, error) {
		handshaked, err := tls.ServerHandshake(handshakeCtx, raw, h.tlsConfig)
		if err != nil {
			return wire.HandshakedConn{}, err
		}
		state := handshaked.ConnectionState()
		material, err := state.ExportKeyingMaterial(
			wire.TLSExporterLabel,
			wire.EmptyTLSExporterContext(),
			wire.TLSExporterLen,
		)
		if err != nil {
			_ = handshaked.Close()
			return wire.HandshakedConn{}, E.Cause(err, "nowhere: TLS exporter unavailable")
		}
		if len(material) != wire.TLSExporterLen {
			_ = handshaked.Close()
			return wire.HandshakedConn{}, E.New("nowhere: invalid TLS exporter length")
		}
		var exporter wire.TLSExporter
		copy(exporter[:], material)
		return wire.HandshakedConn{
			Conn: handshaked,
			TLSHandshakeInfo: wire.TLSHandshakeInfo{
				TLSVersion: state.Version, NegotiatedALPN: state.NegotiatedProtocol, Exporter: exporter,
			},
		}, nil
	}, server.AsCloseHandler(onClose))
	if err != nil && !errors.Is(err, context.Canceled) && !server.IsReported(err) {
		h.logger.DebugContext(ctx, E.Cause(err, "process Nowhere connection from ", metadata.Source))
	}
}
