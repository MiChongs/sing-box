package nowhere

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/morph"
	"github.com/sagernet/sing-box/protocol/nowhere/core/portal"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	"github.com/sagernet/sing-box/protocol/nowhere/internal/quicsettings"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// InboundV3 is the Nowhere 3 Portal. It serves one transport with ALPN nw3 and
// TLS 1.3, applies the Nowhere 3 Morph transform when enabled, and either
// routes authenticated flows through the sing-box router or bridges them to a
// single registered Egress exit (egress mode).
type InboundV3 struct {
	inbound.Adapter
	ctx       context.Context
	logger    log.ContextLogger
	sharedKey string

	portal            *portal.Server
	tlsConfig         *tls.Config
	net               string
	morph             bool
	quicOptions       option.QUICOptions
	congestionControl quicsettings.CongestionControl

	listener *listener.Listener

	lifecycleMu sync.Mutex
	started     bool
	closed      bool
	restarting  bool
	serveCtx    context.Context
	cancelServe context.CancelFunc
	serveDone   chan struct{}
	packetConn  net.PacketConn
}

// NewInboundV3 builds the Nowhere 3 Portal inbound. The nw2 inbound keeps its
// own constructor; NewInbound dispatches between the two.
func NewInboundV3(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NowhereInboundOptions) (adapter.Inbound, error) {
	if err := validateNowhereV3InboundOptions(&options); err != nil {
		return nil, err
	}
	transport, err := nowhereV3Net(options.Net)
	if err != nil {
		return nil, err
	}
	if err := validateNowhereV3InboundNetworks(&options, transport); err != nil {
		return nil, err
	}
	// The Egress registration handshake only exists on the QUIC transport, so an
	// exit bridge cannot be served over the TCP transport.
	if options.Egress && transport != nowhereV3NetUDP {
		return nil, E.New("nowhere: egress mode requires net udp")
	}
	if err := wire.ValidateServiceKey(options.Password); err != nil {
		return nil, E.Cause(err, "nowhere: portal key")
	}
	congestionControl, err := quicsettings.ParseCongestionControl(options.QUICCongestionControl)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := buildNowhereV3ServerTLS(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	var upstream portal.Upstream
	if !options.Egress {
		upstream = newRouterNw3Upstream(tag, C.TypeNowhere, options.ListenOptions.Detour, router)
	}
	portalServer, err := portal.New(portal.Config{
		SharedKey: options.Password,
		Morph:     resolveNowhereMorph(options.Morph, nowhereStackNw3),
		TLS:       tlsConfig,
		Upstream:  upstream,
		Egress:    options.Egress,
	})
	if err != nil {
		return nil, err
	}
	networks := []string{N.NetworkTCP}
	if transport == nowhereV3NetUDP {
		networks = []string{N.NetworkUDP}
	}
	return &InboundV3{
		Adapter:           inbound.NewAdapter(C.TypeNowhere, tag),
		ctx:               ctx,
		logger:            logger,
		sharedKey:         options.Password,
		portal:            portalServer,
		tlsConfig:         tlsConfig,
		net:               transport,
		morph:             resolveNowhereMorph(options.Morph, nowhereStackNw3),
		quicOptions:       options.QUICOptions,
		congestionControl: congestionControl,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Network: networks,
			Listen:  options.ListenOptions,
		}),
	}, nil
}

func (h *InboundV3) Start(stage adapter.StartStage, scope *adapter.Scope) error {
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
	h.started = true
	h.lifecycleMu.Unlock()

	logNowhereV3PortalFingerprint(h.logger, h.tlsConfig)
	serveCtx, cancelServe := context.WithCancel(h.ctx)
	serveDone := make(chan struct{})
	h.lifecycleMu.Lock()
	h.serveCtx = serveCtx
	h.cancelServe = cancelServe
	h.serveDone = serveDone
	h.lifecycleMu.Unlock()
	if err := h.serve(serveCtx, serveDone); err != nil {
		h.lifecycleMu.Lock()
		h.started = false
		h.serveCtx = nil
		h.cancelServe = nil
		h.serveDone = nil
		h.lifecycleMu.Unlock()
		cancelServe()
		return err
	}
	if scope != nil {
		scope.Add(h.Close)
	}
	return nil
}

// serve binds the transport socket and hands it to the vendored Portal. The
// Portal closes its own listener when serveCtx ends; the UDP socket stays
// owned by the host because the QUIC transport only borrows it. serveDone is
// always closed exactly once.
func (h *InboundV3) serve(serveCtx context.Context, serveDone chan struct{}) error {
	if h.net == nowhereV3NetTCP {
		tcpListener, err := h.listener.ListenTCP()
		if err != nil {
			close(serveDone)
			return err
		}
		go func() {
			defer close(serveDone)
			_ = h.portal.Serve(serveCtx, tcpListener)
		}()
		return nil
	}
	packetConn, err := h.listener.ListenUDP()
	if err != nil {
		close(serveDone)
		return err
	}
	h.lifecycleMu.Lock()
	h.packetConn = packetConn
	h.lifecycleMu.Unlock()
	if h.morph {
		packetConn = morph.WrapPacketConn(packetConn, nowhereV3MorphKeys(h.sharedKey), false)
	}
	quicListener, err := listenNowhereV3QUIC(serveCtx, packetConn, h.tlsConfig, h.quicOptions, h.congestionControl)
	if err != nil {
		_ = packetConn.Close()
		h.lifecycleMu.Lock()
		h.packetConn = nil
		h.lifecycleMu.Unlock()
		close(serveDone)
		return err
	}
	go func() {
		defer close(serveDone)
		_ = h.portal.ServeQUIC(serveCtx, quicListener)
	}()
	return nil
}

// InterfaceUpdated rebinds the QUIC transport socket, mirroring the nw2 inbound's
// QUIC restart. The TCP listener is address-bound and needs no refresh.
func (h *InboundV3) InterfaceUpdated(ctx context.Context) {
	if h.net != nowhereV3NetUDP {
		return
	}
	h.lifecycleMu.Lock()
	if h.closed || !h.started || h.restarting {
		h.lifecycleMu.Unlock()
		return
	}
	h.restarting = true
	cancelServe := h.cancelServe
	serveDone := h.serveDone
	packetConn := h.packetConn
	h.cancelServe = nil
	h.serveDone = nil
	h.packetConn = nil
	h.lifecycleMu.Unlock()

	if cancelServe != nil {
		cancelServe()
	}
	if serveDone != nil {
		<-serveDone
	}
	if packetConn != nil {
		_ = packetConn.Close()
	}

	serveCtx, newCancel := context.WithCancel(h.ctx)
	done := make(chan struct{})
	h.lifecycleMu.Lock()
	h.serveCtx = serveCtx
	h.cancelServe = newCancel
	h.serveDone = done
	h.lifecycleMu.Unlock()
	err := h.serve(serveCtx, done)
	if err != nil {
		h.lifecycleMu.Lock()
		h.started = false
		h.serveCtx = nil
		h.cancelServe = nil
		h.serveDone = nil
		h.lifecycleMu.Unlock()
		h.logger.Error(E.Cause(err, "nowhere: refresh QUIC listener after interface update"))
	}
	h.lifecycleMu.Lock()
	h.restarting = false
	h.lifecycleMu.Unlock()
}

func (h *InboundV3) Close() error {
	h.lifecycleMu.Lock()
	if h.closed {
		h.lifecycleMu.Unlock()
		return nil
	}
	h.closed = true
	cancelServe := h.cancelServe
	serveDone := h.serveDone
	packetConn := h.packetConn
	h.cancelServe = nil
	h.serveDone = nil
	h.packetConn = nil
	h.lifecycleMu.Unlock()
	if cancelServe != nil {
		cancelServe()
	}
	if serveDone != nil {
		<-serveDone
	}
	if packetConn != nil {
		_ = packetConn.Close()
	}
	return h.listener.Close()
}

var (
	_ adapter.Inbound                 = (*InboundV3)(nil)
	_ adapter.InterfaceUpdateListener = (*InboundV3)(nil)
)
