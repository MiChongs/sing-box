package server

import (
	"context"
	"net"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	nwserver "github.com/sagernet/sing-box/protocol/nowhere/core/server"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// RouterUpstream adapts SingBox ConnectionRouterEx to the nw2 core server Upstream.
// Route*Ex takes ownership asynchronously; Handle* returns immediately.
type RouterUpstream struct {
	Tag    string
	Type   string
	Detour string
	Router adapter.ConnectionRouterEx
}

func (u *RouterUpstream) HandleStream(ctx context.Context, conn net.Conn, source net.Addr, target wire.Target, readiness nwserver.FlowReadiness) error {
	ctx = log.ContextWithNewID(ctx)
	metadata := u.metadata(source, target)
	onClose := asSingClose(nwserver.CloseHandlerFromContext(ctx))
	u.Router.RouteConnectionEx(ctx, &routeReadyConn{Conn: conn, readiness: readiness}, metadata, onClose)
	return nil
}

func (u *RouterUpstream) HandlePacket(ctx context.Context, pc net.PacketConn, source net.Addr, target wire.Target, readiness nwserver.FlowReadiness) error {
	ctx = log.ContextWithNewID(ctx)
	metadata := u.metadata(source, target)
	packetConn := bufio.NewPacketConn(pc)
	onClose := asSingClose(nwserver.CloseHandlerFromContext(ctx))
	u.Router.RoutePacketConnectionEx(ctx, &routeReadyPacketConn{PacketConn: packetConn, readiness: readiness}, metadata, onClose)
	return nil
}

type routeReadyConn struct {
	net.Conn
	readiness nwserver.FlowReadiness
}

func (c *routeReadyConn) ConnHandshakeSuccess(net.Conn) error {
	return c.readiness.Ready()
}

func (c *routeReadyConn) HandshakeSuccess() error {
	return c.readiness.Ready()
}

func (c *routeReadyConn) HandshakeFailure(err error) error {
	return c.readiness.Reject(err)
}

type routeReadyPacketConn struct {
	N.PacketConn
	readiness nwserver.FlowReadiness
}

func (c *routeReadyPacketConn) PacketConnHandshakeSuccess(net.PacketConn) error {
	return c.readiness.Ready()
}

func (c *routeReadyPacketConn) HandshakeSuccess() error {
	return c.readiness.Ready()
}

func (c *routeReadyPacketConn) HandshakeFailure(err error) error {
	return c.readiness.Reject(err)
}

func (u *RouterUpstream) metadata(source net.Addr, target wire.Target) adapter.InboundContext {
	var metadata adapter.InboundContext
	metadata.Inbound = u.Tag
	metadata.InboundType = u.Type
	//nolint:staticcheck
	metadata.InboundDetour = u.Detour
	metadata.Source = M.SocksaddrFromNet(source)
	metadata.Destination = M.ParseSocksaddr(targetAddress(target))
	return metadata
}

func targetAddress(target wire.Target) string {
	host := target.Host
	if target.Type != wire.TargetTypeDomain {
		host = target.Addr.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(target.Port)))
}

func asSingClose(onClose nwserver.CloseHandler) N.CloseHandlerFunc {
	if onClose == nil {
		return nil
	}
	return N.CloseHandlerFunc(onClose)
}

// ContextLogger is the subset of sing-box log.ContextLogger we need.
type ContextLogger interface {
	InfoContext(ctx context.Context, args ...any)
	DebugContext(ctx context.Context, args ...any)
	WarnContext(ctx context.Context, args ...any)
	ErrorContext(ctx context.Context, args ...any)
}

type observerAdapter struct {
	l ContextLogger
}

// AdaptObserver wraps a sing-box ContextLogger as a structured nw2 core observer.
func AdaptObserver(l ContextLogger) diagnostic.Observer {
	if l == nil {
		return diagnostic.NopObserver{}
	}
	return &observerAdapter{l: l}
}

func (a *observerAdapter) Observe(ctx context.Context, event diagnostic.Event) {
	msg := formatDiagnosticEvent(event)
	switch event.Level {
	case diagnostic.LevelDebug:
		a.l.DebugContext(ctx, msg)
	case diagnostic.LevelWarn:
		a.l.WarnContext(ctx, msg)
	case diagnostic.LevelError:
		a.l.ErrorContext(ctx, msg)
	default:
		a.l.InfoContext(ctx, msg)
	}
}

func formatDiagnosticEvent(event diagnostic.Event) string {
	return diagnostic.FormatEvent(event)
}

// NewHandler builds a nw2 core Handler wired to the SingBox router.
func NewHandler(tag, typ, detour string, cfg *Config, router adapter.ConnectionRouterEx, logger ContextLogger, observers ...diagnostic.Observer) (*Handler, error) {
	up := &RouterUpstream{Tag: tag, Type: typ, Detour: detour, Router: router}
	return NewHandlerWithUpstream(cfg, up, logger, observers...)
}

// NewHandlerWithUpstream builds a nw2 core Handler wired to a custom Upstream.
func NewHandlerWithUpstream(cfg *Config, upstream Upstream, logger ContextLogger, observers ...diagnostic.Observer) (*Handler, error) {
	observer := AdaptObserver(logger)
	if len(observers) > 0 && observers[0] != nil {
		observer = observers[0]
	}
	return nwserver.NewHandler(nwserver.HandlerOptions{
		Config: cfg, Upstream: upstream, Observer: observer,
	})
}

// NewPortalUpstream returns a native Portal-to-Portal forwarding Upstream.
// The bundle remains caller-owned and must be closed after the handler using
// it has been shut down.
var NewPortalUpstream = nwserver.NewPortalUpstream

// AsCloseHandler converts N.CloseHandlerFunc to the nw2 core CloseHandler.
func AsCloseHandler(onClose N.CloseHandlerFunc) nwserver.CloseHandler {
	if onClose == nil {
		return nil
	}
	return nwserver.CloseHandler(onClose)
}

var _ Upstream = (*RouterUpstream)(nil)
