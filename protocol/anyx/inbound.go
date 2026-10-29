package anyx

import (
	"context"
	"net"
	"os"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	anyx "github.com/sagernet/sing-box/common/anyx"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.AnyXInboundOptions](registry, C.TypeAnyX, NewInbound)
}

type closeHandlerKey struct{}

func contextWithCloseHandler(ctx context.Context, onClose N.CloseHandlerFunc) context.Context {
	return context.WithValue(ctx, closeHandlerKey{}, onClose)
}

func closeHandlerFromContext(ctx context.Context) N.CloseHandlerFunc {
	if onClose, ok := ctx.Value(closeHandlerKey{}).(N.CloseHandlerFunc); ok {
		return onClose
	}
	return nil
}

type Inbound struct {
	inbound.Adapter
	tlsConfig                tls.ServerConfig
	transport                adapter.V2RayServerTransport
	ssService                shadowsocks.Service
	router                   adapter.ConnectionRouterEx
	logger                   logger.ContextLogger
	listener                 *listener.Listener
	service                  *anyx.MultiService[string]
	fallbackAddr             M.Socksaddr
	fallbackAddrTLSNextProto map[string]M.Socksaddr
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyXInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeAnyX, tag),
		router:  uot.NewRouter(router, logger),
		logger:  logger,
	}

	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}

	if options.Transport != nil {
		var err error
		inbound.transport, err = v2ray.NewServerTransport(ctx, logger, common.PtrValueOrDefault(options.Transport), inbound.tlsConfig, (*inboundTransportHandler)(inbound))
		if err != nil {
			return nil, E.Cause(err, "create server transport: ", options.Transport.Type)
		}
	}

	ssService, err := NewShadowsocksServer(ctx, options.Encryption, inbound.onSSDecryptedConnection)
	if err != nil {
		return nil, err
	}
	inbound.ssService = ssService

	var paddingScheme []byte
	if len(options.PaddingScheme) > 0 {
		paddingScheme = []byte(strings.Join(options.PaddingScheme, "\n"))
	} else {
		paddingScheme = []byte("off")
	}

	var fallbackHandler N.TCPConnectionHandlerEx
	if options.Fallback != nil && options.Fallback.Server != "" || len(options.FallbackForALPN) > 0 {
		if options.Fallback != nil && options.Fallback.Server != "" {
			inbound.fallbackAddr = options.Fallback.Build()
			if !inbound.fallbackAddr.IsValid() {
				return nil, E.New("invalid fallback address: ", inbound.fallbackAddr)
			}
		}
		if len(options.FallbackForALPN) > 0 {
			if inbound.tlsConfig == nil {
				return nil, E.New("fallback for ALPN is not supported without TLS")
			}
			inbound.fallbackAddrTLSNextProto = make(map[string]M.Socksaddr)
			for nextProto, destination := range options.FallbackForALPN {
				if destination == nil || !destination.Build().IsValid() {
					return nil, E.New("invalid fallback address for ALPN ", nextProto)
				}
				inbound.fallbackAddrTLSNextProto[nextProto] = destination.Build()
			}
		}
		fallbackHandler = adapter.NewUpstreamContextHandler(inbound.fallbackConnection, nil)
	}

	service, err := anyx.NewMultiService[string](anyx.ServiceOptions{
		PaddingScheme:         paddingScheme,
		PaddingSchemeInterval: options.PaddingSchemeInterval.Build(),
		PaddingLimit:          options.PaddingLimit,
		Handler:               (*inboundHandler)(inbound),
		FallbackHandler:       fallbackHandler,
		Logger:                logger,
	})
	if err != nil {
		return nil, err
	}
	err = service.UpdateUsers(
		common.Map(options.Users, func(it option.AnyXUser) string { return it.Name }),
		common.Map(options.Users, func(it option.AnyXUser) string { return it.Password }),
	)
	if err != nil {
		return nil, err
	}
	inbound.service = service
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return err
		}
		scope.Add(h.tlsConfig.Close)
	}
	if h.transport == nil {
		err := h.listener.Start()
		if err != nil {
			return err
		}
		scope.Add(h.listener.Close)
		return nil
	}
	scope.Add(h.transport.Close)
	scope.Add(h.listener.Close)
	if common.Contains(h.transport.Network(), N.NetworkTCP) {
		tcpListener, err := h.listener.ListenTCP()
		if err != nil {
			return err
		}
		go func() {
			sErr := h.transport.Serve(tcpListener)
			if sErr != nil && !E.IsClosed(sErr) {
				h.logger.Error("transport serve error: ", sErr)
			}
		}()
	}
	if common.Contains(h.transport.Network(), N.NetworkUDP) {
		udpConn, err := h.listener.ListenUDP()
		if err != nil {
			return err
		}
		go func() {
			sErr := h.transport.ServePacket(udpConn)
			if sErr != nil && !E.IsClosed(sErr) {
				h.logger.Error("transport serve error: ", sErr)
			}
		}()
	}
	return nil
}

// Level 1: 原生 TCP 监听回调（负责完成 TLS 握手并隔离错误日志）
func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	ctx = adapter.WithContext(ctx, &metadata)
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	h.dispatchStream(ctx, conn, metadata, onClose)
}

// Level 2: 归一化流分发（此时底层 TLS/Transport 已完全终结，在此根据加密配置分流）
func (h *Inbound) dispatchStream(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.ssService != nil {
		if onClose != nil {
			ctx = contextWithCloseHandler(ctx, onClose)
		}
		err := h.ssService.NewConnection(ctx, conn, adapter.UpstreamMetadata(metadata))
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": shadowsocks handshake"))
		}
		return
	}
	h.forwardToService(ctx, conn, metadata, onClose)
}

// Level 3: AnyX 会话接入
func (h *Inbound) forwardToService(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := h.service.NewConnection(ctx, conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

func (h *Inbound) onSSDecryptedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return h.service.NewConnection(ctx, conn, metadata.Source, closeHandlerFromContext(ctx))
}

func (h *Inbound) fallbackConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	var fallbackAddr M.Socksaddr
	if len(h.fallbackAddrTLSNextProto) > 0 {
		if tlsConn, loaded := common.Cast[tls.Conn](conn); loaded {
			nextProto := tlsConn.ConnectionState().NegotiatedProtocol
			if nextProto != "" {
				if fallbackAddr, loaded = h.fallbackAddrTLSNextProto[nextProto]; !loaded {
					h.logger.DebugContext(ctx, "process connection from ", metadata.Source, ": fallback disabled for ALPN: ", nextProto)
					N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
					return
				}
			}
		}
	}
	if !fallbackAddr.IsValid() {
		if !h.fallbackAddr.IsValid() {
			h.logger.DebugContext(ctx, "process connection from ", metadata.Source, ": fallback disabled by default")
			N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
			return
		}
		fallbackAddr = h.fallbackAddr
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Destination = fallbackAddr
	h.logger.InfoContext(ctx, "fallback connection to ", fallbackAddr)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

var _ adapter.V2RayServerTransportHandler = (*inboundTransportHandler)(nil)

type inboundTransportHandler Inbound

// Level 1: Transport 解协议完成后的回调（直接递交 Level 2 分发，不重复执行 TLS 握手）
func (h *inboundTransportHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Source = source
	metadata.Destination = destination
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	h.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	ctx = adapter.WithContext(ctx, &metadata)
	(*Inbound)(h).dispatchStream(ctx, conn, metadata, onClose)
}