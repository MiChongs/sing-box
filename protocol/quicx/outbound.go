//go:build with_quic

package quicx

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/quicx"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/udpgso"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service/filemanager"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.QUICXOutboundOptions](registry, C.TypeQUICX, NewOutbound)
}

var (
	_ adapter.Lifecycle               = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
	client *quicx.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.QUICXOutboundOptions) (adapter.Outbound, error) {
	options.UDPFragmentDefault = true
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	// QUIC handshakes run on crypto/tls: like the other QUIC transports, a
	// uTLS fingerprint is ignored instead of failing every dial.
	tlsConfig, err = tls.QUICClientConfig(tlsConfig)
	if err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	var tracer qlogTracer
	if options.QLOGDirectory != "" {
		var qlogMaxSize int64
		if options.QLOGMaxSize != nil {
			qlogMaxSize = int64(options.QLOGMaxSize.Value())
		}
		tracer, err = newQLOGTracer(logger, filemanager.BasePath(ctx, os.ExpandEnv(options.QLOGDirectory)), qlogMaxSize)
		if err != nil {
			return nil, err
		}
	}
	client, err := quicx.NewClient(quicx.ClientOptions{
		Context:       ctx,
		Dialer:        outboundDialer,
		ServerAddress: options.ServerOptions.Build(),
		TLSConfig:     tlsConfig,
		TLSDialConfig: tls.QUICDialConfig,
		QUICOptions: qtls.QUICOptions{
			DisableGSO:              udpgso.Disabled(options.UDPGSO),
			IdleTimeout:             options.IdleTimeout.Build(),
			KeepAlivePeriod:         options.KeepAlivePeriod.Build(),
			StreamReceiveWindow:     options.StreamReceiveWindow.Value(),
			ConnectionReceiveWindow: options.ConnectionReceiveWindow.Value(),
			MaxConcurrentStreams:    options.MaxConcurrentStreams,
			InitialPacketSize:       options.InitialPacketSize,
			DisablePathMTUDiscovery: options.DisablePathMTUDiscovery,
		},
		Password:   options.Password,
		Heartbeat:  time.Duration(options.Heartbeat),
		BBRProfile: options.BBRProfile,
		Tracer:     tracer,
		Logger:     logger,
	})
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeQUICX, tag, options.Network.Build(), options.DialerOptions),
		logger:  logger,
		client:  client,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialConn(ctx, destination)
	case N.NetworkUDP:
		conn, err := h.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), nil
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.client.ListenPacket(ctx)
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(h.Close)
	return nil
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	_ = h.client.CloseWithError(E.New("network changed"))
}

func (h *Outbound) Close() error {
	return h.client.CloseWithError(os.ErrClosed)
}
