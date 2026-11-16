package anyx

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	anyx "github.com/sagernet/sing-box/common/anyx"
	"github.com/sagernet/sing-box/common/anyx/pseudovpn"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	shadowsocks2 "github.com/sagernet/sing-shadowsocks2"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AnyXOutboundOptions](registry, C.TypeAnyX, NewOutbound)
}

var (
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
	_ adapter.FlowOutbound            = (*Outbound)(nil)
	_ tun.Port                        = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	dialer          N.Dialer
	tlsDialer       tls.Dialer
	server          M.Socksaddr
	tlsConfig       tls.Config
	transport       adapter.V2RayClientTransport
	ssMethod        shadowsocks2.Method
	clientOptions   anyx.ClientOptions
	client          *anyx.Client
	uotClient       *uot.Client
	disableReuse    bool
	logger          log.ContextLogger
	pseudoVPNEngine *pseudovpn.ClientEngine
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyXOutboundOptions) (adapter.Outbound, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	networks := options.Network.Build()
	var pseudoVPNEngine *pseudovpn.ClientEngine
	if options.PseudoVPN != nil && options.PseudoVPN.Enabled {
		if err := pseudovpn.ValidateUDPMode(options.PseudoVPN.UDP); err != nil {
			return nil, err
		}
		networks = append(networks, N.NetworkICMP)
		pseudoVPNEngine = pseudovpn.NewClientEngine(pseudovpn.ClientEngineOptions{
			Enabled:        true,
			MTU:            options.PseudoVPN.MTU,
			TCPMSSClamping: options.PseudoVPN.TCPMSSClamping,
			UDP:            options.PseudoVPN.UDP,
			Logger:         logger,
		})
	}

	outbound := &Outbound{
		Adapter:         outbound.NewAdapterWithDialerOptions(C.TypeAnyX, tag, networks, options.DialerOptions),
		server:          options.ServerOptions.Build(),
		logger:          logger,
		disableReuse:    options.DisableReuse,
		pseudoVPNEngine: pseudoVPNEngine,
	}

	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		outbound.tlsConfig = tlsConfig
	}

	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: options.ServerIsDomain(),
	})
	if err != nil {
		return nil, err
	}
	outbound.dialer = outboundDialer

	if outbound.tlsConfig != nil {
		outbound.tlsDialer = tls.NewDialer(outboundDialer, outbound.tlsConfig)
	}

	if options.Transport != nil {
		outbound.transport, err = v2ray.NewClientTransport(ctx, outboundDialer, outbound.server, common.PtrValueOrDefault(options.Transport), outbound.tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "create client transport: ", options.Transport.Type)
		}
	}

	ssMethod, err := NewShadowsocksClient(ctx, options.Encryption)
	if err != nil {
		return nil, err
	}
	outbound.ssMethod = ssMethod

	var paddingScheme []byte
	if len(options.PaddingScheme) > 0 {
		paddingScheme = []byte(strings.Join(options.PaddingScheme, "\n"))
	} else {
		paddingScheme = []byte("auto")
	}

	outbound.clientOptions = anyx.ClientOptions{
		Password:                 options.Password,
		ClientMetadata:           clientMetadataOrDefault(options.ClientMetadata),
		PaddingScheme:            paddingScheme,
		PaddingSchemeInterval:    options.PaddingSchemeInterval.Build(),
		DisableReuse:             options.DisableReuse,
		DialOut:                  outbound.dialOut,
		IdleSessionCheckInterval: options.IdleSessionCheckInterval.Build(),
		IdleSessionMinTimeout:    options.IdleSessionMinTimeout.Build(),
		IdleSessionTimeout:       options.IdleSessionTimeout.Build(),
		MinIdleSession:           options.MinIdleSession,
		Logger:                   logger,
		FrameHandler: func(cmd byte, packet []byte) {
			if pseudoVPNEngine != nil && cmd == pseudovpn.FrameCommandPseudoVPN {
				pseudoVPNEngine.HandleDownlink(packet)
			}
		},
	}
	return outbound, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		if h.transport != nil {
			scope.Add(h.transport.Close)
		}
		client, err := anyx.NewClient(h.clientOptions)
		if err != nil {
			return err
		}
		h.client = client
		scope.Add(client.Close)
		h.uotClient = &uot.Client{
			Dialer:  anyxDialer(client.DialContext),
			Version: uot.Version,
		}
		if h.pseudoVPNEngine != nil {
			h.pseudoVPNEngine.SetSessionProvider(func(ctx context.Context) (pseudovpn.Session, error) {
				if h.client == nil {
					return nil, net.ErrClosed
				}
				return h.client.GetOrDialSession(ctx)
			})
		}
	case adapter.StartStateStart:
		if h.pseudoVPNEngine != nil {
			h.pseudoVPNEngine.Start()
			scope.Add(h.pseudoVPNEngine.Close)
		}
	}
	return nil
}

type anyxDialer func(ctx context.Context, destination M.Socksaddr) (net.Conn, error)

func clientMetadataOrDefault(metadata *string) string {
	if metadata == nil {
		return anyx.DefaultClientMetadata + " sing-box/" + C.Version
	}
	return *metadata
}

func (d anyxDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d(ctx, destination)
}

func (d anyxDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (h *Outbound) dialOut(ctx context.Context) (net.Conn, error) {
	conn, err := h.dialTransportStream(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, E.Cause(err, "dial transport/tls to ", h.server))
		return nil, err
	}
	conn, err = h.wrapEncryption(ctx, conn)
	if err != nil {
		h.logger.ErrorContext(ctx, E.Cause(err, "shadowsocks handshake with ", h.server))
		return nil, err
	}
	return conn, nil
}

func (h *Outbound) dialTransportStream(ctx context.Context) (net.Conn, error) {
	dialCtx := adapter.ContextForMultiplexSession(ctx)
	if h.transport != nil {
		return h.transport.DialContext(dialCtx)
	}
	if h.tlsDialer != nil {
		return h.tlsDialer.DialTLSContext(dialCtx, h.server)
	}
	return h.dialer.DialContext(dialCtx, N.NetworkTCP, h.server)
}

func (h *Outbound) wrapEncryption(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return DialShadowsocksConn(ctx, h.ssMethod, conn)
}

func (h *Outbound) MultiplexEnabled() bool {
	return !h.disableReuse
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	if h.transport != nil {
		h.transport.Close()
	}
	if h.client != nil {
		h.client.Reset()
	}
	if h.pseudoVPNEngine != nil {
		h.pseudoVPNEngine.OnInterfaceUpdated()
	}
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	if transportKeeper, isTransportKeeper := h.transport.(adapter.IdleConnectionKeeper); isTransportKeeper {
		transportKeeper.SetKeepIdleConnections(keep)
	}
	if h.client != nil {
		h.client.SetKeepIdleConnections(keep)
	}
}

func (h *Outbound) CloseIdleConnections() {
	if transportKeeper, isTransportKeeper := h.transport.(adapter.IdleConnectionKeeper); isTransportKeeper {
		transportKeeper.CloseIdleConnections()
	}
	if h.client != nil {
		h.client.CloseIdleConnections()
	}
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialContext(ctx, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.DialContext(ctx, network, destination)
	}
	return nil, os.ErrInvalid
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	return h.uotClient.ListenPacket(ctx, destination)
}

func (h *Outbound) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	if h.pseudoVPNEngine != nil {
		return h.pseudoVPNEngine.PreMatchAction(network)
	}
	return adapter.PreMatchContinue
}

func (h *Outbound) WritePackets(packets [][]byte) error {
	if h.pseudoVPNEngine != nil {
		return h.pseudoVPNEngine.WritePackets(packets)
	}
	return os.ErrInvalid
}

func (h *Outbound) PortAddresses() (netip.Addr, netip.Addr) {
	if h.pseudoVPNEngine != nil {
		return h.pseudoVPNEngine.PortAddresses()
	}
	return netip.Addr{}, netip.Addr{}
}

func (h *Outbound) PortMTU() uint32 {
	if h.pseudoVPNEngine != nil {
		return h.pseudoVPNEngine.PortMTU()
	}
	return 0
}

func (h *Outbound) UpstreamPort() any {
	if h.pseudoVPNEngine != nil {
		return h.pseudoVPNEngine.UpstreamPort()
	}
	return nil
}

func (h *Outbound) AttachReturn(returnPath tun.Return) error {
	if h.pseudoVPNEngine != nil {
		return h.pseudoVPNEngine.AttachReturn(returnPath)
	}
	return nil
}

func (h *Outbound) DetachReturn(returnPath tun.Return) error {
	if h.pseudoVPNEngine != nil {
		return h.pseudoVPNEngine.DetachReturn(returnPath)
	}
	return nil
}
