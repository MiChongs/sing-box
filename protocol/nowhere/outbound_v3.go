package nowhere

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/nowhere/core/morph"
	"github.com/sagernet/sing-box/protocol/nowhere/core/qio"
	"github.com/sagernet/sing-box/protocol/nowhere/core/vector"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	"github.com/sagernet/sing-box/protocol/nowhere/internal/quicsettings"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// OutboundV3 is the Nowhere 3 Vector client. One endpoint speaks one transport
// toward one Portal; the vendored Vector performs the nw3 handshake on the
// first flow (TCP transport) or on the first dial (UDP transport) and multiplexes
// every later flow over the same session.
type OutboundV3 struct {
	outbound.Adapter
	logger log.ContextLogger

	mu     sync.Mutex
	client *vector.Client
	closed bool
}

// NewOutboundV3 builds the Nowhere 3 outbound. The nw2 outbound keeps its own
// constructor; NewOutbound dispatches between the two.
func NewOutboundV3(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NowhereOutboundOptions) (adapter.Outbound, error) {
	if options.Password == "" {
		return nil, E.New("nowhere: missing password")
	}
	if err := validateNowhereV3OutboundOptions(&options); err != nil {
		return nil, err
	}
	transport, err := nowhereV3Net(options.Net)
	if err != nil {
		return nil, err
	}
	if err := wire.ValidateServiceKey(options.Password); err != nil {
		return nil, E.Cause(err, "nowhere: password")
	}
	congestionControl, err := quicsettings.ParseCongestionControl(options.QUICCongestionControl)
	if err != nil {
		return nil, err
	}
	server := options.ServerOptions.Build()
	tlsConfig, err := buildNowhereV3ClientTLS(ctx, logger, server.String(), common.PtrValueOrDefault(options.TLS), options.Pin)
	if err != nil {
		return nil, err
	}
	morphEnabled := resolveNowhereMorph(options.Morph, nowhereStackNw3)
	var morphKeys *morph.Keys
	if morphEnabled {
		keys := nowhereV3MorphKeys(options.Password)
		morphKeys = &keys
	}
	clientConfig := vector.Config{
		SharedKey:  options.Password,
		Morph:      morphEnabled,
		PortalAddr: server.String(),
		TLS:        tlsConfig,
	}
	if transport == nowhereV3NetTCP {
		portalDialer, err := dialer.NewWithOptions(dialer.Options{
			Context:        ctx,
			Options:        options.DialerOptions,
			RemoteIsDomain: options.ServerIsDomain(),
		})
		if err != nil {
			return nil, E.Cause(err, "nowhere: build portal dialer")
		}
		clientConfig.DialTCP = func(dialCtx context.Context, addr string) (net.Conn, error) {
			return portalDialer.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr(addr))
		}
	} else {
		quicDialer, err := dialer.NewWithOptions(dialer.Options{
			Context:        ctx,
			Options:        options.DialerOptions,
			RemoteIsDomain: options.ServerIsDomain(),
		})
		if err != nil {
			return nil, E.Cause(err, "nowhere: build portal dialer")
		}
		clientConfig.TLS = nil
		clientConfig.PortalAddr = ""
		clientConfig.DialQUIC = func(dialCtx context.Context) (qio.Conn, error) {
			return dialNowhereV3QUICCarrier(dialCtx, quicDialer, server, tlsConfig, options.QUICOptions, congestionControl, morphKeys)
		}
	}
	client, err := vector.New(clientConfig)
	if err != nil {
		return nil, err
	}
	return &OutboundV3{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeNowhere, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:  logger,
		client:  client,
	}, nil
}

func (o *OutboundV3) getClient() (*vector.Client, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.client == nil {
		return nil, net.ErrClosed
	}
	return o.client, nil
}

func (o *OutboundV3) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	client, err := o.getClient()
	if err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return client.OpenTCP(ctx, nw3TargetFromSocksaddr(destination))
	case N.NetworkUDP:
		conn, err := o.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination.UDPAddr()), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (o *OutboundV3) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	client, err := o.getClient()
	if err != nil {
		return nil, err
	}
	conn, err := client.OpenUDP(ctx, nw3TargetFromSocksaddr(destination))
	if err != nil {
		return nil, err
	}
	return bufio.NewUnbindPacketConnWithAddr(conn, destination), nil
}

// InterfaceUpdated drops the cached QUIC session so the next flow re-dials the
// Portal; the vendored Vector rebuilds it on its own after a Close. The client
// reference itself must survive: getClient treats a nil one as closed, and the
// TCP transport dials every flow through this same client, so dropping it here
// would leave the outbound permanently unable to open flows.
func (o *OutboundV3) InterfaceUpdated(ctx context.Context) {
	o.mu.Lock()
	client := o.client
	o.mu.Unlock()
	if client != nil {
		if err := client.Close(); err != nil {
			o.logger.Warn(E.Cause(err, "nowhere: close vector session after interface update"))
		}
	}
}

func (o *OutboundV3) Close() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	client := o.client
	o.client = nil
	o.mu.Unlock()
	if client == nil {
		return nil
	}
	return client.Close()
}

var _ adapter.Outbound = (*OutboundV3)(nil)

// nw3TargetFromSocksaddr converts a sing destination into a Nowhere 3 target.
func nw3TargetFromSocksaddr(destination M.Socksaddr) wire.Target {
	if destination.IsIP() {
		target, err := wire.NewIPTarget(destination.Addr, destination.Port)
		if err == nil {
			return target
		}
	}
	target, err := wire.NewDomainTarget(destination.Fqdn, destination.Port)
	if err != nil {
		return wire.Target{Port: destination.Port}
	}
	return target
}
