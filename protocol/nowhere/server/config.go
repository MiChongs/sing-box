package server

import (
	"github.com/sagernet/sing-box/option"
	nwserver "github.com/sagernet/sing-box/protocol/nowhere/core/server"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	N "github.com/sagernet/sing/common/network"
)

// Type aliases for thin re-export of the vendored nw2 core server.
type (
	Config       = nwserver.Config
	Handler      = nwserver.Handler
	Upstream     = nwserver.Upstream
	CloseHandler = nwserver.CloseHandler
	QuicConn     = nwserver.QuicConn
	QuicListener = nwserver.QuicListener
	QuicStream   = nwserver.QuicStream
)

// IsReported reports whether the protocol core already emitted the error.
var IsReported = nwserver.IsReported

// NewConfig builds nw2 core server Config from SingBox inbound options.
func NewConfig(options option.NowhereInboundOptions) (*Config, error) {
	credentials, err := wire.NewCredentials(options.Password)
	if err != nil {
		return nil, err
	}
	rawNetworks := options.Network.Build()
	networks := make([]nwserver.Network, 0, len(rawNetworks))
	for _, network := range rawNetworks {
		switch network {
		case N.NetworkTCP:
			networks = append(networks, nwserver.NetworkTCP)
		case N.NetworkUDP:
			networks = append(networks, nwserver.NetworkUDP)
		default:
			networks = append(networks, nwserver.Network(network))
		}
	}
	limits := nwserver.Limits{}
	if options.MaxUnauthenticatedConnections != nil {
		limits.MaxUnauthenticatedConnections = *options.MaxUnauthenticatedConnections
	}
	if options.MaxUnauthenticatedPerSource != nil {
		limits.MaxUnauthenticatedPerSource = *options.MaxUnauthenticatedPerSource
	}
	alpn := wire.DefaultALPN
	if options.TLS != nil && len(options.TLS.ALPN) == 1 {
		alpn = string(options.TLS.ALPN[0])
	}
	// MorphSharedKey mirrors nowhere.MorphSharedKey inline: package server
	// cannot import package nowhere (import cycle).
	var morphSharedKey []byte
	if options.Morph && options.Password != "" {
		morphSharedKey = []byte(options.Password)
	}
	return nwserver.NewConfig(nwserver.ConfigOptions{
		Credentials:    credentials,
		ALPN:           alpn,
		Networks:       networks,
		Limits:         limits,
		MorphSharedKey: morphSharedKey,
	})
}
