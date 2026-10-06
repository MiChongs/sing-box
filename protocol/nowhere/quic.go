//go:build with_quic

package nowhere

import (
	quic "github.com/sagernet/sing-box/protocol/nowhere/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier"
)

const quicIncluded = true

// QUICConfig remains available to with_quic host integrations while the
// untagged facade stays free of concrete QUIC dependencies.
type QUICConfig = quic.QUICConfig

func newQuicBackend(options quicBackendOptions) carrier.QuicBackend {
	return NewQuicBackend(&quic.QUICConfig{
		Context:           options.context,
		Addr:              options.address,
		ServerName:        options.serverName,
		TLSConfig:         options.tlsConfig,
		QUICConfig:        quic.BuildQUICConfig(options.quicOptions),
		Dialer:            options.dialer,
		CongestionControl: options.congestionControl,
		MorphSharedKey:    options.morphSharedKey,
		Observer:          options.observer,
	})
}
