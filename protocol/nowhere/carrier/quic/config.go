//go:build with_quic

package quic

import (
	"context"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	nwquic "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	N "github.com/sagernet/sing/common/network"
)

const (
	defaultHandshakeIdleTimeout        = 5 * time.Second
	defaultIdleTimeout                 = 120 * time.Second
	defaultStreamReceiveWindow  uint64 = nwquic.RecommendedStreamReceiveWindow
	defaultInitialConnWindow    uint64 = nwquic.RecommendedConnectionReceiveWindow
	defaultMaxConnWindow        uint64 = nwquic.RecommendedConnectionReceiveWindow
	defaultMaxIncomingStreams   int64  = 1024
	// quic-go uses a negative Config value to encode an advertised zero; zero
	// itself means "use the library default" during config normalization.
	nowhereUniStreams int64 = -1
)

// Note: Vector 1.5.2 also sets send_window=32MiB and datagram buffers=4MiB
// (nwquic.RecommendedSendWindow / RecommendedDatagramBufferSize). sagernet
// quic-go Config does not expose those knobs.

// QUICConfig holds per-proxy QUIC/TLS settings.
type QUICConfig struct {
	Context           context.Context
	Addr              string
	ServerName        string
	TLSConfig         tls.Config
	QUICConfig        *quic.Config
	Dialer            N.Dialer
	CongestionControl CongestionControl
	// MorphSharedKey enables the Morph keyed transform under QUIC when
	// non-empty: every client packet socket seals udp c2s and opens udp s2c.
	MorphSharedKey []byte
	Observer       diagnostic.Observer
	IdleCloseDelay time.Duration
	// DialBackoffInitial / DialBackoffMax control portal session establish backoff.
	DialBackoffInitial time.Duration
	DialBackoffMax     time.Duration
}

// BuildQUICServerConfig configures the host transport for the session admission
// limit and no unidirectional streams. The server adapter enforces the one
// pre-auth bidirectional stream rule, because stock quic-go cannot safely
// raise a transport-level stream limit on an established connection.
func BuildQUICServerConfig(options option.QUICOptions) *quic.Config {
	config := BuildQUICConfig(options)
	config.MaxIncomingUniStreams = nowhereUniStreams
	return config
}

// BuildQUICConfig applies shared sing-box QUIC options over Nowhere defaults.
func BuildQUICConfig(options option.QUICOptions) *quic.Config {
	config := &quic.Config{
		EnableDatagrams:                true,
		Allow0RTT:                      false,
		MaxIncomingStreams:             defaultMaxIncomingStreams,
		MaxIncomingUniStreams:          nowhereUniStreams,
		InitialStreamReceiveWindow:     defaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         defaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: defaultInitialConnWindow,
		MaxConnectionReceiveWindow:     defaultMaxConnWindow,
		KeepAlivePeriod:                0,
		HandshakeIdleTimeout:           defaultHandshakeIdleTimeout,
		MaxIdleTimeout:                 defaultIdleTimeout,
		DisablePathMTUDiscovery:        false,
	}
	applyQUICOptions(config, options)
	return config
}

// applyQUICOptions applies user-provided QUIC options over the defaults,
// mirroring the legacy sing-quic ApplyQUICOptions behavior.
func applyQUICOptions(config *quic.Config, options option.QUICOptions) {
	if streamReceiveWindow := options.StreamReceiveWindow.Value(); streamReceiveWindow != 0 {
		config.InitialStreamReceiveWindow = streamReceiveWindow
		config.MaxStreamReceiveWindow = streamReceiveWindow
	}
	if connectionReceiveWindow := options.ConnectionReceiveWindow.Value(); connectionReceiveWindow != 0 {
		config.InitialConnectionReceiveWindow = connectionReceiveWindow
		config.MaxConnectionReceiveWindow = connectionReceiveWindow
	}
	if options.MaxConcurrentStreams > 0 {
		config.MaxIncomingStreams = int64(options.MaxConcurrentStreams)
	}
	if keepAlivePeriod := options.KeepAlivePeriod.Build(); keepAlivePeriod > 0 {
		config.KeepAlivePeriod = keepAlivePeriod
	}
	if idleTimeout := options.IdleTimeout.Build(); idleTimeout > 0 {
		config.MaxIdleTimeout = idleTimeout
	}
	if options.InitialPacketSize > 0 {
		config.InitialPacketSize = uint16(options.InitialPacketSize)
	}
	if options.DisablePathMTUDiscovery {
		config.DisablePathMTUDiscovery = true
	}
}
