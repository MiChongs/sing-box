// Package tcptls is the TLS/TCP carrier pool for Nowhere outbound.
package tcptls

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/dialgate"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/morph"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const (
	defaultPoolSize = 5
	// DefaultPoolSize is the protocol-aligned TLS/TCP idle carrier target.
	DefaultPoolSize = defaultPoolSize
	// MaxPoolSize matches the Rust carrier pool's public upper bound.
	MaxPoolSize = 256

	// DefaultMaxConcurrentDials caps in-flight physical TCP dials per outbound.
	// Conservative default for mixed TCP/QUIC bursts (dial+TLS+auth share the slot).
	DefaultMaxConcurrentDials = 16
	// DefaultWarmBackoffInitial is the first warm-prepare retry delay after failure.
	DefaultWarmBackoffInitial = time.Second
	// DefaultWarmBackoffMax caps exponential warm-prepare backoff.
	DefaultWarmBackoffMax = 30 * time.Second

	// DefaultDialBackoffInitial is the first portal dial retry after refused/timeout.
	DefaultDialBackoffInitial = dialgate.DefaultInitial
	// DefaultDialBackoffMax caps portal dial exponential backoff.
	DefaultDialBackoffMax = dialgate.DefaultMax
)

// TCPDialer establishes the physical TCP carrier connection.
type TCPDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// TLSDialer performs the host-owned TLS 1.3 client handshake on a carrier and
// returns the connection together with its TLS exporter. The exporter is
// required for connection-bound authentication; a host that cannot produce one
// must fail the handshake rather than return a zero exporter.
type TLSDialer interface {
	DialTLSConn(ctx context.Context, conn net.Conn) (wire.HandshakedConn, error)
}

// TCPOptions builds an immutable TLS/TCP carrier Config.
type TCPOptions struct {
	// Address is the logical Portal address used by the carrier.
	Address string
	// ConnectAddress optionally overrides the physical dial destination while
	// preserving Address for diagnostics and host TLS policy.
	ConnectAddress string
	// Dialer establishes the raw TCP connection.
	Dialer TCPDialer
	// TLSDialer performs the TLS 1.3 handshake and captures exporter state.
	TLSDialer TLSDialer
	// Observer receives structured lifecycle and failure events.
	Observer diagnostic.Observer

	// MaxConcurrentDials limits in-flight physical dials (TCP+TLS+auth) per pool.
	// Zero uses DefaultMaxConcurrentDials; negative values are rejected.
	MaxConcurrentDials int
	// WarmBackoffInitial is the first delay after a warm-prepare failure.
	// Zero uses DefaultWarmBackoffInitial; negative values are rejected.
	WarmBackoffInitial time.Duration
	// WarmBackoffMax caps warm-prepare exponential backoff.
	// Zero uses DefaultWarmBackoffMax; negative values are rejected.
	WarmBackoffMax time.Duration
	// DialBackoffInitial is the first delay after portal connection refused / dial timeout.
	// Zero uses DefaultDialBackoffInitial; negative values are rejected.
	DialBackoffInitial time.Duration
	// MorphSharedKey enables the Morph TCP transform when non-empty.
	MorphSharedKey []byte
	// DialBackoffMax caps portal dial exponential backoff.
	// Zero uses DefaultDialBackoffMax; negative values are rejected.
	DialBackoffMax time.Duration
}

// Config is immutable and safe to share between bundles.
type Config struct {
	address            string
	connectAddress     string
	credentials        *wire.Credentials
	alpn               string
	dialer             TCPDialer
	tlsDialer          TLSDialer
	observer           diagnostic.Observer
	sessionID          wire.SessionID
	logger             carrier.Logger
	maxConcurrentDials int
	warmBackoffInitial time.Duration
	warmBackoffMax     time.Duration
	dialBackoffInitial time.Duration
	dialBackoffMax     time.Duration
	morph              *morph.Keys
}

// NewConfig validates a TLS/TCP carrier configuration.
func NewConfig(options TCPOptions) (*Config, error) {
	if options.Address == "" {
		return nil, fmt.Errorf("nowhere: empty TCP carrier address")
	}
	if options.Dialer == nil {
		return nil, fmt.Errorf("nowhere: nil TCP dialer")
	}
	if options.TLSDialer == nil {
		return nil, fmt.Errorf("nowhere: nil TLS dialer")
	}
	maxDials := options.MaxConcurrentDials
	if maxDials < 0 {
		return nil, fmt.Errorf("nowhere: max concurrent dials must be >= 0")
	}
	if maxDials == 0 {
		maxDials = DefaultMaxConcurrentDials
	}
	warmInitial := options.WarmBackoffInitial
	if warmInitial < 0 {
		return nil, fmt.Errorf("nowhere: warm backoff initial must be >= 0")
	}
	if warmInitial == 0 {
		warmInitial = DefaultWarmBackoffInitial
	}
	warmMax := options.WarmBackoffMax
	if warmMax < 0 {
		return nil, fmt.Errorf("nowhere: warm backoff max must be >= 0")
	}
	if warmMax == 0 {
		warmMax = DefaultWarmBackoffMax
	}
	if warmInitial > warmMax {
		return nil, fmt.Errorf("nowhere: warm backoff initial exceeds max")
	}
	dialInitial := options.DialBackoffInitial
	if dialInitial < 0 {
		return nil, fmt.Errorf("nowhere: dial backoff initial must be >= 0")
	}
	if dialInitial == 0 {
		dialInitial = DefaultDialBackoffInitial
	}
	dialMax := options.DialBackoffMax
	if dialMax < 0 {
		return nil, fmt.Errorf("nowhere: dial backoff max must be >= 0")
	}
	if dialMax == 0 {
		dialMax = DefaultDialBackoffMax
	}
	if dialInitial > dialMax {
		return nil, fmt.Errorf("nowhere: dial backoff initial exceeds max")
	}
	config := &Config{
		address: options.Address, connectAddress: options.ConnectAddress,
		dialer:    options.Dialer,
		tlsDialer: options.TLSDialer, observer: options.Observer,
		maxConcurrentDials: maxDials,
		warmBackoffInitial: warmInitial,
		warmBackoffMax:     warmMax,
		dialBackoffInitial: dialInitial,
		dialBackoffMax:     dialMax,
	}
	config.logger = observerLogger{observer: options.Observer}
	if len(options.MorphSharedKey) > 0 {
		keys := morph.Derive(options.MorphSharedKey)
		config.morph = &keys
	}
	return config, nil
}

// BindSession returns a copy bound to one bundle's credentials, identity, and
// expected ALPN. Authentication is always domain-separated as TLS/TCP inside
// this package.
func (c *Config) BindSession(credentials *wire.Credentials, sessionID wire.SessionID, alpn string) (*Config, error) {
	if c == nil {
		return nil, fmt.Errorf("nowhere: nil TCP carrier config")
	}
	if credentials == nil {
		return nil, wire.ErrMissingCredentials
	}
	if sessionID == (wire.SessionID{}) {
		return nil, fmt.Errorf("nowhere: missing session id")
	}
	normalizedALPN, err := wire.NormalizeALPN(alpn)
	if err != nil {
		return nil, err
	}
	clone := *c
	clone.credentials = credentials
	clone.sessionID = sessionID
	clone.alpn = normalizedALPN
	return &clone, nil
}

// MaxConcurrentDials returns the normalized dial concurrency cap.
func (c *Config) MaxConcurrentDials() int {
	if c == nil {
		return DefaultMaxConcurrentDials
	}
	return c.maxConcurrentDials
}

// WarmBackoffInitial returns the normalized warm-prepare backoff floor.
func (c *Config) WarmBackoffInitial() time.Duration {
	if c == nil {
		return DefaultWarmBackoffInitial
	}
	return c.warmBackoffInitial
}

// WarmBackoffMax returns the normalized warm-prepare backoff ceiling.
func (c *Config) WarmBackoffMax() time.Duration {
	if c == nil {
		return DefaultWarmBackoffMax
	}
	return c.warmBackoffMax
}

// DialBackoffInitial returns the normalized portal dial backoff floor.
func (c *Config) DialBackoffInitial() time.Duration {
	if c == nil {
		return DefaultDialBackoffInitial
	}
	return c.dialBackoffInitial
}

// DialBackoffMax returns the normalized portal dial backoff ceiling.
func (c *Config) DialBackoffMax() time.Duration {
	if c == nil {
		return DefaultDialBackoffMax
	}
	return c.dialBackoffMax
}

// Observer returns the configured diagnostic observer (may be nil).
func (c *Config) Observer() diagnostic.Observer {
	if c == nil {
		return nil
	}
	return c.observer
}

type observerLogger struct{ observer diagnostic.Observer }

func (l observerLogger) Debugf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	ev := diagnostic.ParseCarrierLog(msg)
	ev.Level = diagnostic.LevelDebug
	diagnostic.Emit(context.Background(), l.observer, ev)
}

func (l observerLogger) Warnf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	ev := diagnostic.ParseCarrierLog(msg)
	ev.Level = diagnostic.LevelWarn
	if ev.Code == "" || ev.Code == "carrier_debug" {
		ev.Code = "carrier_warning"
	}
	diagnostic.Emit(context.Background(), l.observer, ev)
}
