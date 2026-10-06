package server

import (
	"fmt"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/morph"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const (
	// DefaultTLSHandshakeTimeout bounds the host-provided TLS handshake.
	DefaultTLSHandshakeTimeout = 5 * time.Second
	// DefaultAuthTimeout is the center of the jittered authentication deadline.
	DefaultAuthTimeout = 5 * time.Second
	// DefaultRequestIdleTimeout bounds the first request after authentication.
	DefaultRequestIdleTimeout = 40 * time.Second
	// DefaultFlowPairTimeout bounds asymmetric half pairing.
	DefaultFlowPairTimeout = 15 * time.Second
	// DefaultUDPIdleTimeout closes inactive UDP flows.
	DefaultUDPIdleTimeout = 120 * time.Second
	// DefaultTCPReadGrace bounds the remaining relay direction after half-close.
	DefaultTCPReadGrace = 30 * time.Second
	// DefaultShutdownTimeout is normalized into Timeouts.Shutdown for host-controlled shutdown.
	DefaultShutdownTimeout = 5 * time.Second
)

const (
	// DefaultPendingFlowsPerSession is the per-session claim ceiling (active or pending).
	DefaultPendingFlowsPerSession = 4096
	// DefaultUDPFlowsPerSession is retained as a UDP route budget; 2.0 has no separate application UDP quota.
	DefaultUDPFlowsPerSession = 4096
	// DefaultUDPQueueBytes is the shared datagram queue byte budget per session.
	DefaultUDPQueueBytes = 4 * 1024 * 1024
	// DefaultUDPQueuePackets limits queued datagrams per flow.
	DefaultUDPQueuePackets = 64
	// DefaultActiveQUICSessions limits authenticated QUIC sessions.
	DefaultActiveQUICSessions = 1024
	// DefaultAuthenticatedTCPIdleConnections limits authenticated TCP halves awaiting use.
	DefaultAuthenticatedTCPIdleConnections = 4096
	// DefaultPortalClaims is the pairing-registry admission ceiling.
	DefaultPortalClaims = 65536
)

// Network selects a Portal ingress carrier.
type Network string

const (
	// NetworkTCP enables TLS-over-TCP carriers.
	NetworkTCP Network = "tcp"
	// NetworkUDP enables QUIC/UDP carriers.
	NetworkUDP Network = "udp"
)

// Timeouts controls bounded server operations. Zero values use protocol defaults.
type Timeouts struct {
	// TLSHandshake bounds the host-provided TLS handshake.
	TLSHandshake time.Duration
	// Auth is the center of the jittered carrier authentication deadline.
	Auth time.Duration
	// RequestIdle bounds the first FLOW request after TCP authentication.
	RequestIdle time.Duration
	// FlowPair bounds OPEN/ATTACH pairing.
	FlowPair time.Duration
	// UDPIdle closes an inactive UDP flow.
	UDPIdle time.Duration
	// TCPReadGrace bounds the remaining relay direction after a half-close.
	TCPReadGrace time.Duration
	// Shutdown bounds shared handler and listener cleanup.
	Shutdown time.Duration
}

// Limits controls process and session resource bounds. Zero values use defaults.
type Limits struct {
	// PendingFlowsPerSession limits unresolved split-flow pairs.
	PendingFlowsPerSession int
	// UDPFlowsPerSession limits active and pending UDP flows.
	UDPFlowsPerSession int
	// UDPQueueBytes limits queued packets and retained reassembly bytes.
	UDPQueueBytes int
	// UDPQueuePackets limits queued datagrams per flow.
	UDPQueuePackets int
	// ActiveQUICSessions limits authenticated QUIC sessions.
	ActiveQUICSessions int
	// AuthenticatedTCPIdleConnections limits authenticated TCP halves awaiting use.
	AuthenticatedTCPIdleConnections int
	// MaxUnauthenticatedConnections is the process-wide pre-auth admission cap.
	MaxUnauthenticatedConnections int
	// MaxUnauthenticatedPerSource is the IPv4 /32 or IPv6 /64 pre-auth cap.
	MaxUnauthenticatedPerSource int
	// MaxConcurrentHandshakes limits in-flight host TLS handshakes.
	MaxConcurrentHandshakes int
}

// ConfigOptions builds an immutable server Config.
type ConfigOptions struct {
	// Credentials authenticates every enabled ingress carrier.
	Credentials *wire.Credentials
	// ALPN is the expected carrier ALPN; empty uses wire.DefaultALPN.
	ALPN string
	// Networks selects ingress carriers; empty enables TCP and UDP.
	Networks []Network
	// Timeouts overrides bounded-operation defaults.
	Timeouts Timeouts
	// Limits overrides server resource defaults.
	Limits Limits
	// MorphSharedKey enables Morph on accepted TCP carriers when non-empty.
	MorphSharedKey []byte
}

// Config is normalized and immutable after construction.
type Config struct {
	credentials *wire.Credentials
	alpn        string
	networks    []Network
	enableTCP   bool
	enableUDP   bool
	timeouts    Timeouts
	limits      Limits
	morph       *morph.Keys
}

// NewConfig validates and normalizes server configuration.
func NewConfig(options ConfigOptions) (*Config, error) {
	if options.Credentials == nil {
		return nil, fmt.Errorf("%w: nil credentials", ErrInvalidConfig)
	}
	alpn, err := wire.NormalizeALPN(options.ALPN)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	timeouts, err := normalizeTimeouts(options.Timeouts)
	if err != nil {
		return nil, err
	}
	limits, err := normalizeLimits(options.Limits)
	if err != nil {
		return nil, err
	}
	networks := options.Networks
	if len(networks) == 0 {
		networks = []Network{NetworkTCP, NetworkUDP}
	}
	seen := make(map[Network]struct{}, len(networks))
	cfg := &Config{
		credentials: options.Credentials,
		alpn:        alpn,
		timeouts:    timeouts,
		limits:      limits,
		networks:    append([]Network(nil), networks...),
	}
	for _, network := range networks {
		if _, exists := seen[network]; exists {
			return nil, fmt.Errorf("%w: duplicate network %q", ErrInvalidConfig, network)
		}
		seen[network] = struct{}{}
		switch network {
		case NetworkTCP:
			cfg.enableTCP = true
		case NetworkUDP:
			cfg.enableUDP = true
		default:
			return nil, fmt.Errorf("%w: unsupported network %q", ErrInvalidConfig, network)
		}
	}
	if len(options.MorphSharedKey) > 0 {
		keys := morph.Derive(options.MorphSharedKey)
		cfg.morph = &keys
	}
	return cfg, nil
}

func normalizeTimeouts(value Timeouts) (Timeouts, error) {
	defaults := Timeouts{
		TLSHandshake: DefaultTLSHandshakeTimeout,
		Auth:         DefaultAuthTimeout,
		RequestIdle:  DefaultRequestIdleTimeout,
		FlowPair:     DefaultFlowPairTimeout,
		UDPIdle:      DefaultUDPIdleTimeout,
		TCPReadGrace: DefaultTCPReadGrace,
		Shutdown:     DefaultShutdownTimeout,
	}
	fields := []struct {
		name string
		in   *time.Duration
		out  *time.Duration
	}{
		{"tls handshake timeout", &value.TLSHandshake, &defaults.TLSHandshake},
		{"auth timeout", &value.Auth, &defaults.Auth},
		{"request idle timeout", &value.RequestIdle, &defaults.RequestIdle},
		{"flow pair timeout", &value.FlowPair, &defaults.FlowPair},
		{"udp idle timeout", &value.UDPIdle, &defaults.UDPIdle},
		{"tcp read grace", &value.TCPReadGrace, &defaults.TCPReadGrace},
		{"shutdown timeout", &value.Shutdown, &defaults.Shutdown},
	}
	for _, field := range fields {
		if *field.in < 0 {
			return Timeouts{}, fmt.Errorf("%w: negative %s", ErrInvalidConfig, field.name)
		}
		if *field.in > 0 {
			*field.out = *field.in
		}
	}
	return defaults, nil
}

func normalizeLimits(value Limits) (Limits, error) {
	defaults := Limits{
		PendingFlowsPerSession:          DefaultPendingFlowsPerSession,
		UDPFlowsPerSession:              DefaultUDPFlowsPerSession,
		UDPQueueBytes:                   DefaultUDPQueueBytes,
		UDPQueuePackets:                 DefaultUDPQueuePackets,
		ActiveQUICSessions:              DefaultActiveQUICSessions,
		AuthenticatedTCPIdleConnections: DefaultAuthenticatedTCPIdleConnections,
		MaxUnauthenticatedConnections:   DefaultMaxUnauthenticatedConnections,
		MaxUnauthenticatedPerSource:     DefaultMaxUnauthenticatedPerSource,
		MaxConcurrentHandshakes:         DefaultMaxConcurrentHandshakes,
	}
	fields := []struct {
		name string
		in   *int
		out  *int
	}{
		{"pending flows per-session", &value.PendingFlowsPerSession, &defaults.PendingFlowsPerSession},
		{"udp flows per-session", &value.UDPFlowsPerSession, &defaults.UDPFlowsPerSession},
		{"udp queue bytes", &value.UDPQueueBytes, &defaults.UDPQueueBytes},
		{"udp queue packets", &value.UDPQueuePackets, &defaults.UDPQueuePackets},
		{"active quic sessions", &value.ActiveQUICSessions, &defaults.ActiveQUICSessions},
		{"authenticated tcp idle connections", &value.AuthenticatedTCPIdleConnections, &defaults.AuthenticatedTCPIdleConnections},
		{"max unauthenticated connections", &value.MaxUnauthenticatedConnections, &defaults.MaxUnauthenticatedConnections},
		{"max unauthenticated per source", &value.MaxUnauthenticatedPerSource, &defaults.MaxUnauthenticatedPerSource},
		{"max concurrent handshakes", &value.MaxConcurrentHandshakes, &defaults.MaxConcurrentHandshakes},
	}
	for _, field := range fields {
		if *field.in < 0 {
			return Limits{}, fmt.Errorf("%w: negative %s", ErrInvalidConfig, field.name)
		}
		if *field.in > 0 {
			*field.out = *field.in
		}
	}
	if defaults.MaxUnauthenticatedPerSource > defaults.MaxUnauthenticatedConnections {
		return Limits{}, fmt.Errorf("%w: per-source unauthenticated limit exceeds global limit", ErrInvalidConfig)
	}
	return defaults, nil
}

// TCPEnabled reports whether TCP ingress is enabled.
func (c *Config) TCPEnabled() bool { return c != nil && c.enableTCP }

// UDPEnabled reports whether QUIC/UDP ingress is enabled.
func (c *Config) UDPEnabled() bool { return c != nil && c.enableUDP }

// Networks returns a defensive copy of the configured ingress carriers.
func (c *Config) Networks() []Network {
	if c == nil {
		return nil
	}
	return append([]Network(nil), c.networks...)
}

// Credentials returns the immutable credentials used for connection-bound auth.
func (c *Config) Credentials() *wire.Credentials {
	if c == nil {
		return nil
	}
	return c.credentials
}

// ALPN returns the normalized single expected application protocol.
func (c *Config) ALPN() string {
	if c == nil {
		return wire.DefaultALPN
	}
	return c.alpn
}

// Timeouts returns the normalized timeout values by value.
func (c *Config) Timeouts() Timeouts {
	if c == nil {
		return Timeouts{}
	}
	return c.timeouts
}

// Limits returns the normalized resource limits by value.
func (c *Config) Limits() Limits {
	if c == nil {
		return Limits{}
	}
	return c.limits
}
