// Package bundle orchestrates symmetric/asymmetric Nowhere carrier sessions.
package bundle

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/tcptls"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const (
	// DefaultMaxUDPQueueBytes is the shared DATA/reassembly budget per physical
	// QUIC session.
	DefaultMaxUDPQueueBytes = 4 * 1024 * 1024
	// DefaultMaxPendingCloses bounds reliable, de-duplicated CLOSE delivery.
	DefaultMaxPendingCloses = 1024
)

// BundleOptions builds an immutable carrier bundle.
type BundleOptions struct {
	// QUIC is required when either direction can select CarrierQUIC,
	// including any mix policy.
	QUIC carrier.QuicBackend
	// TCP is required when either direction can select CarrierTLSTCP,
	// including any mix policy.
	TCP *tcptls.Config
	// Credentials authenticates every physical carrier in the bundle.
	Credentials *wire.Credentials
	// ALPN is the expected carrier ALPN; empty uses wire.DefaultALPN.
	ALPN string
	// Observer receives structured lifecycle and failure events.
	Observer diagnostic.Observer
	// PoolSize is the TLS/TCP idle target for tcp/tcp and must be zero
	// whenever either direction can select QUIC, including mix.
	PoolSize int
	// MaxUDPQueueBytes bounds queued and reassembling QUIC DATAGRAM payload.
	MaxUDPQueueBytes int
	// MaxPendingCloses bounds reliable, de-duplicated CLOSE delivery.
	MaxPendingCloses int
	// PrewarmOnStart starts TLS/TCP pool preparation during construction.
	PrewarmOnStart bool
	// Up selects the client-to-target physical carrier when MixUp is false.
	Up wire.Carrier
	// Down selects the target-to-client physical carrier when MixDown is false.
	Down wire.Carrier
	// MixUp treats uplink as the 1.8.3 mix policy. FlowHeader never carries mix.
	MixUp bool
	// MixDown treats downlink as the 1.8.3 mix policy. mix/mix resolves only
	// to tcp/tcp or udp/udp.
	MixDown bool
	// MixFallbackTimeout is the primary mix-route preparation budget. Zero
	// uses DefaultMixFallbackTimeout. READY and payload failures do not fall back.
	MixFallbackTimeout time.Duration
	// Mux selects dedicated TLS lanes (0, default) or marked Mux shards (1).
	// Portal accepts both on the same listener. Mux has no effect on QUIC
	// and canonicalizes to 0 for a fixed udp/udp route.
	Mux MuxMode
}

type bundleConfig struct {
	quic               carrier.QuicBackend
	tcp                *tcptls.Config
	credentials        *wire.Credentials
	alpn               string
	observer           diagnostic.Observer
	poolSize           int
	maxUDPQueueBytes   int
	maxPendingCloses   int
	prewarmOnStart     bool
	up                 wire.Carrier
	down               wire.Carrier
	upMode             CarrierMode
	downMode           CarrierMode
	usesTCP            bool
	usesQUIC           bool
	routeSeed          uint64
	mixFallbackTimeout time.Duration
	mux                MuxMode
}

// CarrierBundle shares one session id across carriers and allocates flow ids.
//
// In Nowhere 1.5 the bundle owns the session id and the QUIC auth handshake:
// it generates a session id with crypto/rand, reads the TLS exporter off each
// physical session, and prefixes the first flow with the connection-bound auth
// frame. The injected QUIC backend never learns the session id.
type CarrierBundle struct {
	cfg bundleConfig

	sessionIDOnce sync.Once
	sessionID     wire.SessionID
	sessionIDErr  error

	quicOnce sync.Once
	quic     carrier.QuicBackend
	quicErr  error

	tcpOnce sync.Once
	tcp     *tcptls.TCPPool
	tcpErr  error

	muxOnce sync.Once
	mux     *tcptls.MuxManager
	muxErr  error

	// nextFlowID is the next 1.5 flow id to hand out. Flow ids are uint32 and
	// must skip zero; the allocator wraps within the nonzero u32 space.
	nextFlowID atomic.Uint32

	lifecycleMu sync.Mutex
	closed      bool
	closeOnce   sync.Once
	closeErr    error
}

// NewCarrierBundle validates options and returns an isolated session bundle.
func NewCarrierBundle(options BundleOptions) (*CarrierBundle, error) {
	upMode, err := carrierMode(options.Up, options.MixUp)
	if err != nil {
		return nil, err
	}
	downMode, err := carrierMode(options.Down, options.MixDown)
	if err != nil {
		return nil, err
	}
	if err := options.Mux.validate(); err != nil {
		return nil, err
	}
	if options.Credentials == nil {
		return nil, wire.ErrMissingCredentials
	}
	alpn, err := wire.NormalizeALPN(options.ALPN)
	if err != nil {
		return nil, err
	}
	usesTCP := upMode != ModeUDP || downMode != ModeUDP
	usesQUIC := upMode != ModeTCP || downMode != ModeTCP
	up, down := options.Up, options.Down
	if upMode.IsMix() {
		up = 0
	}
	if downMode.IsMix() {
		down = 0
	}
	mux := options.Mux
	if !usesTCP {
		mux = MuxDisabled
	}
	if usesTCP && options.TCP == nil {
		return nil, errors.New("nowhere: nil TCP carrier config")
	}
	if usesQUIC && options.QUIC == nil {
		return nil, errors.New("nowhere: nil quic backend")
	}
	if options.PoolSize < 0 || options.PoolSize > tcptls.MaxPoolSize {
		return nil, errors.New("nowhere: TCP pool size outside 0..256")
	}
	if usesQUIC && options.PoolSize != 0 {
		return nil, errors.New("nowhere: pool must be zero when either carrier is QUIC")
	}
	if mux == MuxEnabled && options.PoolSize != 0 {
		return nil, errors.New("nowhere: pool must be zero when TLS mux is enabled")
	}
	if options.MixFallbackTimeout < 0 {
		return nil, errors.New("nowhere: negative mix fallback timeout")
	}
	mixFallbackTimeout := options.MixFallbackTimeout
	if mixFallbackTimeout == 0 {
		mixFallbackTimeout = DefaultMixFallbackTimeout
	}
	maxUDPQueueBytes := options.MaxUDPQueueBytes
	if maxUDPQueueBytes == 0 {
		maxUDPQueueBytes = DefaultMaxUDPQueueBytes
	}
	if maxUDPQueueBytes < 0 {
		return nil, errors.New("nowhere: negative UDP queue byte limit")
	}
	maxPendingCloses := options.MaxPendingCloses
	if maxPendingCloses == 0 {
		maxPendingCloses = DefaultMaxPendingCloses
	}
	if maxPendingCloses < 0 {
		return nil, errors.New("nowhere: negative pending CLOSE limit")
	}
	bundle := &CarrierBundle{cfg: bundleConfig{
		quic: options.QUIC, tcp: options.TCP, credentials: options.Credentials,
		alpn: alpn, observer: options.Observer, poolSize: options.PoolSize,
		maxUDPQueueBytes: maxUDPQueueBytes, maxPendingCloses: maxPendingCloses,
		prewarmOnStart: options.PrewarmOnStart,
		up:             up, down: down,
		upMode: upMode, downMode: downMode,
		usesTCP: usesTCP, usesQUIC: usesQUIC,
		mixFallbackTimeout: mixFallbackTimeout,
		mux:                mux,
	}}
	bundle.nextFlowID.Store(1)
	sessionID, err := bundle.SessionID()
	if err != nil {
		return nil, err
	}
	bundle.cfg.routeSeed = seedFromSession(sessionID)
	if options.PrewarmOnStart && options.PoolSize > 0 {
		if _, err := bundle.tcpPool(); err != nil {
			return nil, err
		}
	}
	return bundle, nil
}

// SessionID returns the lazily generated identity shared by all bundle carriers.
//
// The session id is generated with crypto/rand and never leaves the bundle for
// QUIC (the TCP carrier needs it to build the auth frame, since the TCP carrier
// performs auth on the physical connection). A random-source failure makes the
// bundle unusable.
func (b *CarrierBundle) SessionID() (wire.SessionID, error) {
	b.sessionIDOnce.Do(func() {
		if _, err := rand.Read(b.sessionID[:]); err != nil {
			b.sessionIDErr = err
			return
		}
		// TCP carrier needs the session id to bind the auth frame to the
		// bundle identity. The QUIC backend is NOT told the session id; the
		// bundle reads the exporter and writes the auth frame itself.
		if b.cfg.tcp != nil {
			b.cfg.tcp, b.sessionIDErr = b.cfg.tcp.BindSession(b.cfg.credentials, b.sessionID, b.cfg.alpn)
		}
	})
	return b.sessionID, b.sessionIDErr
}

// UpCarrier returns the configured uplink carrier. Mix uplink is 0.
func (b *CarrierBundle) UpCarrier() wire.Carrier { return b.cfg.up }

// DownCarrier returns the configured downlink carrier. Mix downlink is 0.
func (b *CarrierBundle) DownCarrier() wire.Carrier { return b.cfg.down }

// UpMode returns the client uplink policy, including mix.
func (b *CarrierBundle) UpMode() CarrierMode { return b.cfg.upMode }

// DownMode returns the client downlink policy, including mix.
func (b *CarrierBundle) DownMode() CarrierMode { return b.cfg.downMode }

// MixEnabled reports whether either direction uses the mix policy.
func (b *CarrierBundle) MixEnabled() bool {
	return b.cfg.upMode.IsMix() || b.cfg.downMode.IsMix()
}

// Asymmetric reports whether the configured policies select different
// carriers. mix/mix is symmetric; a one-sided mix can resolve to either.
func (b *CarrierBundle) Asymmetric() bool { return b.cfg.upMode != b.cfg.downMode }

// PoolTarget returns the configured TLS/TCP idle-pool target.
func (b *CarrierBundle) PoolTarget() int { return b.cfg.poolSize }

// ErrFlowIDExhausted is returned after a bundle has allocated every nonzero flow ID.
var ErrFlowIDExhausted = errors.New("nowhere: flow id space exhausted")

// allocFlowID returns the next flow id in 1..=wire.MaxFlowID. A bundle that
// issues the entire 30-bit space is treated as exhausted rather than reusing
// IDs still held by live flows.
func (b *CarrierBundle) allocFlowID() (wire.FlowID, error) {
	for {
		next := b.nextFlowID.Load()
		if next == 0 || next > wire.MaxFlowID {
			return 0, ErrFlowIDExhausted
		}
		if b.nextFlowID.CompareAndSwap(next, next+1) {
			return next, nil
		}
	}
}

func (b *CarrierBundle) quicClient() (carrier.QuicBackend, error) {
	if !b.cfg.usesQUIC {
		return nil, nil
	}
	b.quicOnce.Do(func() {
		b.lifecycleMu.Lock()
		defer b.lifecycleMu.Unlock()
		if b.closed {
			b.quicErr = net.ErrClosed
			return
		}
		sessionID, err := b.SessionID()
		if err != nil {
			b.quicErr = err
			return
		}
		auth := func(_ context.Context, session carrier.QuicSession) (wire.AuthFrame, error) {
			return buildQUICAuthFrame(session, b.cfg.credentials, b.cfg.alpn, sessionID)
		}
		b.quic = newQUICMuxBackend(b.cfg.quic, auth, b.cfg.maxUDPQueueBytes, b.cfg.maxPendingCloses, b.cfg.observer)
	})
	return b.quic, b.quicErr
}

// buildQUICAuthFrame binds one physical QUIC session to the bundle identity.
// The returned frame is retained by the mux and prepended atomically when the
// first flow commits its setup bytes on the first stream.
func buildQUICAuthFrame(session carrier.QuicSession, creds *wire.Credentials, alpn string, sessionID wire.SessionID) (wire.AuthFrame, error) {
	if session == nil {
		return wire.AuthFrame{}, errors.New("nowhere: nil quic session")
	}
	handshake, err := session.TLSHandshakeInfo()
	if err != nil {
		return wire.AuthFrame{}, err
	}
	if err := handshake.Validate(alpn); err != nil {
		return wire.AuthFrame{}, err
	}
	return wire.EncodeAuthFrame(creds, wire.AuthTransportQUIC, handshake.Exporter, sessionID)
}

func (b *CarrierBundle) tcpPool() (*tcptls.TCPPool, error) {
	if !b.cfg.usesTCP {
		return nil, nil
	}
	if b.cfg.mux == MuxEnabled {
		return nil, nil
	}
	b.tcpOnce.Do(func() {
		b.lifecycleMu.Lock()
		defer b.lifecycleMu.Unlock()
		if b.closed {
			b.tcpErr = net.ErrClosed
			return
		}
		if _, err := b.SessionID(); err != nil {
			b.tcpErr = err
			return
		}
		b.tcp, b.tcpErr = tcptls.NewTCPPool(b.cfg.tcp, b.cfg.poolSize)
		if b.tcpErr == nil && b.cfg.prewarmOnStart && b.cfg.poolSize > 0 {
			b.tcp.Prewarm()
		}
	})
	return b.tcp, b.tcpErr
}

// Prewarm starts preparing the TLS/TCP idle pool up to its target. It is a
// no-op without an idle pool (pool=0, TLS mux or QUIC-only policies) and safe
// to call repeatedly: the pool only tops itself up to the target.
func (b *CarrierBundle) Prewarm() error {
	if b == nil || b.cfg.poolSize <= 0 {
		return nil
	}
	pool, err := b.tcpPool()
	if err != nil {
		return err
	}
	pool.Prewarm()
	return nil
}

// Close releases initialized carrier resources. It is safe on a nil bundle.
func (b *CarrierBundle) Close() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		b.lifecycleMu.Lock()
		b.closed = true
		quicClient := b.quic
		tcpPool := b.tcp
		muxMgr := b.mux
		b.lifecycleMu.Unlock()
		var errs []error
		if quicClient != nil {
			errs = append(errs, quicClient.Close())
		}
		if tcpPool != nil {
			errs = append(errs, tcpPool.Close())
		}
		if muxMgr != nil {
			errs = append(errs, muxMgr.Close())
		}
		b.closeErr = errors.Join(errs...)
	})
	return b.closeErr
}
