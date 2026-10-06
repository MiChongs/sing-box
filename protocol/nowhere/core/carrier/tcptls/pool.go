package tcptls

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier"
	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/dialgate"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const warmTTL = 30 * time.Second

func loggerFrom(cfg *Config) carrier.Logger {
	if cfg != nil && cfg.logger != nil {
		return cfg.logger
	}
	return carrier.NopLogger{}
}

func (p *TCPPool) logger() carrier.Logger {
	return loggerFrom(p.cfg)
}

const (
	nowhereTCPSocketBufferEnv = "NOWHERE_TCP_SOCKET_BUFFER"
	tcpKeepAlivePeriod        = 30 * time.Second
)

type warmConn struct {
	conn     net.Conn
	exporter wire.TLSExporter
	carrier  *carrierInfo
	expiry   *time.Timer
}

type poolSnapshot struct {
	idle      int
	preparing int
	target    int
}

// TCPPool holds warm authenticated TLS/TCP connections.
// Idle entries are pre-auth only; after a request frame the carrier is consumed
// (no Release/Put). Each Acquire pops at most one connection under p.mu.
type TCPPool struct {
	cfg       *Config
	target    int
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	dialSlots chan struct{}
	dialGate  *dialgate.Gate
	mu        sync.Mutex
	idle      []*warmConn
	preparing int
	closed    bool
	closeOnce sync.Once
	closeErr  error

	warmFailCount int
	nextWarmRetry time.Time
}

// NewTCPPool creates a pool from a session-bound Config and validates the idle
// carrier target. Callers normally let bundle.CarrierBundle create the pool.
func NewTCPPool(cfg *Config, target int) (*TCPPool, error) {
	if cfg == nil || cfg.credentials == nil || cfg.dialer == nil || cfg.tlsDialer == nil {
		return nil, errors.New("nowhere: incomplete TCP pool config")
	}
	if target < 0 || target > MaxPoolSize {
		return nil, fmt.Errorf("nowhere: TCP pool size %d outside 0..%d", target, MaxPoolSize)
	}
	maxDials := cfg.maxConcurrentDials
	if maxDials <= 0 {
		maxDials = DefaultMaxConcurrentDials
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &TCPPool{
		cfg:       cfg,
		target:    target,
		ctx:       ctx,
		cancel:    cancel,
		dialSlots: make(chan struct{}, maxDials),
		dialGate: dialgate.New(dialgate.Options{
			Initial: cfg.DialBackoffInitial(),
			Max:     cfg.DialBackoffMax(),
		}),
	}, nil
}

// Target returns the current idle-carrier target.
func (p *TCPPool) Target() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.target
}

// Resize changes the idle-carrier target and closes excess warm carriers.
func (p *TCPPool) Resize(target int) error {
	if target < 0 || target > MaxPoolSize {
		return fmt.Errorf("nowhere: TCP pool size %d outside 0..%d", target, MaxPoolSize)
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return net.ErrClosed
	}
	p.target = target
	var dropped []*warmConn
	for len(p.idle) > target {
		// Drop oldest idle first so resize matches FIFO borrow order.
		wc := p.idle[0]
		p.idle = p.idle[1:]
		if wc.expiry != nil {
			wc.expiry.Stop()
		}
		wc.carrier.transition(stateClosed)
		p.logger().Debugf("[Nowhere] [carrier] pool_resize_drop carrier_id=%d new_target=%d", wc.carrier.id, target)
		dropped = append(dropped, wc)
	}
	p.mu.Unlock()
	var closeErrors []error
	for _, wc := range dropped {
		closeErrors = append(closeErrors, wc.conn.Close())
	}
	return errors.Join(closeErrors...)
}

func (p *TCPPool) snapshotLocked() poolSnapshot {
	return poolSnapshot{
		idle:      len(p.idle),
		preparing: p.preparing,
		target:    p.target,
	}
}

func (p *TCPPool) replenishBudget(afterWarmHit bool) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.replenishBudgetLocked(afterWarmHit)
}

func (p *TCPPool) replenishBudgetLocked(afterWarmHit bool) int {
	max := 0
	if afterWarmHit {
		max = 2
	} else if len(p.idle)+p.preparing == 0 {
		max = 1
	}
	if max <= 0 || p.target <= 0 {
		return 0
	}
	if !p.warmAllowedLocked() {
		return 0
	}
	room := p.target - (len(p.idle) + p.preparing)
	if room <= 0 {
		return 0
	}
	if max > room {
		return room
	}
	return max
}

func (p *TCPPool) maybeStartPrepare(count int) {
	if count <= 0 {
		return
	}
	p.mu.Lock()
	if p.closed || p.target <= 0 {
		p.mu.Unlock()
		return
	}
	if !p.warmAllowedLocked() {
		delay := time.Until(p.nextWarmRetry)
		p.mu.Unlock()
		p.logger().Debugf("[Nowhere] [carrier] warm_backoff delay_ms=%d", delay.Milliseconds())
		return
	}
	room := p.target - (len(p.idle) + p.preparing)
	if room <= 0 {
		p.mu.Unlock()
		return
	}
	if count > room {
		count = room
	}
	p.preparing += count
	for i := 0; i < count; i++ {
		p.wg.Add(1)
		go p.prepareOne()
	}
	p.mu.Unlock()
}

// Prewarm starts background prepares up to the configured pool target.
// Business Acquire still shares dial slots and takes priority under contention.
func (p *TCPPool) Prewarm() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.closed || p.target <= 0 {
		p.mu.Unlock()
		return
	}
	need := p.target - (len(p.idle) + p.preparing)
	p.mu.Unlock()
	if need > 0 {
		p.logger().Debugf("[Nowhere] [carrier] pool_prewarm pool_target=%d count=%d", p.Target(), need)
		p.maybeStartPrepare(need)
	}
}

func (p *TCPPool) warmAllowedLocked() bool {
	if p.nextWarmRetry.IsZero() {
		return true
	}
	return !time.Now().Before(p.nextWarmRetry)
}

func (p *TCPPool) noteWarmFailureLocked() {
	p.warmFailCount++
	base := p.cfg.warmBackoffInitial
	if base <= 0 {
		base = DefaultWarmBackoffInitial
	}
	max := p.cfg.warmBackoffMax
	if max <= 0 {
		max = DefaultWarmBackoffMax
	}
	delay := base
	for i := 1; i < p.warmFailCount; i++ {
		if delay >= max {
			delay = max
			break
		}
		next := delay * 2
		if next > max || next < delay {
			delay = max
			break
		}
		delay = next
	}
	delay = jitterDuration(delay)
	if delay > max {
		delay = max
	}
	p.nextWarmRetry = time.Now().Add(delay)
	p.logger().Debugf("[Nowhere] [carrier] warm_prepare_failed fail_count=%d next_retry_ms=%d",
		p.warmFailCount, delay.Milliseconds())
}

func (p *TCPPool) clearWarmBackoffLocked() {
	p.warmFailCount = 0
	p.nextWarmRetry = time.Time{}
}

func jitterDuration(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return base
	}
	ratio := float64(binary.BigEndian.Uint64(raw[:])) / float64(^uint64(0))
	factor := 0.8 + ratio*0.4
	return time.Duration(float64(base) * factor)
}

func (p *TCPPool) acquireDialSlot(ctx context.Context) (func(), error) {
	if p == nil || p.dialSlots == nil {
		return func() {}, nil
	}
	select {
	case p.dialSlots <- struct{}{}:
		return func() { <-p.dialSlots }, nil
	case <-ctx.Done():
		p.logger().Debugf("[Nowhere] [carrier] dial_throttled outcome=context_canceled")
		return nil, ctx.Err()
	}
}

func (p *TCPPool) tryAcquireDialSlot() (func(), bool) {
	if p == nil || p.dialSlots == nil {
		return func() {}, true
	}
	select {
	case p.dialSlots <- struct{}{}:
		return func() { <-p.dialSlots }, true
	default:
		return nil, false
	}
}

// DialAttempts returns portal establish attempts observed by the dial gate (tests).
func (p *TCPPool) DialAttempts() uint64 {
	if p == nil || p.dialGate == nil {
		return 0
	}
	return p.dialGate.Attempts()
}

func (p *TCPPool) runPortalDial(ctx context.Context, fn func(context.Context) error) error {
	if p == nil || p.dialGate == nil {
		return fn(ctx)
	}
	return p.dialGate.Run(ctx, fn)
}

func logPoolAcquire(cfg *Config, outcome string, flowID wire.FlowID, carrierID uint64, snapshot poolSnapshot, start time.Time) {
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] pool_acquire outcome=%s flow_id=%d carrier_id=%d pool_idle=%d pool_preparing=%d pool_target=%d acquire_wait_ms=%d",
		outcome, flowID, carrierID, snapshot.idle, snapshot.preparing, snapshot.target, time.Since(start).Milliseconds())
}

func relayNetwork(kind wire.FlowKind) string {
	if kind == wire.FlowKindUDP {
		return "udp"
	}
	return "tcp"
}

// Close stops background preparation, closes every idle carrier, and returns
// the joined close error. Repeated calls return the same result.
func (p *TCPPool) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.cancel()
		idle := p.idle
		p.idle = nil
		p.mu.Unlock()
		p.wg.Wait()
		var closeErrors []error
		for _, wc := range idle {
			if wc.expiry != nil {
				wc.expiry.Stop()
			}
			wc.carrier.transition(stateClosed)
			closeErrors = append(closeErrors, wc.conn.Close())
		}
		p.closeErr = errors.Join(closeErrors...)
	})
	return p.closeErr
}

func (p *TCPPool) prepareOne() {
	defer p.wg.Done()

	release, ok := p.tryAcquireDialSlot()
	if !ok {
		p.mu.Lock()
		p.preparing--
		p.mu.Unlock()
		p.logger().Debugf("[Nowhere] [carrier] dial_throttled outcome=warm_skipped")
		return
	}
	defer release()

	ctx, cancel := context.WithTimeout(p.ctx, 15*time.Second)
	conn, exporter, ci, err := prepare(ctx, p.cfg)
	cancel()
	if err != nil {
		p.logger().Debugf("[Nowhere] warm prepare failed: %v", err)
		p.mu.Lock()
		p.preparing--
		p.noteWarmFailureLocked()
		p.mu.Unlock()
		return
	}

	wc := &warmConn{conn: conn, exporter: exporter, carrier: ci}
	p.mu.Lock()
	p.preparing--
	p.clearWarmBackoffLocked()
	if p.closed || len(p.idle) >= p.target {
		p.mu.Unlock()
		ci.transition(stateClosed)
		_ = conn.Close()
		return
	}
	wc.expiry = time.AfterFunc(warmTTL, func() { p.evict(wc) })
	p.idle = append(p.idle, wc)
	ci.transition(stateAuthenticatedIdle)
	p.logger().Debugf("[Nowhere] [carrier] warm_ready carrier_id=%d pool_size=%d", ci.id, len(p.idle))
	p.mu.Unlock()
}

func dialAddr(cfg *Config) string {
	if cfg.connectAddress != "" {
		return cfg.connectAddress
	}
	return cfg.address
}

func (p *TCPPool) evict(wc *warmConn) {
	p.mu.Lock()
	removed := false
	for i, c := range p.idle {
		if c == wc {
			p.idle = append(p.idle[:i], p.idle[i+1:]...)
			removed = true
			break
		}
	}
	p.mu.Unlock()
	if !removed {
		return
	}
	if wc.expiry != nil {
		wc.expiry.Stop()
	}
	wc.carrier.transition(stateClosed)
	p.logger().Debugf("[Nowhere] [carrier] warm_evicted carrier_id=%d (ttl expired)", wc.carrier.id)
	_ = wc.conn.Close()
}

type openTiming struct {
	start        time.Time
	rawDial      time.Duration
	tlsHandshake time.Duration
	authWrite    time.Duration
	requestWrite time.Duration
}

func newOpenTiming() openTiming {
	return openTiming{start: time.Now()}
}

func logOpenTiming(cfg *Config, outcome string, flowID wire.FlowID, carrierID uint64, stage string, network string, target string, timing openTiming) {
	server := dialAddr(cfg)
	// Warm prepare has no business destination; only portal server address.
	if strings.HasPrefix(stage, "tls") || stage == "warm_prepare" || strings.Contains(outcome, "warm_prepare") {
		loggerFrom(cfg).Debugf("[Nowhere] [carrier] open_timing outcome=%s flow_id=%d carrier_id=%d stage=%s network=%s server=%s raw_dial_ms=%d tls_ms=%d auth_write_ms=%d request_write_ms=%d open_total_ms=%d",
			outcome, flowID, carrierID, stage, network, server,
			timing.rawDial.Milliseconds(), timing.tlsHandshake.Milliseconds(),
			timing.authWrite.Milliseconds(), timing.requestWrite.Milliseconds(),
			time.Since(timing.start).Milliseconds())
		return
	}
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] open_timing outcome=%s flow_id=%d carrier_id=%d stage=%s network=%s target=%s server=%s raw_dial_ms=%d tls_ms=%d auth_write_ms=%d request_write_ms=%d open_total_ms=%d",
		outcome, flowID, carrierID, stage, network, target, server,
		timing.rawDial.Milliseconds(), timing.tlsHandshake.Milliseconds(),
		timing.authWrite.Milliseconds(), timing.requestWrite.Milliseconds(),
		time.Since(timing.start).Milliseconds())
}

func writeFullTimed(conn net.Conn, payload []byte) (time.Duration, error) {
	start := time.Now()
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if n < 0 || n > len(payload) {
			return time.Since(start), io.ErrShortWrite
		}
		if n > 0 {
			payload = payload[n:]
		}
		if err != nil {
			return time.Since(start), err
		}
		if n == 0 {
			return time.Since(start), io.ErrNoProgress
		}
	}
	return time.Since(start), nil
}

type noDelaySetter interface {
	SetNoDelay(bool) error
}

type keepAliveSetter interface {
	SetKeepAlive(bool) error
}

type keepAlivePeriodSetter interface {
	SetKeepAlivePeriod(time.Duration) error
}

type readBufferSetter interface {
	SetReadBuffer(int) error
}

type writeBufferSetter interface {
	SetWriteBuffer(int) error
}

func tuneNowhereTCPConn(cfg *Config, conn net.Conn, carrierID uint64, stage string) {
	log := loggerFrom(cfg)
	if setter, ok := conn.(noDelaySetter); ok {
		if err := setter.SetNoDelay(true); err != nil {
			log.Debugf("[Nowhere] [carrier] tcp_tune_failed carrier_id=%d stage=%s option=no_delay err=%v", carrierID, stage, err)
		}
	}
	if setter, ok := conn.(keepAliveSetter); ok {
		if err := setter.SetKeepAlive(true); err != nil {
			loggerFrom(cfg).Debugf("[Nowhere] [carrier] tcp_tune_failed carrier_id=%d stage=%s option=keepalive err=%v", carrierID, stage, err)
		}
	}
	if setter, ok := conn.(keepAlivePeriodSetter); ok {
		if err := setter.SetKeepAlivePeriod(tcpKeepAlivePeriod); err != nil {
			loggerFrom(cfg).Debugf("[Nowhere] [carrier] tcp_tune_failed carrier_id=%d stage=%s option=keepalive_period err=%v", carrierID, stage, err)
		}
	}
	bufferBytes, forced, invalidValue := configuredTCPSocketBuffer()
	if invalidValue != "" {
		loggerFrom(cfg).Debugf("[Nowhere] [carrier] socket_buffer_invalid carrier_id=%d stage=%s value=%s", carrierID, stage, invalidValue)
	}
	if !forced {
		loggerFrom(cfg).Debugf("[Nowhere] [carrier] socket_buffer carrier_id=%d stage=%s forced=false", carrierID, stage)
		return
	}
	if setter, ok := conn.(readBufferSetter); ok {
		if err := setter.SetReadBuffer(bufferBytes); err != nil {
			loggerFrom(cfg).Debugf("[Nowhere] [carrier] tcp_tune_failed carrier_id=%d stage=%s option=read_buffer err=%v", carrierID, stage, err)
		}
	}
	if setter, ok := conn.(writeBufferSetter); ok {
		if err := setter.SetWriteBuffer(bufferBytes); err != nil {
			loggerFrom(cfg).Debugf("[Nowhere] [carrier] tcp_tune_failed carrier_id=%d stage=%s option=write_buffer err=%v", carrierID, stage, err)
		}
	}
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] socket_buffer carrier_id=%d stage=%s forced=true bytes=%d", carrierID, stage, bufferBytes)
}

func configuredTCPSocketBuffer() (bytes int, forced bool, invalidValue string) {
	raw, ok := os.LookupEnv(nowhereTCPSocketBufferEnv)
	if !ok {
		return 0, false, ""
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, false, ""
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, false, raw
	}
	if n == 0 {
		return 0, false, ""
	}
	return n, true, ""
}

// prepare dials, TLS-handshakes, and authenticates. Caller moves to authenticatedIdle.
// The returned exporter is bound to the physical connection's TLS handshake.
func prepare(ctx context.Context, cfg *Config) (net.Conn, wire.TLSExporter, *carrierInfo, error) {
	ci := newCarrierInfo(loggerFrom(cfg))
	timing := newOpenTiming()
	stage := "tls"
	target := dialAddr(cfg)
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] dial_start carrier_id=%d stage=tls", ci.id)
	rawDialStart := time.Now()
	raw, err := cfg.dialer.DialContext(ctx, "tcp", dialAddr(cfg))
	timing.rawDial = time.Since(rawDialStart)
	if err != nil {
		ci.transition(stateClosed)
		logOpenTiming(cfg, "warm_prepare_failed", 0, ci.id, stage, "tcp", target, timing)
		return nil, wire.TLSExporter{}, nil, err
	}
	raw, err = wrapMorphClient(cfg, raw)
	if err != nil {
		ci.transition(stateClosed)
		logOpenTiming(cfg, "warm_prepare_failed", 0, ci.id, stage, "tcp", target, timing)
		return nil, wire.TLSExporter{}, nil, err
	}
	tuneNowhereTCPConn(cfg, raw, ci.id, stage)
	tlsStart := time.Now()
	handshaked, err := cfg.tlsDialer.DialTLSConn(ctx, raw)
	timing.tlsHandshake = time.Since(tlsStart)
	if err != nil {
		_ = raw.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, "warm_prepare_failed", 0, ci.id, stage, "tcp", target, timing)
		return nil, wire.TLSExporter{}, nil, err
	}
	tlsConn := handshaked.Conn
	if tlsConn == nil {
		_ = raw.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, "warm_prepare_failed", 0, ci.id, stage, "tcp", target, timing)
		return nil, wire.TLSExporter{}, nil, errors.New("nowhere: TLS dialer returned nil connection")
	}
	if err := handshaked.TLSHandshakeInfo.Validate(cfg.alpn); err != nil {
		_ = tlsConn.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, "warm_prepare_failed", 0, ci.id, stage, "tcp", target, timing)
		return nil, wire.TLSExporter{}, nil, err
	}
	exporter := handshaked.Exporter
	auth, err := tcpAuthFrame(cfg, exporter)
	if err != nil {
		_ = tlsConn.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, "warm_prepare_failed", 0, ci.id, stage, "tcp", target, timing)
		return nil, wire.TLSExporter{}, nil, err
	}
	timing.authWrite, err = writeFullTimed(tlsConn, auth)
	if err != nil {
		_ = tlsConn.Close()
		ci.transition(stateClosed)
		logOpenTiming(cfg, "warm_prepare_failed", 0, ci.id, stage, "tcp", target, timing)
		return nil, wire.TLSExporter{}, nil, err
	}
	logOpenTiming(cfg, "warm_prepare", 0, ci.id, stage, "tcp", target, timing)
	loggerFrom(cfg).Debugf("[Nowhere] [carrier] auth_ok carrier_id=%d", ci.id)
	return tlsConn, exporter, ci, nil
}

// tcpAuthFrame builds the connection-bound auth frame using the credentials,
// the physical transport and this connection's TLS exporter. The session id is
// supplied by the bundle via BindSession; a zero session id is rejected to
// avoid authenticating before the bundle has generated one.
func tcpAuthFrame(cfg *Config, exporter wire.TLSExporter) ([]byte, error) {
	if cfg.sessionID == (wire.SessionID{}) {
		return nil, errors.New("nowhere: missing session id for auth frame")
	}
	frame, err := wire.EncodeAuthFrame(cfg.credentials, wire.AuthTransportTLSTCP, exporter, cfg.sessionID)
	if err != nil {
		return nil, err
	}
	return frame[:], nil
}
