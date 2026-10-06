package tcptls

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

// PreparedFlowHalf is a TLS/TCP carrier that has not yet sent a FLOW setup.
// Warm lanes are already authenticated; fresh lanes retain AUTH so Commit can
// coalesce it with FLOW, TARGET, and an optional initial TCP payload. Exactly
// one of Commit, CommitWithPayload, or Close must complete.
type PreparedFlowHalf struct {
	pool     *TCPPool
	cfg      *Config
	conn     net.Conn
	exporter wire.TLSExporter
	ci       *carrierInfo
	target   wire.Target
	header   wire.FlowHeader
	auth     []byte

	DialQueueMs int64
	RawDialMs   int64
	TLSms       int64
	AuthMs      int64

	warmBorrow bool

	once      sync.Once
	committed bool
	closed    bool
}

// PrepareFlowHalf acquires a TLS/TCP carrier without writing FLOW. It prefers
// the authenticated warm pool; on a miss, fresh AUTH remains pending until
// Commit so the opening envelope can be coalesced.
func (p *TCPPool) PrepareFlowHalf(ctx context.Context, target wire.Target, header wire.FlowHeader) (*PreparedFlowHalf, error) {
	return p.prepareFlowHalf(ctx, target, header, true)
}

// PrepareAuthenticatedFlowHalf acquires a carrier and eagerly authenticates a
// fresh TLS connection while still deferring FLOW. Bundle paths that do not
// carry an initial payload use this form so a large set of prepared ATTACH
// lanes cannot consume the server's unauthenticated admission budget.
func (p *TCPPool) PrepareAuthenticatedFlowHalf(ctx context.Context, target wire.Target, header wire.FlowHeader) (*PreparedFlowHalf, error) {
	return p.prepareFlowHalf(ctx, target, header, false)
}

func (p *TCPPool) prepareFlowHalf(ctx context.Context, target wire.Target, header wire.FlowHeader, deferAuth bool) (*PreparedFlowHalf, error) {
	if p == nil {
		return nil, errors.New("nowhere: tcp pool unavailable")
	}
	if err := validatePrepareHeader(header); err != nil {
		return nil, err
	}
	if header.CarriesTarget() {
		if err := target.Validate(); err != nil {
			return nil, err
		}
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return nil, errors.New("nowhere: tcp pool closed")
	}

	start := time.Now()
	var half *PreparedFlowHalf
	var dialQueueMs int64
	err := p.runPortalDial(ctx, func(ctx context.Context) error {
		queueStart := time.Now()
		release, err := p.acquireDialSlot(ctx)
		if err != nil {
			return err
		}
		dialQueueMs = time.Since(queueStart).Milliseconds()
		h, err := p.borrowOrDial(ctx, target, header, deferAuth)
		release()
		if err != nil {
			return err
		}
		half = h
		return nil
	})
	if err != nil {
		return nil, err
	}
	half.pool = p
	half.DialQueueMs = dialQueueMs

	p.mu.Lock()
	snapshot := p.snapshotLocked()
	p.mu.Unlock()
	outcome := "fresh"
	if half.warmBorrow {
		outcome = "warm"
	}
	logPoolAcquire(p.cfg, outcome, header.FlowID, half.ci.id, snapshot, start)
	return half, nil
}

func (p *TCPPool) borrowOrDial(ctx context.Context, target wire.Target, header wire.FlowHeader, deferAuth bool) (*PreparedFlowHalf, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("nowhere: tcp pool closed")
	}
	var selected *warmConn
	if len(p.idle) > 0 {
		// FIFO: oldest idle first (store at tail, borrow from head).
		wc := p.idle[0]
		p.idle = p.idle[1:]
		if wc.expiry != nil {
			wc.expiry.Stop()
		}
		selected = wc
	}
	snapshot := p.snapshotLocked()
	p.mu.Unlock()

	if selected != nil {
		selected.carrier.transition(stateBorrowed)
		p.logger().Debugf("[Nowhere] [carrier] borrow_warm flow_id=%d carrier_id=%d pool_remaining=%d",
			header.FlowID, selected.carrier.id, func() int { p.mu.Lock(); n := len(p.idle); p.mu.Unlock(); return n }())
		half, err := p.prepareFromWarm(selected.conn, selected.exporter, selected.carrier, target, header)
		if err != nil {
			p.logger().Debugf("[Nowhere] [carrier] activate_warm_failed flow_id=%d carrier_id=%d err=%v (falling back to fresh)",
				header.FlowID, selected.carrier.id, err)
			selected.carrier.transition(stateClosed)
			_ = selected.conn.Close()
			p.mu.Lock()
			snapshot = p.snapshotLocked()
			p.mu.Unlock()
		} else {
			p.maybeStartPrepare(p.replenishBudget(true))
			return half, nil
		}
	}

	half, err := p.prepareFresh(ctx, target, header, snapshot, deferAuth)
	if err != nil {
		return nil, err
	}
	p.maybeStartPrepare(p.replenishBudget(false))
	return half, nil
}

func (p *TCPPool) prepareFromWarm(conn net.Conn, exporter wire.TLSExporter, ci *carrierInfo, target wire.Target, header wire.FlowHeader) (*PreparedFlowHalf, error) {
	return &PreparedFlowHalf{
		pool:       p,
		cfg:        p.cfg,
		conn:       conn,
		exporter:   exporter,
		ci:         ci,
		target:     target,
		header:     header,
		warmBorrow: true,
	}, nil
}

func (p *TCPPool) prepareFresh(ctx context.Context, target wire.Target, header wire.FlowHeader, snapshot poolSnapshot, deferAuth bool) (*PreparedFlowHalf, error) {
	ci := newCarrierInfo(loggerFrom(p.cfg))
	timing := newOpenTiming()
	stage := "flow_prepare"
	if header.Kind == wire.FlowKindUDP {
		stage = "udp_flow_prepare"
	}
	network := relayNetwork(header.Kind)
	role := "asymmetric_tcp"
	if header.Kind == wire.FlowKindUDP {
		role = "asymmetric_uot"
	}
	loggerFrom(p.cfg).Debugf("[Nowhere] [carrier] flow_start flow_id=%d carrier_id=%d role=%s target=%s stage=prepare", header.FlowID, ci.id, role, targetString(target))
	loggerFrom(p.cfg).Debugf("[Nowhere] [carrier] dial_start carrier_id=%d flow_id=%d stage=%s", ci.id, header.FlowID, stage)
	ci.transition(stateBorrowed)

	rawDialStart := time.Now()
	raw, err := p.cfg.dialer.DialContext(ctx, "tcp", dialAddr(p.cfg))
	timing.rawDial = time.Since(rawDialStart)
	if err != nil {
		ci.transition(stateClosed)
		logOpenTiming(p.cfg, "fresh_failed", header.FlowID, ci.id, stage, network, targetString(target), timing)
		return nil, err
	}
	raw, err = wrapMorphClient(p.cfg, raw)
	if err != nil {
		ci.transition(stateClosed)
		logOpenTiming(p.cfg, "fresh_failed", header.FlowID, ci.id, stage, network, targetString(target), timing)
		return nil, err
	}
	tuneNowhereTCPConn(p.cfg, raw, ci.id, stage)
	tlsStart := time.Now()
	handshaked, err := p.cfg.tlsDialer.DialTLSConn(ctx, raw)
	timing.tlsHandshake = time.Since(tlsStart)
	if err != nil {
		_ = raw.Close()
		ci.transition(stateClosed)
		logOpenTiming(p.cfg, "fresh_failed", header.FlowID, ci.id, stage, network, targetString(target), timing)
		return nil, err
	}
	tlsConn := handshaked.Conn
	if tlsConn == nil {
		_ = raw.Close()
		ci.transition(stateClosed)
		logOpenTiming(p.cfg, "fresh_failed", header.FlowID, ci.id, stage, network, targetString(target), timing)
		return nil, errors.New("nowhere: TLS dialer returned nil connection")
	}
	if err := handshaked.TLSHandshakeInfo.Validate(p.cfg.alpn); err != nil {
		_ = tlsConn.Close()
		ci.transition(stateClosed)
		logOpenTiming(p.cfg, "fresh_failed", header.FlowID, ci.id, stage, network, targetString(target), timing)
		return nil, err
	}
	exporter := handshaked.Exporter

	auth, err := tcpAuthFrame(p.cfg, exporter)
	if err != nil {
		_ = tlsConn.Close()
		ci.transition(stateClosed)
		logOpenTiming(p.cfg, "fresh_failed", header.FlowID, ci.id, stage, network, targetString(target), timing)
		return nil, err
	}
	var pendingAuth []byte
	if deferAuth {
		pendingAuth = auth
	} else {
		timing.authWrite, err = writeFullTimed(tlsConn, auth)
		if err != nil {
			_ = tlsConn.Close()
			ci.transition(stateClosed)
			logOpenTiming(p.cfg, "fresh_failed", header.FlowID, ci.id, stage, network, targetString(target), timing)
			return nil, err
		}
		loggerFrom(p.cfg).Debugf("[Nowhere] [carrier] auth_ok carrier_id=%d flow_id=%d stage=prepare", ci.id, header.FlowID)
	}
	logOpenTiming(p.cfg, "fresh_prepare", header.FlowID, ci.id, stage, network, targetString(target), timing)

	return &PreparedFlowHalf{
		cfg:       p.cfg,
		conn:      tlsConn,
		exporter:  exporter,
		ci:        ci,
		target:    target,
		header:    header,
		auth:      pendingAuth,
		RawDialMs: timing.rawDial.Milliseconds(),
		TLSms:     timing.tlsHandshake.Milliseconds(),
		AuthMs:    timing.authWrite.Milliseconds(),
	}, nil
}

// Commit writes the FLOW setup bytes and transfers ownership of the conn.
func (h *PreparedFlowHalf) Commit() (net.Conn, error) {
	return h.CommitWithPayload(nil)
}

// CommitWithPayload writes AUTH when pending, FLOW, TARGET, and payloadPrefix
// as one contiguous opening envelope, then transfers ownership of the conn.
// The payload is consumed synchronously and is never retained.
func (h *PreparedFlowHalf) CommitWithPayload(payloadPrefix []byte) (net.Conn, error) {
	if h == nil {
		return nil, errors.New("nowhere: nil prepared flow half")
	}
	var (
		conn net.Conn
		err  error
	)
	h.once.Do(func() {
		if h.closed || h.conn == nil || h.ci == nil {
			err = errors.New("nowhere: prepared flow half closed")
			return
		}
		timing := newOpenTiming()
		stage := "flow_commit"
		if h.header.Kind == wire.FlowKindUDP {
			stage = "udp_flow_commit"
		}
		network := relayNetwork(h.header.Kind)
		setup, encErr := encodeFlowSetup(h.header, h.target)
		if encErr != nil {
			err = encErr
			h.forceClose()
			return
		}
		opening := make([]byte, 0, len(h.auth)+len(setup)+len(payloadPrefix))
		opening = append(opening, h.auth...)
		opening = append(opening, setup...)
		opening = append(opening, payloadPrefix...)
		timing.requestWrite, err = writeFullTimed(h.conn, opening)
		if err != nil {
			if h.warmBorrow {
				logOpenTiming(h.cfg, "warm_failed", h.header.FlowID, h.ci.id, "warm_activate", network, targetString(h.target), timing)
			} else {
				logOpenTiming(h.cfg, "fresh_failed", h.header.FlowID, h.ci.id, stage, network, targetString(h.target), timing)
			}
			h.forceClose()
			return
		}
		if len(h.auth) > 0 {
			timing.authWrite = timing.requestWrite
			h.AuthMs = timing.authWrite.Milliseconds()
			loggerFrom(h.cfg).Debugf("[Nowhere] [carrier] auth_ok carrier_id=%d flow_id=%d stage=commit", h.ci.id, h.header.FlowID)
		}
		h.auth = nil
		h.ci.transition(stateRequestSent)
		h.ci.transition(stateConsumed)
		if h.warmBorrow {
			logOpenTiming(h.cfg, "warm", h.header.FlowID, h.ci.id, "warm_activate", network, targetString(h.target), timing)
		} else {
			logOpenTiming(h.cfg, "fresh", h.header.FlowID, h.ci.id, stage, network, targetString(h.target), timing)
		}
		loggerFrom(h.cfg).Debugf("[Nowhere] [carrier] request_sent flow_id=%d carrier_id=%d target=%s consumed=true",
			h.header.FlowID, h.ci.id, targetString(h.target))
		conn = wrapRelay(h.conn, h.ci, h.header.FlowID, h.header.Kind, targetString(h.target))
		h.conn = nil
		h.committed = true
	})
	if err != nil {
		return nil, err
	}
	if !h.committed || conn == nil {
		return nil, errors.New("nowhere: prepared flow half already closed")
	}
	return conn, nil
}

// Close abandons a prepared half that was never committed.
func (h *PreparedFlowHalf) Close() error {
	if h == nil {
		return nil
	}
	var err error
	h.once.Do(func() {
		h.closed = true
		err = h.forceClose()
	})
	return err
}

func (h *PreparedFlowHalf) forceClose() error {
	if h.conn == nil {
		return nil
	}
	if h.ci != nil {
		h.ci.transition(stateClosing)
	}
	err := h.conn.Close()
	if h.ci != nil {
		h.ci.transition(stateClosed)
	}
	h.conn = nil
	return err
}

// CarrierID returns the local diagnostic carrier id.
func (h *PreparedFlowHalf) CarrierID() uint64 {
	if h == nil || h.ci == nil {
		return 0
	}
	return h.ci.id
}

// encodeFlowSetup writes the 5-byte flow header followed, when the role carries
// a target, by the SOCKS5 target bytes.
func encodeFlowSetup(header wire.FlowHeader, target wire.Target) ([]byte, error) {
	hdrBytes, err := wire.WriteFlowHeader(header)
	if err != nil {
		return nil, err
	}
	if !header.CarriesTarget() {
		out := make([]byte, wire.FlowHeaderLen)
		copy(out, hdrBytes[:])
		return out, nil
	}
	targetBytes, err := wire.EncodeTarget(target)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, wire.FlowHeaderLen+len(targetBytes))
	out = append(out, hdrBytes[:]...)
	out = append(out, targetBytes...)
	return out, nil
}

// targetString renders a target for diagnostics only; never parsed back.
func targetString(t wire.Target) string {
	switch t.Type {
	case wire.TargetTypeIPv4, wire.TargetTypeIPv6:
		return net.JoinHostPort(t.Addr.String(), itoa(int(t.Port)))
	case wire.TargetTypeDomain:
		return net.JoinHostPort(t.Host, itoa(int(t.Port)))
	default:
		return ""
	}
}

// itoa is a small allocation-free int-to-string for diagnostic port rendering.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func validatePrepareHeader(header wire.FlowHeader) error {
	return header.Validate()
}
