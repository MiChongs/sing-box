package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	carrierquic "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const (
	preAuthDatagramBudget     = 64 * 1024
	preactivationControlLimit = 64
	preactivationTTL          = 10 * time.Second
)

type reassemblyTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type realReassemblyTicker struct {
	*time.Ticker
}

func (t *realReassemblyTicker) Chan() <-chan time.Time { return t.C }

// sessionManager tracks authenticated QUIC sessions by Nowhere session_id.
// A newer connection with the same session_id replaces the previous one.
type sessionManager struct {
	mu                  sync.Mutex
	sessions            map[wire.SessionID]*portalSession
	claims              *claimRegistry
	nextGeneration      uint64
	generationExhausted bool
	max                 int
	accepting           bool
	closed              bool
}

func newSessionManager(registries ...*claimRegistry) *sessionManager {
	var claims *claimRegistry
	if len(registries) > 0 {
		claims = registries[0]
	}
	return &sessionManager{
		sessions:  make(map[wire.SessionID]*portalSession),
		claims:    claims,
		max:       DefaultActiveQUICSessions,
		accepting: true,
	}
}

func (m *sessionManager) configureLimit(max int) {
	m.mu.Lock()
	m.max = max
	m.mu.Unlock()
}

func (m *sessionManager) Current(sessionID wire.SessionID) *portalSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[sessionID]
}

func (m *sessionManager) Register(session *portalSession) error {
	if m == nil || session == nil {
		return fmt.Errorf("%w: nil session", ErrInvalidHandler)
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	if !m.accepting {
		m.mu.Unlock()
		return ErrDraining
	}
	old := m.sessions[session.ID]
	if old == session {
		m.mu.Unlock()
		return nil
	}
	if old == nil && len(m.sessions) >= m.max {
		m.mu.Unlock()
		return ErrSessionLimit
	}
	var cleanup *sessionReplacementCleanup
	if m.claims != nil {
		session.Generation, cleanup = m.claims.beginSessionRegistration(session.ID, old != nil, markForcedTermination(ErrClosed))
	} else {
		if m.generationExhausted || m.nextGeneration == ^uint64(0) {
			m.generationExhausted = true
			m.mu.Unlock()
			return fmt.Errorf("%w: session generation exhausted", ErrSessionLimit)
		}
		m.nextGeneration++
		session.Generation = m.nextGeneration
	}
	m.sessions[session.ID] = session
	m.mu.Unlock()

	if old != nil {
		if m.claims != nil {
			m.claims.unregisterSessionGeneration(old.ID, old.Generation)
		}
		old.Close()
	}
	cleanup.run()
	return nil
}

func (m *sessionManager) Unregister(session *portalSession) {
	if m == nil || session == nil {
		return
	}
	m.mu.Lock()
	if cur, ok := m.sessions[session.ID]; ok && cur == session {
		delete(m.sessions, session.ID)
	}
	m.mu.Unlock()
	if m.claims != nil {
		m.claims.unregisterSessionGeneration(session.ID, session.Generation)
	}
}

func (m *sessionManager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.accepting = false
	sessions := make([]*portalSession, 0, len(m.sessions))
	for id, session := range m.sessions {
		sessions = append(sessions, session)
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	for _, session := range sessions {
		if m.claims != nil {
			m.claims.unregisterSessionGeneration(session.ID, session.Generation)
		}
		session.Close()
	}
}

func (m *sessionManager) BeginDrain() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.accepting = false
	m.mu.Unlock()
}

// portalSession is one authenticated QUIC connection (via QuicConn).
type pendingUDPControl struct {
	created time.Time
	frames  []wire.UDPFrame
	bytes   int
}

type portalSession struct {
	ID         wire.SessionID
	Generation uint64
	Conn       QuicConn
	Handler    *Handler
	Source     net.Addr

	cancel context.CancelCauseFunc

	mu              sync.Mutex
	flows           map[wire.FlowID]*nowuFlow
	pendingControls map[wire.FlowID]*pendingUDPControl
	pendingFrames   int
	pendingBytes    int
	queuedBytes     int
	budget          *byteBudget
	prober          *carrierquic.DatagramProber
	reassembler     *udpReassembler
	expiryCancel    context.CancelFunc
	expiryDone      chan struct{}
	closeDone       chan struct{}
	closed          bool
	transportOnce   sync.Once

	dropMu        sync.Mutex
	dropCount     int
	dropBytes     uint64
	dropFlowID    wire.FlowID
	dropDirection string
	dropReason    string
	dropLastEmit  time.Time
}

// quicDatagramPump is the single owner of ReceiveDatagram for a QUIC
// connection. It deliberately discards packets until authentication and
// session registration complete; that prevents unauthenticated datagrams from
// being replayed into a later authenticated session.
type quicDatagramPump struct {
	conn QuicConn

	mu      sync.RWMutex
	session *portalSession
	done    chan struct{}
}

func newQUICDatagramPump(conn QuicConn) *quicDatagramPump {
	return &quicDatagramPump{conn: conn, done: make(chan struct{})}
}

func (p *quicDatagramPump) run(ctx context.Context) {
	defer close(p.done)
	for {
		data, err := p.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		p.mu.RLock()
		session := p.session
		if session != nil {
			session.handleDatagram(ctx, data)
		}
		p.mu.RUnlock()
	}
}

func (p *quicDatagramPump) activate(session *portalSession) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.session = session
	p.mu.Unlock()
}

func (p *quicDatagramPump) stop() {
	if p == nil {
		return
	}
	_ = p.conn.CloseWithError(0, "")
	<-p.done
}

func newPortalSession(id wire.SessionID, conn QuicConn, handler *Handler, source net.Addr) *portalSession {
	queueBytes := DefaultUDPQueueBytes
	if handler != nil && handler.config != nil {
		queueBytes = handler.config.limits.UDPQueueBytes
	}
	budget := &byteBudget{limit: queueBytes}
	session := &portalSession{
		ID:              id,
		Conn:            conn,
		Handler:         handler,
		Source:          source,
		flows:           make(map[wire.FlowID]*nowuFlow),
		pendingControls: make(map[wire.FlowID]*pendingUDPControl),
		budget:          budget,
		reassembler:     newUDPReassembler(nowuPartialLimit, nowuPartialTTL, budget),
	}
	session.prober = carrierquic.NewDatagramProber(session.transportMaxDatagramSize)
	return session
}

func (s *portalSession) Close() {
	s.shutdownSession(markForcedTermination(ErrClosed))
}

func (s *portalSession) shutdownSession(cause error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closeDone != nil {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		return
	}
	done := make(chan struct{})
	s.closeDone = done
	s.closed = true
	flows := s.flows
	s.flows = nil
	s.pendingControls = nil
	s.pendingFrames = 0
	s.pendingBytes = 0
	cancel := s.cancel
	expiryCancel := s.expiryCancel
	expiryDone := s.expiryDone
	s.mu.Unlock()

	if cause == nil {
		cause = markForcedTermination(ErrClosed)
	}
	if cancel != nil {
		cancel(cause)
	}
	if expiryCancel != nil {
		expiryCancel()
	}
	if expiryDone != nil {
		<-expiryDone
	}
	for _, f := range flows {
		f.shutdown(cause)
	}
	if s.reassembler != nil {
		s.reassembler.Close()
	}
	s.flushUDPDrop()
	s.closeTransport(cause)
	close(done)
}

func (s *portalSession) closeTransport(error) {
	if s == nil {
		return
	}
	s.transportOnce.Do(func() {
		if s.Conn != nil {
			_ = s.Conn.CloseWithError(0, "")
		}
	})
}

func (s *portalSession) startReassemblyExpiry() {
	if s == nil || s.Handler == nil || s.Handler.newReassemblyTicker == nil || s.reassembler == nil {
		return
	}
	ticker := s.Handler.newReassemblyTicker(nowuPartialTTL / 2)
	if ticker == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.mu.Lock()
	if s.closed || s.expiryCancel != nil {
		s.mu.Unlock()
		cancel()
		ticker.Stop()
		return
	}
	s.expiryCancel = cancel
	s.expiryDone = done
	s.mu.Unlock()
	go func() {
		defer close(done)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.Chan():
				now := time.Now()
				if s.Handler.now != nil {
					now = s.Handler.now()
				}
				s.reassembler.Expire(now)
				s.expirePendingControls(now)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *portalSession) SendDatagram(ctx context.Context, b []byte) error {
	return s.Conn.SendDatagram(ctx, b)
}

func (s *portalSession) recordUDPDrop(flowID wire.FlowID, bytes int, direction, reason string) {
	now := time.Now()
	if s.Handler != nil && s.Handler.now != nil {
		now = s.Handler.now()
	}
	s.dropMu.Lock()
	s.dropCount++
	if bytes > 0 {
		s.dropBytes += uint64(bytes)
	}
	s.dropFlowID = flowID
	s.dropDirection = direction
	s.dropReason = reason
	if s.dropLastEmit.IsZero() {
		s.dropLastEmit = now
		s.dropMu.Unlock()
		return
	}
	if now.Sub(s.dropLastEmit) < time.Second {
		s.dropMu.Unlock()
		return
	}
	event := s.takeUDPDropLocked(now)
	s.dropMu.Unlock()
	if s.Handler != nil {
		diagnostic.Emit(context.Background(), s.Handler.observer, event)
	}
}

func (s *portalSession) flushUDPDrop() {
	s.dropMu.Lock()
	event := s.takeUDPDropLocked(time.Now())
	s.dropMu.Unlock()
	if event.Count > 0 && s.Handler != nil {
		diagnostic.Emit(context.Background(), s.Handler.observer, event)
	}
}

func (s *portalSession) takeUDPDropLocked(now time.Time) diagnostic.Event {
	if s.dropCount == 0 {
		return diagnostic.Event{}
	}
	event := diagnostic.Event{
		Level: diagnostic.LevelWarn, Code: "udp_queue_drop_total",
		Component: "server", Carrier: diagnostic.CarrierQUIC,
		Source: s.Source, SessionID: s.ID, FlowID: s.dropFlowID,
		State: s.dropDirection, Outcome: s.dropReason,
		Count: s.dropCount, Bytes: s.dropBytes,
	}
	s.dropCount = 0
	s.dropBytes = 0
	s.dropLastEmit = now
	return event
}

// transportMaxDatagramSize reads the live transport-reported DATAGRAM limit.
func (s *portalSession) transportMaxDatagramSize() int {
	if s != nil && s.Conn != nil {
		if provider, ok := s.Conn.(interface{ CurrentMaxDatagramSize() int }); ok {
			if size := provider.CurrentMaxDatagramSize(); size > nowuDataHeaderLen {
				return size
			}
		}
	}
	return defaultMaxDatagramSize
}

// maxDatagramSize is the prober-adjusted limit: the transport value raised by
// successful optimistic probes, so large packets stop fragmenting once the
// path proves it can carry them.
func (s *portalSession) maxDatagramSize() int {
	if s != nil && s.prober != nil {
		return s.prober.MaxDatagramSize()
	}
	return s.transportMaxDatagramSize()
}

func (s *portalSession) getFlow(id wire.FlowID) *nowuFlow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flows[id]
}

func (s *portalSession) removeFlow(id wire.FlowID, flow *nowuFlow) {
	s.mu.Lock()
	if current := s.flows[id]; current == flow {
		delete(s.flows, id)
	}
	s.mu.Unlock()
}

func (s *portalSession) beginPendingUDPControl(header wire.FlowHeader) (*pendingUDPControl, error) {
	if err := validateFlowTransport(header, wire.CarrierQUIC); err != nil {
		return nil, err
	}
	if header.Role == wire.FlowRoleAttach {
		return nil, nil
	}
	if header.Role != wire.FlowRoleOpen && header.Role != wire.FlowRoleDuplex {
		return nil, fmt.Errorf("%w: invalid UDP flow role", ErrUnsupportedFlow)
	}
	now := time.Now()
	if s.Handler != nil && s.Handler.now != nil {
		now = s.Handler.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expirePendingControlsLocked(now)
	if s.closed {
		return nil, ErrClosed
	}
	if s.flows[header.FlowID] != nil || s.pendingControls[header.FlowID] != nil {
		return nil, ErrDuplicateHalf
	}
	if len(s.pendingControls) >= preactivationControlLimit {
		return nil, ErrPairLimit
	}
	pending := &pendingUDPControl{created: now}
	s.pendingControls[header.FlowID] = pending
	return pending, nil
}

func (s *portalSession) cancelPendingUDPControl(flowID wire.FlowID, pending *pendingUDPControl) {
	if pending == nil {
		return
	}
	s.mu.Lock()
	if s.pendingControls[flowID] == pending {
		s.removePendingControlLocked(flowID, pending)
	}
	s.mu.Unlock()
}

func (s *portalSession) expirePendingControls(now time.Time) {
	s.mu.Lock()
	s.expirePendingControlsLocked(now)
	s.mu.Unlock()
}

func (s *portalSession) expirePendingControlsLocked(now time.Time) {
	for flowID, pending := range s.pendingControls {
		if !now.Before(pending.created.Add(preactivationTTL)) {
			s.removePendingControlLocked(flowID, pending)
		}
	}
}

func (s *portalSession) removePendingControlLocked(flowID wire.FlowID, pending *pendingUDPControl) {
	if s.pendingControls[flowID] != pending {
		return
	}
	delete(s.pendingControls, flowID)
	s.pendingFrames -= len(pending.frames)
	s.pendingBytes -= pending.bytes
	if s.pendingFrames < 0 {
		s.pendingFrames = 0
	}
	if s.pendingBytes < 0 {
		s.pendingBytes = 0
	}
	pending.frames = nil
	pending.bytes = 0
}

func (s *portalSession) reserveQueueBytes(count int) bool {
	if s == nil || count < 0 {
		return false
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed || !s.budget.reserve(count) {
		return false
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.budget.release(count)
		return false
	}
	s.queuedBytes += count
	s.mu.Unlock()
	return true
}

func (s *portalSession) releaseQueueBytes(count int) {
	if s == nil || count <= 0 {
		return
	}
	s.mu.Lock()
	s.queuedBytes -= count
	if s.queuedBytes < 0 {
		s.queuedBytes = 0
	}
	s.mu.Unlock()
	s.budget.release(count)
}

// ServeQUIC authenticates and serves one QuicConn until it closes.
func (h *Handler) ServeQUIC(parent context.Context, conn QuicConn) error {
	if err := h.validate(); err != nil {
		if conn != nil {
			_ = conn.CloseWithError(1, "access denied")
		}
		return err
	}
	if conn == nil {
		return fmt.Errorf("%w: nil quic connection", ErrInvalidHandler)
	}
	taskCtx, finish, err := h.tasks.StartTransport(parent, func(error) {
		_ = conn.CloseWithError(0, "")
	})
	if err != nil {
		_ = conn.CloseWithError(1, "access denied")
		return err
	}
	defer finish()
	source := conn.RemoteAddr()
	guard, ok := h.admission.tryAcquire(source)
	if !ok {
		_ = conn.CloseWithError(1, "access denied")
		h.emitAdmissionLimited(taskCtx, source)
		return report(ErrAdmissionLimit)
	}
	releaseAdmission := guard.Release
	defer releaseAdmission()

	ctx, cancel := context.WithCancelCause(taskCtx)
	defer cancel(nil)
	pump := newQUICDatagramPump(conn)
	go pump.run(ctx)
	defer pump.stop()

	session, firstStream, err := h.authenticateQuic(ctx, conn)
	if err != nil {
		_ = conn.CloseWithError(1, "access denied")
		h.emitQUIC(ctx, diagnostic.LevelError, "auth_failed", source, "", wire.SessionID{}, 0, err)
		return err
	}
	releaseAdmission()
	session.cancel = cancel
	if err := h.sessions.Register(session); err != nil {
		_ = conn.CloseWithError(1, "access denied")
		return err
	}
	defer h.sessions.Unregister(session)
	defer session.Close()
	session.startReassemblyExpiry()
	pump.activate(session)
	if notifier, ok := conn.(QuicAuthenticationNotifier); ok {
		notifier.MarkAuthenticated()
	}

	h.emitQUIC(ctx, diagnostic.LevelInfo, "session_started", source, "", session.ID, 0, nil)
	if firstStream != nil {
		go session.handleStream(ctx, firstStream, true)
	}
	session.acceptStreams(ctx)
	return nil
}

func (h *Handler) authenticateQuic(ctx context.Context, conn QuicConn) (*portalSession, QuicStream, error) {
	deadline := h.authDeadline()
	authCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	handshake, err := conn.TLSHandshakeInfo()
	if err != nil {
		return nil, nil, err
	}
	if err := handshake.Validate(h.config.alpn); err != nil {
		return nil, nil, err
	}

	type authResult struct {
		id     wire.SessionID
		stream QuicStream
		err    error
	}
	authCh := make(chan authResult, 1)
	go func() {
		stream, err := conn.AcceptStream(authCtx)
		if err != nil {
			authCh <- authResult{err: err}
			return
		}
		_ = stream.SetReadDeadline(deadline)
		id, err := wire.ReadAuthFrame(stream, h.config.credentials, wire.AuthTransportQUIC, handshake.Exporter)
		authCh <- authResult{id: id, stream: stream, err: err}
	}()

	select {
	case res := <-authCh:
		if res.err != nil {
			h.waitAuthFailure(ctx, deadline)
			return nil, nil, res.err
		}
		return newPortalSession(res.id, conn, h, conn.RemoteAddr()), res.stream, nil
	case <-authCtx.Done():
		h.waitAuthFailure(ctx, deadline)
		return nil, nil, authCtx.Err()
	}
}

func (s *portalSession) acceptStreams(ctx context.Context) {
	for {
		stream, err := s.Conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.handleStream(ctx, stream, false)
	}
}

func (s *portalSession) handleStream(ctx context.Context, stream QuicStream, first bool) {
	conn := wrapQuicStream(stream, s.Conn.LocalAddr(), s.Conn.RemoteAddr())
	source := s.Source
	_ = conn.SetReadDeadline(s.Handler.now().Add(s.Handler.config.timeouts.RequestIdle))

	header, err := wire.ReadFlowHeader(conn)
	if err != nil {
		_ = conn.Close()
		if first && errors.Is(err, io.EOF) {
			return
		}
		s.Handler.emitQUIC(ctx, diagnostic.LevelError, "request_read_failed", source, "", s.ID, 0, err)
		return
	}
	target, err := s.Handler.readFlowTarget(conn, header)
	if err != nil {
		s.Handler.rejectFlowSetupGeneration(conn, s.ID, s.Generation, true, header, wire.SetupResultInvalidRequest)
		_ = conn.Close()
		s.Handler.emitQUIC(ctx, diagnostic.LevelError, "request_read_failed", source, "", s.ID, header.FlowID, err)
		return
	}
	var pending *pendingUDPControl
	if header.Kind == wire.FlowKindUDP {
		pending, err = s.beginPendingUDPControl(header)
		if err != nil {
			if errors.Is(err, ErrDuplicateHalf) {
				rejectQUICControl(conn, header, setupFailureCode(err))
			} else {
				s.Handler.rejectFlowSetupGeneration(conn, s.ID, s.Generation, true, header, setupFailureCode(err))
			}
			_ = conn.Close()
			s.Handler.emitQUIC(ctx, diagnostic.LevelError, "request_read_failed", source, targetAddress(target), s.ID, header.FlowID, err)
			return
		}
		defer s.cancelPendingUDPControl(header.FlowID, pending)

		// UDP uses a dedicated control stream, so FIN is the setup boundary.
		var trailing [1]byte
		n, tailErr := conn.Read(trailing[:])
		if n != 0 || !errors.Is(tailErr, io.EOF) {
			err = wire.ErrInvalidFrame
			s.Handler.rejectFlowSetupGeneration(conn, s.ID, s.Generation, true, header, wire.SetupResultInvalidRequest)
			_ = conn.Close()
			s.Handler.emitQUIC(ctx, diagnostic.LevelError, "request_read_failed", source, targetAddress(target), s.ID, header.FlowID, err)
			return
		}
	}
	_ = conn.SetDeadline(time.Time{})

	if header.Kind == wire.FlowKindUDP {
		err = s.handleUDPControl(ctx, conn, source, header, target, pending)
	} else {
		err = s.Handler.handleFlowGeneration(ctx, conn, source, s.ID, s.Generation, true, header, target, wire.CarrierQUIC)
	}
	if err != nil && !IsReported(err) {
		s.Handler.emitQUIC(ctx, diagnostic.LevelWarn, "flow_failed", source, targetAddress(target), s.ID, header.FlowID, err)
	}
}

func (s *portalSession) handleUDPControl(ctx context.Context, conn net.Conn, source net.Addr, header wire.FlowHeader, target wire.Target, pending *pendingUDPControl) error {
	if err := validateFlowTransport(header, wire.CarrierQUIC); err != nil {
		s.Handler.rejectFlowSetupGeneration(conn, s.ID, s.Generation, true, header, setupFailureCode(err))
		_ = conn.Close()
		return err
	}

	half := udpHalf{Role: header.Role}
	switch header.Role {
	case wire.FlowRoleOpen:
		flow := newNowuFlow(s, header.FlowID, target)
		if err := s.activateNOWUFlow(flow, pending); err != nil {
			flow.shutdown(err)
			rejectQUICControl(conn, header, setupFailureCode(err))
			_ = conn.Close()
			return err
		}
		half.Uplink = flow
		err := s.Handler.submitAndRouteUDPGeneration(ctx, source, s.ID, s.Generation, true, header, target, half)
		_ = conn.Close()
		return err
	case wire.FlowRoleAttach:
		half.Downlink = newQUICUDPDownlink(conn, s.SendDatagram, s.maxDatagramSize, s.prober, s.closeTransport)
		return s.Handler.submitAndRouteUDPGeneration(ctx, source, s.ID, s.Generation, true, header, target, half)
	case wire.FlowRoleDuplex:
		flow := newNowuFlow(s, header.FlowID, target)
		if err := s.activateNOWUFlow(flow, pending); err != nil {
			flow.shutdown(err)
			rejectQUICControl(conn, header, setupFailureCode(err))
			_ = conn.Close()
			return err
		}
		half.Uplink = flow
		half.Downlink = newQUICUDPDownlink(conn, s.SendDatagram, s.maxDatagramSize, s.prober, s.closeTransport)
		return s.Handler.submitAndRouteUDPGeneration(ctx, source, s.ID, s.Generation, true, header, target, half)
	default:
		_ = conn.Close()
		return fmt.Errorf("%w: invalid UDP flow role", ErrUnsupportedFlow)
	}
}

var errStalePendingUDPControl = errors.New("nowhere: stale pending UDP control")

func (s *portalSession) activateNOWUFlow(flow *nowuFlow, pending *pendingUDPControl) error {
	flow.mu.Lock()
	frames, err := s.activateNOWUFlowLocked(flow, pending)
	if err != nil {
		flow.mu.Unlock()
		return err
	}
	for _, frame := range frames {
		s.recordUDPDrop(flow.flowID, len(frame.Fragment.Payload), "uplink", "before_ready")
	}
	flow.mu.Unlock()
	return nil
}

func (s *portalSession) activateNOWUFlowLocked(flow *nowuFlow, pending *pendingUDPControl) ([]wire.UDPFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if pending == nil || s.pendingControls[flow.flowID] != pending {
		return nil, errStalePendingUDPControl
	}
	if s.flows[flow.flowID] != nil {
		return nil, ErrDuplicateHalf
	}
	flow.ownsReassembly.Store(true)
	s.flows[flow.flowID] = flow
	frames := pending.frames
	s.removePendingControlLocked(flow.flowID, pending)
	return frames, nil
}

func rejectQUICControl(conn net.Conn, header wire.FlowHeader, code wire.SetupResult) {
	_ = newSetupResult(conn, header.Kind, wire.CarrierQUIC).reject(code)
}

func (s *portalSession) handleDatagram(ctx context.Context, data []byte) {
	s.handleNowu(ctx, data)
}

func (s *portalSession) handleNowu(ctx context.Context, data []byte) {
	frame, err := wire.DecodeUDPFrame(data)
	if err != nil {
		return
	}
	switch frame.Type {
	case wire.UDPFrameTypeData:
		if flow := s.getFlow(frame.FlowID); flow != nil {
			flow.deliver(frame.Payload)
		} else {
			s.recordUDPDrop(frame.FlowID, len(frame.Payload), "uplink", "unknown_flow")
		}
	case wire.UDPFrameTypeFragment:
		if flow := s.getFlow(frame.FlowID); flow != nil {
			flow.deliverFragment(frame.Fragment)
		} else {
			s.recordUDPDrop(frame.FlowID, len(frame.Fragment.Payload), "uplink", "unknown_flow")
		}
	case wire.UDPFrameTypeClose:
		if flow := s.getFlow(frame.FlowID); flow != nil {
			flow.shutdown(io.EOF)
		}
	}
}

// --- NOWU UDP flow as net.PacketConn ---

type nowuFlow struct {
	session        *portalSession
	flowID         wire.FlowID
	target         wire.Target
	dest           net.Addr
	waiter         chan nowuQueuedPacket
	done           chan struct{}
	mu             sync.Mutex
	closed         bool
	closeErr       error
	closeOnce      sync.Once
	ready          atomic.Bool
	readDL         deadlineSignal
	writeDL        deadlineSignal
	idle           *time.Timer
	ownsReassembly atomic.Bool
	nextPacketID   atomic.Uint32
}

type nowuQueuedPacket struct {
	payload []byte
	release func()
}

func newNowuFlow(session *portalSession, flowID wire.FlowID, target wire.Target) *nowuFlow {
	flow := &nowuFlow{
		session: session,
		flowID:  flowID,
		target:  target,
		dest:    targetNetAddr(target),
		waiter:  make(chan nowuQueuedPacket, session.Handler.config.limits.UDPQueuePackets),
		done:    make(chan struct{}),
	}
	flow.resetIdle()
	return flow
}

const (
	nowuPartialLimit = 64
	nowuPartialTTL   = 10 * time.Second
)

func (f *nowuFlow) deliverFragment(fragment wire.UDPFragment) {
	if !f.ready.Load() {
		f.session.recordUDPDrop(f.flowID, len(fragment.Payload), "uplink", "before_ready")
		return
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	outcome := f.pushFragmentLocked(fragment)
	f.mu.Unlock()
	if outcome.Complete {
		f.enqueue(outcome.Packet, outcome.Release)
	} else if outcome.Dropped {
		f.session.recordUDPDrop(f.flowID, len(fragment.Payload), "uplink", "reassembly")
	}
}

func (f *nowuFlow) pushFragmentLocked(fragment wire.UDPFragment) reassemblyOutcome {
	now := time.Now()
	if f.session.Handler != nil && f.session.Handler.now != nil {
		now = f.session.Handler.now()
	}
	return f.session.reassembler.Push(f.flowID, fragment, now)
}

func (f *nowuFlow) deliver(payload []byte) {
	if !f.ready.Load() {
		f.session.recordUDPDrop(f.flowID, len(payload), "uplink", "before_ready")
		return
	}
	if !f.session.reserveQueueBytes(len(payload)) {
		f.session.recordUDPDrop(f.flowID, len(payload), "uplink", "byte_limit")
		return
	}
	f.enqueue(payload, func() { f.session.releaseQueueBytes(len(payload)) })
}

func (f *nowuFlow) markReady() {
	if f != nil {
		f.ready.Store(true)
	}
}

func (f *nowuFlow) enqueue(payload []byte, release func()) {
	if release == nil {
		release = func() {}
	}
	packet := nowuQueuedPacket{payload: payload, release: release}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		release()
		return
	}
	select {
	case f.waiter <- packet:
		f.mu.Unlock()
		f.resetIdle()
	default:
		f.mu.Unlock()
		release()
		f.session.recordUDPDrop(f.flowID, len(payload), "uplink", "queue_full")
	}
}

func (f *nowuFlow) shutdown(err error) {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.closeErr = err
		if f.idle != nil {
			f.idle.Stop()
		}
		f.readDL.stop()
		f.writeDL.stop()
		f.mu.Unlock()
		if f.ownsReassembly.Load() && f.session.reassembler != nil {
			f.session.reassembler.RemoveFlow(f.flowID)
		}
		close(f.done)
		for {
			select {
			case packet := <-f.waiter:
				packet.release()
			default:
				f.session.removeFlow(f.flowID, f)
				return
			}
		}
	})
}

func (f *nowuFlow) ReadPacket() ([]byte, error) {
	select {
	case packet := <-f.waiter:
		packet.release()
		f.resetIdle()
		return packet.payload, nil
	case <-f.done:
		return nil, f.err()
	case <-f.readDL.wait():
		return nil, deadlineError()
	}
}

func (f *nowuFlow) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	payload, err := f.ReadPacket()
	if err != nil {
		return 0, nil, err
	}
	return copy(p, payload), f.dest, nil
}

func (f *nowuFlow) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	select {
	case <-f.done:
		return 0, f.err()
	case <-f.writeDL.wait():
		return 0, deadlineError()
	default:
	}
	prober := f.session.prober
	if prober == nil {
		prober = carrierquic.NewDatagramProber(func() int { return defaultMaxDatagramSize })
	}
	nextPacketID := func() uint32 {
		packetID := f.nextPacketID.Add(1)
		if packetID == 0 {
			packetID = f.nextPacketID.Add(1)
		}
		return packetID
	}
	ctx := context.Background()
	cancel := func() {}
	if done := f.session.Conn.Context().Done(); done != nil {
		ctx, cancel = context.WithCancel(f.session.Conn.Context())
	}
	if deadline := f.writeDL.wait(); deadline != nil {
		parent := ctx
		var deadlineCancel context.CancelFunc
		ctx, deadlineCancel = context.WithCancel(parent)
		previousCancel := cancel
		cancel = func() {
			deadlineCancel()
			previousCancel()
		}
		go func() {
			select {
			case <-deadline:
				deadlineCancel()
			case <-ctx.Done():
			}
		}()
	}
	defer cancel()
	if err := carrierquic.SendUDPData(ctx, f.session.SendDatagram, prober, f.flowID, nextPacketID, p); err != nil {
		if ctx.Err() != nil && f.writeDL.wait() != nil {
			return 0, deadlineError()
		}
		if errors.Is(err, carrierquic.ErrDatagramMTUUnstable) {
			f.session.recordUDPDrop(f.flowID, len(p), "downlink", "mtu_unstable")
			f.resetIdle()
			return len(p), nil
		}
		return 0, err
	}
	f.resetIdle()
	return len(p), nil
}

func (f *nowuFlow) Close() error {
	f.shutdown(net.ErrClosed)
	return nil
}

func (f *nowuFlow) LocalAddr() net.Addr {
	if s := f.session; s != nil && s.Conn != nil {
		return s.Conn.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (f *nowuFlow) SetDeadline(value time.Time) error {
	f.readDL.set(value)
	f.writeDL.set(value)
	return nil
}

func (f *nowuFlow) SetReadDeadline(value time.Time) error {
	f.readDL.set(value)
	return nil
}

func (f *nowuFlow) SetWriteDeadline(value time.Time) error {
	f.writeDL.set(value)
	return nil
}

func (f *nowuFlow) resetIdle() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	if f.idle != nil {
		f.idle.Stop()
	}
	timeout := f.session.Handler.config.timeouts.UDPIdle
	f.idle = time.AfterFunc(timeout, func() { f.shutdown(context.DeadlineExceeded) })
	f.mu.Unlock()
}

func (f *nowuFlow) err() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closeErr != nil {
		return f.closeErr
	}
	return io.EOF
}

var _ net.PacketConn = (*nowuFlow)(nil)

// --- stream helpers ---

type bufferedStreamConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedStreamConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *bufferedStreamConn) CloseRead() error           { return closeReadSide(c.Conn) }
func (c *bufferedStreamConn) CloseWrite() error          { return closeWriteSide(c.Conn) }

type quicStreamConn struct {
	QuicStream
	local  net.Addr
	remote net.Addr
	once   sync.Once
}

func wrapQuicStream(stream QuicStream, local, remote net.Addr) net.Conn {
	return &quicStreamConn{QuicStream: stream, local: local, remote: remote}
}

func (c *quicStreamConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return &net.UDPAddr{}
}

func (c *quicStreamConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return &net.UDPAddr{}
}

func (c *quicStreamConn) Close() error {
	var err error
	c.once.Do(func() {
		c.CancelRead(0)
		err = c.QuicStream.Close()
	})
	return err
}

func (c *quicStreamConn) CloseRead() error {
	c.CancelRead(0)
	return nil
}

func (c *quicStreamConn) CloseWrite() error {
	return c.QuicStream.Close()
}

func (c *quicStreamConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

var (
	_ net.Conn = (*quicStreamConn)(nil)
	_ net.Conn = (*bufferedStreamConn)(nil)
)
