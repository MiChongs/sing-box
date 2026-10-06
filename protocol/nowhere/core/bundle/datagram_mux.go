package bundle

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier"
	carrierquic "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const (
	quicDatagramFlowQueue = 64
	quicSendQueue         = 1
	quicReassemblySweep   = time.Second
)

// Invalidation has one owner: either a per-raw failure/explicit invalidation or
// backend Close. The owner removes the mux only after the host close completes.
const (
	quicInvalidationNone int32 = iota
	quicInvalidationRaw
	quicInvalidationBackendClose
	quicInvalidationFinished
)

var (
	errManagedDatagramReceive    = errors.New("nowhere: quic datagram receive is bundle managed")
	errQUICAuthenticationAborted = errors.New("nowhere: first quic stream closed before authentication")
)

// ErrPendingCloseLimit prevents unbounded reliable CLOSE retention. Overflow
// invalidates the physical QUIC session so the peer cannot retain leaked flows.
var ErrPendingCloseLimit = errors.New("nowhere: pending QUIC CLOSE limit exceeded")

type quicByteBudget struct {
	mu    sync.Mutex
	limit int
	used  int
}

func (b *quicByteBudget) reserve(count int) (wire.ByteReservation, bool) {
	if b == nil || count < 0 {
		return nil, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit > 0 && b.used+count > b.limit {
		return nil, false
	}
	b.used += count
	return &quicByteReservation{budget: b, count: count}, true
}

type quicByteReservation struct {
	once   sync.Once
	budget *quicByteBudget
	count  int
}

func (r *quicByteReservation) Release() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.budget.mu.Lock()
		r.budget.used -= r.count
		if r.budget.used < 0 {
			r.budget.used = 0
		}
		r.budget.mu.Unlock()
	})
}

const (
	quicSendQueued uint32 = iota
	quicSendStarted
	quicSendCompleted
	quicSendCanceled
)

type quicSendRequest struct {
	owner  *qSessionHandle
	ctx    context.Context
	frame  []byte
	result chan error
	state  atomic.Uint32
}

func (r *quicSendRequest) start() bool {
	return r.state.CompareAndSwap(quicSendQueued, quicSendStarted)
}

func (r *quicSendRequest) cancel() bool {
	return r.state.CompareAndSwap(quicSendQueued, quicSendCanceled)
}

func (r *quicSendRequest) finish(err error) {
	r.state.Store(quicSendCompleted)
	r.result <- err
}

// quicAuthFrameBuilder binds a fresh physical QUIC session to the bundle
// identity. It is supplied by the bundle (which owns the Credentials +
// Transport + Session ID) and called exactly once per physical session. The
// mux retains the result until the first flow commits.
type quicAuthFrameBuilder func(ctx context.Context, session carrier.QuicSession) (wire.AuthFrame, error)

// quicMuxBackend owns one receive loop and one bounded send owner for every
// physical QUIC session returned by the injected backend.
type quicMuxBackend struct {
	backend          carrier.QuicBackend
	auth             quicAuthFrameBuilder
	maxUDPQueueBytes int
	maxPendingCloses int
	observer         diagnostic.Observer

	mu       sync.Mutex
	sessions map[carrier.QuicSession]*quicSessionMux
	closed   bool
}

func newQUICMuxBackend(
	backend carrier.QuicBackend,
	auth quicAuthFrameBuilder,
	maxUDPQueueBytes int,
	maxPendingCloses int,
	observer diagnostic.Observer,
) *quicMuxBackend {
	return &quicMuxBackend{
		backend:          backend,
		auth:             auth,
		maxUDPQueueBytes: maxUDPQueueBytes,
		maxPendingCloses: maxPendingCloses,
		observer:         observer,
		sessions:         make(map[carrier.QuicSession]*quicSessionMux),
	}
}

func (b *quicMuxBackend) AcquireSession(ctx context.Context) (carrier.QuicSession, error) {
	for {
		raw, err := b.backend.AcquireSession(ctx)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			return nil, errors.New("nowhere: nil quic session")
		}

		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			b.backend.InvalidateSession(raw)
			return nil, net.ErrClosed
		}
		if session := b.sessions[raw]; session != nil {
			if session.invalidation.Load() != quicInvalidationNone {
				done := session.invalidationDone
				b.mu.Unlock()
				select {
				case <-done:
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			b.mu.Unlock()
			return session, nil
		}
		// First time the mux sees this physical session: derive and retain its
		// connection-bound auth frame. PrepareStream will reserve the first
		// stream and Commit will write auth || first FLOW in one operation.
		if b.auth == nil {
			b.mu.Unlock()
			b.backend.InvalidateSession(raw)
			return nil, errors.New("nowhere: missing quic authenticator")
		}
		authFrame, authErr := b.auth(ctx, raw)
		if authErr != nil {
			b.mu.Unlock()
			b.backend.InvalidateSession(raw)
			return nil, authErr
		}
		session, err := newQUICSessionMux(b, raw, authFrame)
		if err != nil {
			b.mu.Unlock()
			b.backend.InvalidateSession(raw)
			return nil, err
		}
		// Publish before starting receiveLoop so an immediate raw-session death
		// can remove this entry (stream-only TCP-over-QUIC never registers UDP).
		b.sessions[raw] = session
		b.mu.Unlock()
		session.startReceiveLoop()
		return session, nil
	}
}

func (b *quicMuxBackend) InvalidateSession(session carrier.QuicSession) {
	raw := session
	var managed *quicSessionMux
	if state, ok := session.(*quicSessionMux); ok {
		managed = state
		raw = managed.raw
	} else {
		b.mu.Lock()
		managed = b.sessions[session]
		b.mu.Unlock()
	}
	if managed == nil {
		b.backend.InvalidateSession(raw)
		return
	}
	managed.invalidateRaw(net.ErrClosed)
	<-managed.loopDone
	<-managed.sendLoopDone
}

func (b *quicMuxBackend) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	sessions := make([]*quicSessionMux, 0, len(b.sessions))
	for _, session := range b.sessions {
		sessions = append(sessions, session)
	}
	b.mu.Unlock()

	for _, session := range sessions {
		session.prepareBackendClose()
	}
	err := b.backend.Close()
	for _, session := range sessions {
		session.completeBackendClose()
	}
	for _, session := range sessions {
		<-session.loopDone
		<-session.sendLoopDone
	}
	return err
}

func (b *quicMuxBackend) remove(session *quicSessionMux) {
	b.mu.Lock()
	if b.sessions[session.raw] == session {
		delete(b.sessions, session.raw)
	}
	b.mu.Unlock()
}

var _ carrier.QuicBackend = (*quicMuxBackend)(nil)

// quicSessionMux presents one carrier session, runs the single receive loop,
// and owns every raw SendDatagram call. DATA retains bounded native
// backpressure; CLOSE uses a reliable in-memory queue so flow teardown cannot
// be lost while the DATA queue or raw sender is blocked. Fragment reassembly
// delegates to the wire.DatagramReassembler (matches the Rust oracle).
type quicSessionMux struct {
	backend *quicMuxBackend
	raw     carrier.QuicSession
	ctx     context.Context
	cancel  context.CancelFunc

	authMu       sync.Mutex
	authFrame    wire.AuthFrame
	authClaimed  bool
	authComplete bool
	authErr      error
	authDone     chan struct{}

	mu               sync.Mutex
	flows            map[wire.FlowID]*quicDatagramFlow
	reassembler      *wire.DatagramReassembler
	budget           *quicByteBudget
	prober           *carrierquic.DatagramProber
	closeQueue       []wire.FlowID
	closeSet         map[wire.FlowID]struct{}
	maxPendingCloses int
	observer         diagnostic.Observer
	sessionID        wire.SessionID
	started          bool
	closed           bool
	cause            error

	startOnce        sync.Once
	closeOnce        sync.Once
	finishOnce       sync.Once
	invalidation     atomic.Int32
	invalidationDone chan struct{}
	done             chan struct{}
	loopDone         chan struct{}
	sendQueue        chan *quicSendRequest
	closeReady       chan struct{}
	sendLoopDone     chan struct{}

	dropMu        sync.Mutex
	dropCount     int
	dropBytes     uint64
	dropFlowID    wire.FlowID
	dropDirection string
	dropReason    string
	dropLastEmit  time.Time
}

func newQUICSessionMux(backend *quicMuxBackend, raw carrier.QuicSession, authFrame wire.AuthFrame) (*quicSessionMux, error) {
	ctx, cancel := context.WithCancel(context.Background())
	reassembler, err := wire.NewDatagramReassembler(wire.DefaultReassemblyConfig())
	if err != nil {
		cancel()
		return nil, err
	}
	session := &quicSessionMux{
		backend:          backend,
		raw:              raw,
		ctx:              ctx,
		cancel:           cancel,
		authFrame:        authFrame,
		authDone:         make(chan struct{}),
		flows:            make(map[wire.FlowID]*quicDatagramFlow),
		reassembler:      reassembler,
		budget:           &quicByteBudget{limit: backend.maxUDPQueueBytes},
		closeSet:         make(map[wire.FlowID]struct{}),
		maxPendingCloses: backend.maxPendingCloses,
		observer:         backend.observer,
		invalidationDone: make(chan struct{}),
		done:             make(chan struct{}),
		loopDone:         make(chan struct{}),
		sendQueue:        make(chan *quicSendRequest, quicSendQueue),
		closeReady:       make(chan struct{}, 1),
		sendLoopDone:     make(chan struct{}),
	}
	copy(session.sessionID[:], authFrame[:wire.SessionIDLen])
	session.prober = carrierquic.NewDatagramProber(raw.CurrentMaxDatagramSize)
	go session.sendLoop()
	return session, nil
}

// startReceiveLoop watches the raw session for terminal datagram errors so the
// mux can tear down even when no UDP flow was ever registered (TCP-over-QUIC).
// Without this, an idle/peer close leaves sendLoop blocked and the sessions map
// entry orphaned after the host replaces the physical session.
func (s *quicSessionMux) startReceiveLoop() {
	if s == nil {
		return
	}
	s.startOnce.Do(func() {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		s.started = true
		s.mu.Unlock()
		go s.receiveLoop()
	})
}

func (s *quicSessionMux) PrepareStream(ctx context.Context) (carrier.QuicPreparedStream, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	s.authMu.Lock()
	if s.authComplete {
		err := s.authErr
		s.authMu.Unlock()
		if err != nil {
			return nil, err
		}
		return s.raw.PrepareStream(ctx)
	}
	if s.authClaimed {
		done := s.authDone
		s.authMu.Unlock()
		select {
		case <-done:
			s.authMu.Lock()
			err := s.authErr
			s.authMu.Unlock()
			if err != nil {
				return nil, err
			}
			return s.raw.PrepareStream(ctx)
		case <-s.done:
			return nil, s.terminalError()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.authClaimed = true
	s.authMu.Unlock()

	stream, err := s.raw.PrepareStream(ctx)
	if err != nil {
		s.failAuthentication(err)
		return nil, err
	}
	return &quicAuthPreparedStream{session: s, stream: stream}, nil
}

func (s *quicSessionMux) completeAuthentication(err error) {
	s.authMu.Lock()
	if !s.authComplete {
		s.authComplete = true
		s.authErr = err
		close(s.authDone)
	}
	s.authMu.Unlock()
}

func (s *quicSessionMux) failAuthentication(err error) {
	if err == nil {
		err = errQUICAuthenticationAborted
	}
	s.completeAuthentication(err)
	s.invalidateRaw(err)
}

// quicAuthPreparedStream owns the first raw stream. Its single Commit sends
// the fixed auth frame and the first FLOW setup as one opaque payload, keeping
// the caller's FIN choice for the logical flow.
type quicAuthPreparedStream struct {
	session *quicSessionMux
	stream  carrier.QuicPreparedStream
	once    sync.Once
}

func (p *quicAuthPreparedStream) Commit(ctx context.Context, setup []byte, finishWrite bool) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	p.once.Do(func() {
		if p.session == nil || p.stream == nil {
			err = net.ErrClosed
			return
		}
		payload := make([]byte, 0, wire.AuthFrameLen+len(setup))
		payload = append(payload, p.session.authFrame[:]...)
		payload = append(payload, setup...)
		conn, err = p.stream.Commit(ctx, payload, finishWrite)
		if err == nil && conn == nil {
			err = net.ErrClosed
		}
		if err != nil {
			p.session.failAuthentication(err)
			return
		}
		p.session.completeAuthentication(nil)
	})
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (p *quicAuthPreparedStream) Close() error {
	var err error
	p.once.Do(func() {
		if p.stream != nil {
			err = p.stream.Close()
		}
		if p.session != nil {
			// Auth is bound to the first stream on a physical QUIC session.
			// Abandoning it (mix fallback, caller cancel) must tear the session
			// down; the identity cannot be reused on a later stream.
			p.session.failAuthentication(errors.Join(errQUICAuthenticationAborted, err))
		}
	})
	return err
}

// TLSHandshakeInfo delegates to the underlying physical session. The bundle
// reads it once during authentication (before the mux caches the session), so this
// method exists primarily to satisfy the carrier.QuicSession interface for the
// cached wrapper.
func (s *quicSessionMux) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	return s.raw.TLSHandshakeInfo()
}

func (s *quicSessionMux) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, errManagedDatagramReceive
}

func (s *quicSessionMux) CurrentMaxDatagramSize() int {
	if s.prober != nil {
		return s.prober.MaxDatagramSize()
	}
	return s.raw.CurrentMaxDatagramSize()
}

func (s *quicSessionMux) SendDatagram(ctx context.Context, frame []byte) error {
	return s.sendDatagram(ctx, nil, frame, nil)
}
func (s *quicSessionMux) LocalAddr() net.Addr { return s.raw.LocalAddr() }

func (s *quicSessionMux) sendDatagram(ctx context.Context, owner *qSessionHandle, frame []byte, deadline *datagramDeadline) error {
	if ctx == nil {
		ctx = context.Background()
	}
	request := &quicSendRequest{owner: owner, ctx: ctx, frame: frame, result: make(chan error, 1)}
	var ownerDone <-chan struct{}
	if owner != nil {
		ownerDone = owner.doneSignal()
	}
	for {
		at, deadlineSignal, deadlineClosed := deadline.snapshot()
		if deadlineClosed {
			return net.ErrClosed
		}
		if deadlineExpired(at) {
			return errDatagramDeadline
		}
		select {
		case s.sendQueue <- request:
			goto queued
		case <-deadlineSignal:
			continue
		case <-ownerDone:
			return net.ErrClosed
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			return s.terminalError()
		}
	}

queued:
	for {
		select {
		case <-s.done:
			request.cancel()
			return s.terminalError()
		default:
		}
		if request.state.Load() == quicSendCompleted {
			return <-request.result
		}
		at, deadlineSignal, deadlineClosed := deadline.snapshot()
		if deadlineClosed {
			if request.cancel() {
				return net.ErrClosed
			}
			if request.state.Load() == quicSendCompleted {
				return <-request.result
			}
			return net.ErrClosed
		}
		if deadlineExpired(at) {
			if request.cancel() {
				return errDatagramDeadline
			}
			if request.state.Load() == quicSendCompleted {
				return <-request.result
			}
			return errDatagramDeadline
		}
		select {
		case err := <-request.result:
			select {
			case <-s.done:
				return s.terminalError()
			default:
				return err
			}
		case <-deadlineSignal:
			continue
		case <-ownerDone:
			if request.cancel() {
				return net.ErrClosed
			}
			if request.state.Load() == quicSendCompleted {
				return <-request.result
			}
			return net.ErrClosed
		case <-ctx.Done():
			if request.cancel() {
				return ctx.Err()
			}
			return ctx.Err()
		case <-s.done:
			request.cancel()
			return s.terminalError()
		}
	}
}

func (s *quicSessionMux) enqueueClose(flowID wire.FlowID) error {
	if flowID == 0 {
		return errors.New("nowhere: zero CLOSE flow id")
	}
	s.mu.Lock()
	if s.closed {
		cause := s.cause
		s.mu.Unlock()
		if cause == nil {
			return net.ErrClosed
		}
		return cause
	}
	if _, exists := s.closeSet[flowID]; exists {
		s.mu.Unlock()
		return nil
	}
	if len(s.closeQueue) >= s.maxPendingCloses {
		s.mu.Unlock()
		s.invalidateRaw(ErrPendingCloseLimit)
		return ErrPendingCloseLimit
	}
	s.closeSet[flowID] = struct{}{}
	s.closeQueue = append(s.closeQueue, flowID)
	select {
	case s.closeReady <- struct{}{}:
	default:
	}
	s.mu.Unlock()
	return nil
}

func (s *quicSessionMux) popClose() (wire.FlowID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.closeQueue) == 0 {
		return 0, false
	}
	flowID := s.closeQueue[0]
	s.closeQueue = s.closeQueue[1:]
	delete(s.closeSet, flowID)
	if len(s.closeQueue) > 0 {
		select {
		case s.closeReady <- struct{}{}:
		default:
		}
	}
	return flowID, true
}

func (s *quicSessionMux) sendLoop() {
	defer close(s.sendLoopDone)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		if flowID, ok := s.popClose(); ok {
			frame, encodeErr := wire.EncodeUDPClose(flowID)
			if encodeErr != nil {
				s.invalidateRaw(encodeErr)
				return
			}
			ctx, cancel := context.WithTimeout(s.ctx, 100*time.Millisecond)
			err := s.raw.SendDatagram(ctx, frame[:])
			cancel()
			if err != nil {
				select {
				case <-s.done:
					return
				default:
				}
				if s.ctx.Err() != nil {
					return
				}
				if errors.Is(err, context.DeadlineExceeded) {
					_ = s.enqueueClose(flowID)
					continue
				}
				s.invalidateRaw(err)
				return
			}
			continue
		}
		select {
		case request := <-s.sendQueue:
			if !request.start() {
				continue
			}
			if request.owner != nil {
				if err := request.owner.stateError(); err != nil {
					request.finish(err)
					continue
				}
			}
			request.finish(s.raw.SendDatagram(request.ctx, request.frame))
		case <-s.closeReady:
		case <-s.done:
			return
		}
	}
}

func (s *quicSessionMux) terminalError() error {
	s.mu.Lock()
	err := s.cause
	s.mu.Unlock()
	if err == nil {
		return net.ErrClosed
	}
	return err
}

func (s *quicSessionMux) recordUDPDrop(flowID wire.FlowID, bytes int, direction, reason string) {
	now := time.Now()
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
	diagnostic.Emit(context.Background(), s.observer, event)
}

func (s *quicSessionMux) flushUDPDrop() {
	s.dropMu.Lock()
	event := s.takeUDPDropLocked(time.Now())
	s.dropMu.Unlock()
	if event.Count > 0 {
		diagnostic.Emit(context.Background(), s.observer, event)
	}
}

func (s *quicSessionMux) takeUDPDropLocked(now time.Time) diagnostic.Event {
	if s.dropCount == 0 {
		return diagnostic.Event{}
	}
	event := diagnostic.Event{
		Level: diagnostic.LevelWarn, Code: "udp_queue_drop_total",
		Component: "bundle", Carrier: diagnostic.CarrierQUIC,
		SessionID: s.sessionID, FlowID: s.dropFlowID,
		State: s.dropDirection, Outcome: s.dropReason,
		Count: s.dropCount, Bytes: s.dropBytes,
	}
	s.dropCount = 0
	s.dropBytes = 0
	s.dropLastEmit = now
	return event
}

func (s *quicSessionMux) register(flowID wire.FlowID) (*quicDatagramFlow, error) {
	if flowID == 0 {
		return nil, errors.New("nowhere: zero flow id")
	}
	flow := newQUICDatagramFlow(s, flowID)

	s.mu.Lock()
	if s.closed {
		cause := s.cause
		s.mu.Unlock()
		return nil, cause
	}
	if s.flows[flowID] != nil {
		s.mu.Unlock()
		return nil, errors.New("nowhere: duplicate quic udp flow")
	}
	s.flows[flowID] = flow
	s.mu.Unlock()
	s.startReceiveLoop()
	return flow, nil
}

func (s *quicSessionMux) unregister(flowID wire.FlowID, flow *quicDatagramFlow, cause error) {
	s.mu.Lock()
	if s.flows[flowID] != flow {
		s.mu.Unlock()
		return
	}
	delete(s.flows, flowID)
	s.reassembler.RemoveFlow(flowID)
	s.mu.Unlock()
	flow.finish(cause)
}

func (s *quicSessionMux) receiveLoop() {
	defer close(s.loopDone)
	for {
		receiveCtx, cancel := context.WithTimeout(s.ctx, quicReassemblySweep)
		data, err := s.raw.ReceiveDatagram(receiveCtx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && s.ctx.Err() == nil {
				s.mu.Lock()
				s.reassembler.Expire(time.Now())
				s.mu.Unlock()
				continue
			}
			if s.ctx.Err() != nil {
				return
			}
			s.invalidateRaw(err)
			return
		}
		frame, err := wire.DecodeUDPFrame(data)
		if err != nil {
			continue
		}
		switch frame.Type {
		case wire.UDPFrameTypeData:
			// Unfragmented DATA: deliver immediately (zero-length is legal).
			s.deliver(frame.FlowID, frame.Payload)
		case wire.UDPFrameTypeFragment:
			s.handleFragment(frame.FlowID, frame.Fragment)
		case wire.UDPFrameTypeClose:
			s.closeFlow(frame.FlowID)
		}
	}
}

// deliver hands an already-complete UDP payload to its flow if registered.
func (s *quicSessionMux) deliver(flowID wire.FlowID, payload []byte) {
	s.mu.Lock()
	flow := s.flows[flowID]
	s.mu.Unlock()
	if flow == nil {
		s.recordUDPDrop(flowID, len(payload), "downlink", "unknown_flow")
		return
	}
	if !flow.ready() {
		s.recordUDPDrop(flowID, len(payload), "downlink", "before_ready")
		return
	}
	reservation, ok := s.budget.reserve(len(payload))
	if !ok {
		s.recordUDPDrop(flowID, len(payload), "downlink", "byte_limit")
		return
	}
	if !flow.enqueue(payload, reservation) {
		s.recordUDPDrop(flowID, len(payload), "downlink", "queue_full")
	}
}

func (s *quicSessionMux) handleFragment(flowID wire.FlowID, fragment wire.UDPFragment) {
	now := time.Now()
	s.mu.Lock()
	flow := s.flows[flowID]
	closed := s.closed
	s.mu.Unlock()
	if flow == nil || closed {
		s.recordUDPDrop(flowID, len(fragment.Payload), "downlink", "unknown_flow")
		return
	}
	if !flow.ready() {
		s.recordUDPDrop(flowID, len(fragment.Payload), "downlink", "before_ready")
		return
	}
	// Hand the fragment to the wire reassembler (it owns slot/byte/TTL limits,
	// identical-duplicate handling, and metadata-conflict drops).
	outcome := s.reassembler.PushWithReservation(flowID, fragment, now, s.budget.reserve)
	if outcome.DropReason != wire.ReassemblyDropNone {
		s.recordUDPDrop(flowID, len(fragment.Payload), "downlink", outcome.DropReason.String())
	}
	if outcome.Done {
		if !flow.enqueue(outcome.Payload, outcome.Reservation) {
			s.recordUDPDrop(flowID, len(outcome.Payload), "downlink", "queue_full")
		}
	}
}

func (s *quicSessionMux) closeFlow(flowID wire.FlowID) {
	s.mu.Lock()
	flow := s.flows[flowID]
	s.mu.Unlock()
	if flow != nil {
		s.unregister(flowID, flow, io.EOF)
	}
}

func (s *quicSessionMux) invalidateRaw(cause error) {
	if s.invalidation.CompareAndSwap(quicInvalidationNone, quicInvalidationRaw) {
		s.close(cause)
		s.backend.backend.InvalidateSession(s.raw)
		s.finishInvalidation()
		return
	}
	<-s.invalidationDone
}

func (s *quicSessionMux) prepareBackendClose() {
	if s.invalidation.CompareAndSwap(quicInvalidationNone, quicInvalidationBackendClose) {
		s.close(net.ErrClosed)
	}
}

func (s *quicSessionMux) completeBackendClose() {
	if s.invalidation.Load() == quicInvalidationBackendClose {
		s.finishInvalidation()
	}
	<-s.invalidationDone
}

func (s *quicSessionMux) finishInvalidation() {
	s.finishOnce.Do(func() {
		s.backend.remove(s)
		s.invalidation.Store(quicInvalidationFinished)
		close(s.invalidationDone)
	})
}

func (s *quicSessionMux) close(cause error) {
	s.closeOnce.Do(func() {
		if cause == nil || errors.Is(cause, context.Canceled) {
			cause = net.ErrClosed
		}
		s.completeAuthentication(cause)
		s.cancel()

		s.mu.Lock()
		s.closed = true
		s.cause = cause
		flows := make([]*quicDatagramFlow, 0, len(s.flows))
		for _, flow := range s.flows {
			flows = append(flows, flow)
		}
		s.flows = make(map[wire.FlowID]*quicDatagramFlow)
		s.reassembler.Clear()
		s.closeQueue = nil
		s.closeSet = make(map[wire.FlowID]struct{})
		started := s.started
		s.mu.Unlock()

		if !started {
			close(s.loopDone)
		}
		for _, flow := range flows {
			flow.finish(cause)
		}
		s.flushUDPDrop()
		close(s.done)
	})
}

var (
	_ carrier.QuicSession        = (*quicSessionMux)(nil)
	_ carrier.QuicPreparedStream = (*quicAuthPreparedStream)(nil)
)

type quicQueuedPacket struct {
	payload     []byte
	reservation wire.ByteReservation
}

type quicDatagramFlowState uint8

const (
	quicFlowRegistered quicDatagramFlowState = iota
	quicFlowReady
	quicFlowClosed
)

type quicDatagramFlow struct {
	session *quicSessionMux
	flowID  wire.FlowID
	packets chan quicQueuedPacket
	done    chan struct{}

	mu         sync.Mutex
	cause      error
	state      quicDatagramFlowState
	finishOnce sync.Once
}

func newQUICDatagramFlow(session *quicSessionMux, flowID wire.FlowID) *quicDatagramFlow {
	return &quicDatagramFlow{
		session: session,
		flowID:  flowID,
		packets: make(chan quicQueuedPacket, quicDatagramFlowQueue),
		done:    make(chan struct{}),
	}
}

func (f *quicDatagramFlow) markReady() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != quicFlowRegistered {
		return false
	}
	f.state = quicFlowReady
	return true
}

func (f *quicDatagramFlow) ready() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state == quicFlowReady
}

func (f *quicDatagramFlow) enqueue(payload []byte, reservation wire.ByteReservation) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != quicFlowReady {
		if reservation != nil {
			reservation.Release()
		}
		return false
	}
	select {
	case f.packets <- quicQueuedPacket{payload: payload, reservation: reservation}:
		return true
	default:
		if reservation != nil {
			reservation.Release()
		}
		return false
	}
}

func (f *quicDatagramFlow) readPacket(ctx context.Context, deadline *datagramDeadline) ([]byte, error) {
	for {
		at, deadlineSignal, deadlineClosed := deadline.snapshot()
		if deadlineClosed {
			return nil, net.ErrClosed
		}
		if deadlineExpired(at) {
			return nil, errDatagramDeadline
		}
		select {
		case packet := <-f.packets:
			if packet.reservation != nil {
				packet.reservation.Release()
			}
			if deadline.expired() {
				return nil, errDatagramDeadline
			}
			return packet.payload, nil
		default:
		}
		select {
		case packet := <-f.packets:
			if packet.reservation != nil {
				packet.reservation.Release()
			}
			if deadline.expired() {
				return nil, errDatagramDeadline
			}
			return packet.payload, nil
		case <-deadlineSignal:
			continue
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.done:
			select {
			case packet := <-f.packets:
				if packet.reservation != nil {
					packet.reservation.Release()
				}
				return packet.payload, nil
			default:
			}
			return nil, f.closeCause()
		}
	}
}

func (f *quicDatagramFlow) closeCause() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cause == nil {
		return io.EOF
	}
	return f.cause
}

func (f *quicDatagramFlow) finish(cause error) {
	f.finishOnce.Do(func() {
		if cause == nil {
			cause = io.EOF
		}
		f.mu.Lock()
		f.state = quicFlowClosed
		f.cause = cause
		close(f.done)
		f.mu.Unlock()
		for {
			select {
			case packet := <-f.packets:
				if packet.reservation != nil {
					packet.reservation.Release()
				}
			default:
				return
			}
		}
	})
}

func (f *quicDatagramFlow) unregister(cause error) {
	f.session.unregister(f.flowID, f, cause)
}
