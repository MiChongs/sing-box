package bundle

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/carrier"
	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
)

func TestQUICMuxReleasesOnRawCloseWithoutUDPFlow(t *testing.T) {
	// TCP-over-QUIC never calls register(), so receiveLoop must start at
	// AcquireSession time; otherwise idle/peer close orphans sendLoop + map entry.
	raw := &muxLifecycleSession{receive: make(chan []byte), fail: make(chan struct{})}
	backend := &muxLifecycleBackend{}
	muxBackend := &quicMuxBackend{
		backend:          backend,
		auth:             func(context.Context, carrier.QuicSession) (wire.AuthFrame, error) { return wire.AuthFrame{1}, nil },
		maxUDPQueueBytes: 64,
		maxPendingCloses: 4,
		sessions:         make(map[carrier.QuicSession]*quicSessionMux),
	}
	backend.acquire = func(context.Context) (carrier.QuicSession, error) { return raw, nil }

	session, err := muxBackend.AcquireSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mux, ok := session.(*quicSessionMux)
	if !ok {
		t.Fatalf("session type %T, want *quicSessionMux", session)
	}
	if got := len(muxBackend.sessions); got != 1 {
		t.Fatalf("sessions after acquire = %d, want 1", got)
	}

	close(raw.fail)

	select {
	case <-mux.sendLoopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("sendLoop did not exit after raw session death without UDP flow")
	}
	select {
	case <-mux.loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("receiveLoop did not exit after raw session death without UDP flow")
	}
	if got := len(muxBackend.sessions); got != 0 {
		t.Fatalf("sessions after raw close = %d, want 0", got)
	}
	if got := backend.invalidations.Load(); got != 1 {
		t.Fatalf("backend invalidations = %d, want 1", got)
	}
}

func TestQUICMuxAcquireAfterCloseFailsFast(t *testing.T) {
	raw := &muxLifecycleSession{receive: make(chan []byte)}
	backend := &muxLifecycleBackend{}
	muxBackend := &quicMuxBackend{
		backend:          backend,
		auth:             func(context.Context, carrier.QuicSession) (wire.AuthFrame, error) { return wire.AuthFrame{1}, nil },
		maxUDPQueueBytes: 64,
		maxPendingCloses: 4,
		sessions:         make(map[carrier.QuicSession]*quicSessionMux),
	}
	backend.acquire = func(context.Context) (carrier.QuicSession, error) { return raw, nil }

	if err := muxBackend.Close(); err != nil {
		t.Fatal(err)
	}
	// The drain token rejects the acquire before the host is consulted, so a
	// closed mux consumes no physical session (upstream 206f9c1).
	if _, err := muxBackend.AcquireSession(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("AcquireSession after Close = %v, want net.ErrClosed", err)
	}
	if got := backend.acquires.Load(); got != 0 {
		t.Fatalf("backend acquires after close = %d, want 0", got)
	}
	if got := len(muxBackend.sessions); got != 0 {
		t.Fatalf("sessions after closed acquire = %d, want 0", got)
	}
}

func TestQUICMuxAcquireRacingCloseInvalidatesRaw(t *testing.T) {
	raw := &muxLifecycleSession{receive: make(chan []byte)}
	backend := &blockedMuxLifecycleBackend{raw: raw, entered: make(chan struct{}), release: make(chan struct{})}
	muxBackend := &quicMuxBackend{
		backend:          backend,
		auth:             func(context.Context, carrier.QuicSession) (wire.AuthFrame, error) { return wire.AuthFrame{1}, nil },
		maxUDPQueueBytes: 64,
		maxPendingCloses: 4,
		sessions:         make(map[carrier.QuicSession]*quicSessionMux),
	}

	acquired := make(chan error, 1)
	go func() {
		_, err := muxBackend.AcquireSession(context.Background())
		acquired <- err
	}()
	select {
	case <-backend.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("acquire never reached the host backend")
	}
	if err := muxBackend.Close(); err != nil {
		t.Fatal(err)
	}
	// The session handed out after the gate closed is invalidated, not retained.
	close(backend.release)
	select {
	case err := <-acquired:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("AcquireSession racing Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acquire did not observe the drain token")
	}
	if got := backend.invalidations.Load(); got != 1 {
		t.Fatalf("backend invalidations = %d, want 1", got)
	}
	if got := len(muxBackend.sessions); got != 0 {
		t.Fatalf("sessions after racing acquire = %d, want 0", got)
	}
}

func TestQUICMuxStartReceiveLoopAfterCloseDoesNotPanic(t *testing.T) {
	for i := 0; i < 200; i++ {
		raw := &muxLifecycleSession{receive: make(chan []byte)}
		backend := &muxLifecycleBackend{}
		muxBackend := &quicMuxBackend{
			backend:          backend,
			auth:             func(context.Context, carrier.QuicSession) (wire.AuthFrame, error) { return wire.AuthFrame{1}, nil },
			maxUDPQueueBytes: 64,
			maxPendingCloses: 4,
			sessions:         make(map[carrier.QuicSession]*quicSessionMux),
		}
		session, err := newQUICSessionMux(muxBackend, raw, wire.AuthFrame{1})
		if err != nil {
			t.Fatal(err)
		}
		muxBackend.sessions[raw] = session
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			session.close(net.ErrClosed)
		}()
		go func() {
			defer wg.Done()
			session.startReceiveLoop()
		}()
		wg.Wait()
		select {
		case <-session.loopDone:
		case <-time.After(2 * time.Second):
			t.Fatal("loopDone did not close")
		}
		select {
		case <-session.sendLoopDone:
		case <-time.After(2 * time.Second):
			t.Fatal("sendLoopDone did not close")
		}
	}
}

func TestQUICMuxDropsDataBeforeReadyAndReleasesOnClose(t *testing.T) {
	session := newTestQUICSessionMux(t, 64, 4)
	flow, err := session.register(1)
	if err != nil {
		t.Fatal(err)
	}
	session.deliver(1, []byte("before-ready"))
	if got := len(flow.packets); got != 0 {
		t.Fatalf("packets before READY = %d, want 0", got)
	}
	if got := session.budget.used; got != 0 {
		t.Fatalf("budget before READY = %d, want 0", got)
	}

	if !flow.markReady() {
		t.Fatal("failed to mark flow READY")
	}
	session.deliver(1, []byte("ready"))
	if got := len(flow.packets); got != 1 {
		t.Fatalf("packets after READY = %d, want 1", got)
	}
	if got := session.budget.used; got != len("ready") {
		t.Fatalf("budget after enqueue = %d, want %d", got, len("ready"))
	}
	session.close(net.ErrClosed)
	if got := session.budget.used; got != 0 {
		t.Fatalf("budget after shutdown = %d, want 0", got)
	}
}

func TestPreparedQUICDatagramsActivateOnlyAfterREADY(t *testing.T) {
	session := newTestQUICSessionMux(t, 64, 4)
	prep := &quicPreparedStream{session: session, id: 9}
	prepared, err := prepareQUICDatagrams(prep, 9)
	if err != nil {
		t.Fatal(err)
	}
	flow := session.flows[9]
	if flow == nil || flow.ready() {
		t.Fatalf("prepared flow = %v ready=%t", flow, flow != nil && flow.ready())
	}
	session.deliver(9, []byte("before-ready"))
	if got := len(flow.packets); got != 0 {
		t.Fatalf("packets before READY = %d", got)
	}
	handle, err := prepared.Activate()
	if err != nil {
		t.Fatal(err)
	}
	if !flow.ready() || handle.flow != flow || handle.flowID != 9 {
		t.Fatalf("activated handle = %+v ready=%t", handle, flow.ready())
	}
	session.deliver(9, []byte("ready"))
	if got := len(flow.packets); got != 1 {
		t.Fatalf("packets after READY = %d", got)
	}
	if err := handle.closePacket(); err != nil {
		t.Fatal(err)
	}
}

func TestAbandonedPreparedQUICDatagramsDoNotQueueClose(t *testing.T) {
	session := newTestQUICSessionMux(t, 64, 4)
	prep := &quicPreparedStream{session: session, id: 11}
	prepared, err := prepareQUICDatagrams(prep, 11)
	if err != nil {
		t.Fatal(err)
	}
	if session.flows[11] == nil {
		t.Fatal("flow was not registered during preparation")
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if session.flows[11] != nil {
		t.Fatal("abandoned registration was not removed")
	}
	if got := len(session.closeQueue); got != 0 {
		t.Fatalf("abandoned registration queued %d CLOSE frames", got)
	}
}

func TestCancelledUDPSetupRemovesTentativeRoute(t *testing.T) {
	session := newTestQUICSessionMux(t, 64, 4)
	prep := &quicPreparedStream{session: session, id: 7}
	prepared, err := prepareQUICDatagrams(prep, 7)
	if err != nil {
		t.Fatal(err)
	}
	if session.flows[7] == nil {
		t.Fatal("flow was not registered during preparation")
	}

	// The setup is cancelled before the FlowHeader is committed, so the
	// tentative registration is released (upstream 6ebfebb).
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if session.flows[7] != nil {
		t.Fatal("cancelled UDP setup left a tentative route behind")
	}
}

func TestStaleUDPSetupDoesNotRemoveReusedFlowID(t *testing.T) {
	session := newTestQUICSessionMux(t, 64, 4)
	stalePrep := &quicPreparedStream{session: session, id: 7}
	stale, err := prepareQUICDatagrams(stalePrep, 7)
	if err != nil {
		t.Fatal(err)
	}
	staleFlow := stale.flow
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}

	// A later attempt takes the same flow id over.
	current, err := prepareQUICDatagrams(&quicPreparedStream{session: session, id: 7}, 7)
	if err != nil {
		t.Fatal(err)
	}
	if session.flows[7] != current.flow {
		t.Fatal("reused flow id was not registered")
	}

	// The abandoned attempt finishes late; it must not drop the live route.
	session.unregister(7, staleFlow, net.ErrClosed)
	if session.flows[7] != current.flow {
		t.Fatal("stale UDP setup removed the reused flow id")
	}

	if err := current.Close(); err != nil {
		t.Fatal(err)
	}
	if session.flows[7] != nil {
		t.Fatal("current registration was not removed")
	}
}

func TestCommittedUDPSetupOutlivesSetupGuard(t *testing.T) {
	session := newTestQUICSessionMux(t, 64, 4)
	prep := &quicPreparedStream{session: session, id: 7}
	prepared, err := prepareQUICDatagrams(prep, 7)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := prepared.Activate()
	if err != nil {
		t.Fatal(err)
	}

	// A late abandon on the setup guard must not drop the committed route.
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if session.flows[7] != handle.flow {
		t.Fatal("committed UDP route was dropped by its setup guard")
	}
	if !handle.flow.ready() {
		t.Fatal("committed UDP route is not READY")
	}

	if err := handle.closePacket(); err != nil {
		t.Fatal(err)
	}
	if session.flows[7] != nil {
		t.Fatal("closed UDP route was not removed")
	}
}

// pipePreparedStream commits setup bytes onto a pipe whose peer never answers
// with a SetupResult, which is how a stalled or cancelled Portal dial looks.
type pipePreparedStream struct {
	conn net.Conn
}

func (p *pipePreparedStream) Commit(_ context.Context, setup []byte, _ bool) (net.Conn, error) {
	if _, err := p.conn.Write(setup); err != nil {
		return nil, err
	}
	return p.conn, nil
}

func (p *pipePreparedStream) Close() error { return p.conn.Close() }

func TestCancelledUDPCommitReleasesTentativeRoute(t *testing.T) {
	session := newTestQUICSessionMux(t, 64, 4)
	server, client := net.Pipe()
	// The peer reads the opening setup and then abandons the control stream,
	// so the client observes a failed setup instead of READY.
	aborted := make(chan struct{})
	go func() {
		defer close(aborted)
		buf := make([]byte, 4096)
		if _, err := server.Read(buf); err != nil {
			return
		}
		_ = server.Close()
	}()
	defer func() {
		<-aborted
	}()
	prep := &quicPreparedStream{
		session: session,
		stream:  &pipePreparedStream{conn: client},
		id:      7,
	}
	lanes := &preparedLanes{up: &physicalLane{carrier: wire.CarrierQUIC, quic: prep}}
	route := resolvedRoute{uplink: wire.CarrierQUIC, downlink: wire.CarrierQUIC}
	if err := lanes.prepareUDPDownlink(wire.FlowKindUDP, route, 7); err != nil {
		t.Fatal(err)
	}
	if session.flows[7] == nil {
		t.Fatal("flow was not registered during preparation")
	}

	// The peer abandons the control stream before answering, so the commit
	// fails and the caller releases the prepared lanes.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target, err := wire.NewDomainTarget("example.com", 53)
	if err != nil {
		t.Fatal(err)
	}
	b := &CarrierBundle{}
	if _, err := b.commitUDPRoute(ctx, lanes, route, 7, target, 0); err == nil {
		t.Fatal("commitUDPRoute succeeded without a SetupResult")
	}
	if err := lanes.Close(); err != nil {
		t.Fatal(err)
	}
	if session.flows[7] != nil {
		t.Fatal("cancelled UDP commit left a tentative route behind")
	}
	if got := len(session.closeQueue); got != 0 {
		t.Fatalf("cancelled UDP commit queued %d CLOSE frames", got)
	}
}

func TestQUICMuxFragmentReservationReleasedOnShutdown(t *testing.T) {
	session := newTestQUICSessionMux(t, 64, 4)
	flow, err := session.register(1)
	if err != nil {
		t.Fatal(err)
	}
	flow.markReady()
	session.handleFragment(1, wire.UDPFragment{
		PacketID: 1, FragmentIndex: 0, FragmentCount: 2,
		TotalLen: 10, Payload: []byte("12345"),
	})
	if got := session.budget.used; got != 10 {
		t.Fatalf("fragment reservation = %d, want 10", got)
	}
	session.close(net.ErrClosed)
	if got := session.budget.used; got != 0 {
		t.Fatalf("fragment reservation after shutdown = %d, want 0", got)
	}
}

func TestQUICMuxPendingCloseDeduplicatesAndInvalidatesAtLimit(t *testing.T) {
	raw := &muxLifecycleSession{}
	backend := &muxLifecycleBackend{}
	reassembler, err := wire.NewDatagramReassembler(wire.DefaultReassemblyConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	muxBackend := &quicMuxBackend{
		backend:  backend,
		sessions: make(map[carrier.QuicSession]*quicSessionMux),
	}
	session := &quicSessionMux{
		backend:          muxBackend,
		raw:              raw,
		ctx:              ctx,
		cancel:           cancel,
		authDone:         make(chan struct{}),
		flows:            make(map[wire.FlowID]*quicDatagramFlow),
		reassembler:      reassembler,
		budget:           &quicByteBudget{limit: 64},
		closeSet:         make(map[wire.FlowID]struct{}),
		maxPendingCloses: 1,
		invalidationDone: make(chan struct{}),
		done:             make(chan struct{}),
		loopDone:         make(chan struct{}),
		sendQueue:        make(chan *quicSendRequest, 1),
		closeReady:       make(chan struct{}, 1),
		sendLoopDone:     make(chan struct{}),
	}
	muxBackend.sessions[raw] = session

	if err := session.enqueueClose(1); err != nil {
		t.Fatal(err)
	}
	if err := session.enqueueClose(1); err != nil {
		t.Fatal(err)
	}
	if got := len(session.closeQueue); got != 1 {
		t.Fatalf("deduplicated CLOSE queue length = %d, want 1", got)
	}
	if err := session.enqueueClose(2); !errors.Is(err, ErrPendingCloseLimit) {
		t.Fatalf("overflow error = %v, want ErrPendingCloseLimit", err)
	}
	if got := backend.invalidations.Load(); got != 1 {
		t.Fatalf("backend invalidations = %d, want 1", got)
	}
	select {
	case <-session.done:
	default:
		t.Fatal("pending CLOSE overflow did not shut down session")
	}
}

func TestQUICMuxConcurrentDuplicateRegistration(t *testing.T) {
	session := newTestQUICSessionMux(t, 64, 4)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := session.register(1); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful duplicate registrations = %d, want 1", got)
	}
	session.close(net.ErrClosed)
}

func newTestQUICSessionMux(t *testing.T, budget, closeLimit int) *quicSessionMux {
	t.Helper()
	raw := &muxLifecycleSession{receive: make(chan []byte)}
	backend := &quicMuxBackend{
		backend:          &muxLifecycleBackend{},
		maxUDPQueueBytes: budget,
		maxPendingCloses: closeLimit,
		sessions:         make(map[carrier.QuicSession]*quicSessionMux),
	}
	session, err := newQUICSessionMux(backend, raw, wire.AuthFrame{1})
	if err != nil {
		t.Fatal(err)
	}
	backend.sessions[raw] = session
	t.Cleanup(func() {
		session.close(net.ErrClosed)
		<-session.sendLoopDone
	})
	return session
}

type muxLifecycleBackend struct {
	invalidations atomic.Int32
	acquires      atomic.Int32
	acquire       func(context.Context) (carrier.QuicSession, error)
}

func (b *muxLifecycleBackend) AcquireSession(ctx context.Context) (carrier.QuicSession, error) {
	b.acquires.Add(1)
	if b.acquire != nil {
		return b.acquire(ctx)
	}
	return nil, errors.New("unused")
}

func (b *muxLifecycleBackend) InvalidateSession(carrier.QuicSession) {
	b.invalidations.Add(1)
}
func (*muxLifecycleBackend) Close() error { return nil }

// blockedMuxLifecycleBackend parks an acquire until release closes, which is
// how a test drives a close that races an in-flight acquire.
type blockedMuxLifecycleBackend struct {
	muxLifecycleBackend
	raw     *muxLifecycleSession
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockedMuxLifecycleBackend) AcquireSession(ctx context.Context) (carrier.QuicSession, error) {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return b.raw, nil
}

type muxLifecycleSession struct {
	receive chan []byte
	fail    chan struct{}
	send    func([]byte) error
	prepare func(context.Context) (carrier.QuicPreparedStream, error)
}

func (*muxLifecycleSession) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	return wire.TLSHandshakeInfo{TLSVersion: 0x0304, NegotiatedALPN: wire.DefaultALPN}, nil
}

func (s *muxLifecycleSession) PrepareStream(ctx context.Context) (carrier.QuicPreparedStream, error) {
	if s.prepare != nil {
		return s.prepare(ctx)
	}
	return nil, errors.New("unused")
}

func (s *muxLifecycleSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if s.fail != nil {
		select {
		case <-s.fail:
			return nil, net.ErrClosed
		default:
		}
	}
	if s.receive == nil {
		if s.fail != nil {
			select {
			case <-s.fail:
				return nil, net.ErrClosed
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	select {
	case data := <-s.receive:
		return data, nil
	case <-s.fail:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*muxLifecycleSession) CurrentMaxDatagramSize() int { return 1200 }
func (s *muxLifecycleSession) SendDatagram(ctx context.Context, payload []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		if s.send != nil {
			return s.send(payload)
		}
		return nil
	}
}
func (*muxLifecycleSession) LocalAddr() net.Addr { return &net.UDPAddr{} }
