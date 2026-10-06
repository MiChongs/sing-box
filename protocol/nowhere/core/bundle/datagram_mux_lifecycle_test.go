package bundle

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
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

func TestQUICMuxAcquireAfterCloseInvalidatesRaw(t *testing.T) {
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
	if _, err := muxBackend.AcquireSession(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("AcquireSession after Close = %v, want net.ErrClosed", err)
	}
	if got := backend.invalidations.Load(); got != 1 {
		t.Fatalf("backend invalidations = %d, want 1", got)
	}
	if got := len(muxBackend.sessions); got != 0 {
		t.Fatalf("sessions after closed acquire = %d, want 0", got)
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
	acquire       func(context.Context) (carrier.QuicSession, error)
}

func (b *muxLifecycleBackend) AcquireSession(ctx context.Context) (carrier.QuicSession, error) {
	if b.acquire != nil {
		return b.acquire(ctx)
	}
	return nil, errors.New("unused")
}

func (b *muxLifecycleBackend) InvalidateSession(carrier.QuicSession) {
	b.invalidations.Add(1)
}
func (*muxLifecycleBackend) Close() error { return nil }

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
