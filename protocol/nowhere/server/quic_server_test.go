//go:build with_quic

package server

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
	qtls "github.com/sagernet/sing-quic"
)

func TestQUICServerLifecycle(t *testing.T) {
	server, factory := newTestQUICServer(nil)
	firstPacket := &fakePacketConn{}
	if err := server.Start(firstPacket); err != nil {
		t.Fatal(err)
	}
	firstRuntime := factory.runtime(t, 0)
	firstRuntime.waitAccept(t)

	secondPacket := &fakePacketConn{}
	if err := server.Start(secondPacket); !errors.Is(err, errQUICServerStarted) {
		t.Fatalf("second Start error = %v, want %v", err, errQUICServerStarted)
	}
	if secondPacket.closeCalls.Load() != 1 {
		t.Fatalf("rejected packet close calls = %d, want 1", secondPacket.closeCalls.Load())
	}

	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	firstRuntime.assertClosedOnce(t)
	if firstPacket.closeCalls.Load() != 1 {
		t.Fatalf("owned packet close calls = %d, want 1", firstPacket.closeCalls.Load())
	}

	afterClose := &fakePacketConn{}
	if err := server.Start(afterClose); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Start after Close error = %v, want net.ErrClosed", err)
	}
	if afterClose.closeCalls.Load() != 1 {
		t.Fatalf("packet passed after Close was closed %d times", afterClose.closeCalls.Load())
	}
	if err := server.Restart(func() (net.PacketConn, error) { return &fakePacketConn{}, nil }); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Restart after Close error = %v, want net.ErrClosed", err)
	}
}

func TestQUICServerRestartRebindsAfterOldRuntimeStops(t *testing.T) {
	server, factory := newTestQUICServer(nil)
	firstPacket := &fakePacketConn{}
	if err := server.Start(firstPacket); err != nil {
		t.Fatal(err)
	}
	firstRuntime := factory.runtime(t, 0)
	firstRuntime.waitAccept(t)

	secondPacket := &fakePacketConn{}
	if err := server.Restart(func() (net.PacketConn, error) {
		firstRuntime.assertClosedOnce(t)
		if firstPacket.closeCalls.Load() != 1 {
			t.Fatalf("old packet still open during rebind")
		}
		return secondPacket, nil
	}); err != nil {
		t.Fatal(err)
	}
	secondRuntime := factory.runtime(t, 1)
	secondRuntime.waitAccept(t)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	secondRuntime.assertClosedOnce(t)
	if secondPacket.closeCalls.Load() != 1 {
		t.Fatalf("replacement packet close calls = %d, want 1", secondPacket.closeCalls.Load())
	}
}

func TestQUICServerRestartFailureLeavesRetryableIdleState(t *testing.T) {
	server, factory := newTestQUICServer(nil)
	if err := server.Start(&fakePacketConn{}); err != nil {
		t.Fatal(err)
	}
	factory.runtime(t, 0).waitAccept(t)
	wantErr := errors.New("rebind failed")
	if err := server.Restart(func() (net.PacketConn, error) { return nil, wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("Restart error = %v, want %v", err, wantErr)
	}

	retryPacket := &fakePacketConn{}
	if err := server.Restart(func() (net.PacketConn, error) { return retryPacket, nil }); err != nil {
		t.Fatalf("retry Restart: %v", err)
	}
	factory.runtime(t, 1).waitAccept(t)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestQUICServerListenFailureClosesPacketExactlyOnce(t *testing.T) {
	wantErr := errors.New("listen failed")
	server, factory := newTestQUICServer(nil)
	factory.failNext = wantErr
	packetConn := &fakePacketConn{}
	if err := server.Start(packetConn); !errors.Is(err, wantErr) {
		t.Fatalf("Start error = %v, want %v", err, wantErr)
	}
	if packetConn.closeCalls.Load() != 1 {
		t.Fatalf("failed packet close calls = %d, want 1", packetConn.closeCalls.Load())
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestQUICServerAcceptErrorEmitsObserverEvent(t *testing.T) {
	wantErr := errors.New("accept failed")
	events := make(chan diagnostic.Event, 1)
	server, factory := newTestQUICServer(diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
		events <- event
	}))
	factory.acceptErr = wantErr
	if err := server.Start(&fakePacketConn{}); err != nil {
		t.Fatal(err)
	}

	select {
	case event := <-events:
		if event.Code != "quic_accept_failed" || !errors.Is(event.Err, wantErr) {
			t.Fatalf("unexpected event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("accept failure was not observed")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestQUICServerAcceptFailureRecoversToIdleState(t *testing.T) {
	wantErr := errors.New("accept failed")
	events := make(chan diagnostic.Event, 1)
	server, factory := newTestQUICServer(diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
		if event.Code == "quic_accept_failed" {
			events <- event
		}
	}))
	factory.acceptErr = wantErr
	firstPacket := &fakePacketConn{}
	if err := server.Start(firstPacket); err != nil {
		t.Fatal(err)
	}

	select {
	case event := <-events:
		if !errors.Is(event.Err, wantErr) {
			t.Fatalf("unexpected event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("accept failure was not observed")
	}

	// Wait for the accept loop goroutine to finish updating state.
	var state quicServerState
	var current *quicServerRun
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		server.mu.Lock()
		state, current = server.state, server.current
		server.mu.Unlock()
		if state == quicServerIdle && current == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if state != quicServerIdle || current != nil {
		t.Fatalf("after accept failure state=%d current=%v, want idle/nil", state, current != nil)
	}
	if firstPacket.closeCalls.Load() != 1 {
		t.Fatalf("failed runtime packet close calls = %d, want 1", firstPacket.closeCalls.Load())
	}

	secondPacket := &fakePacketConn{}
	if err := server.Start(secondPacket); err != nil {
		t.Fatalf("restart Start after accept failure: %v", err)
	}
	runtime1 := factory.runtime(t, 1)
	runtime1.waitAccept(t)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	runtime1.assertClosedOnce(t)
	if secondPacket.closeCalls.Load() != 1 {
		t.Fatalf("second packet close calls = %d, want 1", secondPacket.closeCalls.Load())
	}
}

func TestQUICServerCloseSuppressesExpectedAcceptError(t *testing.T) {
	events := make(chan diagnostic.Event, 1)
	server, factory := newTestQUICServer(diagnostic.ObserverFunc(func(_ context.Context, event diagnostic.Event) {
		events <- event
	}))
	if err := server.Start(&fakePacketConn{}); err != nil {
		t.Fatal(err)
	}
	factory.runtime(t, 0).waitAccept(t)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		t.Fatalf("expected close emitted event: %+v", event)
	default:
	}
}

func TestQUICServerConcurrentCloseAndRestart(t *testing.T) {
	for iteration := 0; iteration < 50; iteration++ {
		server, factory := newTestQUICServer(nil)
		if err := server.Start(&fakePacketConn{}); err != nil {
			t.Fatal(err)
		}
		factory.runtime(t, 0).waitAccept(t)
		barrier := make(chan struct{})
		var restartErr error
		var closeErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-barrier
			restartErr = server.Restart(func() (net.PacketConn, error) { return &fakePacketConn{}, nil })
		}()
		go func() {
			defer wg.Done()
			<-barrier
			closeErr = server.Close()
		}()
		close(barrier)
		wg.Wait()
		if restartErr != nil && !errors.Is(restartErr, net.ErrClosed) {
			t.Fatalf("iteration %d Restart: %v", iteration, restartErr)
		}
		if closeErr != nil {
			t.Fatalf("iteration %d Close: %v", iteration, closeErr)
		}
		if err := server.Close(); err != nil {
			t.Fatalf("iteration %d final Close: %v", iteration, err)
		}
		server.mu.Lock()
		state, current := server.state, server.current
		server.mu.Unlock()
		if state != quicServerClosed || current != nil {
			t.Fatalf("iteration %d final state=%d current=%v", iteration, state, current != nil)
		}
	}
}

func newTestQUICServer(observer diagnostic.Observer) (*QUICServer, *fakeRuntimeFactory) {
	factory := &fakeRuntimeFactory{}
	server := &QUICServer{ctx: context.Background(), observer: observer, listenFn: factory.listen}
	return server, factory
}

type fakeRuntimeFactory struct {
	mu        sync.Mutex
	runtimes  []*fakeRuntime
	failNext  error
	acceptErr error
}

func (f *fakeRuntimeFactory) listen(packetConn net.PacketConn) (qtls.Listener, io.Closer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	transport := &fakeTransport{packetConn: packetConn}
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return nil, transport, err
	}
	runtime := newFakeRuntime(transport, f.acceptErr)
	f.runtimes = append(f.runtimes, runtime)
	return runtime.listener, runtime.transport, nil
}

func (f *fakeRuntimeFactory) runtime(t *testing.T, index int) *fakeRuntime {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if index >= len(f.runtimes) {
		t.Fatalf("runtime %d not created; count=%d", index, len(f.runtimes))
	}
	return f.runtimes[index]
}

type fakeRuntime struct {
	listener  *fakeQUICListener
	transport *fakeTransport
}

func newFakeRuntime(transport *fakeTransport, acceptErr error) *fakeRuntime {
	return &fakeRuntime{
		listener: &fakeQUICListener{
			closed: make(chan struct{}), acceptStarted: make(chan struct{}), acceptErr: acceptErr,
		},
		transport: transport,
	}
}

func (r *fakeRuntime) waitAccept(t *testing.T) {
	t.Helper()
	select {
	case <-r.listener.acceptStarted:
	case <-time.After(time.Second):
		t.Fatal("accept loop did not start")
	}
}

func (r *fakeRuntime) assertClosedOnce(t *testing.T) {
	t.Helper()
	if r.listener.closeCalls.Load() != 1 || r.transport.closeCalls.Load() != 1 {
		t.Fatalf("runtime close calls listener=%d transport=%d, want 1/1", r.listener.closeCalls.Load(), r.transport.closeCalls.Load())
	}
}

type fakeQUICListener struct {
	closed        chan struct{}
	acceptStarted chan struct{}
	acceptOnce    sync.Once
	closeOnce     sync.Once
	closeCalls    atomic.Int32
	acceptErr     error
}

func (l *fakeQUICListener) Accept(ctx context.Context) (*quic.Conn, error) {
	l.acceptOnce.Do(func() { close(l.acceptStarted) })
	if l.acceptErr != nil {
		return nil, l.acceptErr
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *fakeQUICListener) Close() error {
	l.closeCalls.Add(1)
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (*fakeQUICListener) Addr() net.Addr { return &net.UDPAddr{} }

type fakeTransport struct {
	packetConn net.PacketConn
	closeCalls atomic.Int32
}

func (t *fakeTransport) Close() error {
	t.closeCalls.Add(1)
	return nil
}

type fakePacketConn struct {
	closeCalls atomic.Int32
}

func (*fakePacketConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, net.ErrClosed }
func (*fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *fakePacketConn) Close() error                            { c.closeCalls.Add(1); return nil }
func (*fakePacketConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (*fakePacketConn) SetDeadline(time.Time) error               { return nil }
func (*fakePacketConn) SetReadDeadline(time.Time) error           { return nil }
func (*fakePacketConn) SetWriteDeadline(time.Time) error          { return nil }

var (
	_ qtls.Listener  = (*fakeQUICListener)(nil)
	_ io.Closer      = (*fakeTransport)(nil)
	_ net.PacketConn = (*fakePacketConn)(nil)
)
