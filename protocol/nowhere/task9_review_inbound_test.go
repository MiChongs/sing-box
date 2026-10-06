package nowhere

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	nwserver "github.com/sagernet/sing-box/protocol/nowhere/core/server"
	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
	"github.com/sagernet/sing-box/protocol/nowhere/server"
)

func TestInboundConcurrentCloseSharesCleanupAndResult(t *testing.T) {
	wantErr := errors.New("test: listener close")
	phase := newTask9ClosePhase(wantErr, true)
	inbound := &Inbound{
		config:   task9ShutdownConfig(t, time.Second),
		listener: &task9InboundListener{closePhase: phase},
	}

	const callers = 8
	start := make(chan struct{})
	results := make(chan error, callers)
	for range callers {
		go func() {
			<-start
			results <- inbound.Close()
		}()
	}
	close(start)
	phase.waitEntered(t)
	if phase.calls.Load() != 1 {
		t.Fatalf("listener Close calls = %d, want 1", phase.calls.Load())
	}
	select {
	case err := <-results:
		t.Fatalf("Close returned before shared cleanup completed: %v", err)
	default:
	}
	phase.release()
	for range callers {
		select {
		case err := <-results:
			if !errors.Is(err, wantErr) {
				t.Fatalf("Close error = %v, want %v", err, wantErr)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent Close did not receive shared result")
		}
	}
	waitTask9InboundCleanup(t, inbound)
	if phase.calls.Load() != 1 {
		t.Fatalf("listener Close calls after join = %d, want 1", phase.calls.Load())
	}
}

func TestInboundShutdownDeadlineOwnsAndJoinsPhaseWorkers(t *testing.T) {
	for _, phaseName := range []string{"listener", "quic", "tls"} {
		t.Run(phaseName, func(t *testing.T) {
			phase := newTask9ClosePhase(nil, true)
			inbound := &Inbound{config: task9ShutdownConfig(t, time.Second)}
			switch phaseName {
			case "listener":
				inbound.listener = &task9InboundListener{closePhase: phase}
			case "quic":
				inbound.quicServer = &task9InboundQUICServer{closePhase: phase}
			case "tls":
				inbound.tlsConfig = &task9InboundTLS{closePhase: phase}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- inbound.shutdown(ctx) }()
			phase.waitEntered(t)
			select {
			case err := <-result:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("shutdown error = %v, want deadline exceeded", err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("shutdown did not honor caller deadline")
			}
			select {
			case <-inbound.shutdownCoordinator.cleanupDoneForTest():
				t.Fatal("cleanup joined before blocked phase was released")
			default:
			}
			phase.release()
			waitTask9InboundCleanup(t, inbound)
			if phase.calls.Load() != 1 {
				t.Fatalf("%s Close calls = %d, want 1", phaseName, phase.calls.Load())
			}
		})
	}
}

func TestInboundShutdownAggregatesPhaseErrors(t *testing.T) {
	listenerErr := errors.New("test: listener")
	quicErr := errors.New("test: quic")
	tlsErr := errors.New("test: tls")
	inbound := &Inbound{
		config:     task9ShutdownConfig(t, time.Second),
		listener:   &task9InboundListener{closePhase: newTask9ClosePhase(listenerErr, false)},
		quicServer: &task9InboundQUICServer{closePhase: newTask9ClosePhase(quicErr, false)},
		tlsConfig:  &task9InboundTLS{closePhase: newTask9ClosePhase(tlsErr, false)},
	}

	err := inbound.Close()
	for _, wantErr := range []error{listenerErr, quicErr, tlsErr} {
		if !errors.Is(err, wantErr) {
			t.Fatalf("Close error = %v, missing %v", err, wantErr)
		}
	}
	waitTask9InboundCleanup(t, inbound)
}

func TestInboundShutdownDeadlinePrioritizesContextAndKeepsCompletedErrors(t *testing.T) {
	wantErr := errors.New("test: listener close")
	listenerPhase := newTask9ClosePhase(wantErr, false)
	tlsPhase := newTask9ClosePhase(nil, true)
	inbound := &Inbound{
		config:    task9ShutdownConfig(t, time.Second),
		listener:  &task9InboundListener{closePhase: listenerPhase},
		tlsConfig: &task9InboundTLS{closePhase: tlsPhase},
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- inbound.shutdown(ctx) }()
	listenerPhase.waitFinished(t)
	select {
	case <-inbound.shutdownCoordinator.phaseObservedForTest():
	case <-time.After(time.Second):
		t.Fatal("coordinator did not observe completed listener close")
	}
	tlsPhase.waitEntered(t)
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, wantErr) {
			t.Fatalf("shutdown error = %v, want context cancellation and %v", err, wantErr)
		}
		if !strings.HasPrefix(err.Error(), context.Canceled.Error()) {
			t.Fatalf("shutdown error priority = %q, want context cancellation first", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not return after cancellation")
	}
	select {
	case <-inbound.shutdownCoordinator.cleanupDoneForTest():
		t.Fatal("cleanup joined before blocked TLS close was released")
	default:
	}
	tlsPhase.release()
	waitTask9InboundCleanup(t, inbound)
}

func TestInboundShutdownCanceledBeforeStartDoesNotSpawnWorkers(t *testing.T) {
	listenerPhase := newTask9ClosePhase(nil, false)
	quicPhase := newTask9ClosePhase(nil, false)
	tlsPhase := newTask9ClosePhase(nil, false)
	inbound := &Inbound{
		config:     task9ShutdownConfig(t, time.Second),
		listener:   &task9InboundListener{closePhase: listenerPhase},
		quicServer: &task9InboundQUICServer{closePhase: quicPhase},
		tlsConfig:  &task9InboundTLS{closePhase: tlsPhase},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := inbound.shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown error = %v, want context.Canceled", err)
	}
	waitTask9InboundCleanup(t, inbound)
	for name, phase := range map[string]*task9ClosePhase{
		"listener": listenerPhase,
		"quic":     quicPhase,
		"tls":      tlsPhase,
	} {
		if calls := phase.calls.Load(); calls != 0 {
			t.Fatalf("%s phase calls = %d, want 0", name, calls)
		}
	}
}

func TestInboundLifecycleIOOutsideMutex(t *testing.T) {
	t.Run("start", func(t *testing.T) {
		startPhase := newTask9ClosePhase(nil, true)
		tlsConfig := &task9InboundTLS{startPhase: startPhase, closePhase: newTask9ClosePhase(nil, false)}
		inbound := &Inbound{config: task9ShutdownConfig(t, time.Second), tlsConfig: tlsConfig}
		startResult := make(chan error, 1)
		go func() { startResult <- inbound.Start(adapter.StartStateStart, nil) }()
		startPhase.waitEntered(t)

		assertTask9ShutdownNotBlockedByLifecycleMutex(t, inbound)
		startPhase.release()
		select {
		case <-startResult:
		case <-time.After(time.Second):
			t.Fatal("Start did not finish")
		}
		waitTask9InboundCleanup(t, inbound)
	})

	t.Run("restart", func(t *testing.T) {
		restartPhase := newTask9ClosePhase(nil, true)
		quicServer := &task9InboundQUICServer{restartPhase: restartPhase, closePhase: newTask9ClosePhase(nil, false)}
		inbound := &Inbound{
			config:     task9ShutdownConfig(t, time.Second),
			listener:   &task9InboundListener{},
			quicServer: quicServer,
			enableUDP:  true,
			started:    true,
		}
		restartDone := make(chan struct{})
		go func() {
			inbound.InterfaceUpdated(context.Background())
			close(restartDone)
		}()
		restartPhase.waitEntered(t)

		assertTask9ShutdownNotBlockedByLifecycleMutex(t, inbound)
		restartPhase.release()
		select {
		case <-restartDone:
		case <-time.After(time.Second):
			t.Fatal("InterfaceUpdated did not finish")
		}
		waitTask9InboundCleanup(t, inbound)
	})
}

func assertTask9ShutdownNotBlockedByLifecycleMutex(t *testing.T, inbound *Inbound) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- inbound.shutdown(ctx) }()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shutdown error = %v, want deadline exceeded", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("shutdown was blocked by lifecycle mutex held across I/O")
	}
}

func task9ShutdownConfig(t *testing.T, timeout time.Duration) *server.Config {
	t.Helper()
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	config, err := nwserver.NewConfig(nwserver.ConfigOptions{
		Credentials: credentials,
		Networks:    []nwserver.Network{nwserver.NetworkTCP},
		Timeouts:    nwserver.Timeouts{Shutdown: timeout},
	})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func waitTask9InboundCleanup(t *testing.T, inbound *Inbound) {
	t.Helper()
	select {
	case <-inbound.shutdownCoordinator.cleanupDoneForTest():
	case <-time.After(time.Second):
		t.Fatal("inbound cleanup workers were not joined")
	}
}

type task9ClosePhase struct {
	entered      chan struct{}
	enteredOnce  sync.Once
	finished     chan struct{}
	finishedOnce sync.Once
	releaseCh    chan struct{}
	releaseOnce  sync.Once
	err          error
	calls        atomic.Int32
}

func newTask9ClosePhase(err error, blocked bool) *task9ClosePhase {
	phase := &task9ClosePhase{entered: make(chan struct{}), finished: make(chan struct{}), err: err}
	if blocked {
		phase.releaseCh = make(chan struct{})
	}
	return phase
}

func (p *task9ClosePhase) run() error {
	p.calls.Add(1)
	p.enteredOnce.Do(func() { close(p.entered) })
	if p.releaseCh != nil {
		<-p.releaseCh
	}
	p.finishedOnce.Do(func() { close(p.finished) })
	return p.err
}

func (p *task9ClosePhase) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-p.entered:
	case <-time.After(time.Second):
		t.Fatal("phase did not enter")
	}
}

func (p *task9ClosePhase) waitFinished(t *testing.T) {
	t.Helper()
	select {
	case <-p.finished:
	case <-time.After(time.Second):
		t.Fatal("phase did not finish")
	}
}

func (p *task9ClosePhase) release() {
	if p.releaseCh != nil {
		p.releaseOnce.Do(func() { close(p.releaseCh) })
	}
}

type task9InboundListener struct {
	startPhase *task9ClosePhase
	closePhase *task9ClosePhase
}

func (l *task9InboundListener) Start() error {
	if l.startPhase != nil {
		return l.startPhase.run()
	}
	return nil
}

func (*task9InboundListener) ListenUDP() (net.PacketConn, error) {
	return &task9ReviewPacketConn{}, nil
}

func (l *task9InboundListener) Close() error {
	if l.closePhase != nil {
		return l.closePhase.run()
	}
	return nil
}

type task9InboundQUICServer struct {
	restartPhase *task9ClosePhase
	closePhase   *task9ClosePhase
}

func (*task9InboundQUICServer) Start(net.PacketConn) error { return nil }
func (s *task9InboundQUICServer) Restart(func() (net.PacketConn, error)) error {
	if s.restartPhase != nil {
		return s.restartPhase.run()
	}
	return nil
}

func (s *task9InboundQUICServer) Close() error {
	if s.closePhase != nil {
		return s.closePhase.run()
	}
	return nil
}

type task9InboundTLS struct {
	boxTLS.ServerConfig
	startPhase *task9ClosePhase
	closePhase *task9ClosePhase
}

func (c *task9InboundTLS) Start() error {
	if c.startPhase != nil {
		return c.startPhase.run()
	}
	return nil
}

func (c *task9InboundTLS) Close() error {
	if c.closePhase != nil {
		return c.closePhase.run()
	}
	return nil
}

type task9ReviewPacketConn struct{}

func (*task9ReviewPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (*task9ReviewPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return len(payload), nil
}
func (*task9ReviewPacketConn) Close() error                     { return nil }
func (*task9ReviewPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*task9ReviewPacketConn) SetDeadline(time.Time) error      { return nil }
func (*task9ReviewPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*task9ReviewPacketConn) SetWriteDeadline(time.Time) error { return nil }
