package nowhere

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxTLS "github.com/sagernet/sing-box/common/tls"
)

func TestInboundStartFlightSharesPhaseFailureAcrossCloseRace(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		build func(*task9RereviewStartStep) *Inbound
	}{
		{
			name: "tls",
			build: func(step *task9RereviewStartStep) *Inbound {
				return &Inbound{tlsConfig: &task9RereviewTLS{start: step.run}}
			},
		},
		{
			name: "listener",
			build: func(step *task9RereviewStartStep) *Inbound {
				return &Inbound{enableTCP: true, listener: &task9RereviewListener{start: step.run}}
			},
		},
		{
			name: "listen_udp",
			build: func(step *task9RereviewStartStep) *Inbound {
				return &Inbound{
					enableUDP:  true,
					listener:   &task9RereviewListener{listenUDP: step.runPacket},
					quicServer: &task9RereviewQUICServer{},
				}
			},
		},
		{
			name: "quic_start",
			build: func(step *task9RereviewStartStep) *Inbound {
				return &Inbound{
					enableUDP:  true,
					listener:   &task9RereviewListener{},
					quicServer: &task9RereviewQUICServer{start: step.runQUIC},
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			wantErr := errors.New("test: " + testCase.name + " start failure")
			step := newTask9RereviewStartStep(wantErr)
			inbound := testCase.build(step)
			inbound.config = task9ShutdownConfig(t, time.Second)

			const callers = 8
			results := launchTask9RereviewStartCallers(inbound, callers)
			step.waitEntered(t)
			yieldTask9RereviewCallers()

			closeResult := make(chan error, 1)
			go func() { closeResult <- inbound.Close() }()
			waitTask9RereviewInboundClosed(t, inbound)
			assertTask9RereviewNoStartResult(t, results)
			select {
			case err := <-closeResult:
				t.Fatalf("Close returned before blocked start flight completed: %v", err)
			default:
			}

			step.release()
			assertTask9RereviewStartResults(t, results, callers, wantErr)
			select {
			case err := <-closeResult:
				if err != nil {
					t.Fatalf("Close error = %v, want nil", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Close did not finish after start flight completed")
			}
			waitTask9InboundCleanup(t, inbound)
			if calls := step.calls.Load(); calls != 1 {
				t.Fatalf("start phase calls = %d, want 1", calls)
			}
		})
	}
}

func TestInboundStartFlightSeparatesAttempts(t *testing.T) {
	firstErr := errors.New("test: first start failure")
	secondErr := errors.New("test: second start failure")
	first := newTask9RereviewStartStep(firstErr)
	second := newTask9RereviewStartStep(secondErr)
	sequence := &task9RereviewStartSequence{steps: []*task9RereviewStartStep{first, second}}
	inbound := &Inbound{tlsConfig: &task9RereviewTLS{start: sequence.run}}

	const callers = 6
	firstResults := launchTask9RereviewStartCallers(inbound, callers)
	first.waitEntered(t)
	yieldTask9RereviewCallers()
	first.release()
	assertTask9RereviewStartResults(t, firstResults, callers, firstErr)

	secondResults := launchTask9RereviewStartCallers(inbound, callers)
	second.waitEntered(t)
	yieldTask9RereviewCallers()
	second.release()
	assertTask9RereviewStartResults(t, secondResults, callers, secondErr)

	if calls := sequence.calls.Load(); calls != 2 {
		t.Fatalf("start attempts = %d, want 2", calls)
	}
}

func launchTask9RereviewStartCallers(inbound *Inbound, callers int) <-chan error {
	ready := make(chan struct{})
	begin := make(chan struct{})
	results := make(chan error, callers)
	var readyWait sync.WaitGroup
	readyWait.Add(callers)
	for range callers {
		go func() {
			readyWait.Done()
			<-begin
			results <- inbound.Start(adapter.StartStateStart, nil)
		}()
	}
	go func() {
		readyWait.Wait()
		close(ready)
	}()
	<-ready
	close(begin)
	return results
}

func yieldTask9RereviewCallers() {
	for range 1024 {
		runtime.Gosched()
	}
}

func waitTask9RereviewInboundClosed(t *testing.T, inbound *Inbound) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		inbound.lifecycleMu.Lock()
		closed := inbound.closed
		inbound.lifecycleMu.Unlock()
		if closed {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("Close did not mark inbound closed")
}

func assertTask9RereviewNoStartResult(t *testing.T, results <-chan error) {
	t.Helper()
	select {
	case err := <-results:
		t.Fatalf("Start returned before blocked winning attempt completed: %v", err)
	default:
	}
}

func assertTask9RereviewStartResults(t *testing.T, results <-chan error, callers int, wantErr error) {
	t.Helper()
	for range callers {
		select {
		case err := <-results:
			if !errors.Is(err, wantErr) {
				t.Fatalf("Start error = %v, want shared flight error %v", err, wantErr)
			}
		case <-time.After(time.Second):
			t.Fatal("Start caller did not receive flight result")
		}
	}
}

type task9RereviewStartStep struct {
	entered     chan struct{}
	enteredOnce sync.Once
	releaseCh   chan struct{}
	releaseOnce sync.Once
	err         error
	calls       atomic.Int32
}

func newTask9RereviewStartStep(err error) *task9RereviewStartStep {
	return &task9RereviewStartStep{entered: make(chan struct{}), releaseCh: make(chan struct{}), err: err}
}

func (s *task9RereviewStartStep) run() error {
	s.calls.Add(1)
	s.enteredOnce.Do(func() { close(s.entered) })
	<-s.releaseCh
	return s.err
}

func (s *task9RereviewStartStep) runPacket() (net.PacketConn, error) {
	if err := s.run(); err != nil {
		return nil, err
	}
	return &task9ReviewPacketConn{}, nil
}

func (s *task9RereviewStartStep) runQUIC(net.PacketConn) error { return s.run() }

func (s *task9RereviewStartStep) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-s.entered:
	case <-time.After(time.Second):
		t.Fatal("start phase did not enter")
	}
}

func (s *task9RereviewStartStep) release() {
	s.releaseOnce.Do(func() { close(s.releaseCh) })
}

type task9RereviewStartSequence struct {
	mu    sync.Mutex
	steps []*task9RereviewStartStep
	calls atomic.Int32
}

func (s *task9RereviewStartSequence) run() error {
	index := int(s.calls.Add(1)) - 1
	s.mu.Lock()
	if index >= len(s.steps) {
		s.mu.Unlock()
		return errors.New("test: unexpected start attempt")
	}
	step := s.steps[index]
	s.mu.Unlock()
	return step.run()
}

type task9RereviewTLS struct {
	boxTLS.ServerConfig
	start func() error
}

func (c *task9RereviewTLS) Start() error {
	if c.start != nil {
		return c.start()
	}
	return nil
}
func (*task9RereviewTLS) Close() error { return nil }

type task9RereviewListener struct {
	start     func() error
	listenUDP func() (net.PacketConn, error)
}

func (l *task9RereviewListener) Start() error {
	if l.start != nil {
		return l.start()
	}
	return nil
}

func (l *task9RereviewListener) ListenUDP() (net.PacketConn, error) {
	if l.listenUDP != nil {
		return l.listenUDP()
	}
	return &task9ReviewPacketConn{}, nil
}
func (*task9RereviewListener) Close() error { return nil }

type task9RereviewQUICServer struct {
	start func(net.PacketConn) error
}

func (s *task9RereviewQUICServer) Start(packetConn net.PacketConn) error {
	if s.start != nil {
		return s.start(packetConn)
	}
	return nil
}
func (*task9RereviewQUICServer) Restart(func() (net.PacketConn, error)) error { return nil }
func (*task9RereviewQUICServer) Close() error                                 { return nil }
