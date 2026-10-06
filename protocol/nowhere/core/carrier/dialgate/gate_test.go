package dialgate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClassifyRetryableAndAuth(t *testing.T) {
	if Classify(errors.New("dial tcp: connection refused")) != ClassRetryable {
		t.Fatal("want retryable")
	}
	if Classify(errors.New("authentication failed")) != ClassAuth {
		t.Fatal("want auth")
	}
	if Classify(context.Canceled) != ClassCanceled {
		t.Fatal("want canceled")
	}
}

func TestGateCoalescesConcurrentRefused(t *testing.T) {
	gate := New(Options{Initial: 500 * time.Millisecond, Max: time.Second})
	refused := errors.New("connect: connection refused")

	// Seed degraded state with one failure.
	if err := gate.Run(context.Background(), func(context.Context) error { return refused }); err == nil {
		t.Fatal("expected refused")
	}
	seedAttempts := gate.Attempts()

	var dials atomic.Uint64
	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := gate.Run(context.Background(), func(context.Context) error {
				dials.Add(1)
				return refused
			})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil {
			t.Fatal("expected error")
		}
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("dials during backoff coalesce=%d, want 0", got)
	}
	if gate.Attempts() != seedAttempts {
		t.Fatalf("attempts=%d, want seed %d", gate.Attempts(), seedAttempts)
	}
}

func TestGateAuthDoesNotTightLoop(t *testing.T) {
	gate := New(Options{
		Initial:     10 * time.Millisecond,
		Max:         20 * time.Millisecond,
		AuthBackoff: 200 * time.Millisecond,
	})
	authErr := errors.New("authentication failed: bad password")
	if err := gate.Run(context.Background(), func(context.Context) error { return authErr }); err == nil {
		t.Fatal("expected auth error")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	err := gate.Run(ctx, func(context.Context) error {
		t.Fatal("should not dial during auth backoff")
		return nil
	})
	if err == nil {
		t.Fatal("expected error during auth backoff")
	}
	if gate.Attempts() != 1 {
		t.Fatalf("attempts=%d, want 1", gate.Attempts())
	}
}

func TestGateSuccessClearsBackoff(t *testing.T) {
	gate := New(Options{Initial: 100 * time.Millisecond, Max: time.Second})
	_ = gate.Run(context.Background(), func(context.Context) error {
		return &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	})
	if err := gate.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
		// May still be in backoff coalesce returning refused — wait it out.
		time.Sleep(150 * time.Millisecond)
		if err := gate.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if err := gate.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatalf("success did not clear backoff")
	}
}

func TestGateAlwaysCoalesceInitialConcurrentSingleFlight(t *testing.T) {
	gate := New(Options{AlwaysCoalesce: true})
	const callers = 32

	var calls atomic.Uint64
	leaderStarted := make(chan struct{})
	releaseLeader := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseLeader) })

	results := make(chan error, callers)
	go func() {
		results <- gate.Run(context.Background(), func(context.Context) error {
			calls.Add(1)
			close(leaderStarted)
			<-releaseLeader
			return nil
		})
	}()
	waitSignal(t, leaderStarted, "leader callback")

	observed := make([]<-chan struct{}, 0, callers-1)
	for i := 1; i < callers; i++ {
		ctx := newObservedDoneContext(context.Background())
		observed = append(observed, ctx.observed)
		go func() {
			results <- gate.Run(ctx, func(context.Context) error {
				calls.Add(1)
				return nil
			})
		}()
	}
	for i, waiting := range observed {
		waitSignal(t, waiting, fmt.Sprintf("waiter %d joined flight", i+1))
	}

	releaseOnce.Do(func() { close(releaseLeader) })
	for i := 0; i < callers; i++ {
		if err := waitResult(t, results, fmt.Sprintf("caller %d", i)); err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("callback calls=%d, want 1", got)
	}
	if got := gate.Attempts(); got != 1 {
		t.Fatalf("attempts=%d, want 1", got)
	}
}

func TestGateAlreadyDoneCallerReturnsOwnContextError(t *testing.T) {
	gate := New(Options{AuthBackoff: time.Hour})
	globalErr := errors.New("authentication failed: cached")
	if err := gate.Run(context.Background(), func(context.Context) error { return globalErr }); !errors.Is(err, globalErr) {
		t.Fatalf("seed error=%v, want %v", err, globalErr)
	}
	seedAttempts := gate.Attempts()

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	deadlineCtx, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	for _, tt := range []struct {
		name    string
		ctx     context.Context
		wantErr error
	}{
		{name: "cancel", ctx: cancelCtx, wantErr: context.Canceled},
		{name: "deadline", ctx: deadlineCtx, wantErr: context.DeadlineExceeded},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var called atomic.Bool
			err := gate.Run(tt.ctx, func(context.Context) error {
				called.Store(true)
				return nil
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Run error=%v, want %v", err, tt.wantErr)
			}
			if called.Load() {
				t.Fatal("callback ran for an already-done caller context")
			}
			if got := gate.Attempts(); got != seedAttempts {
				t.Fatalf("attempts=%d, want seed %d", got, seedAttempts)
			}
		})
	}
}

func TestGateDegradedSuccessFollowerRunsOwnAttempt(t *testing.T) {
	gate := New(Options{})
	gate.mu.Lock()
	gate.degraded = true
	gate.failErr = errors.New("previous portal failure")
	gate.nextAllowed = time.Now().Add(-time.Second)
	gate.mu.Unlock()

	var calls atomic.Uint64
	leaderStarted := make(chan struct{})
	releaseLeader := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseLeader) })

	leaderResult := make(chan error, 1)
	go func() {
		leaderResult <- gate.Run(context.Background(), func(context.Context) error {
			calls.Add(1)
			close(leaderStarted)
			<-releaseLeader
			return nil
		})
	}()
	waitSignal(t, leaderStarted, "degraded probe")

	followerCtx := newObservedDoneContext(context.Background())
	followerResult := make(chan error, 1)
	go func() {
		followerResult <- gate.Run(followerCtx, func(context.Context) error {
			calls.Add(1)
			return nil
		})
	}()
	waitSignal(t, followerCtx.observed, "TCP-compatible follower joined flight")

	releaseOnce.Do(func() { close(releaseLeader) })
	if err := waitResult(t, leaderResult, "degraded probe"); err != nil {
		t.Fatalf("degraded probe: %v", err)
	}
	if err := waitResult(t, followerResult, "TCP-compatible follower"); err != nil {
		t.Fatalf("TCP-compatible follower: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("callback calls=%d, want 2", got)
	}
	if got := gate.Attempts(); got != 2 {
		t.Fatalf("attempts=%d, want 2", got)
	}
}

func TestGateFollowerCancelDoesNotAffectOtherWaiters(t *testing.T) {
	gate := New(Options{AlwaysCoalesce: true})
	var calls atomic.Uint64
	leaderStarted := make(chan struct{})
	releaseLeader := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseLeader) })

	leaderResult := make(chan error, 1)
	go func() {
		leaderResult <- gate.Run(context.Background(), func(context.Context) error {
			calls.Add(1)
			close(leaderStarted)
			<-releaseLeader
			return nil
		})
	}()
	waitSignal(t, leaderStarted, "leader callback")

	followerBase, cancelFollower := context.WithCancel(context.Background())
	defer cancelFollower()
	followerCtx := newObservedDoneContext(followerBase)
	followerResult := make(chan error, 1)
	go func() {
		followerResult <- gate.Run(followerCtx, func(context.Context) error {
			calls.Add(1)
			return nil
		})
	}()
	waitSignal(t, followerCtx.observed, "canceling follower joined flight")

	liveCtx := newObservedDoneContext(context.Background())
	liveResult := make(chan error, 1)
	go func() {
		liveResult <- gate.Run(liveCtx, func(context.Context) error {
			calls.Add(1)
			return nil
		})
	}()
	waitSignal(t, liveCtx.observed, "live waiter joined flight")

	cancelFollower()
	if err := waitResult(t, followerResult, "canceling follower"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceling follower error=%v, want context.Canceled", err)
	}

	releaseOnce.Do(func() { close(releaseLeader) })
	if err := waitResult(t, leaderResult, "leader"); err != nil {
		t.Fatalf("leader: %v", err)
	}
	if err := waitResult(t, liveResult, "live waiter"); err != nil {
		t.Fatalf("live waiter: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("callback calls=%d, want 1", got)
	}
}

func TestGateLeaderCallerLocalErrorDoesNotAffectLiveWaiter(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "cancel", err: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gate := New(Options{
				Initial:        time.Hour,
				Max:            time.Hour,
				AuthBackoff:    time.Hour,
				AlwaysCoalesce: true,
			})
			var calls atomic.Uint64

			leaderCtx := newControlledErrorContext()
			leaderStarted := make(chan struct{})
			leaderResult := make(chan error, 1)
			go func() {
				leaderResult <- gate.Run(leaderCtx, func(ctx context.Context) error {
					calls.Add(1)
					close(leaderStarted)
					<-ctx.Done()
					return fmt.Errorf("establish stopped: %w", ctx.Err())
				})
			}()
			waitSignal(t, leaderStarted, "leader callback")

			liveCtx := newObservedDoneContext(context.Background())
			liveStarted := make(chan struct{})
			releaseLive := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(releaseLive) })
			liveResult := make(chan error, 1)
			go func() {
				liveResult <- gate.Run(liveCtx, func(context.Context) error {
					calls.Add(1)
					close(liveStarted)
					<-releaseLive
					return nil
				})
			}()
			waitSignal(t, liveCtx.observed, "live waiter joined flight")

			leaderCtx.fail(tt.err)
			if err := waitResult(t, leaderResult, "leader"); !errors.Is(err, tt.err) {
				t.Fatalf("leader error=%v, want %v", err, tt.err)
			}

			select {
			case <-liveStarted:
			case err := <-liveResult:
				t.Fatalf("live waiter inherited leader-local error: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("live waiter did not start a replacement flight")
			}

			gate.mu.Lock()
			failErr := gate.failErr
			step := gate.step
			nextAllowed := gate.nextAllowed
			gate.mu.Unlock()
			if failErr != nil || step != 0 || !nextAllowed.IsZero() {
				t.Fatalf("caller-local error changed backoff: failErr=%v step=%d nextAllowed=%v", failErr, step, nextAllowed)
			}

			releaseOnce.Do(func() { close(releaseLive) })
			if err := waitResult(t, liveResult, "live waiter"); err != nil {
				t.Fatalf("live waiter: %v", err)
			}
			if got := calls.Load(); got != 2 {
				t.Fatalf("callback calls=%d, want 2", got)
			}
		})
	}
}

func TestGateHealthyParallel(t *testing.T) {
	gate := New(Options{})
	var calls atomic.Uint64
	var active atomic.Int32
	var max atomic.Int32
	const n = 8
	start := make(chan struct{})
	entered := make(chan struct{}, n)
	release := make(chan struct{})
	results := make(chan error, n)

	for i := 0; i < n; i++ {
		go func() {
			<-start
			results <- gate.Run(context.Background(), func(context.Context) error {
				calls.Add(1)
				cur := active.Add(1)
				for {
					old := max.Load()
					if cur <= old || max.CompareAndSwap(old, cur) {
						break
					}
				}
				entered <- struct{}{}
				<-release
				active.Add(-1)
				return nil
			})
		}()
	}
	close(start)
	for i := 0; i < n; i++ {
		waitSignal(t, entered, fmt.Sprintf("parallel callback %d", i))
	}
	close(release)
	for i := 0; i < n; i++ {
		if err := waitResult(t, results, fmt.Sprintf("parallel caller %d", i)); err != nil {
			t.Fatalf("parallel caller %d: %v", i, err)
		}
	}
	if got := calls.Load(); got != n {
		t.Fatalf("callback calls=%d, want %d", got, n)
	}
	if got := max.Load(); got != int32(n) {
		t.Fatalf("max parallel=%d, want %d", got, n)
	}
	if got := gate.Attempts(); got != n {
		t.Fatalf("attempts=%d, want %d", got, n)
	}
}

type observedDoneContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func newObservedDoneContext(ctx context.Context) *observedDoneContext {
	return &observedDoneContext{Context: ctx, observed: make(chan struct{})}
}

func (c *observedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

type controlledErrorContext struct {
	context.Context
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	err  error
}

func newControlledErrorContext() *controlledErrorContext {
	return &controlledErrorContext{Context: context.Background(), done: make(chan struct{})}
}

func (c *controlledErrorContext) Done() <-chan struct{} {
	return c.done
}

func (c *controlledErrorContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *controlledErrorContext) fail(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
	c.once.Do(func() { close(c.done) })
}

func waitSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func waitResult(t *testing.T, result <-chan error, name string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		return nil
	}
}
