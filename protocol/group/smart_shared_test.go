package group

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// TestStaggeredInitialDelay_Spreads: groups with consecutive ordinals
// must get distinct offsets inside min(period/4, 30s) so their tasks
// don't fire in lockstep.
func TestStaggeredInitialDelay_Spreads(t *testing.T) {
	base := 10 * time.Second
	period := 2 * time.Minute
	spread := 30 * time.Second
	seen := make(map[time.Duration]bool)
	for ordinal := int64(1); ordinal <= 16; ordinal++ {
		d := staggeredInitialDelay(base, period, ordinal)
		if d < base || d >= base+spread {
			t.Fatalf("ordinal %d: delay %v outside [%v, %v)", ordinal, d, base, base+spread)
		}
		if seen[d] {
			t.Fatalf("ordinal %d: delay %v repeated", ordinal, d)
		}
		seen[d] = true
	}
	if d := staggeredInitialDelay(base, 4*time.Second, 7); d < base || d >= base+time.Second {
		t.Fatalf("short period: delay %v outside [%v, %v)", d, base, base+time.Second)
	}
}

// TestSharedWorker_Singleton: the process-wide worker must survive repeated
// calls and not reinitialise its pool on each access.
func TestSharedWorker_Singleton(t *testing.T) {
	w1 := getSmartWorker()
	w2 := getSmartWorker()
	if w1 != w2 {
		t.Fatalf("getSmartWorker returned different instances; expected singleton")
	}
	if w1.freshnessCache == nil {
		t.Fatal("freshnessCache nil")
	}
}

// TestSharedWorker_FreshnessCache: cached probeResult entries within
// freshWindow return the cached value without re-running the probe.
func TestSharedWorker_FreshnessCache(t *testing.T) {
	w := getSmartWorker()
	w.freshnessCache.Store("test-tag", probeResult{
		at:    time.Now(),
		delay: 123,
		err:   nil,
	})
	got, ok := w.freshnessCache.Load("test-tag")
	if !ok || got.delay != 123 {
		t.Fatalf("freshnessCache didn't return the stored value: got=%+v ok=%v", got, ok)
	}
	// Expired entries stay in the map but probeOnce would skip them — here
	// we just verify Load still sees the stale value (the expiry check is
	// in probeOnce, not the cache itself).
	w.freshnessCache.Delete("test-tag")
}

// TestPeriodSched_ResumesFromNowAfterClockJump: after a suspend the wheel
// hands Next a prev far in the past; the next firing must be one period
// from now, not a replay of every missed period.
func TestPeriodSched_ResumesFromNowAfterClockJump(t *testing.T) {
	sched := &periodSched{period: time.Minute, firstAt: time.Now()}
	_ = sched.Next(time.Now()) // initial scheduling
	next := sched.Next(time.Now().Add(-time.Hour))
	if until := time.Until(next); until < 59*time.Second || until > time.Minute {
		t.Fatalf("next firing in %v, want about one period from now", until)
	}
}

// TestPeriodSched_OneShotStopsAfterFirstFiring: a period of 0 must end
// the schedule once the first firing happened.
func TestPeriodSched_OneShotStopsAfterFirstFiring(t *testing.T) {
	sched := &periodSched{firstAt: time.Now().Add(time.Second)}
	if first := sched.Next(time.Now()); first.IsZero() {
		t.Fatal("one-shot never scheduled")
	}
	if next := sched.Next(time.Now()); !next.IsZero() {
		t.Fatalf("one-shot rescheduled at %v", next)
	}
}

// TestScheduleTask_OneShotRunsOnce drives a real wheel: a one-shot task
// fires exactly once.
func TestScheduleTask_OneShotRunsOnce(t *testing.T) {
	var runs atomic.Int32
	getSmartWorker().scheduleTask(10*time.Millisecond, 0, func() { runs.Add(1) }, true, context.Background())
	time.Sleep(500 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("one-shot ran %d times, want 1", got)
	}
}

// TestEnqueueProbe_JoinsAndSkips: requests for a queued or running probe
// share one run, and a probe that cannot start before its deadline is
// reported as skipped without running.
func TestEnqueueProbe_JoinsAndSkips(t *testing.T) {
	w := getSmartWorker()
	release := make(chan struct{})
	var runs atomic.Int32
	results := make(chan error, 3)
	run := func(ctx context.Context) (uint16, error) {
		runs.Add(1)
		<-release
		return 42, nil
	}
	done := func(delay uint16, err error) {
		if err == nil && delay != 42 {
			err = errors.New("unexpected delay")
		}
		results <- err
	}
	w.enqueueProbe("test-join", time.Second, time.Now().Add(time.Minute), run, done)
	w.enqueueProbe("test-join", time.Second, time.Now().Add(time.Minute), run, done)
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("joined probe ran %d times, want 1", got)
	}

	w.enqueueProbe("test-expired", time.Second, time.Now().Add(-time.Second), func(context.Context) (uint16, error) {
		runs.Add(1)
		return 1, nil
	}, done)
	if err := <-results; !errors.Is(err, errProbeSkipped) {
		t.Fatalf("expired probe err = %v, want errProbeSkipped", err)
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("expired probe ran")
	}
}

// TestEnqueueProbe_TimeoutStartsWhenProbeRuns: a probe queued behind
// busy workers still gets its full timeout once it starts.
func TestEnqueueProbe_TimeoutStartsWhenProbeRuns(t *testing.T) {
	w := getSmartWorker()
	release := make(chan struct{})
	blockers := smartProbeWorkers()
	for i := range blockers {
		w.enqueueProbe("test-blocker-"+strconv.Itoa(i), time.Minute, time.Time{}, func(context.Context) (uint16, error) {
			<-release
			return 1, nil
		}, func(uint16, error) {})
	}
	result := make(chan error, 1)
	w.enqueueProbe("test-queued", 200*time.Millisecond, time.Time{}, func(ctx context.Context) (uint16, error) {
		select {
		case <-time.After(50 * time.Millisecond):
			return 1, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}, func(_ uint16, err error) { result <- err })
	time.Sleep(300 * time.Millisecond) // longer than the queued probe's timeout
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("queued probe failed: %v (its timeout ran while it waited)", err)
	}
}

// TestBookkeep_NeverBlocks: a full bookkeeping queue drops work instead
// of blocking the caller.
func TestBookkeep_NeverBlocks(t *testing.T) {
	w := &smartSharedWorker{bookkeeping: make(chan func(), 1)}
	if !w.bookkeep(func() {}) {
		t.Fatal("first task rejected")
	}
	finished := make(chan bool, 1)
	go func() { finished <- w.bookkeep(func() {}) }()
	select {
	case accepted := <-finished:
		if accepted {
			t.Fatal("full queue accepted a task")
		}
	case <-time.After(time.Second):
		t.Fatal("bookkeep blocked on a full queue")
	}
}
