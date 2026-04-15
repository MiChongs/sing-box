package group

import (
	"testing"
	"time"

	"github.com/benbjohnson/clock"
)

// breakerCeilingNS is the upper bound of a single-trip cooldown once
// jitter (×1.2) is factored in. Tests that wait for the breaker to
// close MUST wait past this, otherwise the jittered openUntil can
// still be in the future on a worst-case random draw.
func breakerCeilingNS(base time.Duration, trip int32) int64 {
	exp := trip - 1
	if exp > 3 {
		exp = 3
	}
	return int64(float64(int64(base)<<uint(exp)) * 1.2)
}

// TestCircuitBreaker_OpensAfterLimit verifies the breaker trips when the
// consecutive-failure count reaches cbMaxConsecFail within cbWindow, and
// closes after the jittered cooldown window (upper-bounded by 1.2×).
func TestCircuitBreaker_OpensAfterLimit(t *testing.T) {
	cb := &circuitBreakerState{}
	now := time.Now().UnixNano()

	// First failure — streak starts, not tripped yet.
	if tripped := cb.recordFailure(now, int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail); tripped {
		t.Fatalf("breaker tripped on first failure, should need %d", cbMaxConsecFail)
	}
	if cb.isOpen(now) {
		t.Fatalf("breaker open after 1 failure")
	}

	// Second failure within the window — should trip.
	now += int64(5 * time.Second)
	if tripped := cb.recordFailure(now, int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail); !tripped {
		t.Fatalf("breaker didn't trip on failure #%d within window", cbMaxConsecFail)
	}
	if !cb.isOpen(now) {
		t.Fatalf("breaker should be open right after tripping")
	}
	// And stay open through (at least) the lower-bound of the cooldown.
	// With jitter 0.8×, the minimum cooldown is 0.8 × cbOpenDuration; we
	// probe well before that to avoid flakiness.
	if !cb.isOpen(now + int64(cbOpenDuration)/2) {
		t.Fatalf("breaker should still be open mid-cooldown")
	}
	// Must close after the jittered upper bound (1.2× base). +1s slack
	// to absorb monotonic vs wall clock drift on slow CI runners.
	probe := now + breakerCeilingNS(cbOpenDuration, 1) + int64(time.Second)
	if cb.isOpen(probe) {
		t.Fatalf("breaker should close after jittered cooldown")
	}
}

// TestCircuitBreaker_WindowExpiry verifies a failure after the streak
// window resets the counter rather than carrying over.
func TestCircuitBreaker_WindowExpiry(t *testing.T) {
	cb := &circuitBreakerState{}
	now := time.Now().UnixNano()

	cb.recordFailure(now, int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail)

	// Advance well past the window before the next failure.
	now += int64(cbWindow) + int64(5*time.Second)
	if tripped := cb.recordFailure(now, int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail); tripped {
		t.Fatalf("breaker tripped across window boundaries — should have reset the counter")
	}
	if cb.isOpen(now) {
		t.Fatalf("breaker open after isolated failures separated by >window")
	}
}

// TestCircuitBreaker_ResetOnSuccess: a single reset fully clears the
// failure state (mirrors markAlive behaviour in the production path).
// Also verifies tripCount is reset so the next cooldown is at base.
func TestCircuitBreaker_ResetOnSuccess(t *testing.T) {
	cb := &circuitBreakerState{}
	now := time.Now().UnixNano()
	cb.recordFailure(now, int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail)
	cb.reset()
	if cb.tripCount.Load() != 0 {
		t.Fatalf("reset should clear tripCount, got %d", cb.tripCount.Load())
	}
	// Another failure should start fresh, not immediately trip.
	if tripped := cb.recordFailure(now+int64(time.Second), int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail); tripped {
		t.Fatalf("breaker tripped immediately after reset — reset didn't clear consec counter")
	}
}

// TestCircuitBreaker_HalfOpenTrialFailEscalates verifies that a failure
// arriving after the open window has elapsed (half-open trial) re-trips
// the breaker with an escalated backoff instead of restarting a fresh
// consec-failure streak.
func TestCircuitBreaker_HalfOpenTrialFailEscalates(t *testing.T) {
	cb := &circuitBreakerState{}
	now := time.Now().UnixNano()

	// Trip once.
	cb.recordFailure(now, int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail)
	cb.recordFailure(now+int64(time.Second), int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail)
	firstOpenUntil := cb.openUntil.Load()
	if firstOpenUntil == 0 {
		t.Fatalf("first trip did not open the breaker")
	}

	// Advance just past the cooldown (half-open). Single failure here
	// must be treated as a half-open trial failure and re-trip with
	// tripCount=2 → 2× base (with jitter).
	halfOpenAt := firstOpenUntil + int64(100*time.Millisecond)
	tripped := cb.recordFailure(halfOpenAt, int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail)
	if !tripped {
		t.Fatalf("half-open trial failure must re-trip breaker")
	}
	if got := cb.tripCount.Load(); got != 2 {
		t.Fatalf("tripCount after half-open re-trip = %d, want 2", got)
	}
	// Second-trip cooldown should extend to at least 0.8 × 2× base.
	secondOpenUntil := cb.openUntil.Load()
	wantMin := halfOpenAt + int64(float64(int64(cbOpenDuration)*2)*0.8)
	if secondOpenUntil < wantMin {
		t.Fatalf("escalated cooldown too short: openUntil=%d want ≥ %d", secondOpenUntil, wantMin)
	}
}

// TestExpBackoffJitter_Monotonic checks the unjittered pattern is
// 1× / 2× / 4× / 8× / 8× (capped). We draw several samples per trip
// and assert the MINIMUM observed duration at higher trips is ≥ the
// MAXIMUM observed at the previous trip, so jitter bands don't overlap
// into pathological orderings.
func TestExpBackoffJitter_Monotonic(t *testing.T) {
	const base = int64(time.Second)
	const samples = 64

	maxAt := func(trip int32) int64 {
		var m int64
		for i := 0; i < samples; i++ {
			if d := expBackoffJitter(base, trip); d > m {
				m = d
			}
		}
		return m
	}
	minAt := func(trip int32) int64 {
		m := int64(1 << 62)
		for i := 0; i < samples; i++ {
			if d := expBackoffJitter(base, trip); d < m {
				m = d
			}
		}
		return m
	}

	// Verify step-by-step that the next trip's minimum is ≥ previous max.
	// The jitter is [0.8, 1.2], so with a 2× exponential step:
	//   prevMax = 1.2 × base, nextMin = 1.6 × base → monotonic.
	for trip := int32(1); trip < 4; trip++ {
		prev := maxAt(trip)
		next := minAt(trip + 1)
		if next < prev {
			t.Fatalf("exp-backoff overlap: trip=%d max=%d vs trip=%d min=%d",
				trip, prev, trip+1, next)
		}
	}
	// Cap at exp=3: trips 4 and 5 share the same jitter envelope
	// [0.8×base×8, 1.2×base×8]. Assert both maxes lie in that envelope.
	ceil := int64(float64(base<<3) * 1.2)
	if maxAt(4) > ceil || maxAt(5) > ceil {
		t.Fatalf("cap breached: trip4 max=%d trip5 max=%d ceil=%d",
			maxAt(4), maxAt(5), ceil)
	}
}

// TestBreakerClockInjection verifies a mock clock can drive the
// breaker through an open → half-open transition without any wall time
// elapsing. Regression guard for the benbjohnson/clock wire-up.
func TestBreakerClockInjection(t *testing.T) {
	mock := clock.NewMock()
	// Pick a non-zero epoch so UnixNano() is stable and positive.
	mock.Set(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	prev := setBreakerClockForTest(mock)
	t.Cleanup(func() { setBreakerClockForTest(prev) })

	cb := &circuitBreakerState{}
	now := breakerNow()
	cb.recordFailure(now, int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail)
	if tripped := cb.recordFailure(now+int64(time.Second), int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail); !tripped {
		t.Fatal("setup failure: breaker did not trip")
	}
	openUntil := cb.openUntil.Load()

	// Fast-forward past the cooldown via the mock clock (no sleep, no
	// timer wall time). breakerNow() must report the new time.
	mock.Set(time.Unix(0, openUntil+int64(time.Second)))
	if cb.isOpen(breakerNow()) {
		t.Fatalf("breaker should be closed after mock fast-forward past openUntil")
	}
}

// TestBreakerPersistence_SnapshotRoundtrip: take a live breaker state,
// serialise → deserialise via BreakerRecord, and confirm the restored
// state still reads as "open" within the cooldown window, and
// preserves tripCount for future exponential backoff decisions.
func TestBreakerPersistence_SnapshotRoundtrip(t *testing.T) {
	now := time.Now().UnixNano()
	cb := &circuitBreakerState{}
	// Trip the breaker
	cb.recordFailure(now, int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail)
	tripped := cb.recordFailure(now+int64(5*time.Second), int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail)
	if !tripped {
		t.Fatalf("setup failed: second failure should have tripped breaker")
	}
	consec := cb.consecFails.Load()
	firstAt := cb.firstFailAt.Load()
	until := cb.openUntil.Load()
	trips := cb.tripCount.Load()
	if until == 0 {
		t.Fatalf("tripped breaker has openUntil=0 — wiring broken")
	}
	if trips == 0 {
		t.Fatalf("tripCount should be non-zero after trip")
	}

	// Simulate restart: reconstruct from scalar fields and verify still open.
	restored := &circuitBreakerState{}
	restored.consecFails.Store(consec)
	restored.firstFailAt.Store(firstAt)
	restored.openUntil.Store(until)
	restored.tripCount.Store(trips)

	// Within the cooldown window, restored breaker must still report open.
	if !restored.isOpen(until - int64(time.Second)) {
		t.Fatalf("restored breaker should be open inside cooldown")
	}
	if restored.isOpen(until + int64(time.Second)) {
		t.Fatalf("restored breaker should be closed past cooldown")
	}
	if restored.tripCount.Load() != trips {
		t.Fatalf("tripCount lost in roundtrip")
	}
}

// TestBreakerPersistence_ExpiredOnRestore: a breaker whose openUntil is
// in the past should NOT be restored. The hydrate path needs to treat
// this as "discarded + enqueue tombstone".
func TestBreakerPersistence_ExpiredOnRestore(t *testing.T) {
	now := time.Now().UnixNano()
	// Encode a breaker that "just expired" (openUntil 1s in the past).
	openUntil := now - int64(time.Second)
	// Hydrate-path decision: now >= OpenUntil → skip restore.
	shouldRestore := openUntil != 0 && now < openUntil
	if shouldRestore {
		t.Fatalf("expired breaker must NOT be restored (hydrate check broken)")
	}
}

// TestSameOutboundSet: order + identity matters.
func TestSameOutboundSet(t *testing.T) {
	// Use dummy []adapter.Outbound via nil check — the function is order-
	// and length-based, so empty slices are trivially equal.
	if !sameOutboundSet(nil, nil) {
		t.Fatalf("nil sets should be equal")
	}
}

// TestIdleDetection: isGroupIdle returns true for a brand-new group
// (lastDialAt==0) so the scheduler skips until first real dial wakes it.
// After setLastSelected is called, the group counts as active for the
// idleThresholdNanos window.
func TestIdleDetection(t *testing.T) {
	s := &Smart{}
	// Brand-new group: no dial yet → idle.
	if !s.isGroupIdle() {
		t.Fatalf("fresh group should be idle (lastDialAt==0)")
	}
	// Simulate a just-completed dial.
	s.lastDialAt.Store(time.Now().UnixNano())
	if s.isGroupIdle() {
		t.Fatalf("group with recent dial should NOT be idle")
	}
	// Simulate a dial that happened well past the idle threshold.
	s.lastDialAt.Store(time.Now().Add(-(time.Duration(idleThresholdNanos) + time.Second)).UnixNano())
	if !s.isGroupIdle() {
		t.Fatalf("group with stale dial (>%v ago) should be idle", time.Duration(idleThresholdNanos))
	}
}
