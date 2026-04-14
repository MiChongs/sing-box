package group

import (
	"testing"
	"time"
)

// TestCircuitBreaker_OpensAfterLimit verifies the breaker trips when the
// consecutive-failure count reaches cbMaxConsecFail within cbWindow.
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
	// And stay open through the cooldown.
	if !cb.isOpen(now + int64(cbOpenDuration/2)) {
		t.Fatalf("breaker should still be open mid-cooldown")
	}
	// But close after the cooldown.
	if cb.isOpen(now + int64(cbOpenDuration+time.Second)) {
		t.Fatalf("breaker should close after cooldown")
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

// TestCircuitBreaker_ResetOnSuccess: a single success fully clears the
// failure state (mirrors markAlive behaviour in the production path).
func TestCircuitBreaker_ResetOnSuccess(t *testing.T) {
	cb := &circuitBreakerState{}
	now := time.Now().UnixNano()
	cb.recordFailure(now, int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail)
	cb.reset()
	// Another failure should start fresh, not immediately trip.
	if tripped := cb.recordFailure(now+int64(time.Second), int64(cbWindow), int64(cbOpenDuration), cbMaxConsecFail); tripped {
		t.Fatalf("breaker tripped immediately after reset — reset didn't clear consec counter")
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
