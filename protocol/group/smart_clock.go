package group

import (
	"sync/atomic"

	"github.com/benbjohnson/clock"
)

// breakerClock is the process-wide injectable clock used by the Smart
// circuit-breaker code path. Production uses a real wall clock via
// clock.New(); tests swap in clock.NewMock() to fast-forward through
// the cooldown / half-open trial windows in microseconds instead of
// taking seconds per test case.
//
// We store an atomic.Value so swapping the clock in tests is safe even
// while goroutines are reading it. All reads go through breakerNow()
// below, which narrows the clock API surface to the single "what time
// is it in UnixNano" question the breaker actually needs.
//
// Why a global singleton instead of a field on Smart: circuit-breaker
// state (circuitBreakerState + persistBreaker) lives on xsync.MapOf
// keyed by proxy tag and is allocated lazily per tag. Threading a
// clock.Clock through every breakerFor/recordFailure/isBreakerOpen
// site would touch ~30 call sites for a feature (test time injection)
// that is ONLY used in unit tests. The singleton gives tests the
// knob they need with zero overhead in production.
// breakerClockHolder wraps a clock.Clock in a concrete struct so
// atomic.Value's "same type on every Store" invariant is satisfied.
// clock.New() returns *clock.clock while clock.NewMock() returns
// *clock.Mock — both satisfy clock.Clock but have different dynamic
// types; storing them directly trips atomic.Value's type check.
type breakerClockHolder struct{ c clock.Clock }

var breakerClock atomic.Value // holds *breakerClockHolder

func init() {
	breakerClock.Store(&breakerClockHolder{c: clock.New()})
}

// breakerNow returns the current time as unix-nanoseconds, using the
// injectable clock. Cheap enough to inline — one atomic.Value load and
// a single time.UnixNano().
func breakerNow() int64 {
	return breakerClock.Load().(*breakerClockHolder).c.Now().UnixNano()
}

// setBreakerClockForTest swaps the breaker clock. Exported only to the
// `group` test package — production code has no reason to call this.
// Returns the previous clock so tests can restore it via t.Cleanup.
//
//nolint:unused
func setBreakerClockForTest(c clock.Clock) clock.Clock {
	prev := breakerClock.Load().(*breakerClockHolder).c
	breakerClock.Store(&breakerClockHolder{c: c})
	return prev
}
