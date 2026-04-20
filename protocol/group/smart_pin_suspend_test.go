package group

import (
	"testing"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
)

// newSmartForSuspendTest builds a minimal Smart for pin-suspend tests.
// We only exercise the state-transition helpers and Now() — no dial
// path is required, so we can skip store / connection / interrupt
// wiring.
func newSmartForSuspendTest(t *testing.T) *Smart {
	t.Helper()
	s := &Smart{
		knownDead: xsync.NewMapOf[string, time.Time](),
		breakers:  xsync.NewMapOf[string, *circuitBreakerState](),
		aliveAt:   xsync.NewMapOf[string, int64](),
		logger:    stubLogger{},
		interval:  3 * time.Minute,
	}
	s.history = urltest.NewHistoryStorage()
	return s
}

// TestPinSuspend_InitialStateFalse — zero-value Smart must report
// suspended=false so the Clash API defaults to "pin working" when
// no fallback has occurred.
func TestPinSuspend_InitialStateFalse(t *testing.T) {
	s := newSmartForSuspendTest(t)
	if s.PinSuspended() {
		t.Fatal("fresh Smart reports PinSuspended=true")
	}
}

// TestPinSuspend_SetSwap — setPinSuspended returns the PRIOR value
// and the log message is routed through stubLogger so the edge is
// observable but harmless in tests.
func TestPinSuspend_SetSwap(t *testing.T) {
	s := newSmartForSuspendTest(t)
	s.manualSelected.Store("A")

	if prev := s.setPinSuspended(true); prev != false {
		t.Fatalf("first Swap: prev=%v, want false", prev)
	}
	if !s.PinSuspended() {
		t.Fatal("after set(true), Load=false")
	}
	if prev := s.setPinSuspended(false); prev != true {
		t.Fatalf("second Swap: prev=%v, want true", prev)
	}
	if s.PinSuspended() {
		t.Fatal("after set(false), Load=true")
	}
}

// TestPinSuspend_MaybeResumeOnPinMatch — maybeResumePin clears the
// flag ONLY when the tag matches the current pin AND suspended is
// set. Non-matching tag, empty pin, or already-cleared flag are all
// cheap no-ops.
func TestPinSuspend_MaybeResumeOnPinMatch(t *testing.T) {
	s := newSmartForSuspendTest(t)
	s.manualSelected.Store("A")
	s.pinSuspended.Store(true)

	// Wrong tag — must NOT clear.
	s.maybeResumePin("B")
	if !s.PinSuspended() {
		t.Fatal("maybeResumePin cleared on wrong tag")
	}

	// Right tag — clears.
	s.maybeResumePin("A")
	if s.PinSuspended() {
		t.Fatal("maybeResumePin failed to clear on matching tag")
	}

	// Already cleared — must be safe to call again.
	s.maybeResumePin("A")

	// No pin set — must not flip anything.
	s.manualSelected.Store("")
	s.pinSuspended.Store(true)
	s.maybeResumePin("A")
	if !s.PinSuspended() {
		t.Fatal("maybeResumePin cleared with no pin set")
	}
}

// TestPinSuspend_MarkAliveClearsOnPin — markAlive() for the pin tag
// MUST trigger maybeResumePin. This is the integration point: the
// user's dial-success path and probe-success path both funnel
// through markAlive, so wiring resume there covers both.
func TestPinSuspend_MarkAliveClearsOnPin(t *testing.T) {
	s := newSmartForSuspendTest(t)
	s.manualSelected.Store("A")
	s.pinSuspended.Store(true)

	// Seed some state markAlive touches so it doesn't NPE on nil
	// persistence hooks — we set knownDead for A so it has something
	// to clear.
	s.knownDead.Store("A", time.Now())

	s.markAlive("A")

	if s.PinSuspended() {
		t.Fatal("markAlive(pin) did not clear suspended")
	}
}

// TestPinSuspend_NowReportsActiveNodeWhenSuspended — the whole point
// of the flag: Clash API Now() must return the actual fallback
// node's tag (not the unavailable pin) when suspended.
func TestPinSuspend_NowReportsActiveNodeWhenSuspended(t *testing.T) {
	s := newSmartForSuspendTest(t)
	s.manualSelected.Store("A")
	s.lastSelectedTag.Store("B") // fallback successfully dialled B
	s.pinSuspended.Store(true)

	got := s.Now()
	if got != "B" {
		t.Fatalf("Now() while suspended = %q, want B (actual active)", got)
	}

	// Clearing the flag (e.g., pin recovered) restores pin-first.
	s.pinSuspended.Store(false)
	if got := s.Now(); got != "A" {
		t.Fatalf("Now() after resume = %q, want A (pin)", got)
	}
}

// TestPinSuspend_SelectOutboundResetsFlag — setting a fresh pin (or
// clearing it) must zero the suspended flag. Users changing their
// pin expect a clean state, not one carrying "suspended" residue
// from the previous pin's failures.
func TestPinSuspend_SelectOutboundResetsFlag(t *testing.T) {
	s, obs := selectProxiesStub(t, []string{"A", "B"}, "A")
	s.pinSuspended.Store(true)

	// Repin to B (exists) — flag must clear.
	if !s.SelectOutbound("B") {
		t.Fatal("SelectOutbound B returned false unexpectedly")
	}
	if s.PinSuspended() {
		t.Fatal("repin did not clear PinSuspended")
	}
	_ = obs // silences the unused returned slice

	// Set flag again and clear pin entirely — must also zero.
	s.pinSuspended.Store(true)
	if !s.SelectOutbound("") {
		t.Fatal("SelectOutbound('') returned false unexpectedly")
	}
	if s.PinSuspended() {
		t.Fatal("unpin did not clear PinSuspended")
	}
}

// TestPinSuspend_NowFallsThroughWhenNoPin — with no pin set, Now()
// routes through the lastSelectedTag → ranking → delay chain. Flag
// must not short-circuit any of that.
func TestPinSuspend_NowFallsThroughWhenNoPin(t *testing.T) {
	s := newSmartForSuspendTest(t)
	s.lastSelectedTag.Store("X")
	// Spurious flag set — no pin, should be ignored.
	s.pinSuspended.Store(true)

	if got := s.Now(); got != "X" {
		t.Fatalf("Now() without pin = %q, want X (last selected)", got)
	}

	// Ensure adapter import is used — compile-time check.
	_ = &adapter.URLTestHistory{}
}
