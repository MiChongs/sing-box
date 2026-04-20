package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

// newSmartForNetChangeTest returns a minimally-wired Smart with a NOP
// logger + cancelled taskCtx so InterfaceUpdated runs without panicking
// but its scheduled warmup (which we DON'T want to fire during the test)
// short-circuits on the s.started / ctx.Done() check inside the
// wrapped task fn.
func newSmartForNetChangeTest(t *testing.T) *Smart {
	t.Helper()
	s := &Smart{
		logger: log.NewNOPFactory().NewLogger(""),
	}
	s.taskCtx, s.taskCancel = context.WithCancel(context.Background())
	// Cancel immediately so any task our stubbed scheduleTask queues
	// observes the Done() channel and returns without touching
	// runHealthCheck (which needs a full Smart setup).
	s.taskCancel()
	s.started.Store(true)
	return s
}

// TestInterfaceUpdatedDebounce verifies rapid callbacks within the
// debounce window collapse into one scheduling, while a callback AFTER
// the window fires a fresh one. We only verify the lastFireNS atomic;
// actual probe dispatch is handled by timing-wheel integration tests.
func TestInterfaceUpdatedDebounce(t *testing.T) {
	s := newSmartForNetChangeTest(t)

	// First call: advances lastFireNS.
	s.InterfaceUpdated()
	firstFire := s.netChange.lastFireNS.Load()
	if firstFire == 0 {
		t.Fatal("first call did not set lastFireNS")
	}

	// Second call within window: must NOT advance.
	s.InterfaceUpdated()
	if s.netChange.lastFireNS.Load() != firstFire {
		t.Fatalf("debounce failed: lastFireNS advanced within window (%d → %d)",
			firstFire, s.netChange.lastFireNS.Load())
	}

	// Rewind past the debounce window and call again: must advance.
	past := time.Now().UnixNano() - int64(netChangeDebounce) - int64(time.Millisecond)
	s.netChange.lastFireNS.Store(past)

	s.InterfaceUpdated()
	if s.netChange.lastFireNS.Load() == past {
		t.Fatal("post-window fire did not advance lastFireNS")
	}
}

// TestInterfaceUpdatedInFlight verifies the CAS guard prevents two
// goroutines racing into the scheduling block.
func TestInterfaceUpdatedInFlight(t *testing.T) {
	s := newSmartForNetChangeTest(t)

	// Hold inFlight manually to simulate a concurrent caller already
	// past the debounce check.
	if !s.netChange.inFlight.CompareAndSwap(false, true) {
		t.Fatal("initial CAS failed — fresh state should be false")
	}

	// Call should observe inFlight=true and bail fast.
	s.InterfaceUpdated()

	// lastFireNS must remain zero because the inFlight guard fired.
	if s.netChange.lastFireNS.Load() != 0 {
		t.Fatalf("inFlight guard failed: lastFireNS=%d, want 0",
			s.netChange.lastFireNS.Load())
	}
	s.netChange.inFlight.Store(false)
}

// TestInterfaceUpdatedNotStarted verifies the hook no-ops when the
// group is not yet in the started state — important during config
// reload when outbounds are being re-registered.
func TestInterfaceUpdatedNotStarted(t *testing.T) {
	s := &Smart{
		logger: log.NewNOPFactory().NewLogger(""),
	}
	// started is false by default.

	s.InterfaceUpdated()

	if s.netChange.lastFireNS.Load() != 0 {
		t.Fatal("started=false did not short-circuit")
	}
	if s.netChange.inFlight.Load() {
		t.Fatal("inFlight was left set after started=false early return")
	}
}
