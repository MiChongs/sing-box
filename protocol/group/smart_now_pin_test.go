package group

import (
	"testing"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
)

// TestNow_ReflectsManualPin: after SelectOutbound("X") succeeds, a
// dashboard query for Now() must immediately see "X" — otherwise the
// UI shows a stale "current node" for seconds and users report the
// pin as "not taking effect".
func TestNow_ReflectsManualPin(t *testing.T) {
	s := &Smart{
		knownDead: xsync.NewMapOf[string, time.Time](),
	}
	s.state.Store(&smartGroupState{
		outbounds: makeStubs("A", "B", "C"),
		tags:      []string{"A", "B", "C"},
	})
	if got := s.Now(); got != "A" {
		t.Fatalf("unseeded Now() = %q, want fallback to first snapshot tag A", got)
	}
	s.manualSelected.Store("B")
	if got := s.Now(); got != "B" {
		t.Fatalf("Now() after pin = %q, want pinned tag B", got)
	}
	s.manualSelected.Store("")
	if got := s.Now(); got != "A" {
		t.Fatalf("Now() after unpin = %q, want A (snapshot first)", got)
	}
}
