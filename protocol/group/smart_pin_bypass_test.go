package group

import (
	"context"
	"testing"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing/common/logger"
)

// stubLogger is a minimal logger.ContextLogger that swallows output.
// The selectProxiesTraced pin-bypass path writes Warn / Info lines;
// production constructs a real logger, unit tests just need to not
// panic when they're called.
type stubLogger struct{}

func (stubLogger) Trace(args ...any)                           {}
func (stubLogger) Debug(args ...any)                           {}
func (stubLogger) Info(args ...any)                            {}
func (stubLogger) Warn(args ...any)                            {}
func (stubLogger) Error(args ...any)                           {}
func (stubLogger) Fatal(args ...any)                           {}
func (stubLogger) Panic(args ...any)                           {}
func (stubLogger) TraceContext(ctx context.Context, args ...any) {}
func (stubLogger) DebugContext(ctx context.Context, args ...any) {}
func (stubLogger) InfoContext(ctx context.Context, args ...any)  {}
func (stubLogger) WarnContext(ctx context.Context, args ...any)  {}
func (stubLogger) ErrorContext(ctx context.Context, args ...any) {}
func (stubLogger) FatalContext(ctx context.Context, args ...any) {}
func (stubLogger) PanicContext(ctx context.Context, args ...any) {}

var _ logger.ContextLogger = stubLogger{}

// selectProxiesStub assembles just enough Smart state for
// selectProxiesTraced's manual-pin branch to execute. Avoids pulling
// in the whole construction pipeline — we only care that the pin
// path responds correctly to healthy vs unhealthy pinned nodes.
func selectProxiesStub(t *testing.T, tags []string, pinnedTag string) (*Smart, []adapter.Outbound) {
	t.Helper()
	s := &Smart{
		knownDead: xsync.NewMapOf[string, time.Time](),
		breakers:  xsync.NewMapOf[string, *circuitBreakerState](),
		aliveAt:   xsync.NewMapOf[string, int64](),
		logger:    stubLogger{},
		// isAlive uses interval*3 as the URLTestHistory freshness
		// window; a zero default makes every history entry look stale
		// and the pin path never sees a healthy node. Real groups get
		// this from config; tests pin a sane value explicitly.
		interval: 3 * time.Minute,
	}
	s.manualSelected.Store(pinnedTag)
	outbounds := makeStubs(tags...)
	// Register a state snapshot so state-reads don't NPE downstream.
	s.state.Store(&smartGroupState{outbounds: outbounds, tags: tags})
	// History is needed by isAlive; provide a noop storage.
	s.history = urltest.NewHistoryStorage()
	return s, outbounds
}

// TestPinBypass_HealthyPinReturned: pinned node is alive and breaker
// closed → selectProxiesTraced returns the single pinned node.
func TestPinBypass_HealthyPinReturned(t *testing.T) {
	s, obs := selectProxiesStub(t, []string{"A", "B", "C"}, "A")
	// Seed a recent URLTestHistory so isAlive reports true for A.
	s.history.StoreURLTestHistory("A", &adapter.URLTestHistory{
		Time: time.Now(), Delay: 100,
	})
	got, isUnwrap, source := s.selectProxiesTraced(nil, obs, false)
	if source != "manual" {
		t.Fatalf("source = %q, want manual", source)
	}
	if !isUnwrap {
		t.Fatal("isUnwrap = false, want true (manual returns wrapped list)")
	}
	if len(got) != 1 || got[0].Tag() != "A" {
		t.Fatalf("got %+v, want [A]", tagsOf(got))
	}
}

// TestPinBypass_DeadPinBypasses: pinned node in knownDead → path
// falls through to algorithm, pin state stays intact for recovery.
func TestPinBypass_DeadPinBypasses(t *testing.T) {
	s, obs := selectProxiesStub(t, []string{"A", "B", "C"}, "A")
	s.knownDead.Store("A", time.Now()) // A is marked dead
	// B has fresh URLTest data → alive; delay ranking prefers it.
	s.history.StoreURLTestHistory("B", &adapter.URLTestHistory{
		Time: time.Now(), Delay: 80,
	})

	got, _, source := s.selectProxiesTraced(nil, obs, false)
	if source == "manual" {
		t.Fatalf("should have bypassed manual, got source=%q result=%+v",
			source, tagsOf(got))
	}
	// The pin state must be preserved so a later recovery snaps back.
	if pin := s.getManualSelected(); pin != "A" {
		t.Fatalf("pin lost during bypass: %q, want A", pin)
	}
}

// TestPinBypass_BreakerOpenBypasses: pinned node has an open circuit
// breaker → bypass path. Mirrors what happens right after the
// watchdog tallies enough RSTs to trip the breaker.
func TestPinBypass_BreakerOpenBypasses(t *testing.T) {
	s, obs := selectProxiesStub(t, []string{"A", "B"}, "A")
	// Trip A's breaker: open for 15 s.
	cb := &circuitBreakerState{}
	cb.openUntil.Store(time.Now().Add(15 * time.Second).UnixNano())
	s.breakers.Store("A", cb)
	s.history.StoreURLTestHistory("B", &adapter.URLTestHistory{
		Time: time.Now(), Delay: 80,
	})

	got, _, source := s.selectProxiesTraced(nil, obs, false)
	if source == "manual" {
		t.Fatalf("breaker-open pin must bypass; got source=%q result=%+v",
			source, tagsOf(got))
	}
	if pin := s.getManualSelected(); pin != "A" {
		t.Fatalf("pin lost: %q", pin)
	}
}

// TestPinBypass_RecoverySnapBack: pin briefly bypassed due to
// knownDead → node recovers (entry cleared) → next selectProxiesTraced
// honours the pin again.
func TestPinBypass_RecoverySnapBack(t *testing.T) {
	s, obs := selectProxiesStub(t, []string{"A", "B"}, "A")
	s.knownDead.Store("A", time.Now())
	s.history.StoreURLTestHistory("B", &adapter.URLTestHistory{
		Time: time.Now(), Delay: 80,
	})

	// First selection: bypass.
	_, _, srcBypass := s.selectProxiesTraced(nil, obs, false)
	if srcBypass == "manual" {
		t.Fatal("expected bypass on dead pin")
	}
	// Simulate recovery: clear knownDead + register URLTest history.
	s.knownDead.Delete("A")
	s.history.StoreURLTestHistory("A", &adapter.URLTestHistory{
		Time: time.Now(), Delay: 100,
	})

	got, _, srcRecover := s.selectProxiesTraced(nil, obs, false)
	if srcRecover != "manual" {
		t.Fatalf("expected snap-back to manual after recovery; got %q", srcRecover)
	}
	if len(got) != 1 || got[0].Tag() != "A" {
		t.Fatalf("snap-back returned %+v, want [A]", tagsOf(got))
	}
}

// TestPinBypass_NonExistentPinCleared: pinned tag that no longer
// matches any outbound gets cleared automatically.
func TestPinBypass_NonExistentPinCleared(t *testing.T) {
	s, obs := selectProxiesStub(t, []string{"B", "C"}, "GONE")
	s.history.StoreURLTestHistory("B", &adapter.URLTestHistory{
		Time: time.Now(), Delay: 50,
	})

	_, _, source := s.selectProxiesTraced(nil, obs, false)
	if source == "manual" {
		t.Fatal("pin pointed to non-existent node; should not have returned manual")
	}
	if pin := s.getManualSelected(); pin != "" {
		t.Fatalf("pin should be cleared for non-existent tag, got %q", pin)
	}
}

func tagsOf(obs []adapter.Outbound) []string {
	out := make([]string, len(obs))
	for i, o := range obs {
		out[i] = o.Tag()
	}
	return out
}
