package group

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// TestTargetHitTracker_CountsAndTopK exercises the hit counter and
// the top-K extraction used by the periodic probe task. Key
// invariants: counts accumulate, order is by frequency descending,
// k > len returns all.
func TestTargetHitTracker_CountsAndTopK(t *testing.T) {
	h := newTargetHitTracker()

	// Hit distribution: a ×10, b ×3, c ×1, d ×7, e ×5.
	for i := 0; i < 10; i++ {
		h.recordHit("a")
	}
	for i := 0; i < 3; i++ {
		h.recordHit("b")
	}
	h.recordHit("c")
	for i := 0; i < 7; i++ {
		h.recordHit("d")
	}
	for i := 0; i < 5; i++ {
		h.recordHit("e")
	}

	top3 := h.topK(3)
	want := []string{"a", "d", "e"}
	if len(top3) != len(want) {
		t.Fatalf("top3 len = %d, want %d", len(top3), len(want))
	}
	for i := range want {
		if top3[i] != want[i] {
			t.Errorf("top3[%d] = %q, want %q", i, top3[i], want[i])
		}
	}

	// k larger than population — returns everything, still sorted.
	all := h.topK(99)
	if len(all) != 5 {
		t.Fatalf("topK(99) returned %d, want 5", len(all))
	}
	if all[0] != "a" || all[len(all)-1] != "c" {
		t.Errorf("topK order wrong: %v", all)
	}
}

// TestTargetHitTracker_EmptyAndZero edge cases.
func TestTargetHitTracker_EmptyAndZero(t *testing.T) {
	h := newTargetHitTracker()
	if got := h.topK(5); got != nil {
		t.Fatalf("empty tracker topK = %v, want nil", got)
	}
	if got := h.topK(0); got != nil {
		t.Fatalf("topK(0) = %v, want nil", got)
	}
	h.recordHit("") // should be no-op
	if got := h.topK(5); got != nil {
		t.Fatalf("empty-string hit should not register, got %v", got)
	}
}

// TestRecordSNIProbeAndSuspicious covers the probe history side of
// isTargetSuspicious: a recent failing probe must flip the node to
// suspicious; a recent success must NOT; an expired entry (outside
// sniProbeTTL) must NOT.
func TestRecordSNIProbeAndSuspicious(t *testing.T) {
	s := &Smart{}
	s.initTargetLiveness()

	// Failing probe → suspicious.
	s.recordSNIProbe("example.com:443", "node-A", false, 0)
	if !s.isTargetSuspicious("example.com:443", "node-A") {
		t.Fatal("recent failing probe did not mark node suspicious")
	}

	// Successful probe → NOT suspicious (and overrides previous).
	s.recordSNIProbe("example.com:443", "node-A", true, 120)
	if s.isTargetSuspicious("example.com:443", "node-A") {
		t.Fatal("successful probe should clear suspicion")
	}

	// Manually age the entry past TTL → must NOT be considered.
	s.recordSNIProbe("example.com:443", "node-A", false, 0)
	key := "example.com:443|node-A"
	if v, ok := s.targetLiveness.probeHistory.Load(key); ok {
		v.tsNS = time.Now().Add(-2 * sniProbeTTL).UnixNano()
	}
	if s.isTargetSuspicious("example.com:443", "node-A") {
		t.Fatal("expired probe entry should be ignored")
	}
}

// TestIsTargetSuspicious_NilSafety guards against NPE on the hot
// path: calling on a Smart where initTargetLiveness never ran (e.g.
// unit tests that bypass PostStart) must return false, not panic.
func TestIsTargetSuspicious_NilSafety(t *testing.T) {
	s := &Smart{}
	// No store, no targetLiveness init — all filters should return
	// false gracefully.
	if s.isTargetSuspicious("x:443", "y") {
		t.Fatal("uninitialised Smart should never report suspicious")
	}
}

// TestDeprioritiseSuspicious_PushesSuspiciousTail verifies that when
// some candidates are marked suspicious they get stably pushed to
// the tail while trusted candidates preserve their existing order.
func TestDeprioritiseSuspicious_PushesSuspiciousTail(t *testing.T) {
	s := &Smart{}
	s.initTargetLiveness()
	// Mark B and D as suspicious for target T.
	s.recordSNIProbe("T:443", "B", false, 0)
	s.recordSNIProbe("T:443", "D", false, 0)

	in := makeStubs("A", "B", "C", "D", "E")
	out := s.deprioritiseSuspicious(in, "T:443")

	// Trusted group (original order): A, C, E.
	// Suspicious group (original order): B, D.
	want := []string{"A", "C", "E", "B", "D"}
	if len(out) != len(want) {
		t.Fatalf("len = %d, want %d", len(out), len(want))
	}
	for i, w := range want {
		if out[i].Tag() != w {
			t.Errorf("out[%d] = %q, want %q", i, out[i].Tag(), w)
		}
	}
}

// TestDeprioritiseSuspicious_EmptyTargetNoop: an empty target
// (direct-IP dial with no sniff) skips all suspicion logic — the
// filter is strictly per-target.
func TestDeprioritiseSuspicious_EmptyTargetNoop(t *testing.T) {
	s := &Smart{}
	s.initTargetLiveness()
	in := makeStubs("A", "B", "C")
	out := s.deprioritiseSuspicious(in, "")
	// Must be same slice, same order.
	for i, ob := range in {
		if out[i].Tag() != ob.Tag() {
			t.Fatalf("empty target mutated order: got[%d]=%q want %q",
				i, out[i].Tag(), ob.Tag())
		}
	}
}

// TestDeprioritiseSuspicious_AllSuspiciousKeepsAll: when EVERY node
// is suspicious we still return all of them (never hard-filter to
// empty). This is the safety contract that prevents a broad network
// outage from stranding the request with no candidates.
func TestDeprioritiseSuspicious_AllSuspiciousKeepsAll(t *testing.T) {
	s := &Smart{}
	s.initTargetLiveness()
	s.recordSNIProbe("T:443", "A", false, 0)
	s.recordSNIProbe("T:443", "B", false, 0)
	s.recordSNIProbe("T:443", "C", false, 0)

	in := makeStubs("A", "B", "C")
	out := s.deprioritiseSuspicious(in, "T:443")
	if len(out) != 3 {
		t.Fatalf("all-suspicious must keep all candidates, got %d", len(out))
	}
	// Order preserved within the suspicious group.
	for i, w := range []string{"A", "B", "C"} {
		if out[i].Tag() != w {
			t.Errorf("out[%d] = %q, want %q", i, out[i].Tag(), w)
		}
	}
}

// Ensure adapter.Outbound is used (silences unused-import when no
// other symbol in the test file needs it).
var _ adapter.Outbound = (*stubOutbound)(nil)
