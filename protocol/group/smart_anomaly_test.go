package group

import (
	"errors"
	"fmt"
	"io"
	"syscall"
	"testing"
	"time"
)

// TestIsResetErr_ClassificationMatrix locks down which errors must
// trigger ERR_CONNECTION_RESET-style handling. The matrix covers the
// happy paths (clean half-close → false), the reset paths (true), and
// the wrapped-error paths (substring fallback for libraries that
// hide the underlying syscall).
func TestIsResetErr_ClassificationMatrix(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"eof_clean", io.EOF, false},
		{"unexpected_eof", io.ErrUnexpectedEOF, false},
		{"econnreset", syscall.ECONNRESET, true},
		{"epipe", syscall.EPIPE, true},
		{"econnaborted", syscall.ECONNABORTED, true},
		{"wrapped_econnreset", fmt.Errorf("write tcp 1.2.3.4:443: %w", syscall.ECONNRESET), true},
		{"substring_reset_by_peer", errors.New("read tcp 10.0.0.1:443: connection reset by peer"), true},
		{"substring_broken_pipe", errors.New("write: broken pipe"), true},
		{"substring_windows_forcibly", errors.New("read tcp 10.0.0.1:443: An existing connection was forcibly closed by the remote host."), true},
		{"unrelated_timeout", errors.New("i/o timeout"), false},
		{"unrelated_dns", errors.New("no such host"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isResetErr(c.err); got != c.want {
				t.Fatalf("isResetErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// TestResetEventTracker_ThresholdCrossing pushes events one at a time
// and asserts the tracker reports false up to threshold-1, then true
// on threshold, then false again on the immediate next push (the
// crossing handler "resets the slot" so a single spike doesn't ban
// the same node twice in a row).
func TestResetEventTracker_ThresholdCrossing(t *testing.T) {
	tr := newResetEventTracker()
	const target, node = "example.com", "node-A"

	// First (threshold-1) events must NOT cross.
	for i := 0; i < resetEventThreshold-1; i++ {
		if tr.record(target, node) {
			t.Fatalf("crossed too early on event #%d (threshold=%d)", i+1, resetEventThreshold)
		}
	}
	// The threshold-th event MUST cross.
	if !tr.record(target, node) {
		t.Fatalf("threshold-th event didn't cross")
	}
	// Slot is wiped after crossing → next event starts fresh.
	if tr.record(target, node) {
		t.Fatalf("immediate post-crossing event should NOT cross again")
	}
}

// TestResetEventTracker_WindowExpiry verifies that events older than
// resetEventWindow are dropped from the slot — a node that misbehaved
// long ago shouldn't get banned for a SINGLE recent reset.
func TestResetEventTracker_WindowExpiry(t *testing.T) {
	tr := newResetEventTracker()
	const target, node = "example.com", "node-A"
	key := target + "|" + node
	// Stage one ancient event manually so we don't have to wait 60 s.
	tr.events[key] = []time.Time{time.Now().Add(-2 * resetEventWindow)}
	// A fresh single event must NOT cross — the ancient one is
	// outside the window and gets pruned by record().
	if tr.record(target, node) {
		t.Fatalf("should not cross with one fresh + one expired event")
	}
}

// TestResetEventTracker_PerNodeIsolation ensures (target, node) is the
// counter granularity — a storm of resets against node B on target T
// must not advance node A's counter on the same target. We assert by
// inspecting the slot length directly so the assertion is independent
// of where the threshold happens to be set.
func TestResetEventTracker_PerNodeIsolation(t *testing.T) {
	tr := newResetEventTracker()
	tr.record("T", "A") // one event for A
	// Storm B until just under threshold, then one more to cross.
	for i := 0; i < resetEventThreshold-1; i++ {
		if tr.record("T", "B") {
			t.Fatalf("B crossed at i=%d before its own threshold", i)
		}
	}
	if !tr.record("T", "B") {
		t.Fatalf("B should cross on its threshold-th event")
	}
	// B's slot was wiped on crossing; A's should still hold exactly
	// one event — proving the storm didn't bleed across the per-node
	// counter boundary.
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if got := len(tr.events["T|A"]); got != 1 {
		t.Fatalf("A's event count = %d, want 1 (must be unaffected by B's storm)", got)
	}
	if _, present := tr.events["T|B"]; present {
		t.Fatalf("B's slot should be wiped after threshold crossing")
	}
}

// TestResetEventTracker_ResetForNode confirms node-scoped purge clears
// every (target, node) slot for the named tag without disturbing
// other nodes' counters.
func TestResetEventTracker_ResetForNode(t *testing.T) {
	tr := newResetEventTracker()
	tr.record("T1", "A")
	tr.record("T2", "A")
	tr.record("T1", "B")
	tr.resetForNode("A")
	// A's slots gone; B's stays.
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if _, exists := tr.events["T1|A"]; exists {
		t.Errorf("T1|A not cleared after resetForNode(A)")
	}
	if _, exists := tr.events["T2|A"]; exists {
		t.Errorf("T2|A not cleared after resetForNode(A)")
	}
	if _, exists := tr.events["T1|B"]; !exists {
		t.Errorf("T1|B should still be present (different node)")
	}
}
