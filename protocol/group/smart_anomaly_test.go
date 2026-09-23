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

// TestIsTransferFatalErr_ClassificationMatrix locks down the wider
// mid-transfer error shapes that must evict the proxy node. Covers
// the three pillars the original isResetErr missed: TLS record-layer
// damage, h2 / QUIC stream termination, proxy-protocol framing errors.
// Also pins the FALSE-POSITIVE guardrails — h2 graceful GOAWAY with
// NO_ERROR, EOF, and io.ErrUnexpectedEOF must NOT trigger.
func TestIsTransferFatalErr_ClassificationMatrix(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		// Negative controls — MUST NOT trigger.
		{"nil", nil, false},
		{"clean EOF", io.EOF, false},
		{"unexpected EOF", io.ErrUnexpectedEOF, false},
		{"h2 graceful GOAWAY", errors.New("http2: server sent GOAWAY and closed the connection; LastStreamID=3, ErrCode=NO_ERROR, debug=\"\""), false},
		{"context cancelled", errors.New("context canceled"), false},
		{"use of closed network", errors.New("use of closed network connection"), false},

		// Pre-existing RST paths — must still trigger (inherited from isResetErr).
		{"ECONNRESET", syscall.ECONNRESET, true},
		{"EPIPE", syscall.EPIPE, true},
		{"connection reset substring", errors.New("read: connection reset by peer"), true},
		{"windows forcibly closed", errors.New("forcibly closed by the remote host"), true},

		// TLS-layer damage — new coverage.
		{"tls bad mac", errors.New("tls: bad record MAC"), true},
		{"tls unexpected message", errors.New("tls: unexpected message"), true},
		{"tls internal error", errors.New("remote error: tls: internal error"), true},
		{"tls handshake failure", errors.New("remote error: tls: handshake failure"), true},
		{"tls alert", errors.New("tls: alert(10): unexpected_message"), true},

		// HTTP/2 termination with non-NO_ERROR code — new coverage.
		{"h2 stream error", errors.New("http2: stream error: stream ID 7; INTERNAL_ERROR"), true},
		{"h2 GOAWAY INTERNAL_ERROR", errors.New("http2: server sent GOAWAY and closed the connection; LastStreamID=5, ErrCode=INTERNAL_ERROR, debug=\"\""), true},
		{"stream closed", errors.New("stream closed"), true},

		// QUIC / mux — new coverage.
		{"quic CRYPTO_ERROR", errors.New("CRYPTO_ERROR (0x10a): tls handshake failed"), true},
		{"quic CONNECTION_CLOSE", errors.New("received CONNECTION_CLOSE: frame encoding error"), true},
		{"quic stream reset", errors.New("stream was reset: 0x10c"), true},
		{"quic application error", errors.New("application error 0x42: server shutting down"), true},

		// Proxy-protocol framing — new coverage.
		{"vmess invalid", errors.New("vmess: invalid response header length"), true},
		{"trojan invalid", errors.New("trojan: invalid authentication"), true},
		{"short read", errors.New("short read while parsing frame"), true},
		{"frame too large", errors.New("frame too large: max 65535 got 131072"), true},
		{"protocol error", errors.New("protocol error: unexpected command byte"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isTransferFatalErr(tc.err)
			if got != tc.want {
				t.Errorf("isTransferFatalErr(%v) = %v; want %v", tc.err, got, tc.want)
			}
		})
	}
}
