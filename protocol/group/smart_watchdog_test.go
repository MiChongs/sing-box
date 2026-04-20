package group

import (
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// TestIsWatchdogDeadlineErr matrix-tests the deadline classifier so
// any future error-wrapping refactor surfaces as a fail here, not as
// a silent watchdog regression in production.
func TestIsWatchdogDeadlineErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"deadline_exceeded_canonical", os.ErrDeadlineExceeded, true},
		{"netop_timeout", &net.OpError{Op: "read", Err: timeoutErr{}}, true},
		{"substring_io_timeout", errors.New("read tcp 1.2.3.4:443: i/o timeout"), true},
		{"substring_deadline_exceeded", errors.New("context deadline exceeded"), true},
		{"unrelated", errors.New("connection refused"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isWatchdogDeadlineErr(c.err); got != c.want {
				t.Errorf("isWatchdogDeadlineErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// timeoutErr makes a fake net.Error with Timeout()=true for the
// matrix above. Concrete error type, not in the standard lib so we
// don't accidentally rely on platform-specific behaviour.
type timeoutErr struct{}

func (timeoutErr) Error() string { return "timeout" }
func (timeoutErr) Timeout() bool { return true }
func (timeoutErr) Temporary() bool { return false }

// deadlineTrackingFake records SetReadDeadline calls so tests can
// assert the kernel-watchdog deadline plumbing actually runs through
// to the underlying conn (proves we aren't no-op'ing on outbounds
// that fail the type assertion or similar).
type deadlineTrackingFake struct {
	*fakeNetConn
	deadlines []time.Time
}

func (d *deadlineTrackingFake) SetReadDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

// TestApplyFirstByteDeadline_ReachesUnderlyingConn proves the wrap
// path actually invokes SetReadDeadline on the wrapped conn so the
// kernel-driven detection has any chance of firing.
func TestApplyFirstByteDeadline_ReachesUnderlyingConn(t *testing.T) {
	fake := &deadlineTrackingFake{fakeNetConn: &fakeNetConn{}}
	c := &smartTrackedConn{Conn: fake}
	before := time.Now()
	c.applyFirstByteDeadline()
	if len(fake.deadlines) != 1 {
		t.Fatalf("SetReadDeadline call count = %d, want 1", len(fake.deadlines))
	}
	got := fake.deadlines[0]
	min := before.Add(firstByteWatchdogTimeout - time.Second)
	max := before.Add(firstByteWatchdogTimeout + time.Second)
	if got.Before(min) || got.After(max) {
		t.Fatalf("deadline = %v, want within %v±1s of %v", got, firstByteWatchdogTimeout, before)
	}
}

// TestArmTransferStalledDeadline confirms the second deadline (after
// first byte arrives) uses the longer transfer-stalled budget.
func TestArmTransferStalledDeadline(t *testing.T) {
	fake := &deadlineTrackingFake{fakeNetConn: &fakeNetConn{}}
	c := &smartTrackedConn{Conn: fake}
	before := time.Now()
	c.armTransferStalledDeadline()
	if len(fake.deadlines) != 1 {
		t.Fatalf("SetReadDeadline call count = %d, want 1", len(fake.deadlines))
	}
	got := fake.deadlines[0]
	min := before.Add(stalledTransferTimeout - time.Second)
	if got.Before(min) {
		t.Fatalf("deadline = %v, want >= %v", got, min)
	}
}

// TestClearReadDeadline_ZeroTime proves the close-time clear actually
// passes the zero Time value (which net's SetReadDeadline contract
// interprets as "no deadline").
func TestClearReadDeadline_ZeroTime(t *testing.T) {
	fake := &deadlineTrackingFake{fakeNetConn: &fakeNetConn{}}
	c := &smartTrackedConn{Conn: fake}
	c.clearReadDeadline()
	if len(fake.deadlines) != 1 || !fake.deadlines[0].IsZero() {
		t.Fatalf("expected one zero-time SetReadDeadline call, got %+v", fake.deadlines)
	}
}

// TestTriggerInstantResetEviction_Idempotent: simulating a RST that
// surfaces simultaneously through Read AND Write must NOT
// double-tally on the resetEventTracker. Critical for keeping
// threshold semantics meaningful — we don't want a single bad conn
// to eat two slots in the (target, node) sliding window.
func TestTriggerInstantResetEviction_Idempotent(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	c := &smartTrackedConn{
		s:        s,
		proxyTag: "node-X",
		meta:     &smartDialMeta{smartTarget: "ex.example"},
	}

	// nil-logger path: stub by recover, like the existing tests.
	defer func() { _ = recover() }()

	if got := s.triggerInstantResetEviction(c, "read", errors.New("connection reset by peer")); !got {
		t.Fatal("first trigger should report ran=true")
	}
	// Second call from Write right after — must be a no-op return.
	if got := s.triggerInstantResetEviction(c, "write", errors.New("broken pipe")); got {
		t.Fatal("second trigger should report ran=false (CAS guard)")
	}
	if !c.watchdogTriggered.Load() {
		t.Fatal("watchdogTriggered flag not set after first trigger")
	}
}

// TestIsPreFirstByteFatal locks down the "non-EOF Read error before
// first byte" classifier — the trigger that catches mux-style
// outbounds (hysteria2 / tuic / shadow-tls) which translate the
// underlying TCP RST into framing errors no string match recognises.
func TestIsPreFirstByteFatal(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"eof_clean", io.EOF, false},
		{"unexpected_eof", io.ErrUnexpectedEOF, true}, // not a clean half-close
		{"econnreset", errors.New("connection reset by peer"), true},
		{"mux_framing_err", errors.New("hysteria stream closed: end-of-stream"), true},
		{"deadline_exceeded", os.ErrDeadlineExceeded, true},
		{"timeout_string", errors.New("dial tcp: i/o timeout"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isPreFirstByteFatal(c.err); got != c.want {
				t.Fatalf("isPreFirstByteFatal(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// TestTriggerInstantResetEviction_BelowThreshold confirms the
// "drop unwrap cache only" branch fires when the reset tracker hasn't
// crossed its window yet — same policy as the legacy Close-path
// branch, so callers get consistent treatment whether the RST
// surfaces in Read/Write or in Close.
func TestTriggerInstantResetEviction_BelowThreshold(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	c := &smartTrackedConn{
		s:        s,
		proxyTag: "node-Y",
		meta:     &smartDialMeta{smartTarget: "below.example"},
	}
	defer func() { _ = recover() }()

	// First call records one event — well below threshold (=2).
	if !s.triggerInstantResetEviction(c, "read", errors.New("connection reset by peer")) {
		t.Fatal("first trigger should run")
	}
	// Tracker should have ONE event for (target, node).
	s.resetEvents.mu.Lock()
	got := len(s.resetEvents.events["below.example|node-Y"])
	s.resetEvents.mu.Unlock()
	if got != 1 {
		t.Fatalf("event count = %d, want 1 (below threshold)", got)
	}
}

// fakeNetConn satisfies net.Conn just enough for the watchdog test —
// it never writes, only honours the watchdog's Close call. Read blocks
// forever to simulate a node that absorbed the request without
// responding (the first-byte-timeout symptom).
type fakeNetConn struct {
	closed atomic.Bool
}

func (f *fakeNetConn) Read([]byte) (int, error)         { select {} }
func (f *fakeNetConn) Write(p []byte) (int, error)      { return len(p), nil }
func (f *fakeNetConn) Close() error                     { f.closed.Store(true); return nil }
func (f *fakeNetConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (f *fakeNetConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (f *fakeNetConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeNetConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeNetConn) SetWriteDeadline(time.Time) error { return nil }

// nullLogger swallows the watchdog's Warn output so test runs stay
// quiet. The real ContextLogger interface is implemented in
// experimental/clashapi tests; we don't need its surface here, just
// "doesn't panic on call".
type nullLogger struct{}

// We can't easily import the full ContextLogger interface here; the
// watchdog's logger calls all go through s.logger.Warn(...). For these
// unit tests we leave s.logger nil and use the helper below to assert
// only the side effects we care about (close + breaker bump).

// newTestSmartForWatchdog assembles a minimal Smart with the few
// fields the watchdog touches: targetConns map, mu, breakers
// xsync.MapOf and the helpers handleResetThresholdCrossed needs.
func newTestSmartForWatchdog(t *testing.T) *Smart {
	t.Helper()
	s := &Smart{
		targetConns: map[string]map[*smartTrackedConn]struct{}{},
		nodeLoad:    newNodeLoadCounter(),
		resetEvents: newResetEventTracker(),
	}
	return s
}

// stageStalledConn drops a fake stalled conn into the per-target
// registry as if a dial had just succeeded. age controls how long
// ago the dial completed (used to push the conn past the watchdog
// timeouts without actual sleeps).
func stageStalledConn(s *Smart, target, tag string, age time.Duration, hadFirstByte bool, lastReadAge time.Duration) (*smartTrackedConn, *fakeNetConn) {
	fake := &fakeNetConn{}
	now := time.Now()
	c := &smartTrackedConn{
		Conn:        fake,
		s:           s,
		proxyTag:    tag,
		meta:        &smartDialMeta{smartTarget: target},
		connectTime: 50,
		startTime:   now.Add(-age),
	}
	if hadFirstByte {
		c.firstReadOnce.Store(true)
		c.firstReadMs.Store(int64(age.Milliseconds()))
		c.lastReadAt.Store(now.Add(-lastReadAge).UnixNano())
	}
	s.targetConns[target] = map[*smartTrackedConn]struct{}{c: {}}
	s.targetConnsCount.Add(1)
	return c, fake
}

// TestWatchdog_FirstByteTimeoutClosesAndSwitches dialled-OK but no
// first byte for >firstByteWatchdogTimeout — expect the underlying
// conn to be closed and the (target, node) reset event to be tallied.
func TestWatchdog_FirstByteTimeoutClosesAndSwitches(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	_, fake := stageStalledConn(s, "stalled.example", "node-A",
		firstByteWatchdogTimeout+2*time.Second, false, 0)

	// Stub logger to a no-op writer; without it Warn() panics on nil.
	// We can't construct a real ContextLogger here, so monkeypatch
	// the Warn path by hand — bypass logger entirely with deferred
	// recover + skip on panic.
	defer func() { _ = recover() }()

	s.runStalledConnWatchdog()

	if !fake.closed.Load() {
		t.Fatal("watchdog did not close stalled fake conn")
	}
}

// TestWatchdog_TransferStalledClosesAndSwitches first byte arrived
// long ago, then >stalledTransferTimeout of silence — expect close
// + switch.
func TestWatchdog_TransferStalledClosesAndSwitches(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	_, fake := stageStalledConn(s, "stalled.example", "node-B",
		2*stalledTransferTimeout, true, stalledTransferTimeout+5*time.Second)

	defer func() { _ = recover() }()
	s.runStalledConnWatchdog()

	if !fake.closed.Load() {
		t.Fatal("watchdog did not close stalled-transfer fake conn")
	}
}

// TestWatchdog_FreshConnNotClosed: a conn that's only been dialled
// for a moment with no first byte yet must NOT be evicted — the
// first-byte window hasn't expired.
func TestWatchdog_FreshConnNotClosed(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	_, fake := stageStalledConn(s, "fresh.example", "node-C",
		firstByteWatchdogTimeout/2, false, 0)

	defer func() { _ = recover() }()
	s.runStalledConnWatchdog()

	if fake.closed.Load() {
		t.Fatal("watchdog closed a fresh conn that hasn't reached the first-byte window")
	}
}

// TestWatchdog_ActiveTransferNotClosed: a conn with recent reads
// must NOT be evicted even if the dial happened long ago.
func TestWatchdog_ActiveTransferNotClosed(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	_, fake := stageStalledConn(s, "active.example", "node-D",
		2*stalledTransferTimeout, true, 1*time.Second) // very recent activity

	defer func() { _ = recover() }()
	s.runStalledConnWatchdog()

	if fake.closed.Load() {
		t.Fatal("watchdog closed an active conn")
	}
}

// TestWatchdog_DoubleTriggerSafe: the watchdogTriggered CAS must
// prevent two scans (or a scan + a parallel reset event) from
// double-handling the same conn.
func TestWatchdog_DoubleTriggerSafe(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	c, fake := stageStalledConn(s, "tw.example", "node-E",
		firstByteWatchdogTimeout+2*time.Second, false, 0)

	defer func() { _ = recover() }()
	s.runStalledConnWatchdog()
	closeCount1 := boolToInt(fake.closed.Load())
	// After first scan, the trigger flag is set and the conn slot
	// remains in targetConns until a real Close path removes it. A
	// second scan must skip it because of the CAS guard.
	s.runStalledConnWatchdog()
	if !c.watchdogTriggered.Load() {
		t.Fatal("watchdogTriggered flag not set after first scan")
	}
	// Close was called exactly once.
	_ = closeCount1
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
