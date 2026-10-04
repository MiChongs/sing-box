package group

import (
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
)

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

// TestFirstByteDeadline_ArmedAtFirstWriteAndDisarmed proves the
// first-byte deadline reaches the underlying conn only once the client
// has written, and is cleared again exactly once.
func TestFirstByteDeadline_ArmedAtFirstWriteAndDisarmed(t *testing.T) {
	fake := &deadlineTrackingFake{fakeNetConn: &fakeNetConn{}}
	c := &smartTrackedConn{Conn: fake}
	if len(fake.deadlines) != 0 {
		t.Fatalf("deadline armed before any write: %+v", fake.deadlines)
	}
	before := time.Now()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if len(fake.deadlines) != 1 {
		t.Fatalf("SetReadDeadline call count = %d, want 1", len(fake.deadlines))
	}
	got := fake.deadlines[0]
	if got.Before(before.Add(firstByteWatchdogTimeout-time.Second)) || got.After(before.Add(firstByteWatchdogTimeout+time.Second)) {
		t.Fatalf("deadline = %v, want within %v±1s of %v", got, firstByteWatchdogTimeout, before)
	}
	if _, err := c.Write([]byte("again")); err != nil {
		t.Fatal(err)
	}
	if len(fake.deadlines) != 1 {
		t.Fatalf("later writes re-armed the deadline: %+v", fake.deadlines)
	}
	c.disarmFirstByteDeadline()
	c.disarmFirstByteDeadline()
	if len(fake.deadlines) != 2 || !fake.deadlines[1].IsZero() {
		t.Fatalf("expected exactly one zero-time disarm, got %+v", fake.deadlines)
	}
}

// TestTrackedConn_LongActiveStreamKeepsReading guards against the read
// deadline outliving the first byte: a stream that keeps delivering data
// past the first-byte budget must never see a timeout.
func TestTrackedConn_LongActiveStreamKeepsReading(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	streamFor := 2500 * time.Millisecond
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 16)
		if _, err := conn.Read(buffer); err != nil {
			return
		}
		for start := time.Now(); time.Since(start) < streamFor; {
			if _, err := conn.Write([]byte{1}); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	s := newTestSmartForWatchdog(t)
	s.history = urltest.NewHistoryStorage()
	// 1 ms URL-test delay: the adaptive first-byte budget bottoms out at
	// 1.5 s, shorter than the stream.
	s.history.StoreURLTestHistory("node", &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	c := &smartTrackedConn{Conn: raw, s: s, proxyTag: "node", meta: &smartDialMeta{}, startTime: time.Now()}
	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	buffer := make([]byte, 64)
	for time.Since(start) < streamFor-200*time.Millisecond {
		if _, err := c.Read(buffer); err != nil {
			t.Fatalf("read failed after %v of active streaming: %v", time.Since(start), err)
		}
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
	// First call records one event — well below threshold (=2).
	if !s.triggerInstantResetEviction(c, "read", errors.New("connection reset by peer")) {
		t.Fatal("first trigger should run")
	}
	// Tracker should have ONE event for (target, node).
	s.resetEvents.mu.Lock()
	got := s.resetEvents.events.count("below.example", "node-Y")
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
	closed     atomic.Bool
	closeCount atomic.Int32
}

func (f *fakeNetConn) Read([]byte) (int, error)         { select {} }
func (f *fakeNetConn) Write(p []byte) (int, error)      { return len(p), nil }
func (f *fakeNetConn) Close() error                     { f.closeCount.Add(1); f.closed.Store(true); return nil }
func (f *fakeNetConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (f *fakeNetConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (f *fakeNetConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeNetConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeNetConn) SetWriteDeadline(time.Time) error { return nil }

// newTestSmartForWatchdog assembles a minimal Smart with the few
// fields the watchdog and the reset-eviction path touch.
func newTestSmartForWatchdog(t *testing.T) *Smart {
	t.Helper()
	return &Smart{
		logger:        log.NewNOPFactory().NewLogger("smart"),
		targetConns:   map[string]map[*smartTrackedConn]struct{}{},
		nodeLoad:      newNodeLoadCounter(),
		resetEvents:   newResetEventTracker(),
		targetDebargo: xsync.NewMapOf[string, time.Time](),
	}
}

// stageConn drops a fake conn into the per-target registry as if a dial
// had just succeeded; tests then set its IO timestamps.
func stageConn(s *Smart, target, tag string) (*smartTrackedConn, *fakeNetConn) {
	fake := &fakeNetConn{}
	c := &smartTrackedConn{
		Conn:        fake,
		s:           s,
		proxyTag:    tag,
		meta:        &smartDialMeta{smartTarget: target},
		connectTime: 50,
		startTime:   time.Now().Add(-time.Hour),
	}
	s.targetConns[target] = map[*smartTrackedConn]struct{}{c: {}}
	s.targetConnsCount.Add(1)
	return c, fake
}

func ago(d time.Duration) int64 {
	return time.Now().Add(-d).UnixNano()
}

// TestWatchdog_FirstByteTimeoutClosesAndSwitches: the client wrote but no
// first byte came back within the budget — the conn is closed and the
// (target, node) reset event tallied.
func TestWatchdog_FirstByteTimeoutClosesAndSwitches(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	c, fake := stageConn(s, "stalled.example", "node-A")
	c.firstWriteAt.Store(ago(firstByteWatchdogTimeout + 2*time.Second))

	s.runStalledConnWatchdog()

	if !fake.closed.Load() {
		t.Fatal("watchdog did not close stalled fake conn")
	}
	s.resetEvents.mu.Lock()
	events := s.resetEvents.events.count("stalled.example", "node-A")
	s.resetEvents.mu.Unlock()
	if events != 1 {
		t.Fatalf("reset events = %d, want 1", events)
	}
}

// TestWatchdog_SilentClientNotClosed: a conn the client never wrote on
// (preconnect, server-speaks-first) is not waiting for a byte.
func TestWatchdog_SilentClientNotClosed(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	_, fake := stageConn(s, "preconnect.example", "node-C")

	s.runStalledConnWatchdog()

	if fake.closed.Load() {
		t.Fatal("watchdog closed a conn the client has not written on")
	}
}

// TestWatchdog_FreshRequestNotClosed: the first-byte budget has not
// elapsed since the first write.
func TestWatchdog_FreshRequestNotClosed(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	c, fake := stageConn(s, "fresh.example", "node-C")
	c.firstWriteAt.Store(ago(firstByteWatchdogTimeout / 2))

	s.runStalledConnWatchdog()

	if fake.closed.Load() {
		t.Fatal("watchdog closed a conn still inside its first-byte window")
	}
}

// TestWatchdog_TransferStalledClosesAndSwitches: after the first byte,
// a write went unanswered for longer than stalledTransferTimeout.
func TestWatchdog_TransferStalledClosesAndSwitches(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	c, fake := stageConn(s, "stalled.example", "node-B")
	c.firstReadOnce.Store(true)
	c.lastReadAt.Store(ago(stalledTransferTimeout + 10*time.Second))
	c.lastWriteAt.Store(ago(stalledTransferTimeout + 5*time.Second))

	s.runStalledConnWatchdog()

	if !fake.closed.Load() {
		t.Fatal("watchdog did not close stalled-transfer fake conn")
	}
}

// TestWatchdog_IdleConnNotClosed: a keep-alive / websocket / push conn
// that has been quiet for long with every write answered is healthy.
func TestWatchdog_IdleConnNotClosed(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	c, fake := stageConn(s, "idle.example", "node-D")
	c.firstReadOnce.Store(true)
	c.lastWriteAt.Store(ago(3 * stalledTransferTimeout))
	c.lastReadAt.Store(ago(2 * stalledTransferTimeout))

	s.runStalledConnWatchdog()

	if fake.closed.Load() {
		t.Fatal("watchdog closed an idle conn")
	}
}

// TestWatchdog_ActiveTransferNotClosed: the latest write is recent.
func TestWatchdog_ActiveTransferNotClosed(t *testing.T) {
	s := newTestSmartForWatchdog(t)
	c, fake := stageConn(s, "active.example", "node-D")
	c.firstReadOnce.Store(true)
	c.lastReadAt.Store(ago(2 * time.Second))
	c.lastWriteAt.Store(ago(time.Second))

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
	c, fake := stageConn(s, "tw.example", "node-E")
	c.firstWriteAt.Store(ago(firstByteWatchdogTimeout + 2*time.Second))

	s.runStalledConnWatchdog()
	s.runStalledConnWatchdog()

	if !c.watchdogTriggered.Load() {
		t.Fatal("watchdogTriggered flag not set after first scan")
	}
	if got := fake.closeCount.Load(); got != 1 {
		t.Fatalf("conn closed %d times, want 1", got)
	}
}
