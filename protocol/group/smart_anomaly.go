package group

import (
	"errors"
	"io"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Connection-anomaly detection layer.
//
// The pre-existing shortLife mechanism catches "user gave up quickly"
// patterns (page closed in 2 s, almost no bytes transferred). It does
// NOT catch the equally important upstream-side anomaly: the proxy node
// dialled OK, but mid-stream the upstream sent TCP RST or the local
// kernel reported broken pipe (manifests as ERR_CONNECTION_RESET in the
// browser). That is a much stronger "this node is broken right now"
// signal than a short-life close — a clean RST in the middle of a
// transfer is almost never the user's fault.
//
// We track those events on the same (target, node) granularity used by
// shortLife, with a tighter threshold (2 events instead of 3) because
// false positives from a single transient TLS reset are acceptable —
// the node is still alive, it just gets demoted for a cooldown
// window and the user's next dial picks a different one.
//
// On threshold crossing the caller marks the node dead, drops the
// unwrap cache so the very next dial re-evaluates candidates, and
// kicks an asynchronous ranking refresh so /weights and selection
// converge to the new reality before the next user request.

const (
	resetEventThreshold = 2                // events before banning the node
	resetEventWindow    = 60 * time.Second // sliding-window length
)

// resetEventTracker mirrors the shortLife pattern but for upstream
// resets. Embedded into Smart at construction so the dial hot path can
// reach it without a lock-walk through the parent struct.
type resetEventTracker struct {
	mu     sync.Mutex
	events map[string][]time.Time // key = "target|node"
}

func newResetEventTracker() *resetEventTracker {
	return &resetEventTracker{events: make(map[string][]time.Time, 64)}
}

// record adds one reset event for (target, node) and reports true when
// the count within resetEventWindow has just crossed the threshold —
// caller takes decisive action (markDead + cache invalidation +
// ranking kick). On crossing we DROP the slot so a single spike isn't
// counted twice in a row.
//
// Empty target/node short-circuits to false; it's harmless and
// prevents accidentally banning a node based on a half-initialised
// dial path that never recorded its target.
func (t *resetEventTracker) record(target, node string) (crossed bool) {
	if target == "" || node == "" {
		return false
	}
	key := target + "|" + node
	now := time.Now()
	cutoff := now.Add(-resetEventWindow)

	t.mu.Lock()
	defer t.mu.Unlock()

	old := t.events[key]
	kept := old[:0]
	for _, ts := range old {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, now)
	t.events[key] = kept
	if len(kept) >= resetEventThreshold {
		delete(t.events, key)
		return true
	}
	return false
}

// reset clears every recorded event — invoked from FlushStore and on
// markAlive so a recovered node starts with a fresh window.
func (t *resetEventTracker) reset() {
	t.mu.Lock()
	t.events = make(map[string][]time.Time, 64)
	t.mu.Unlock()
}

// resetForNode drops every (target, node) slot for the given node tag.
// Cheaper than .reset() when only one node has recovered. Safe to call
// concurrently with record().
func (t *resetEventTracker) resetForNode(node string) {
	if node == "" {
		return
	}
	suffix := "|" + node
	t.mu.Lock()
	for k := range t.events {
		if strings.HasSuffix(k, suffix) {
			delete(t.events, k)
		}
	}
	t.mu.Unlock()
}

// isResetErr reports whether err looks like an upstream-initiated TCP
// reset / broken-pipe / forcibly-closed scenario — the kind of error
// that maps to ERR_CONNECTION_RESET in the browser. Cross-platform:
//
//   - syscall.ECONNRESET / syscall.EPIPE on Unix
//   - syscall.WSAECONNRESET / WSAECONNABORTED on Windows (matched by
//     errno value via errors.Is on the wrapped *net.OpError)
//   - net.ErrClosed (local close after a half-open) — NOT counted as
//     reset (caller closed the connection deliberately)
//   - io.EOF / io.ErrUnexpectedEOF — NOT reset (clean half-close)
//
// We also string-match a small set of well-known reset markers because
// gvisor / utls / quic-go wrap syscall errors in their own types that
// don't always satisfy errors.Is(syscall.ECONNRESET); the substring
// fallback catches those without having to enumerate every wrapper.
func isResetErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	// Substring match for wrapper types that don't propagate the
	// underlying syscall errno. Lower-case once for cheap comparison.
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"connection reset by peer",
		"connection reset",
		"broken pipe",
		"forcibly closed",            // Windows-friendly
		"forcibly closed by the remote", // Windows: WSAECONNRESET text
		"reset by peer",
		"connection aborted",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
