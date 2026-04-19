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

// isTransferFatalErr returns true when err observed on a conn that has
// ALREADY produced its first byte indicates the remote (or an in-path
// adversary like the GFW) tore the stream down in an unrecoverable way.
// Superset of isResetErr that additionally catches the "dirty" error
// shapes proxy protocol stacks produce when the real TCP RST arrives
// through a mux/TLS/QUIC/h2 wrapper and the raw errno is lost.
//
// Concrete coverage beyond isResetErr:
//
//   TLS alerts / record-layer damage — a GFW-style in-path RST on an
//     ongoing TLS session typically surfaces to the Go stack as
//     "remote error: tls: ..." or "tls: bad record MAC" / "tls:
//     unexpected message" because the truncated stream fails MAC
//     verification. These are UNRECOVERABLE mid-stream — dropping
//     the node for this target is correct.
//
//   HTTP/2 stream termination — h2 transports translate the underlying
//     RST into "http2: stream error", "stream closed", or a
//     "server sent GOAWAY" frame. The GOAWAY case is only fatal when
//     the error code is non-zero (GRACEFUL=NO_ERROR is normal shutdown
//     and we must NOT misclassify it); we match "goaway" only when
//     combined with a non-NO_ERROR code token.
//
//   QUIC-based outbounds (hysteria2 / tuic) — the stream layer
//     surfaces "CRYPTO_ERROR", "CONNECTION_CLOSE", "stream reset",
//     "application error". All three mean the node's upstream hop
//     tore the tunnel down, not a local timeout.
//
//   Proxy-protocol framing damage — vmess / trojan / shadowsocks
//     decoders commonly report "invalid", "short read",
//     "authentication failed", "frame too large", "protocol error"
//     when their streams are truncated by an upstream RST. We match
//     a small whitelist of substrings known to correlate strongly
//     with upstream-initiated disruption. Individual matches may
//     false-positive on rare transient errors; the follow-on
//     debargo TTL (see markDeadForTarget) expires in 60 s so the
//     cost of a false positive is bounded.
//
// Deliberately NOT matched (would over-trigger):
//   - io.EOF / io.ErrUnexpectedEOF: clean half-close or legitimate
//     Content-Length < actual. Callers decide whether those are
//     "bad enough" at their layer.
//   - context.Canceled / context.DeadlineExceeded: caller-initiated.
//   - "closed network connection": normally emitted when downstream
//     code closed the conn itself.
//
// Callers: smart_watchdog's mid-transfer Read/Write paths. First-byte
// and close paths continue to use isResetErr for stability.
func isTransferFatalErr(err error) bool {
	if err == nil {
		return false
	}
	if isResetErr(err) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	msg := strings.ToLower(err.Error())

	// GOAWAY: only fatal when the remote reported a real error code.
	// Common benign shape: "http2: server sent goaway and closed the
	// connection; last stream id ... error code no_error". We match on
	// "goaway" AND a non-"no_error" error-code token.
	if strings.Contains(msg, "goaway") && !strings.Contains(msg, "no_error") {
		return true
	}

	// Substring markers with strong correlation to upstream-initiated
	// disruption. Ordered roughly by expected frequency so the common
	// case returns early.
	for _, marker := range []string{
		// TLS layer
		"remote error: tls:",
		"tls: bad record mac",
		"tls: unexpected message",
		"tls: internal error",
		"tls: protocol version not supported",
		"tls: handshake failure",
		"tls: alert",
		// HTTP/2 layer (non-GOAWAY cases)
		"http2: stream error",
		"http2: server closed",
		"stream closed",
		"stream terminated",
		// QUIC layer (quic-go / hysteria / tuic)
		"crypto_error",
		"connection_close",
		"connection closed",
		"stream reset",
		"stream was reset",
		"application error",
		// Proxy-protocol framing damage
		"protocol error",
		"invalid frame",
		"frame too large",
		"short read",
		"authentication failed",
		"mux: invalid",
		"vmess: invalid",
		"trojan: invalid",
		"shadowsocks: ",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
