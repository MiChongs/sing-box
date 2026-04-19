package group

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// Stalled-connection watchdog.
//
// The pre-existing detection layers cover three failure modes:
//
//   - shortLife (smart_anomaly's classifyShortLife) — user gave up
//     quickly after a short connection with little payload.
//   - resetEventTracker — upstream sent TCP RST / forcibly closed
//     mid-stream (ERR_CONNECTION_RESET).
//   - circuitBreaker — explicit dial failures.
//
// The remaining gap is the connection that DIALED OK but then either
// (a) never produces a first byte even after several seconds — the
// node is silently absorbing the request — or (b) successfully
// produced bytes earlier but then stalled mid-transfer. Without an
// explicit watchdog these conns can hang for the full kernel/TLS
// timeout (often a minute or more) before the user's app gives up,
// during which Smart never learns the node is broken and keeps
// re-electing it for new requests to the same target.
//
// The watchdog is a single periodic task per Smart group, not a
// goroutine per conn — at 16 groups × 200 active conns the
// per-conn cost is one (lock-free atomic load + time math) every
// scan interval, while the goroutine count stays at one per group.
//
// On detection the watchdog performs the same node-switch sequence
// as a TCP RST event (handleResetThresholdCrossed). That keeps the
// downstream invariants — breaker tripping, unwrap-cache delete,
// async ranking refresh — identical regardless of WHICH stall pattern
// surfaced the problem.

const (
	// firstByteWatchdogTimeout: dialled OK, no first byte after this
	// → the node is silently eating bytes. 5 s — far enough past a
	// reasonable TLS handshake (typical 200–800 ms) that we don't
	// kill warming connections, but tight enough that the user
	// doesn't sit on a blank page when the upstream is filtered.
	firstByteWatchdogTimeout = 5 * time.Second

	// stalledTransferTimeout: had bytes flowing, then dead silence
	// for this long. 30 s is well past any normal HTTP/2 idle period
	// (the spec keep-alive is shorter) but well before the user
	// would tolerate a frozen page.
	stalledTransferTimeout = 30 * time.Second

	// watchdogScanInterval: backstop scan period. The PRIMARY
	// detection path is kernel-driven via SetReadDeadline (instant
	// response, zero extra goroutines / memory). This periodic scan
	// only catches conns whose underlying outbound silently ignores
	// SetReadDeadline (rare — net.Conn implementations should always
	// honour it, but mux'd transports occasionally don't).
	// Reduced to 2.5s for highly responsive timeout tracking, as the scan
	// takes virtually no CPU time but eliminates "blind wait" UX drops.
	watchdogScanInterval = 2500 * time.Millisecond

	// stalledTransferGrace: wiggle room before the periodic backstop
	// declares a deadline-driven re-arm cycle a "false positive". The
	// kernel deadline can fire moments AFTER a successful read on
	// some transports; this grace prevents us from killing a conn
	// that just had real activity within the last second.
	stalledTransferGrace = 1 * time.Second
)

// applyFirstByteDeadline wires the kernel-level read deadline so a
// silent node returns an error from Read instead of hanging until
// the kernel/TLS timeout. Must be called immediately after wrapConn
// before any Read happens. Best-effort: a transport that returns an
// error from SetReadDeadline still gets caught by the periodic
// backstop scan.
func (c *smartTrackedConn) applyFirstByteDeadline() {
	if c.Conn == nil {
		return
	}
	timeout := firstByteWatchdogTimeout
	if c.s != nil && c.s.history != nil {
		h := c.s.history.LoadURLTestHistory(c.proxyTag)
		if h != nil && h.Delay > 0 {
			adaptive := time.Duration(float64(h.Delay) * 4.0) * time.Millisecond
			if adaptive < 1500*time.Millisecond {
				adaptive = 1500 * time.Millisecond
			}
			if adaptive < timeout {
				timeout = adaptive
			}
		}
	}
	c.currentFirstByteTimeout = timeout
	_ = c.Conn.SetReadDeadline(time.Now().Add(timeout))
}

// armTransferStalledDeadline switches the kernel deadline from the
// (short) first-byte budget to the (longer) transfer-stalled budget
// once the conn has produced at least one payload byte. Called
// exactly once on the first successful Read.
func (c *smartTrackedConn) armTransferStalledDeadline() {
	if c.Conn == nil {
		return
	}
	_ = c.Conn.SetReadDeadline(time.Now().Add(stalledTransferTimeout))
}

// rearmTransferStalledDeadline pushes the deadline forward whenever
// recent activity proves the conn is healthy. Skipped when the
// existing deadline still has plenty of headroom — saves the syscall
// on every Read in steady-state high-throughput streams.
func (c *smartTrackedConn) rearmTransferStalledDeadline() {
	if c.Conn == nil {
		return
	}
	_ = c.Conn.SetReadDeadline(time.Now().Add(stalledTransferTimeout))
}

// clearReadDeadline removes the watchdog's deadline before the conn
// is handed to anything that might block on its own (read until EOF
// patterns, http library copy loops). Called from Close so a
// stale deadline doesn't leak into reused buffers.
func (c *smartTrackedConn) clearReadDeadline() {
	if c.Conn == nil {
		return
	}
	_ = c.Conn.SetReadDeadline(time.Time{})
}

// isWatchdogDeadlineErr reports whether err is the timeout signal
// our deadline produced (vs an unrelated network error). Matches
// every common shape: os.ErrDeadlineExceeded (Go 1.15+ canonical),
// net.OpError-wrapped timeout, and substring "i/o timeout" for
// transports that wrap errors loosely.
func isWatchdogDeadlineErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "i/o timeout") ||
		strings.Contains(err.Error(), "deadline exceeded")
}

// isPreFirstByteFatal reports whether a Read error received BEFORE
// the conn ever produced a payload byte should be treated as "node
// is broken" and trigger an instant eviction.
//
// Without this we relied solely on isResetErr matching the error
// string, but mux/quic-style wrappers (hysteria2 / tuic / shadow-tls)
// translate the underlying TCP RST into their own framing errors that
// no string match catches — the user sees ERR_CONNECTION_RESET in the
// browser while Smart never learns the node is broken.
//
// Pre-first-byte semantics: we ALREADY waited firstByteWatchdogTimeout
// for a real byte. Anything other than a clean io.EOF at this stage
// (server cleanly half-closed before sending data — rare but valid for
// HTTP/2 RST_STREAM) means the node didn't deliver. Counting EOF
// would over-trigger on legitimate 0-byte responses; everything else
// is a "drop and switch" signal.
func isPreFirstByteFatal(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return false
	}
	return true
}

// triggerInstantResetEviction is the real-time RST handler invoked
// directly from Read / Write the moment the kernel returns an
// ECONNRESET / EPIPE / forcibly-closed error. Bypasses the Close()
// path so we don't have to wait for the caller's read-loop to
// observe the error and run its own teardown — which can lag by
// hundreds of milliseconds in HTTP libraries that buffer responses.
//
// Idempotent via watchdogTriggered CAS — concurrent Read+Write hits
// or a follow-up Close() will all see the flag set and skip their
// own (redundant) eviction. Returns true if THIS call did the work
// (caller can inject extra logging or skip tracker.record).
func (s *Smart) triggerInstantResetEviction(c *smartTrackedConn, op string, err error) bool {
	if c == nil || s.resetEvents == nil {
		return false
	}
	if !c.watchdogTriggered.CompareAndSwap(false, true) {
		return false
	}
	if c.meta != nil {
		s.logger.Warn("smart[", s.Tag(), "] ", op, " RST from [",
			c.proxyTag, "] target=[", c.meta.smartTarget, "] err=", err)
		if s.resetEvents.record(c.meta.smartTarget, c.proxyTag) {
			s.handleResetThresholdCrossed(c.meta, c.proxyTag)
		} else if c.meta.smartTarget != "" {
			// Below the global (target, node) threshold but we still
			// observed a real RST — so this specific target on this
			// specific node is untrustworthy RIGHT NOW even though
			// the node itself may be globally healthy (classic GFW
			// pattern: selective per-SNI / per-domain blocking).
			//
			// Combine two cheap responses:
			//
			//   1. Drop the unwrap cache so the next dial re-evaluates
			//      candidates (prevents "stickiness repicks same node
			//      immediately" — this was the pre-existing policy).
			//
			//   2. Install a per-(target, proxy) debargo via
			//      markDeadForTarget. selectProxies already filters
			//      against isTargetDebargoed so the node is pulled
			//      from THIS target's candidate list for targetDebargoTTL,
			//      WITHOUT affecting its weight on other targets. The
			//      debargo auto-expires — no manual recovery needed.
			//      This closes the gap the user hit: single-RST nodes
			//      that previously kept being re-elected because the
			//      global breaker only trips at 2 events.
			if s.store != nil {
				s.store.DeleteUnwrapResult(s.Tag(), smartConfigName,
					c.meta.smartTarget, c.meta.asnCode, c.meta.isUDP)
			}
			s.markDeadForTarget(c.meta.smartTarget, c.proxyTag)
		}
	}
	return true
}

// classifyWatchdogStall returns a short label describing which pattern
// caused the watchdog to evict the conn. Surfaced via logs so
// operators can tell first-byte-timeout (often "node ate the request")
// from transfer-stalled (often "egress filtered mid-stream").
func classifyWatchdogStall(c *smartTrackedConn) string {
	if !c.firstReadOnce.Load() {
		return "first-byte-timeout"
	}
	return "transfer-stalled"
}

// runStalledConnWatchdog is the periodic body invoked by the shared
// timing wheel. Idle groups (no active conns at all) are an O(1)
// check that returns immediately.
func (s *Smart) runStalledConnWatchdog() {
	if s == nil {
		return
	}
	type victim struct {
		c        *smartTrackedConn
		target   string
		kind     string
		ageMS    int64
	}
	now := time.Now()
	var victims []victim

	s.targetConnsMu.Lock()
	for tgt, set := range s.targetConns {
		for c := range set {
			if c == nil || c.watchdogTriggered.Load() {
				continue
			}
			age := now.Sub(c.startTime)
			if !c.firstReadOnce.Load() {
				timeout := c.currentFirstByteTimeout
				if timeout == 0 {
					timeout = firstByteWatchdogTimeout
				}
				if age > timeout {
					victims = append(victims, victim{c, tgt, "first-byte-timeout", age.Milliseconds()})
				}
				continue
			}
			lastNS := c.lastReadAt.Load()
			if lastNS == 0 {
				continue // first read seen but byte-tracking not started — defer judgement
			}
			idle := now.Sub(time.Unix(0, lastNS))
			if idle > stalledTransferTimeout {
				victims = append(victims, victim{c, tgt, "transfer-stalled", idle.Milliseconds()})
			}
		}
	}
	s.targetConnsMu.Unlock()

	for _, v := range victims {
		// CAS the trigger flag so concurrent scans (or a parallel
		// reset event) don't double-handle the same conn.
		if !v.c.watchdogTriggered.CompareAndSwap(false, true) {
			continue
		}
		s.logger.Warn("smart[", s.Tag(), "] watchdog evicting conn (", v.kind,
			") via [", v.c.proxyTag, "] target=[", v.target,
			"] elapsed=", v.ageMS, "ms")

		// Force the underlying conn closed. The Close() pipeline will
		// eventually run and recordStats sees firstReadOnce==false (or
		// stale lastRead) — classifyShortLife already covers the
		// "no first byte" pattern, so the persistent stats stay
		// consistent.
		_ = v.c.Conn.Close()

		// Trigger the same eviction sequence as a TCP RST: bumps the
		// circuit breaker, marks dead, drops unwrap cache, kicks the
		// ranking refresh — algorithm-aware node switch happens on
		// the very next dial without waiting for the natural close
		// timeout.
		s.handleResetThresholdCrossed(v.c.meta, v.c.proxyTag)
	}
}
