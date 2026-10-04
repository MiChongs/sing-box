package group

import (
	"errors"
	"io"
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

	// stalledTransferTimeout: the conn already produced bytes, then the
	// client wrote and nothing came back for this long. Only unanswered
	// writes count — an idle keep-alive, websocket or push conn is not
	// stalled. Long enough to ride out long-poll requests the server
	// legitimately holds open.
	stalledTransferTimeout = 60 * time.Second

	// watchdogScanInterval: backstop scan period. The PRIMARY
	// first-byte detection path is kernel-driven via SetReadDeadline
	// (instant response, zero extra goroutines / memory). This periodic
	// scan catches conns whose underlying outbound silently ignores
	// SetReadDeadline (mux'd transports occasionally do) and stalled
	// transfers. The scan takes virtually no CPU time.
	watchdogScanInterval = 2500 * time.Millisecond
)

// errWatchdogStall is reported to the reset-event tracker when the
// periodic scan evicts a stalled conn.
var errWatchdogStall = errors.New("smart: connection stalled")

// armFirstByteDeadline wires the kernel-level read deadline at the
// client's first Write, so a silent node returns an error from Read
// instead of hanging until the kernel/TLS timeout. Best-effort: a
// transport that ignores SetReadDeadline still gets caught by the
// periodic backstop scan.
func (c *smartTrackedConn) armFirstByteDeadline() {
	now := time.Now()
	c.firstWriteAt.Store(now.UnixNano())
	if c.Conn == nil || c.firstReadOnce.Load() {
		return
	}
	timeout := firstByteWatchdogTimeout
	if c.s != nil && c.s.history != nil {
		h := c.s.history.LoadURLTestHistory(c.proxyTag)
		if h != nil && h.Delay > 0 {
			adaptive := time.Duration(float64(h.Delay)*4.0) * time.Millisecond
			if adaptive < 1500*time.Millisecond {
				adaptive = 1500 * time.Millisecond
			}
			if adaptive < timeout {
				timeout = adaptive
			}
		}
	}
	c.firstByteTimeout.Store(int64(timeout))
	c.deadlineArmed.Store(true)
	_ = c.Conn.SetReadDeadline(now.Add(timeout))
	// Server-speaks-first protocols can deliver the first byte before
	// the client's first write; Read may have disarmed just before we
	// armed, so re-check.
	if c.firstReadOnce.Load() {
		c.disarmFirstByteDeadline()
	}
}

// disarmFirstByteDeadline removes the first-byte deadline once the first
// byte arrived or the conn closes, so it never surfaces as a timeout on a
// healthy conn. Skips the syscall when no deadline was armed.
func (c *smartTrackedConn) disarmFirstByteDeadline() {
	if c.Conn == nil || !c.deadlineArmed.CompareAndSwap(true, false) {
		return
	}
	_ = c.Conn.SetReadDeadline(time.Time{})
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

// runStalledConnWatchdog is the periodic body invoked by the shared
// timing wheel. Idle groups (no active conns at all) are an O(1)
// check that returns immediately.
func (s *Smart) runStalledConnWatchdog() {
	if s == nil {
		return
	}
	// Lock-free fast-path: when the per-group atomic counter reports
	// zero active conns, skip the mutex acquire + map iteration
	// entirely.
	if s.targetConnsCount.Load() == 0 {
		return
	}
	type victim struct {
		c     *smartTrackedConn
		kind  string
		ageMS int64
	}
	nowNS := time.Now().UnixNano()
	var victims []victim

	s.targetConnsMu.Lock()
	for _, set := range s.targetConns {
		for c := range set {
			if c == nil || c.watchdogTriggered.Load() {
				continue
			}
			if !c.firstReadOnce.Load() {
				firstWrite := c.firstWriteAt.Load()
				if firstWrite == 0 {
					continue // the client has not asked for anything yet
				}
				timeout := time.Duration(c.firstByteTimeout.Load())
				if timeout == 0 {
					timeout = firstByteWatchdogTimeout
				}
				if waited := time.Duration(nowNS - firstWrite); waited > timeout {
					victims = append(victims, victim{c, "first-byte-timeout", waited.Milliseconds()})
				}
				continue
			}
			lastWrite := c.lastWriteAt.Load()
			if lastWrite <= c.lastReadAt.Load() {
				continue // every write so far has been answered
			}
			if waited := time.Duration(nowNS - lastWrite); waited > stalledTransferTimeout {
				victims = append(victims, victim{c, "transfer-stalled", waited.Milliseconds()})
			}
		}
	}
	s.targetConnsMu.Unlock()

	for _, v := range victims {
		// Same handling as an upstream reset: the (target, node) pair is
		// debargoed right away and the node is evicted once resets on it
		// cross the threshold. The CAS inside makes concurrent scans and
		// a racing Read/Write error handle the conn once.
		if !s.triggerInstantResetEviction(v.c, "watchdog "+v.kind, errWatchdogStall) {
			continue
		}
		s.logger.Warn("smart[", s.Tag(), "] watchdog evicting conn (", v.kind,
			") via [", v.c.proxyTag, "] waited=", v.ageMS, "ms")
		// Force the underlying conn closed so the caller stops waiting;
		// its Close() then runs recordStats as usual.
		_ = v.c.Conn.Close()
	}
}
