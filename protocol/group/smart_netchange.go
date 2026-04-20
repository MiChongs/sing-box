package group

import (
	"sync/atomic"
	"time"
)

// Network-change hook.
//
// sing-box already delivers a system-wide event when the default network
// interface changes (Wi-Fi ↔ cellular on Android, Ethernet ↔ Wi-Fi on
// desktop, interface-index renumber on routers). Every outbound that
// implements adapter.InterfaceUpdateListener receives InterfaceUpdated().
// Smart's original base class did not implement that interface — so after
// a network switch the group kept serving requests against the OLD
// freshness cache (nodes marked alive from the pre-switch interface),
// resulting in 3-15s of user-visible stalls the first time a new dial
// hit a now-unreachable node.
//
// This file adds the hook and does three things:
//
//   1. Invalidate freshness so the NEXT runHealthCheck cannot shortcut.
//      The per-node aliveAt heartbeats are dropped (the old interface's
//      success is no longer proof of reachability on the new one), and
//      the shared-worker probe freshness cache is dropped for this
//      group's test URL too.
//
//   2. Schedule a ONE-SHOT forced runHealthCheck on the shared timing
//      wheel. urltest.URLTestWithDetail triggers a full TLS/QUIC
//      handshake per node, which for Hysteria2/TUIC/TCP-based outbounds
//      ALSO pre-warms the protocol session. By the time the user issues
//      a real request a moment later, the QUIC session is already live —
//      turning a cold-start stall into a warm-cache hit.
//
//   3. Debounce: network-state transitions often fire multiple callbacks
//      in rapid succession (index change + IP change + carrier change).
//      We coalesce them into one warm-up pass so N Smart groups don't
//      issue redundant probe bursts within hundreds of ms of each other.
//
// Note on correctness: triggering an extra runHealthCheck is
// FUNCTIONALLY equivalent to waiting until the scheduled tick —
// singleflight in smartSharedWorker.probeOnce ensures a concurrent
// scheduled fire coalesces with the forced fire, and the freshness
// window in runHealthCheck keeps it idempotent across debounce races.

const (
	// netChangeDebounce collapses multiple InterfaceUpdated callbacks
	// arriving within this window into one warm-up pass. Chosen short
	// enough that a real "new network is up and usable" signal fires
	// fast, long enough to ride out the 2–3 carrier callbacks that
	// Android / Windows emit back-to-back during a Wi-Fi ↔ cellular
	// handoff.
	netChangeDebounce = 500 * time.Millisecond

	// netChangeWarmupDelay is how far into the future we schedule the
	// forced runHealthCheck after the debounce settles. Small positive
	// delay so the DHCP-assigned IP / routing table on the new
	// interface has a beat to stabilise before probes hit the wire —
	// otherwise the probes themselves fail and mark every node dead.
	netChangeWarmupDelay = 300 * time.Millisecond
)

// netChangeState holds the debounce/scheduling state for a Smart group.
// Inline on *Smart would also work, but a separate struct keeps Smart's
// field list (already very wide) from growing for an opt-in feature.
type netChangeState struct {
	// lastFireNS is the unix-nano at which the MOST RECENT successful
	// warmup was dispatched. Callbacks arriving within netChangeDebounce
	// of this are skipped.
	lastFireNS atomic.Int64
	// inFlight serialises concurrent InterfaceUpdated calls so the
	// debounce check + schedule is atomic. A sync.Mutex is cheaper than
	// an atomic CAS loop here because contention is near-zero (callbacks
	// arrive in tens of ms, not microseconds).
	inFlight atomic.Bool
}

// InterfaceUpdated is invoked by route.NetworkManager whenever the
// default interface changes. Matches adapter.InterfaceUpdateListener.
//
// Runs in the caller's goroutine — must be fast and non-blocking. All
// real work is handed off to the shared timing wheel via a one-shot
// scheduled task.
func (s *Smart) InterfaceUpdated() {
	if s == nil || !s.started.Load() {
		return
	}

	// Debounce: drop if the last warmup fired within the window. Uses
	// atomic to avoid the cost of taking the mutex on every spurious
	// callback — the common case on Android is three callbacks in
	// ~20ms, of which only the first needs to do work.
	nowNS := time.Now().UnixNano()
	lastNS := s.netChange.lastFireNS.Load()
	if lastNS != 0 && nowNS-lastNS < int64(netChangeDebounce) {
		return
	}
	if !s.netChange.inFlight.CompareAndSwap(false, true) {
		return
	}
	defer s.netChange.inFlight.Store(false)

	// Recheck under the inFlight guard — another goroutine may have
	// fired between our read and CAS.
	lastNS = s.netChange.lastFireNS.Load()
	if lastNS != 0 && nowNS-lastNS < int64(netChangeDebounce) {
		return
	}
	s.netChange.lastFireNS.Store(nowNS)

	// Drop aliveAt: every entry was written against the OLD interface's
	// reachability. Keeping them would let the next runHealthCheck
	// skip probing nodes the new interface actually can't reach.
	if s.aliveAt != nil {
		s.aliveAt.Clear()
	}

	// Drop the shared worker's probe freshness for tags we probe. The
	// cache is keyed globally by tag, so clearing our whole-group tags
	// only affects OUR testURL's cached results — other groups' probes
	// stay intact (they'll invalidate themselves when their own
	// InterfaceUpdated fires).
	worker := getSmartWorker()
	if worker != nil && worker.freshnessCache != nil {
		snap := s.state.Load()
		if snap != nil {
			for _, t := range snap.tags {
				worker.freshnessCache.Delete(t)
			}
		}
	}

	s.logger.Info("smart[", s.Tag(), "] network changed — scheduling warmup probe in ",
		netChangeWarmupDelay)

	// Schedule a single one-shot runHealthCheck through the shared
	// wheel. The small positive delay lets the OS finish routing-table
	// adjustments before probes race out on the new interface.
	worker.scheduleTask(netChangeWarmupDelay, 0, func() {
		if !s.started.Load() {
			return
		}
		// Explicitly bypass isGroupIdle: after a network change even an
		// idle group should re-validate its nodes so the next user
		// request doesn't sit on a 5s timeout. isGroupIdle-gated tasks
		// on the normal schedule will resume their own skip behaviour
		// on the next natural tick.
		s.runHealthCheck()
	}, true, s.taskCtx)
}
