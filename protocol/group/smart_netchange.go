package group

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// ErrNetworkChanged is the cancel cause for dials interrupted by a
// default-interface switch. Surfaced to the caller so it can choose to
// retry immediately on the new interface instead of waiting for the
// natural dial timeout (5-15s per candidate).
var ErrNetworkChanged = errors.New("smart: network changed, dial aborted")

// dialHandle is a void-pointer used only for its address identity in
// the dialCancels sync.Map. Must have non-zero size — Go coalesces
// zero-sized struct pointers to a single runtime-wide address, which
// would cause sync.Map to see all dials as the same key and silently
// collapse cancel registrations. The 1-byte pad guarantees each
// &dialHandle{} gets its own heap address.
type dialHandle struct{ _ byte }

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

	// globalWarmupDebounce is the PROCESS-WIDE cooldown for scheduling
	// the heavy warmup (preWarmPriorityNodes + runHealthCheck). Without
	// this, a config with N Smart groups fires N parallel warmup
	// storms on every Wi-Fi ↔ cellular handoff — on a 15-group setup
	// that means ~450 TLS handshakes inside a few hundred ms, which
	// pegs Android CPUs at 100% and grows the heap by tens of MB
	// before the dust settles. Only the FIRST group to observe a
	// network change within this window schedules the heavy work; the
	// rest still run light per-group cleanup (cancelInFlightDials,
	// aliveAt.Clear, freshnessCache.Delete) since those are O(1) or
	// O(small-N) and semantically required per group.
	globalWarmupDebounce = 5 * time.Second
)

// globalWarmupLastNS is the shared timestamp used by every Smart
// group to coordinate the heavy warmup. Reads are cheap (one
// atomic.Int64 load), writes go through CompareAndSwap so only the
// first racer within a debounce window wins.
var globalWarmupLastNS atomic.Int64

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
	// dialCancels tracks every in-flight Dial/ListenPacket originated
	// by this Smart group. Key is a distinct *dialHandle (address
	// identity, never compared), value is the context.CancelCauseFunc.
	// On InterfaceUpdated we cancel every entry so dials stuck on the
	// old interface (which would otherwise sit on a 5-15s per-candidate
	// timeout) fail fast and let the caller retry on the new interface.
	// sync.Map chosen over RWMutex+map because the access pattern is
	// "insert + delete by unique key, occasional global range" — the
	// exact sweet spot for sync.Map.
	dialCancels sync.Map
	// lastCancelNS records the most recent cancelInFlightDials trigger.
	// During the cancelCooldown window that follows, DialContext's
	// registerDial bypasses the cancel-set — new dials kicked off in
	// response to the freshly-cancelled ones won't themselves be
	// cancelled by a spurious second callback inside the same burst.
	// Without this, Android's callback cascade produced an amplifying
	// retry loop: cancel → caller retries → new registerDial → next
	// callback cancels that → caller retries → ...
	lastCancelNS atomic.Int64
}

// cancelCooldown is the quiet window after cancelInFlightDials
// during which new dials stay OUT of the cancel set. Without this,
// a repeat InterfaceUpdated callback inside a burst would cancel
// freshly-retried dials in flight, feeding a ping-pong: cancel →
// caller retries → new dial registered → next callback cancels it
// again → retry. Pick > route.resetCoalesceDelay so a coalesced
// second reset doesn't happen inside this window.
const cancelCooldown = 2 * time.Second

// registerDial enrols a dial ctx into the cancel set UNLESS we're
// inside the cooldown window following a cancelInFlightDials. During
// cooldown the dial still gets a derived ctx (so callers keep a
// clean shutdown signal via parent cancellation), but it's not in
// the cancel-set — so a second InterfaceUpdated within the window
// won't pull the rug out from under this dial.
func (s *Smart) registerDial(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(parent)
	nowNS := time.Now().UnixNano()
	last := s.netChange.lastCancelNS.Load()
	if last != 0 && nowNS-last < int64(cancelCooldown) {
		// Cooldown active: do NOT insert into cancelables. Still
		// return a working ctx/teardown pair so callers don't know
		// the difference.
		return ctx, func() { cancel(nil) }
	}
	h := &dialHandle{}
	s.netChange.dialCancels.Store(h, cancel)
	return ctx, func() {
		s.netChange.dialCancels.Delete(h)
		// Discharge the cancel so the context goroutine exits even if
		// we weren't the one who caused the cancellation.
		cancel(nil)
	}
}

// cancelInFlightDials cancels every registered dial with
// ErrNetworkChanged and stamps the cooldown start. Idempotent:
// dials already finished will have removed themselves from the map.
func (s *Smart) cancelInFlightDials() int {
	var n int
	s.netChange.dialCancels.Range(func(k, v any) bool {
		if cancel, ok := v.(context.CancelCauseFunc); ok {
			cancel(ErrNetworkChanged)
			n++
		}
		return true
	})
	// Stamp the cooldown window start AFTER cancelling so any dial
	// that registered during Range() is still cancelled, but
	// registerDial calls past this moment bypass the set.
	s.netChange.lastCancelNS.Store(time.Now().UnixNano())
	return n
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

	// Cancel every dial stuck on the old interface. A TCP SYN that
	// left via Wi-Fi will sit until the OS-level timeout (usually
	// tens of seconds on Android after a carrier switch); canceling
	// the ctx immediately aborts the dial, the caller sees
	// ErrNetworkChanged, and the app retries against the new
	// interface within milliseconds instead of seconds.
	if n := s.cancelInFlightDials(); n > 0 {
		s.logger.Info("smart[", s.Tag(), "] network changed — cancelled ",
			n, " in-flight dial(s) on the old interface")
	}

	// Process-wide warmup debounce. The per-group block above
	// handles cheap state cleanup (aliveAt.Clear, freshnessCache
	// delete, cancelInFlightDials) — all O(1) or O(small-N) — and
	// every Smart group MUST do that part. But the heavy warmup
	// (preWarmPriorityNodes + runHealthCheck) is what used to
	// stampede: 15 groups each dispatching probes for 30 nodes
	// during a single Wi-Fi↔cellular handoff turned into hundreds
	// of parallel TLS handshakes plus an ants.Pool deadlock
	// (see the comment in runHealthCheck for the deadlock mechanics).
	//
	// We now serialise warmup across ALL Smart groups with a
	// process-global atomic CAS. The first group to observe a
	// network change within globalWarmupDebounce schedules the
	// heavy work; every subsequent group within that window logs
	// a skip and returns. The single warmup still uses singleflight
	// in probeOnce to fan out across all groups' node tags, so no
	// group is actually "missed" — it just doesn't pay the per-
	// group scheduling cost on top.
	globalLast := globalWarmupLastNS.Load()
	if globalLast != 0 && nowNS-globalLast < int64(globalWarmupDebounce) {
		s.logger.Debug("smart[", s.Tag(),
			"] network changed — skipping warmup (another group fired within ",
			globalWarmupDebounce, ")")
		return
	}
	if !globalWarmupLastNS.CompareAndSwap(globalLast, nowNS) {
		// Another group won the race within the same nanosecond —
		// treat as if we were the second caller.
		s.logger.Debug("smart[", s.Tag(),
			"] network changed — lost the warmup CAS race to a peer group")
		return
	}

	s.logger.Info("smart[", s.Tag(), "] network changed — scheduling warmup probe in ",
		netChangeWarmupDelay)

	// Schedule the single one-shot warmup through the shared wheel.
	// The small positive delay lets the OS finish routing-table
	// adjustments before probes race out on the new interface.
	worker.scheduleTask(netChangeWarmupDelay, 0, func() {
		if !s.started.Load() {
			return
		}
		s.preWarmPriorityNodes()
		s.runHealthCheck()
	}, true, s.taskCtx)
}

// preWarmPriorityNodes probes the "most likely to be used next" nodes
// first so the very next user dial lands on a freshly-warmed candidate.
// Runs in the same goroutine as the full health-check but FINISHES
// before the full sweep starts — callers may observe a pin/lastSelected
// node become ready within a few hundred ms of InterfaceUpdated, while
// the broader sweep continues in the background.
//
// Idempotent with runHealthCheck: the shared worker's singleflight
// coalesces any concurrent probe for the same tag, and the freshness
// cache keeps the follow-up sweep from re-probing the same nodes.
func (s *Smart) preWarmPriorityNodes() {
	if s == nil || s.history == nil {
		return
	}
	snap := s.state.Load()
	if snap == nil || len(snap.outbounds) == 0 {
		return
	}

	// Build priority set: manual pin > lastSelected > stop. Both are
	// best-effort — empty strings mean "no signal", skip.
	priority := make([]string, 0, 2)
	if pin := s.getManualSelected(); pin != "" {
		priority = append(priority, pin)
	}
	if v, ok := s.lastSelectedTag.Load().(string); ok && v != "" {
		// Avoid probing the same node twice when pin == lastSelected.
		if len(priority) == 0 || priority[0] != v {
			priority = append(priority, v)
		}
	}
	if len(priority) == 0 {
		return
	}

	// Look up outbound objects for the priority tags.
	tagSet := make(map[string]struct{}, len(priority))
	for _, t := range priority {
		tagSet[t] = struct{}{}
	}
	var targets []adapter.Outbound
	for _, ob := range snap.outbounds {
		if _, ok := tagSet[ob.Tag()]; !ok {
			continue
		}
		if smartSkipType(ob.Type()) {
			continue
		}
		targets = append(targets, ob)
	}
	if len(targets) == 0 {
		return
	}

	worker := getSmartWorker()
	// 3s per-probe budget on a standalone timer — was previously
	// scoped with `defer cancel()` tied to this function, but since
	// we've switched to fire-and-forget (no wg.Wait) the cancel
	// would fire BEFORE any probe starts. ctx.WithTimeout + drop
	// the cancel handle: the internal timer will release resources
	// at deadline expiry regardless.
	probeCtx, cancel := context.WithTimeout(s.taskCtx, 3*time.Second)
	_ = cancel // timer-driven expiry; explicit cancel not required

	for _, ob := range targets {
		ob := ob
		tag := ob.Tag()
		worker.submit(func() {
			delay, err := worker.probeOnce(probeCtx, s.testURL, ob)
			if err != nil || delay == 0 {
				s.history.DeleteURLTestHistory(tag)
				s.markDead(tag)
				s.logger.Debug("smart[", s.Tag(), "] priority warm [",
					tag, "] failed: ", err)
				return
			}
			s.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
				Time:  time.Now(),
				Delay: delay,
			})
			s.markAlive(tag)
			s.maybeResumePin(tag)
			s.logger.Info("smart[", s.Tag(), "] priority warm [",
				tag, "] ready in ", delay, "ms")
		})
	}
	// Fire-and-forget: dropping the wg.Wait that used to block here
	// is what unblocks the ants.Pool during a network-switch storm.
	// See the equivalent note in runHealthCheck for the full
	// deadlock explanation.
}
