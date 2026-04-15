package group

import (
	"math/rand"
	"strings"
	"sync/atomic"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart"
)

// Smart selection algorithms — applied after the tiered selection
// (selectProxiesTraced) returns its candidate list. Each algorithm is
// a pure re-orderer: it never adds or removes candidates, only changes
// the visit order so the dial path tries them in a different sequence.
//
// Why a post-pass instead of replacing the tier logic: the tier logic
// already encodes a robust "what data sources do we trust right now"
// decision (unwrap → prefetch → weight → delay → fallback). The
// algorithm knob is about UX preference once those candidates exist:
// concentrate vs. spread, latency vs. load, etc.
//
// Defaults to strict-best so out-of-box behaviour is identical to
// every previous build — opt-in for the new strategies.

const (
	smartAlgoStrictBest     = "strict-best"
	smartAlgoWeightedRandom = "weighted-random"
	smartAlgoLeastLoaded    = "least-loaded"
	smartAlgoFastestRecent  = "fastest-recent"
	smartAlgoStickySession  = "sticky-session"

	// weightedRandomTopK caps the sampling pool. Sampling across all
	// candidates would dilute the bias toward genuinely good nodes;
	// 5 keeps "comparable nodes" together (the rest are usually
	// long-tail bad nodes that should NEVER be picked).
	weightedRandomTopK = 5

	// leastLoadedSwapBudget caps how far we shuffle from the original
	// weight ordering. A node with 2× more load than another but 50%
	// higher weight should still win — load is a tiebreaker, not a
	// replacement. Limiting the swap distance keeps the algorithm
	// "weight-first, load-aware" instead of "load-first".
	leastLoadedSwapBudget = 3
)

// normalizeAlgorithm canonicalises a user-supplied algorithm string.
// Returns the constant value when recognised (case-insensitive, with or
// without spaces/underscores), or smartAlgoStrictBest as the safe
// default for unknown / empty input.
func normalizeAlgorithm(raw string) string {
	switch strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "_", "-"), " ", "-") {
	case "", "auto", smartAlgoStrictBest, "best", "strict":
		return smartAlgoStrictBest
	case smartAlgoWeightedRandom, "random", "weighted":
		return smartAlgoWeightedRandom
	case smartAlgoLeastLoaded, "least-load", "load":
		return smartAlgoLeastLoaded
	case smartAlgoFastestRecent, "fastest", "recent":
		return smartAlgoFastestRecent
	case smartAlgoStickySession, "sticky", "session":
		return smartAlgoStickySession
	case smartAlgoRoundRobin, "rr", "round-robbin":
		return smartAlgoRoundRobin
	case smartAlgoWeightedRR, "wrr", "weighted-round-robin":
		return smartAlgoWeightedRR
	case smartAlgoP2C, "power-of-two", "two-choices":
		return smartAlgoP2C
	case smartAlgoLatencyBanded, "banded", "latency-bands":
		return smartAlgoLatencyBanded
	}
	return smartAlgoStrictBest
}

// algoRound0Width returns the number of candidates dialWithRetry
// should race in round 0 for the currently-configured algorithm.
//
// "Selection-style" algorithms (sticky / round-robin / weighted-rr /
// p2c / weighted-random) have already chosen a SPECIFIC node by the
// time reorderForAlgorithm finishes — racing a second candidate
// would discard their choice on the loser dial. They get width=1.
//
// "Ranking-style" algorithms (strict-best / least-loaded /
// fastest-recent / latency-banded) just push the best candidate to
// position 0 but treat positions 1..K as comparable; racing the top
// 2 there is a fast-failover win and worth the wasted dial when
// the leader is broken. They keep the legacy width=smartRound0Parallel.
//
// Returned values are clamped to [1, smartRound0Parallel].
func (s *Smart) algoRound0Width() int {
	switch s.currentAlgorithm() {
	case smartAlgoStickySession,
		smartAlgoRoundRobin,
		smartAlgoWeightedRR,
		smartAlgoP2C,
		smartAlgoWeightedRandom:
		return 1
	default:
		return smartRound0Parallel
	}
}

// currentAlgorithm returns the live algorithm setting. Reads the
// atomic so a runtime SetAlgorithm() call is observed by every
// subsequent dial without restart.
func (s *Smart) currentAlgorithm() string {
	if v := s.algorithm.Load(); v != nil {
		return *v
	}
	return smartAlgoStrictBest
}

// SetAlgorithm changes the algorithm at runtime. Returns the
// resolved canonical name (callers should mirror it back to API
// clients so they see what was actually applied). Empty / unknown
// raw inputs collapse to strict-best — never errors.
//
// Lazily allocates per-algorithm bookkeeping (round-robin counters,
// sticky map) the first time the corresponding algorithm is selected
// so groups configured with strict-best never pay the alloc cost.
//
// Diagnostic log policy:
//
//   - Empty raw + canon=strict-best: debug (normal default path).
//   - Raw recognised, canon matches a known algo: info (shows what
//     took effect — operators can confirm by grep).
//   - Raw non-empty but normalize fell back to strict-best: WARN
//     with both the raw string and the corrected value. Catches the
//     common "user typo / underscore" case like `fastest_recent` vs
//     `fastest-recent` that would otherwise silently degrade to the
//     default.
func (s *Smart) SetAlgorithm(raw string) string {
	canon := normalizeAlgorithm(raw)
	switch canon {
	case smartAlgoRoundRobin:
		if s.rrCounter == nil {
			s.rrCounter = &roundRobinCounter{}
		}
	case smartAlgoWeightedRR:
		if s.wrrCounter == nil {
			s.wrrCounter = &roundRobinCounter{}
		}
	case smartAlgoStickySession:
		if s.stickyByTarget == nil {
			s.stickyByTarget = xsync.NewMapOf[stickyKey, string]()
		}
	}
	v := canon
	s.algorithm.Store(&v)
	if s.logger == nil {
		return canon
	}
	trimmedRaw := strings.TrimSpace(raw)
	switch {
	case trimmedRaw == "":
		s.logger.Debug("smart[", s.Tag(), "] algorithm: ", canon, " (default, no config value)")
	case canon == smartAlgoStrictBest && !isStrictBestSynonym(trimmedRaw):
		s.logger.Warn("smart[", s.Tag(), "] algorithm config [", raw,
			"] was not recognised — falling back to ", canon,
			"; accepted values: strict-best / weighted-random / least-loaded /",
			" fastest-recent / sticky-session / round-robin / weighted-rr /",
			" p2c / latency-banded")
	default:
		s.logger.Info("smart[", s.Tag(), "] algorithm: ", canon, " (from config=[", raw, "])")
	}
	return canon
}

// isStrictBestSynonym reports whether the input was an intentional
// way to request strict-best (empty, "auto", "best", "strict", or the
// canonical name itself) vs a typo that silently normalized to it.
// Used by SetAlgorithm to tell the "default" path apart from the
// "misconfiguration" path in its log output.
func isStrictBestSynonym(raw string) bool {
	switch strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(raw), "_", "-"), " ", "-") {
	case "", "auto", smartAlgoStrictBest, "best", "strict":
		return true
	}
	return false
}

// CurrentAlgorithm exposes the live algorithm name to ClashAPI
// surfaces so dashboards can render and verify the active strategy
// without reaching into internals.
func (s *Smart) CurrentAlgorithm() string { return s.currentAlgorithm() }

// HysteresisDuration exposes the configured anti-flap window for
// dashboard display. Zero means hysteresis is disabled.
func (s *Smart) HysteresisDuration() time.Duration { return s.hysteresisWindow }

// nodeLoadCounter is the global "active connections per node tag"
// counter consulted by the least-loaded algorithm. xsync.MapOf gives
// us zero-alloc atomic increments without a fat lock.
type nodeLoadCounter struct {
	counts *xsync.MapOf[string, *atomic.Int64]
}

func newNodeLoadCounter() *nodeLoadCounter {
	return &nodeLoadCounter{counts: xsync.NewMapOf[string, *atomic.Int64]()}
}

func (n *nodeLoadCounter) inc(tag string) {
	if tag == "" {
		return
	}
	c, _ := n.counts.LoadOrCompute(tag, func() *atomic.Int64 { return new(atomic.Int64) })
	c.Add(1)
}

func (n *nodeLoadCounter) dec(tag string) {
	if tag == "" {
		return
	}
	if c, ok := n.counts.Load(tag); ok {
		c.Add(-1)
	}
}

func (n *nodeLoadCounter) get(tag string) int64 {
	if c, ok := n.counts.Load(tag); ok {
		return c.Load()
	}
	return 0
}

// reorderForAlgorithm dispatches the candidate slice through the
// configured algorithm. The slice is mutated in place (no allocation)
// so callers must not retain pointers to specific positions before
// calling. Returns the same slice for fluent chaining.
//
// `target` is the per-request target string (used by sticky-session);
// pass empty when no target context exists.
func (s *Smart) reorderForAlgorithm(candidates []adapter.Outbound, target string, isUDP bool) []adapter.Outbound {
	algo := s.currentAlgorithm()
	if len(candidates) <= 1 || algo == "" || algo == smartAlgoStrictBest {
		return candidates
	}
	switch algo {
	case smartAlgoWeightedRandom:
		return s.reorderWeightedRandom(candidates)
	case smartAlgoLeastLoaded:
		return s.reorderLeastLoaded(candidates)
	case smartAlgoFastestRecent:
		return s.reorderFastestRecent(candidates)
	case smartAlgoStickySession:
		return s.reorderStickySession(candidates, target, isUDP)
	case smartAlgoRoundRobin:
		return s.reorderRoundRobin(candidates)
	case smartAlgoWeightedRR:
		return s.reorderWeightedRoundRobin(candidates)
	case smartAlgoP2C:
		return s.reorderP2C(candidates)
	case smartAlgoLatencyBanded:
		return s.reorderLatencyBanded(candidates)
	}
	return candidates
}

// reorderWeightedRandom samples one of the top-K candidates with
// probability proportional to a synthetic rank-derived weight (top
// position → highest probability), then promotes it to position 0.
// Remaining candidates keep their original ordering. This shifts load
// away from the always-top-pick node WITHOUT giving long-tail bad
// nodes a chance.
func (s *Smart) reorderWeightedRandom(candidates []adapter.Outbound) []adapter.Outbound {
	k := weightedRandomTopK
	if k > len(candidates) {
		k = len(candidates)
	}
	// Synthetic weight: position 0 → k, position 1 → k-1, ..., position
	// k-1 → 1. The actual weight values aren't readily available here
	// (fillProxies has already discarded them), and using rank-as-weight
	// preserves the "top is preferred" bias without re-querying the
	// store on every dial. Total weight = k*(k+1)/2; sample uniformly
	// in [0, total) and pick the bucket.
	total := k * (k + 1) / 2
	pick := rand.Intn(total) // lock-free; jitter doesn't need crypto/rand
	cursor := 0
	for i := 0; i < k; i++ {
		cursor += k - i
		if pick < cursor {
			if i != 0 {
				candidates[0], candidates[i] = candidates[i], candidates[0]
			}
			return candidates
		}
	}
	return candidates
}

// reorderLeastLoaded swaps the top candidate with a less-loaded
// alternative IF the alternative is within leastLoadedSwapBudget
// positions of the top — keeps the algorithm "weight-first,
// load-aware" instead of "load-first". Pure tiebreaker semantics:
// when current loads are roughly equal, ordering doesn't change.
func (s *Smart) reorderLeastLoaded(candidates []adapter.Outbound) []adapter.Outbound {
	if s.nodeLoad == nil {
		return candidates
	}
	limit := leastLoadedSwapBudget
	if limit > len(candidates) {
		limit = len(candidates)
	}
	bestIdx := 0
	bestLoad := s.nodeLoad.get(candidates[0].Tag())
	for i := 1; i < limit; i++ {
		if l := s.nodeLoad.get(candidates[i].Tag()); l < bestLoad {
			bestIdx = i
			bestLoad = l
		}
	}
	if bestIdx != 0 {
		candidates[0], candidates[bestIdx] = candidates[bestIdx], candidates[0]
	}
	return candidates
}

// reorderFastestRecent promotes the candidate with the lowest ShortRTT
// EWMA reading among the top weightedRandomTopK candidates. Falls back
// to the original ordering when no candidate has accumulated enough
// EWMA samples (record == nil or warmup phase).
//
// Why limit to top-K: the same "load is a tiebreaker, not a replacement"
// logic applies to recent latency. A node that just slowed down by 10 ms
// shouldn't beat one that's been 50 ms faster for hours.
func (s *Smart) reorderFastestRecent(candidates []adapter.Outbound) []adapter.Outbound {
	if s.store == nil {
		return candidates
	}
	limit := weightedRandomTopK
	if limit > len(candidates) {
		limit = len(candidates)
	}
	bestIdx := 0
	bestRTT := s.cachedShortRTT(candidates[0].Tag())
	for i := 1; i < limit; i++ {
		rtt := s.cachedShortRTT(candidates[i].Tag())
		if rtt > 0 && (bestRTT <= 0 || rtt < bestRTT) {
			bestIdx = i
			bestRTT = rtt
		}
	}
	if bestIdx != 0 {
		candidates[0], candidates[bestIdx] = candidates[bestIdx], candidates[0]
	}
	return candidates
}

// reorderStickySession promotes the previously-successful node for the
// given target if it's still in the candidate list. Maximises TLS
// session resumption / connection reuse across repeated requests to
// the same target. Empty target → no-op.
//
// The mapping is held in the Smart struct's stickyByTarget xsync.MapOf
// (lazily allocated). Updated on every successful dial via
// rememberStickyChoice; cleared on markDead via forgetStickyChoice.
func (s *Smart) reorderStickySession(candidates []adapter.Outbound, target string, isUDP bool) []adapter.Outbound {
	if target == "" || s.stickyByTarget == nil {
		return candidates
	}
	wantTag, ok := s.stickyByTarget.Load(stickyKey{target, isUDP})
	if !ok || wantTag == "" {
		return candidates
	}
	for i, ob := range candidates {
		if ob.Tag() == wantTag {
			if i != 0 {
				candidates[0], candidates[i] = candidates[i], candidates[0]
			}
			return candidates
		}
	}
	return candidates
}

// rememberStickyChoice records that `node` was the successfully-dialled
// node for `target`. Called from the dial-success path; cheap (one
// xsync store).
func (s *Smart) rememberStickyChoice(target, node string, isUDP bool) {
	if target == "" || node == "" || s.stickyByTarget == nil {
		return
	}
	s.stickyByTarget.Store(stickyKey{target, isUDP}, node)
}

// shortRTTFor reads the short-window EWMA latency for a node tag. Costs
// one bbolt cache lookup + a brief mutex on the AtomicStatsRecord. Returns
// 0 when no record exists (caller treats 0 as "unknown").
func (s *Smart) shortRTTFor(tag string) float64 {
	if s.store == nil || tag == "" {
		return 0
	}
	rec := s.lookupAnyAtomicRecord(tag)
	if rec == nil {
		return 0
	}
	return rec.ShortRTT()
}

// lookupAnyAtomicRecord finds any AtomicStatsRecord for `tag` across
// the in-memory record cache. We don't care which target — we want the
// node-level ShortRTT signal which is the same across every record
// instance. Returns nil when the cache has no entry yet.
func (s *Smart) lookupAnyAtomicRecord(tag string) *smart.AtomicStatsRecord {
	if s.store == nil {
		return nil
	}
	return s.store.LookupAnyAtomicRecord(s.Tag(), smartConfigName, tag)
}
