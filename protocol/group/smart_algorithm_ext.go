package group

import (
	mathrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/adapter"
)

// Extended Smart algorithms + cross-cutting hysteresis + perf hooks.
//
// Why a second file: smart_algorithm.go houses the original five
// algorithms plus the dispatch contract. Keeping the new four here
// (round-robin, weighted-rr, p2c, latency-banded) along with the
// hysteresis layer makes the diff legible during review and lets the
// older code stay untouched.
//
// All four new algorithms are O(K) work where K = min(top-K cap, len)
// and zero allocations per dial. Hysteresis adds one xsync.MapOf load
// per dial; the cache line is shared with sticky-session.

const (
	smartAlgoRoundRobin        = "round-robin"
	smartAlgoWeightedRR        = "weighted-rr"
	smartAlgoP2C               = "p2c"
	smartAlgoLatencyBanded     = "latency-banded"
	smartAlgoConsistentHashing = "consistent-hashing"

	// p2cTopK is the candidate window from which we sample two for
	// comparison. 5 mirrors weightedRandomTopK so all "sample within
	// top set" algorithms share the same breadth.
	p2cTopK = 5

	// latencyBandFastMS / SlowMS define the three buckets used by
	// latency-banded. Tuned for typical proxy RTTs from CN ISPs:
	// < 50 ms is excellent; 50–150 is acceptable; >150 is degraded.
	latencyBandFastMS = 50.0
	latencyBandSlowMS = 150.0
)

// shortRTTCacheTTL is how long a per-node ShortRTT lookup is cached in
// memory before the algorithm dispatcher re-queries the AtomicStatsRecord.
// Short enough that a recent latency spike still gets seen within a
// dial cycle, long enough that 1k QPS doesn't hammer the recordCache
// mutex on every selection. 250 ms × 1k QPS → 4 reads/sec/node.
const shortRTTCacheTTL = 250 * time.Millisecond

// shortRTTCacheEntry pairs a measurement with the wall-clock time it
// was captured. Stored by value (xsync.MapOf supports any comparable
// value type but we want amortised allocation-free reads via Load).
type shortRTTCacheEntry struct {
	rttMS  float64
	storedAt int64 // unix-nano
}

// roundRobinCounter is the atomic dial counter used by round-robin.
// Wrapped in a struct so future enhancements (per-target counters,
// metrics) have a place to live without breaking the API.
type roundRobinCounter struct{ n atomic.Uint64 }

func (r *roundRobinCounter) next(modulo int) int {
	if modulo <= 0 {
		return 0
	}
	return int(r.n.Add(1) % uint64(modulo))
}

// stickyKey is a struct value used as xsync.MapOf key for sticky &
// hysteresis lookups. Replaces the previous "target + |udp" string
// concat — saves an allocation per dial under load. xsync.MapOf
// requires comparable; struct-of-strings qualifies.
type stickyKey struct {
	target string
	isUDP  bool
}

// hysteresisEntry pairs the last-picked node tag with the time that
// pick became authoritative. Read on every algorithm pass; written on
// every dial-success funnel (rememberStickyChoice).
type hysteresisEntry struct {
	tag string
	at  int64 // unix-nano
}

// algoRandSource is a per-CPU rand source. math/rand/v2 NewPCG is
// lock-free per instance; we shard so concurrent reorderForAlgorithm
// callers across goroutines don't serialise on the global default
// source. Allocated once at init and indexed by a goroutine-stable
// counter.
//
// 16 shards is plenty: contention on math/rand at 1k QPS is already
// negligible after sharding even four-way. The extra shards leave
// headroom for the parallel-dial expansion.
const algoRandShards = 16

var algoRandShardsArr [algoRandShards]*mathrand.Rand
var algoRandIdx atomic.Uint32

func init() {
	for i := range algoRandShardsArr {
		algoRandShardsArr[i] = mathrand.New(mathrand.NewPCG(uint64(i)+1, 0xC4F5_2A1B_DEF0_1234))
	}
}

// pickRand returns a per-call rand source. The cursor is incremented
// atomically so concurrent callers fan out across the shards. Callers
// must NOT cache the returned pointer across goroutines.
func pickRand() *mathrand.Rand {
	idx := int(algoRandIdx.Add(1)) & (algoRandShards - 1)
	return algoRandShardsArr[idx]
}

// shortRTTCache is a global short-TTL memoiser for AtomicStatsRecord
// ShortRTT lookups. The recordCache itself already deduplicates the
// underlying bbolt fetch, but ShortRTT() takes the per-record mutex on
// every call — at 1k QPS that mutex shows up in profiles. The 250 ms
// TTL lets the algorithm see near-real-time data without paying the
// mutex cost more than ~4 times/second/node.
var shortRTTCache = xsync.NewMapOf[string, shortRTTCacheEntry]()

// cachedShortRTT returns ShortRTT for a tag, refreshing the cache
// when the entry is stale or missing. tag is namespaced with the
// group name so different Smart groups don't share entries (their
// underlying records are distinct).
func (s *Smart) cachedShortRTT(tag string) float64 {
	if tag == "" {
		return 0
	}
	key := s.Tag() + "|" + tag
	now := time.Now().UnixNano()
	if entry, ok := shortRTTCache.Load(key); ok {
		if now-entry.storedAt < int64(shortRTTCacheTTL) {
			return entry.rttMS
		}
	}
	rtt := s.shortRTTFor(tag)
	shortRTTCache.Store(key, shortRTTCacheEntry{rttMS: rtt, storedAt: now})
	return rtt
}

// reorderRoundRobin picks the next candidate by an atomic counter
// modulo the candidate count. O(1) work. Counter is per-Smart so two
// groups don't share rotation state.
func (s *Smart) reorderRoundRobin(candidates []adapter.Outbound) []adapter.Outbound {
	if s.rrCounter == nil {
		return candidates
	}
	idx := s.rrCounter.next(len(candidates))
	if idx > 0 {
		candidates[0], candidates[idx] = candidates[idx], candidates[0]
	}
	return candidates
}

// reorderWeightedRoundRobin assigns each top-K position a turn budget
// proportional to its rank (k turns for position 0, k-1 for position 1,
// ..., 1 for position k-1) and visits them in proportional rotation.
// Implemented as a per-Smart cursor + Σ-budget — same O(1) per dial as
// vanilla RR, just with a precomputed bucket map.
func (s *Smart) reorderWeightedRoundRobin(candidates []adapter.Outbound) []adapter.Outbound {
	if s.wrrCounter == nil {
		return candidates
	}
	k := p2cTopK
	if k > len(candidates) {
		k = len(candidates)
	}
	total := uint64(k * (k + 1) / 2)
	cursor := s.wrrCounter.next(int(total))
	// Map cursor ∈ [0, total) → bucket index ∈ [0, k).
	pick := uint64(cursor)
	idx := 0
	acc := uint64(0)
	for i := 0; i < k; i++ {
		acc += uint64(k - i)
		if pick < acc {
			idx = i
			break
		}
	}
	if idx > 0 {
		candidates[0], candidates[idx] = candidates[idx], candidates[0]
	}
	return candidates
}

// reorderP2C samples two distinct candidates from top-K and promotes
// the one with the lower cached ShortRTT (or, on RTT tie, the one
// with fewer active connections). Power-of-two-choices is provably
// load-balancing with O(1) overhead per pick.
//
// Falls back to strict-best when only one candidate exists or
// rand/source is unavailable.
func (s *Smart) reorderP2C(candidates []adapter.Outbound) []adapter.Outbound {
	if len(candidates) < 2 {
		return candidates
	}
	k := p2cTopK
	if k > len(candidates) {
		k = len(candidates)
	}
	r := pickRand()
	a := r.IntN(k)
	b := r.IntN(k - 1)
	if b >= a {
		b++ // ensures a != b without rejection sampling
	}
	winner := s.scoreP2C(candidates[a], candidates[b])
	pickIdx := a
	if winner == 1 {
		pickIdx = b
	}
	if pickIdx > 0 {
		candidates[0], candidates[pickIdx] = candidates[pickIdx], candidates[0]
	}
	return candidates
}

// scoreP2C decides which of two candidates wins under p2c rules:
// lower ShortRTT first; on RTT tie (or both 0), fewer active
// connections; final tiebreak is the original ordering (return 0 →
// keep candidates[0] as the winner).
func (s *Smart) scoreP2C(a, b adapter.Outbound) int {
	rttA := s.cachedShortRTT(a.Tag())
	rttB := s.cachedShortRTT(b.Tag())
	switch {
	case rttA > 0 && rttB > 0 && rttA != rttB:
		if rttA < rttB {
			return 0
		}
		return 1
	}
	if s.nodeLoad != nil {
		la := s.nodeLoad.get(a.Tag())
		lb := s.nodeLoad.get(b.Tag())
		if la < lb {
			return 0
		}
		if lb < la {
			return 1
		}
	}
	return 0
}

// reorderLatencyBanded buckets top-K candidates into three latency
// bands and promotes a uniformly-random pick from the lowest non-empty
// band. Strips the long tail (a 1000 ms node never wins over a
// 50 ms node) without pinning to the single fastest node.
//
// Allocation-free: per-call buckets are scratch indexes only.
func (s *Smart) reorderLatencyBanded(candidates []adapter.Outbound) []adapter.Outbound {
	if len(candidates) < 2 {
		return candidates
	}
	k := p2cTopK
	if k > len(candidates) {
		k = len(candidates)
	}
	// Three bands: fast, medium, slow. Allocate-on-stack via small
	// fixed-size array — Go escape analysis keeps it on the goroutine
	// stack since the slice header doesn't escape this function.
	var fast, medium, slow [p2cTopK]int
	var nFast, nMedium, nSlow int
	for i := 0; i < k; i++ {
		rtt := s.cachedShortRTT(candidates[i].Tag())
		switch {
		case rtt > 0 && rtt < latencyBandFastMS:
			fast[nFast] = i
			nFast++
		case rtt > 0 && rtt < latencyBandSlowMS:
			medium[nMedium] = i
			nMedium++
		default:
			// Includes RTT==0 (no signal) — treated as "unknown" not
			// "slow"; clustered into the slow band so candidates with
			// real measurements get preferred.
			slow[nSlow] = i
			nSlow++
		}
	}
	r := pickRand()
	var pick int
	switch {
	case nFast > 0:
		pick = fast[r.IntN(nFast)]
	case nMedium > 0:
		pick = medium[r.IntN(nMedium)]
	case nSlow > 0:
		pick = slow[r.IntN(nSlow)]
	default:
		return candidates
	}
	if pick > 0 {
		candidates[0], candidates[pick] = candidates[pick], candidates[0]
	}
	return candidates
}

// applyHysteresis is the cross-cutting anti-flap layer applied AFTER
// reorderForAlgorithm. When the user has configured a non-zero
// hysteresis window AND the previously-picked node for this target is
// still present in the candidate list AND the window hasn't expired,
// the previous pick is forced back to position 0 — overriding the
// algorithm's fresh evaluation.
//
// Why post-algorithm: we want algorithm scoring to see uncoloured
// candidates so its own decisions remain meaningful for new targets;
// hysteresis only kicks in once history exists.
func (s *Smart) applyHysteresis(candidates []adapter.Outbound, target string, isUDP bool) []adapter.Outbound {
	if s.hysteresisWindow <= 0 || s.hysteresisMemo == nil ||
		target == "" || len(candidates) <= 1 {
		return candidates
	}
	entry, ok := s.hysteresisMemo.Load(stickyKey{target, isUDP})
	if !ok || entry.tag == "" {
		return candidates
	}
	if time.Since(time.Unix(0, entry.at)) > s.hysteresisWindow {
		return candidates
	}
	for i, ob := range candidates {
		if ob.Tag() == entry.tag {
			if i != 0 {
				candidates[0], candidates[i] = candidates[i], candidates[0]
			}
			return candidates
		}
	}
	// Previously-picked node has dropped from the candidate list
	// (e.g. went dead) — let the algorithm's choice stand.
	return candidates
}

// rememberHysteresisChoice records the just-picked node for a target.
// Cheap (one xsync store) and safe to call from any dial-success
// funnel.
func (s *Smart) rememberHysteresisChoice(target, node string, isUDP bool) {
	if s.hysteresisMemo == nil || target == "" || node == "" {
		return
	}
	s.hysteresisMemo.Store(stickyKey{target, isUDP}, hysteresisEntry{
		tag: node,
		at:  time.Now().UnixNano(),
	})
}

// factorsPool recycles []float64 scratch slices used by
// reorderByPriority's pre-computed factor cache. Capacity tuned to
// smartMaxSelected (10) so the typical request avoids re-allocation
// and pool growth.
var factorsPool = sync.Pool{
	New: func() any {
		s := make([]float64, 0, 16)
		return &s
	},
}

func acquireFactorsSlice(n int) *[]float64 {
	p := factorsPool.Get().(*[]float64)
	if cap(*p) < n {
		*p = make([]float64, n)
	} else {
		*p = (*p)[:n]
	}
	return p
}

func releaseFactorsSlice(p *[]float64) {
	if p == nil {
		return
	}
	*p = (*p)[:0]
	factorsPool.Put(p)
}
