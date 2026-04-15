package group

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/common/smart"
)

// Pin-endorsement learning. When the user manually pins a node, every
// successful dial while the pin is active feeds an "endorsement"
// ledger (per Smart group × per node tag). The ledger tracks:
//
//   - Cumulative pin-dial count (frequency proxy for user trust)
//   - Success vs failure split during the pin (did the node deliver?)
//   - First / last pinned timestamps (decay + churn detection)
//   - Per-target hit map (captures context — user pins HK-01 *for
//     youtube* more than for everything)
//
// At selection / weight-write time, a decayed multiplicative boost is
// composed onto the node's priority factor:
//
//	boost = 1 + frequency(count)·successRate·decay(age) + targetCtx
//
// so the preference PERSISTS past the active pin — a formerly-pinned
// node still wins ties in auto-selection for hours to days depending
// on how heavily it was endorsed. Full decay at 14 days guarantees a
// long-forgotten endorsement eventually stops influencing decisions.
//
// Why this shape:
//
//   - log10(1+count) turns raw call count into diminishing returns:
//     100 pins → 2× boost of 10 pins, not 10×. Prevents any single
//     heavy-use day from dominating the model forever.
//
//   - success rate is clamped at ≥ 0.5 — a pinned node that
//     sometimes failed still got the user's explicit trust; we don't
//     actively penalise, just stop boosting when it fully fails.
//
//   - Per-target component: a user who pins HK-01 exclusively for
//     streaming should get HK-01 preferred for streaming targets even
//     after unpin, WITHOUT pulling generic browsing traffic onto it.
//
//   - Separate halfLife (3d) and maxAge (14d) let the formula taper
//     gracefully — by 14d the contribution is ~exp(-14/3) ≈ 0.009,
//     effectively zero but mathematically continuous.

const (
	// endorseHalfLifeSeconds controls the exponential decay of the
	// endorsement boost. 3 days was picked so a pin from last week
	// still counts, but pins from a different subscription refresh /
	// month-long absence don't dominate fresh signals.
	endorseHalfLifeSeconds = 3 * 24 * 60 * 60

	// endorseMaxAgeSeconds is the hard cutoff — past this, the entry
	// stops influencing boost and becomes eligible for sweep-deletion.
	endorseMaxAgeSeconds = 14 * 24 * 60 * 60

	// endorseFrequencyCoef scales log10(count) into the boost; tuned
	// so a healthy ~50-pin history yields a ~14% boost, comparable in
	// magnitude to a policy_priority rule weight.
	endorseFrequencyCoef = 0.08

	// endorseMaxFrequencyBoost caps the frequency component so a
	// power-user with 10 000 pins doesn't turn endorsement into a
	// permanent 2× override. The global composition still saturates
	// below this when success rate or decay are partial.
	endorseMaxFrequencyBoost = 0.30

	// endorseMinSuccessRate clamps the quality factor — see doc
	// above. A fully-failing pinned node still isn't a negative
	// signal; it's "user intent + bad luck", worth muting not
	// punishing.
	endorseMinSuccessRate = 0.5

	// endorseTargetCoef shapes the per-target contextual boost. At
	// most ~10% uplift when a specific target dominated the pin's
	// history. Additive to the global frequency boost.
	endorseTargetCoef = 0.10

	// endorseTopTargetsCap bounds the per-node target map. Captures
	// the user's high-frequency browsing pattern without letting a
	// single noisy ASN explode memory. Least-frequent entry evicted
	// when the cap is reached.
	endorseTopTargetsCap = 16

	// endorsePersistDebounce throttles bbolt writes — a burst of 50
	// pinned dials in a second would otherwise emit 50 identical
	// persist ops. We coalesce to at most one flush per interval.
	endorsePersistDebounce = 3 * time.Second
)

// pinEndorsementEntry is the in-memory reflection of the persisted
// PinEndorsementRecord, augmented with atomics for lock-free hot-path
// reads and a small mutex guarding the target map.
type pinEndorsementEntry struct {
	count         atomic.Int64
	successCount  atomic.Int64
	failureCount  atomic.Int64
	firstPinnedAt atomic.Int64 // unix seconds
	lastPinnedAt  atomic.Int64 // unix seconds

	lastPersistAt atomic.Int64 // unix-nano — for debounce
	baseRTT       atomic.Uint64 // float64 bits

	targetsMu   sync.Mutex
	topTargets  map[string]int64 // target → hit count (≤ endorseTopTargetsCap)
	topASNs     map[string]int64 // asn → hit count
	pinnedHours map[int]int64    // hour -> hit count
}

func evictStringMap(m map[string]int64, cap int) {
	if len(m) < cap {
		return
	}
	var evictKey string
	var evictCount int64 = math.MaxInt64
	for k, v := range m {
		if v < evictCount || (v == evictCount && k < evictKey) {
			evictKey, evictCount = k, v
		}
	}
	if evictKey != "" {
		delete(m, evictKey)
	}
}

func newPinEndorsementEntry() *pinEndorsementEntry {
	return &pinEndorsementEntry{
		topTargets:  make(map[string]int64, 4),
		topASNs:     make(map[string]int64, 4),
		pinnedHours: make(map[int]int64, 4),
	}
}

func fromPinEndorsementRecord(rec *smart.PinEndorsementRecord) *pinEndorsementEntry {
	e := newPinEndorsementEntry()
	e.count.Store(rec.Count)
	e.successCount.Store(rec.SuccessCount)
	e.failureCount.Store(rec.FailureCount)
	e.firstPinnedAt.Store(rec.FirstPinnedAt)
	e.lastPinnedAt.Store(rec.LastPinnedAt)
	e.baseRTT.Store(math.Float64bits(rec.BaseRTT))
	if len(rec.TopTargets) > 0 {
		for k, v := range rec.TopTargets { e.topTargets[k] = v }
	}
	if len(rec.TopASNs) > 0 {
		for k, v := range rec.TopASNs { e.topASNs[k] = v }
	}
	if len(rec.PinnedHours) > 0 {
		for k, v := range rec.PinnedHours { e.pinnedHours[k] = v }
	}
	return e
}

func (e *pinEndorsementEntry) toRecord() *smart.PinEndorsementRecord {
	e.targetsMu.Lock()
	defer e.targetsMu.Unlock()
	out := &smart.PinEndorsementRecord{
		Count:         e.count.Load(),
		SuccessCount:  e.successCount.Load(),
		FailureCount:  e.failureCount.Load(),
		FirstPinnedAt: e.firstPinnedAt.Load(),
		LastPinnedAt:  e.lastPinnedAt.Load(),
		BaseRTT:       math.Float64frombits(e.baseRTT.Load()),
	}
	if len(e.topTargets) > 0 {
		out.TopTargets = make(map[string]int64, len(e.topTargets))
		for k, v := range e.topTargets { out.TopTargets[k] = v }
	}
	if len(e.topASNs) > 0 {
		out.TopASNs = make(map[string]int64, len(e.topASNs))
		for k, v := range e.topASNs { out.TopASNs[k] = v }
	}
	if len(e.pinnedHours) > 0 {
		out.PinnedHours = make(map[int]int64, len(e.pinnedHours))
		for k, v := range e.pinnedHours { out.PinnedHours[k] = v }
	}
	return out
}

// recordHit registers one pinned-dial event. `success` is whether the
// classified dial status was not "failed". Cheap on the hot path:
// atomic bumps plus a small-crit-section map update.
//
// Performs opportunistic eviction when the target map crosses the
// cap — O(N) but bounded by endorseTopTargetsCap, and only runs on
// cap-crossing inserts (dominant case is incrementing an existing
// key, which is pure map-hit + atomic add).
func (e *pinEndorsementEntry) recordHit(meta *smartDialMeta, success bool, currentRTT float64, nowUnix int64) {
	e.count.Add(1)
	if success {
		e.successCount.Add(1)
	} else {
		e.failureCount.Add(1)
	}
	if e.firstPinnedAt.Load() == 0 {
		e.firstPinnedAt.CompareAndSwap(0, nowUnix)
	}
	e.lastPinnedAt.Store(nowUnix)

	oldRTT := math.Float64frombits(e.baseRTT.Load())
	if oldRTT == 0 && currentRTT > 0 {
		e.baseRTT.Store(math.Float64bits(currentRTT))
	} else if currentRTT > 0 {
		newRTT := oldRTT*0.9 + currentRTT*0.1
		e.baseRTT.Store(math.Float64bits(newRTT))
	}

	e.targetsMu.Lock()
	defer e.targetsMu.Unlock()

	hour := time.Unix(nowUnix, 0).Hour()
	e.pinnedHours[hour]++

	if meta != nil {
		if meta.smartTarget != "" {
			if _, ok := e.topTargets[meta.smartTarget]; !ok {
				evictStringMap(e.topTargets, endorseTopTargetsCap)
			}
			e.topTargets[meta.smartTarget]++
		}
		if meta.asnCode != "" {
			if _, ok := e.topASNs[meta.asnCode]; !ok {
				evictStringMap(e.topASNs, endorseTopTargetsCap)
			}
			e.topASNs[meta.asnCode]++
		}
	}
}

// boost returns the multiplicative priority factor contribution from
// this endorsement given the current target and wall-clock time.
// Returns 1.0 when the entry is fully decayed, empty, or stale — so
// call sites can always multiply without a guard.
func (e *pinEndorsementEntry) boost(meta *smartDialMeta, currentRTT float64, nowUnix int64) float64 {
	last := e.lastPinnedAt.Load()
	if last <= 0 {
		return 1.0
	}
	age := nowUnix - last
	if age < 0 {
		age = 0
	}
	if age >= endorseMaxAgeSeconds {
		return 1.0
	}

	base := math.Float64frombits(e.baseRTT.Load())
	if base > 0 && currentRTT > 0 {
		// Performance Aware Degrade
		if currentRTT > base*2.5 {
			return 1.0 // 性能显著恶化，完全熔断所有偏好加成
		}
	}

	decay := math.Exp(-float64(age) / float64(endorseHalfLifeSeconds))
	count := float64(e.count.Load())
	success := float64(e.successCount.Load())
	fail := float64(e.failureCount.Load())

	successRate := 1.0
	if total := success + fail; total > 0 {
		successRate = success / total
	}
	if successRate < endorseMinSuccessRate {
		successRate = endorseMinSuccessRate
	}

	frequency := math.Log10(1+count) * endorseFrequencyCoef
	if frequency > endorseMaxFrequencyBoost {
		frequency = endorseMaxFrequencyBoost
	}

	result := 1.0 + frequency*successRate*decay

	e.targetsMu.Lock()
	var targetBoost, asnBoost, hourBoost float64
	if meta != nil {
		if meta.smartTarget != "" && e.topTargets[meta.smartTarget] > 0 {
			var totalTargetHits int64
			for _, v := range e.topTargets {
				totalTargetHits += v
			}
			targetBoost = math.Sqrt(float64(e.topTargets[meta.smartTarget])/float64(totalTargetHits)) * 0.10 * decay
		}
		if meta.asnCode != "" && e.topASNs[meta.asnCode] > 0 {
			var totalASNHits int64
			for _, v := range e.topASNs {
				totalASNHits += v
			}
			asnBoost = math.Sqrt(float64(e.topASNs[meta.asnCode])/float64(totalASNHits)) * 0.08 * decay
		}
	}

	currentHour := time.Unix(nowUnix, 0).Hour()
	if e.pinnedHours[currentHour] > 0 {
		hourBoost = float64(e.pinnedHours[currentHour]) / float64(e.count.Load()) * 0.15 * decay
	}
	e.targetsMu.Unlock()

	return result + targetBoost + asnBoost + hourBoost
}

// pinEndorsements is the Smart-instance-level store: node tag → entry.
// Lazily allocated the first time the group sees a pinned dial, so
// groups that never get pinned pay zero memory cost.
func (s *Smart) ensurePinEndorsements() {
	if s.pinEndorsements == nil {
		s.pinEndorsementsOnce.Do(func() {
			s.pinEndorsements = xsync.NewMapOf[string, *pinEndorsementEntry]()
		})
	}
}

// applyPinEndorsementBoost returns the composite boost for `tag` at
// `target`, or 1.0 if no endorsement exists. Lock-free fast path.
func (s *Smart) applyPinEndorsementBoost(tag string, meta *smartDialMeta, currentRTT float64) float64 {
	if s.pinEndorsements == nil || tag == "" {
		return 1.0
	}
	entry, ok := s.pinEndorsements.Load(tag)
	if !ok {
		return 1.0
	}
	return entry.boost(meta, currentRTT, time.Now().Unix())
}

// recordPinEndorsement logs a single pinned-dial event. Called from
// recordStats ONLY when the active pin equals the dialed tag; non-
// pinned dials never trigger this so the endorsement only tracks
// explicit user endorsements, not passive through-traffic.
//
// Persistence: writes to the store via the existing global queue
// using a 3 s debounce per-tag so a connection-per-second workload
// generates at most 20 persist ops/min/node instead of thousands.
func (s *Smart) recordPinEndorsement(tag string, meta *smartDialMeta, success bool, currentRTT float64) {
	if tag == "" {
		return
	}
	s.ensurePinEndorsements()
	entry, _ := s.pinEndorsements.LoadOrCompute(tag, newPinEndorsementEntry)
	entry.recordHit(meta, success, currentRTT, time.Now().Unix())

	// Debounced persistence — a burst of pinned dials flushes at most
	// once per endorsePersistDebounce.
	now := time.Now().UnixNano()
	last := entry.lastPersistAt.Load()
	if now-last < int64(endorsePersistDebounce) {
		return
	}
	if !entry.lastPersistAt.CompareAndSwap(last, now) {
		// Another goroutine just flushed — skip.
		return
	}
	s.persistPinEndorsement(tag, entry)
}

// persistPinEndorsement serialises the entry and queues a Save op.
// Safe to call from any goroutine; the queue takes the contention.
func (s *Smart) persistPinEndorsement(tag string, entry *pinEndorsementEntry) {
	if s.store == nil || tag == "" || entry == nil {
		return
	}
	rec := entry.toRecord()
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	s.store.AppendToGlobalQueue(smart.StoreOperation{
		Type:   smart.OpSavePinEndorsement,
		Group:  s.Tag(),
		Config: smartConfigName,
		Node:   tag,
		Data:   data,
	})
}

// persistPinEndorsementDelete emits a tombstone so the group-level
// flush path (ClearSelection / FlushStore) can forget endorsements
// together with all other manual-pin state.
func (s *Smart) persistPinEndorsementDelete(tag string) {
	if s.store == nil || tag == "" {
		return
	}
	s.store.AppendToGlobalQueue(smart.StoreOperation{
		Type:   smart.OpDeletePinEndorsement,
		Group:  s.Tag(),
		Config: smartConfigName,
		Node:   tag,
	})
}

// restorePinEndorsements loads persisted endorsement records from
// bbolt into the in-memory map. Called from PostStart once the store
// is available. Invalid / too-old records are tombstoned so the
// bucket doesn't carry an infinite tail of stale data.
func (s *Smart) restorePinEndorsements() {
	if s.store == nil {
		return
	}
	rows, err := s.store.GetSubBytesByPath(
		smart.FormatDBKey(smart.KeyTypePinEndorsement, smartConfigName, s.Tag()))
	if err != nil || len(rows) == 0 {
		return
	}
	s.ensurePinEndorsements()
	nowUnix := time.Now().Unix()
	restored, expired := 0, 0
	for key, data := range rows {
		var rec smart.PinEndorsementRecord
		if err := json.Unmarshal(data, &rec); err != nil || rec.LastPinnedAt <= 0 {
			continue
		}
		if nowUnix-rec.LastPinnedAt >= endorseMaxAgeSeconds {
			parts := strings.Split(key, "/")
			if len(parts) > 0 {
				node := smart.UnescapeKeyPart(parts[len(parts)-1])
				if node != "" {
					s.persistPinEndorsementDelete(node)
				}
			}
			expired++
			continue
		}
		parts := strings.Split(key, "/")
		if len(parts) == 0 {
			continue
		}
		node := smart.UnescapeKeyPart(parts[len(parts)-1])
		if node == "" {
			continue
		}
		entry := fromPinEndorsementRecord(&rec)
		s.pinEndorsements.Store(node, entry)
		restored++
	}
	if restored > 0 || expired > 0 {
		s.logger.Info("smart[", s.Tag(), "] pin endorsements restored=", restored,
			" expired=", expired)
	}
}

// PinEndorsementDebug returns a stable snapshot of the learning
// ledger for operator diagnostics. Exposes the full record list
// sorted by live boost (highest first) so dashboards can surface
// "which nodes has the user taught me to prefer". Cheap enough to
// serve on /smart/groups/{name}/diag without pagination.
func (s *Smart) PinEndorsementDebug() []map[string]any {
	if s.pinEndorsements == nil {
		return nil
	}
	nowUnix := time.Now().Unix()
	type row struct {
		tag   string
		boost float64
		rec   *smart.PinEndorsementRecord
	}
	rows := make([]row, 0, 8)
	s.pinEndorsements.Range(func(tag string, entry *pinEndorsementEntry) bool {
		rows = append(rows, row{
			tag:   tag,
			boost: entry.boost(nil, 0, nowUnix),
			rec:   entry.toRecord(),
		})
		return true
	})
	sort.Slice(rows, func(i, j int) bool { return rows[i].boost > rows[j].boost })
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{
			"node":           r.tag,
			"boost":          r.boost,
			"count":          r.rec.Count,
			"success":        r.rec.SuccessCount,
			"failure":        r.rec.FailureCount,
			"first_pinned":   r.rec.FirstPinnedAt,
			"last_pinned":    r.rec.LastPinnedAt,
			"top_targets":    r.rec.TopTargets,
			"age_seconds":    nowUnix - r.rec.LastPinnedAt,
		})
	}
	return out
}
