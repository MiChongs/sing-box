package smart

import (
	"bytes"
	"container/heap"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/bbolt"
)

// The stats index is a compact, decoded view of one group's stats rows
// (queue + bbolt): per target, the node rows with exactly the fields
// selection, prefetch and ranking read. Every consumer used to call
// GetAllStats — copying the group's cached scan, re-splitting every key
// and unmarshalling every record — once per target, which made a prefetch
// pass O(targets × records) and a tier-3 dial O(records).
//
// Freshness: an index is built once from a consistent snapshot and then
// kept current incrementally. AppendToGlobalQueue hands every stats write
// for a tracked group to its slot as a pending upsert (O(1), under the
// queue lock so pending order matches queue order); the next query decodes
// just those rows. Queue flushes don't change the logical view and need no
// invalidation; writes that bypass the queue (CleanupOldRecords,
// RemoveNodesData, FlushByLevel, direct puts/deletes) mark the slot stale.
// A TTL backstop forces a periodic full rebuild, which also reclaims the
// space superseded rows leave behind.
//
// Memory: indexes live in a registry bounded by their own share of the
// cache budget; least-recently-used indexes are dropped (and rebuilt on
// demand) when the total exceeds it. The index in use is never dropped.

const (
	// statsIndexTTL is the backstop for incremental maintenance.
	statsIndexTTL = time.Minute
	// statsIndexMaxPending caps buffered upserts for an idle index; past
	// it the slot stops tracking and the next query rebuilds instead.
	statsIndexMaxPending = 1024
)

// Approximate heap cost of index parts for budget accounting, including
// slice growth slack and map overhead (calibrated against measured heap
// on a 4.8k-row group).
const (
	statsRowCost       = 64  // 48 B row
	statsTargetCost    = 112 // map slot + targetRows header
	statsNodeCost      = 72  // map slot + name header
	statsASNWeightCost = 24  // 16 B entry
	statsCandidateCost = 32  // 24 B entry
)

type statsRow struct {
	node     int32
	asnOff   uint32 // ASN-scoped weights live in statsIndex.arena[asnOff:asnOff+asnLen]
	asnLen   uint32
	lastUsed int64
	samples  int64 // Success + Failure
	tcp, udp float64
}

type targetRows struct {
	name string
	rows []statsRow
}

type asnWeight struct {
	key int32 // index into statsIndex.keys
	w   float64
}

// weightKey describes an interned ASN-scoped weight key such as
// "tcp_asn:4134". asn is the ASN GetActiveTargets derives from the key;
// active reports whether it derives one at all.
type weightKey struct {
	name   string
	asn    string
	isUDP  bool
	active bool
}

type asnCandidate struct {
	node     int32
	lastUsed int64
	w        float64
}

type statsIndex struct {
	targetIDs map[string]int32
	targets   []targetRows
	nodeIDs   map[string]int32
	nodes     []string
	keyIDs    map[string]int32
	keys      []weightKey
	arena     []asnWeight

	// byASN groups every positive ASN-scoped weight by weight key. Built on
	// first use, dropped on upsert.
	byASN      map[int32][]asnCandidate
	candidates int

	rows      int
	nameBytes int

	// Decode scratch, reused across rows.
	dec        statsRowRecord
	decWeights map[string]float64
	// Per-query scratch for the ASN aggregation, indexed by node id.
	agg []nodeAgg
}

// statsRowRecord is the subset of StatsRecord the index needs. Decoding
// into it skips every other field — including multi-KiB legacy
// rtt_digest blobs — without materialising them.
type statsRowRecord struct {
	Success  int64              `json:"success"`
	Failure  int64              `json:"failure"`
	LastUsed int64              `json:"last_used"`
	Weights  map[string]float64 `json:"weights"`
}

type nodeAgg struct {
	min, max float64
	seen     bool
}

func newStatsIndex() *statsIndex {
	return &statsIndex{
		targetIDs:  make(map[string]int32),
		nodeIDs:    make(map[string]int32),
		keyIDs:     make(map[string]int32),
		decWeights: make(map[string]float64),
	}
}

func (ix *statsIndex) cost() int64 {
	return int64(len(ix.targets))*statsTargetCost +
		int64(len(ix.nodes))*statsNodeCost +
		int64(ix.rows)*statsRowCost +
		int64(len(ix.arena))*statsASNWeightCost +
		int64(ix.candidates)*statsCandidateCost +
		int64(ix.nameBytes)
}

// splitStatsKey extracts the escaped target and node parts of a stats key
// relative to its group scope: the last two '/'-separated segments of
// rest, matching how GetAllStats has always parsed stats keys.
func splitStatsKey(rest []byte) (target, node []byte, ok bool) {
	j := bytes.LastIndexByte(rest, '/')
	if j < 0 {
		return nil, nil, false
	}
	t := rest[:j]
	return t[bytes.LastIndexByte(t, '/')+1:], rest[j+1:], true
}

func (ix *statsIndex) targetID(esc []byte) int32 {
	if bytes.IndexByte(esc, '%') >= 0 {
		return ix.internTarget(UnescapeKeyPart(string(esc)))
	}
	if id, ok := ix.targetIDs[string(esc)]; ok {
		return id
	}
	return ix.internTarget(string(esc))
}

func (ix *statsIndex) internTarget(name string) int32 {
	if id, ok := ix.targetIDs[name]; ok {
		return id
	}
	id := int32(len(ix.targets))
	ix.targetIDs[name] = id
	ix.targets = append(ix.targets, targetRows{name: name})
	ix.nameBytes += len(name)
	return id
}

func (ix *statsIndex) nodeID(esc []byte) int32 {
	if bytes.IndexByte(esc, '%') >= 0 {
		return ix.internNode(UnescapeKeyPart(string(esc)))
	}
	if id, ok := ix.nodeIDs[string(esc)]; ok {
		return id
	}
	return ix.internNode(string(esc))
}

func (ix *statsIndex) internNode(name string) int32 {
	if id, ok := ix.nodeIDs[name]; ok {
		return id
	}
	id := int32(len(ix.nodes))
	ix.nodeIDs[name] = id
	ix.nodes = append(ix.nodes, name)
	ix.nameBytes += len(name)
	return id
}

func (ix *statsIndex) keyID(name string) int32 {
	if id, ok := ix.keyIDs[name]; ok {
		return id
	}
	// Decoded map keys may alias the decoder's buffer; own the copy.
	name = strings.Clone(name)
	k := weightKey{name: name, isUDP: strings.HasPrefix(name, WeightTypeUDPASN)}
	if parts := strings.Split(name, ":"); len(parts) >= 2 {
		k.asn, k.active = parts[1], true
	}
	id := int32(len(ix.keys))
	ix.keyIDs[name] = id
	ix.keys = append(ix.keys, k)
	ix.nameBytes += len(name)
	return id
}

// decode unmarshals one stored record into the reusable scratch record.
func (ix *statsIndex) decode(data []byte) (*statsRowRecord, bool) {
	clear(ix.decWeights)
	ix.dec = statsRowRecord{Weights: ix.decWeights}
	if unmarshalRecord(data, &ix.dec) != nil {
		return nil, false
	}
	return &ix.dec, true
}

// put upserts the row for (target, node) from a stored record value. An
// undecodable value removes the row: readers have always skipped records
// that fail to unmarshal.
func (ix *statsIndex) put(targetEsc, nodeEsc, data []byte) {
	rec, ok := ix.decode(data)
	if !ok {
		ix.remove(targetEsc, nodeEsc)
		return
	}
	tid := ix.targetID(targetEsc)
	nid := ix.nodeID(nodeEsc)
	t := &ix.targets[tid]
	pos := rowIndex(t.rows, nid)
	row := statsRow{
		node:     nid,
		lastUsed: rec.LastUsed,
		samples:  rec.Success + rec.Failure,
		tcp:      rec.Weights[WeightTypeTCP],
		udp:      rec.Weights[WeightTypeUDP],
		asnOff:   uint32(len(ix.arena)),
	}
	for name, w := range rec.Weights {
		if w > 0 && (strings.HasPrefix(name, WeightTypeTCPASN) || strings.HasPrefix(name, WeightTypeUDPASN)) {
			ix.arena = append(ix.arena, asnWeight{key: ix.keyID(name), w: w})
		}
	}
	row.asnLen = uint32(len(ix.arena)) - row.asnOff
	if pos >= 0 {
		t.rows[pos] = row
	} else {
		t.rows = append(t.rows, row)
		ix.rows++
	}
	ix.byASN = nil
}

// remove drops the row for (target, node), if present.
func (ix *statsIndex) remove(targetEsc, nodeEsc []byte) {
	tid, ok := ix.targetIDs[UnescapeKeyPart(string(targetEsc))]
	if !ok {
		return
	}
	nid, ok := ix.nodeIDs[UnescapeKeyPart(string(nodeEsc))]
	if !ok {
		return
	}
	t := &ix.targets[tid]
	if pos := rowIndex(t.rows, nid); pos >= 0 {
		t.rows = append(t.rows[:pos], t.rows[pos+1:]...)
		ix.rows--
		ix.byASN = nil
	}
}

func rowIndex(rows []statsRow, node int32) int {
	for i := range rows {
		if rows[i].node == node {
			return i
		}
	}
	return -1
}

func (ix *statsIndex) asnWeights(r *statsRow) []asnWeight {
	return ix.arena[r.asnOff : r.asnOff+r.asnLen]
}

// asnCandidates returns the positive weights of one ASN-scoped weight key
// across every row of the group.
func (ix *statsIndex) asnCandidates(key int32) []asnCandidate {
	if ix.byASN == nil {
		ix.byASN = make(map[int32][]asnCandidate)
		ix.candidates = 0
		for ti := range ix.targets {
			rows := ix.targets[ti].rows
			for ri := range rows {
				r := &rows[ri]
				for _, aw := range ix.asnWeights(r) {
					ix.byASN[aw.key] = append(ix.byASN[aw.key], asnCandidate{node: r.node, lastUsed: r.lastUsed, w: aw.w})
					ix.candidates++
				}
			}
		}
	}
	return ix.byASN[key]
}

// bestFor ranks nodes for a target (or, for a non-CDN ASN, for the ASN
// across all targets) — the GetBestProxyForTarget algorithm:
//
//   - target: each node's tcp/udp weight × time decay, weight > 0 only.
//   - ASN: every positive ASN-scoped weight × decay, per node the minimum
//     when it falls below AllowedWeight, else the maximum.
//
// Ordered by weight descending, then node name.
func (ix *statsIndex) bestFor(target, asnNumber string, isUDP bool, now int64) ([]string, []float64) {
	var list []NodeWithWeight
	if asnNumber != "" && !CdnASNs[asnNumber] {
		key, ok := ix.keyIDs[asnWeightKey(isUDP, asnNumber)]
		if !ok {
			return nil, nil
		}
		if cap(ix.agg) < len(ix.nodes) {
			ix.agg = make([]nodeAgg, len(ix.nodes))
		}
		agg := ix.agg[:len(ix.nodes)]
		var touched []int32
		for _, c := range ix.asnCandidates(key) {
			v := c.w * GetTimeDecay(c.lastUsed, now, 0.4)
			a := &agg[c.node]
			if !a.seen {
				*a = nodeAgg{min: v, max: v, seen: true}
				touched = append(touched, c.node)
				continue
			}
			if v < a.min {
				a.min = v
			}
			if v > a.max {
				a.max = v
			}
		}
		list = make([]NodeWithWeight, 0, len(touched))
		for _, n := range touched {
			a := &agg[n]
			w := a.max
			if a.min < AllowedWeight {
				w = a.min
			}
			list = append(list, NodeWithWeight{ix.nodes[n], w})
			*a = nodeAgg{}
		}
	} else {
		tid, ok := ix.targetIDs[target]
		if !ok {
			return nil, nil
		}
		rows := ix.targets[tid].rows
		list = make([]NodeWithWeight, 0, len(rows))
		for i := range rows {
			w := rows[i].tcp
			if isUDP {
				w = rows[i].udp
			}
			if w > 0 {
				list = append(list, NodeWithWeight{ix.nodes[rows[i].node], w * GetTimeDecay(rows[i].lastUsed, now, 0.4)})
			}
		}
	}
	if len(list) == 0 {
		return nil, nil
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Weight != list[j].Weight {
			return list[i].Weight > list[j].Weight
		}
		return list[i].Node < list[j].Node
	})
	nodes := make([]string, len(list))
	weights := make([]float64, len(list))
	for i, nw := range list {
		nodes[i] = nw.Node
		weights[i] = nw.Weight
	}
	return nodes, weights
}

type activeCombo struct {
	asn   string
	isUDP bool
}

// activeTargets returns the `limit` most recently used (target, ASN, UDP)
// combinations. Per target: plain TCP/UDP combos from positive tcp/udp
// weights and ASN combos from positive ASN-scoped weights, each stamped
// with the newest LastUsed among its rows; plain combos are dropped when
// the target has any ASN combo. Ties on LastUsed are broken by
// (target, ASN, UDP) so the selection is deterministic.
func (ix *statsIndex) activeTargets(limit int) []ActiveTarget {
	h := &targetMinHeap{}
	combos := make(map[activeCombo]int64)
	for ti := range ix.targets {
		t := &ix.targets[ti]
		clear(combos)
		hasASN := false
		bump := func(c activeCombo, lastUsed int64) bool {
			if last, ok := combos[c]; ok && lastUsed <= last {
				return false
			}
			combos[c] = lastUsed
			return true
		}
		for ri := range t.rows {
			r := &t.rows[ri]
			if r.tcp > 0 {
				bump(activeCombo{}, r.lastUsed)
			}
			if r.udp > 0 {
				bump(activeCombo{isUDP: true}, r.lastUsed)
			}
			for _, aw := range ix.asnWeights(r) {
				if k := &ix.keys[aw.key]; k.active && bump(activeCombo{k.asn, k.isUDP}, r.lastUsed) {
					hasASN = true
				}
			}
		}
		for c, lastUsed := range combos {
			if c.asn == "" && hasASN {
				continue
			}
			heap.Push(h, ActiveTarget{Target: t.name, ASN: c.asn, IsUDP: c.isUDP, LastUsed: lastUsed})
			if h.Len() > limit {
				heap.Pop(h)
			}
		}
	}
	result := make([]ActiveTarget, h.Len())
	for i := len(result) - 1; i >= 0; i-- {
		result[i] = heap.Pop(h).(ActiveTarget)
	}
	return result
}

// targetMinHeap orders ActiveTargets oldest-first so the bounded heap in
// activeTargets keeps the newest ones.
type targetMinHeap []ActiveTarget

func (h targetMinHeap) Len() int { return len(h) }
func (h targetMinHeap) Less(i, j int) bool {
	a, b := &h[i], &h[j]
	if a.LastUsed != b.LastUsed {
		return a.LastUsed < b.LastUsed
	}
	if a.Target != b.Target {
		return a.Target > b.Target
	}
	if a.ASN != b.ASN {
		return a.ASN > b.ASN
	}
	return a.IsUDP && !b.IsUDP
}
func (h targetMinHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *targetMinHeap) Push(x interface{}) { *h = append(*h, x.(ActiveTarget)) }
func (h *targetMinHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// forEachRow visits every row with its target and node names.
func (ix *statsIndex) forEachRow(fn func(target, node string, r *statsRow)) {
	for ti := range ix.targets {
		t := &ix.targets[ti]
		for ri := range t.rows {
			fn(t.name, ix.nodes[t.rows[ri].node], &t.rows[ri])
		}
	}
}

// statsSlot owns the index of one group scope ("smart/stats/<cfg>/<grp>")
// plus the pending upserts fed by AppendToGlobalQueue.
type statsSlot struct {
	scope string

	mu      sync.Mutex // guards ix, builtAt, cost; held while an index is queried
	ix      *statsIndex
	builtAt time.Time
	cost    int64
	lastUse atomic.Int64
	// resident mirrors ix != nil for lock-free eviction scans.
	resident atomic.Bool

	pendMu   sync.Mutex // leaf lock; may be taken under globalQueueMu
	tracking bool
	stale    bool
	pending  []pendingStat
}

type pendingStat struct {
	key  string
	data []byte
}

var (
	statsSlots     = xsync.NewMapOf[string, *statsSlot]()
	statsIndexCost atomic.Int64
)

// feedStatsIndex queues a stats write for the group's index, if one is
// tracked. Called with globalQueueMu held for writing.
func feedStatsIndex(key string, data []byte) {
	scope, ok := groupScope(key)
	if !ok {
		return
	}
	sl, ok := statsSlots.Load(scope)
	if !ok {
		return
	}
	sl.pendMu.Lock()
	if sl.tracking {
		if len(sl.pending) >= statsIndexMaxPending {
			sl.pending, sl.tracking, sl.stale = nil, false, true
		} else {
			sl.pending = append(sl.pending, pendingStat{key, data})
		}
	}
	sl.pendMu.Unlock()
}

// invalidateStatsIndexes marks every index whose scope lies under prefix
// (segment-aligned) or contains it as stale; the next query rebuilds.
func invalidateStatsIndexes(prefix string) {
	statsSlots.Range(func(scope string, sl *statsSlot) bool {
		if hasScanPrefix(scope, prefix) || hasScanPrefix(prefix, scope) {
			// Free the memory now when the slot is idle; a slot in use
			// is rebuilt by its next query.
			if sl.mu.TryLock() {
				sl.dropLocked()
				sl.mu.Unlock()
			}
			sl.pendMu.Lock()
			sl.pending, sl.tracking, sl.stale = nil, false, true
			sl.pendMu.Unlock()
		}
		return true
	})
}

// withStatsIndex runs fn against the group's up-to-date stats index. fn
// runs under the slot lock and must not re-enter withStatsIndex.
func withStatsIndex(group, config string, fn func(ix *statsIndex)) error {
	scope := FormatDBKey(KeyTypeStats, config, group)
	sl, _ := statsSlots.LoadOrCompute(scope, func() *statsSlot { return &statsSlot{scope: scope} })
	sl.mu.Lock()
	err := sl.refresh()
	if err == nil {
		sl.lastUse.Store(time.Now().UnixNano())
		fn(sl.ix)
		sl.updateCost()
	}
	sl.mu.Unlock()
	if err == nil {
		evictStatsIndexes(sl)
	}
	return err
}

// refresh rebuilds the index when missing, stale or past its TTL, then
// applies pending upserts. Caller holds sl.mu.
func (sl *statsSlot) refresh() error {
	now := time.Now()
	sl.pendMu.Lock()
	rebuild := sl.ix == nil || sl.stale || now.Sub(sl.builtAt) >= statsIndexTTL
	if rebuild {
		// Start tracking before the snapshot: writes racing the build land
		// in pending and are re-applied on top of it, in queue order.
		sl.pending, sl.tracking, sl.stale = sl.pending[:0], true, false
	}
	sl.pendMu.Unlock()
	if rebuild {
		ix, err := buildStatsIndex(sl.scope)
		if err != nil {
			sl.pendMu.Lock()
			sl.pending, sl.tracking = nil, false
			sl.pendMu.Unlock()
			sl.dropLocked()
			return err
		}
		sl.ix, sl.builtAt = ix, now
		sl.resident.Store(true)
	}
	sl.pendMu.Lock()
	pending := sl.pending
	sl.pending = nil
	sl.pendMu.Unlock()
	scopeLen := len(sl.scope) + 1
	for _, p := range pending {
		if target, node, ok := splitStatsKey([]byte(p.key[scopeLen:])); ok {
			sl.ix.put(target, node, p.data)
		}
	}
	return nil
}

func (sl *statsSlot) updateCost() {
	if sl.ix == nil {
		return
	}
	c := sl.ix.cost()
	statsIndexCost.Add(c - sl.cost)
	sl.cost = c
}

// dropLocked releases the slot's index. Caller holds sl.mu.
func (sl *statsSlot) dropLocked() {
	if sl.ix == nil {
		return
	}
	statsIndexCost.Add(-sl.cost)
	sl.ix, sl.cost = nil, 0
	sl.resident.Store(false)
	sl.pendMu.Lock()
	sl.pending, sl.tracking = nil, false
	sl.pendMu.Unlock()
}

// evictStatsIndexes drops least-recently-used indexes other than keep
// until the total fits the budget. Busy slots are skipped.
func evictStatsIndexes(keep *statsSlot) {
	budget := statsIndexBudget()
	if statsIndexCost.Load() <= budget {
		return
	}
	var victims []*statsSlot
	statsSlots.Range(func(_ string, sl *statsSlot) bool {
		if sl != keep && sl.resident.Load() {
			victims = append(victims, sl)
		}
		return true
	})
	sort.Slice(victims, func(i, j int) bool { return victims[i].lastUse.Load() < victims[j].lastUse.Load() })
	for _, sl := range victims {
		if statsIndexCost.Load() <= budget {
			return
		}
		if sl.mu.TryLock() {
			sl.dropLocked()
			sl.mu.Unlock()
		}
	}
}

// buildStatsIndex decodes a group's stats from a consistent snapshot:
// queued and in-flight writes first (they win), then bbolt.
func buildStatsIndex(scope string) (*statsIndex, error) {
	if globalDB == nil {
		return nil, errors.New("smart: store not initialised")
	}
	ix := newStatsIndex()
	overlay := make(map[string][]byte)
	globalQueueMu.RLock()
	for _, ops := range [2][]queuedOp{inflightOps, globalQueueOps} {
		for i := range ops {
			if ops[i].op.Type == OpSaveStats && hasScanPrefix(ops[i].key, scope) {
				overlay[ops[i].key] = ops[i].op.Data
			}
		}
	}
	globalQueueMu.RUnlock()

	head := []byte(scope + "/")
	err := globalDB.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSmartStats)
		if bucket == nil {
			return nil
		}
		c := bucket.Cursor()
		for k, v := c.Seek(head); k != nil && bytes.HasPrefix(k, head); k, v = c.Next() {
			if _, queued := overlay[string(k)]; queued {
				continue
			}
			if target, node, ok := splitStatsKey(k[len(head):]); ok {
				ix.put(target, node, v)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for key, data := range overlay {
		if len(key) > len(head) {
			if target, node, ok := splitStatsKey([]byte(key[len(head):])); ok {
				ix.put(target, node, data)
			}
		}
	}
	return ix, nil
}

func statsIndexBudget() int64 {
	globalCacheParams.mu.RLock()
	defer globalCacheParams.mu.RUnlock()
	return globalCacheParams.IndexBudget
}
