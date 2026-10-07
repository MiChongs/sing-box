package smart

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/bbolt"
)

// json marshal/unmarshal swapped to goccy/go-json — see fastjson.go for
// the rationale. Kept as package-level aliases so call sites look
// identical to before (`json.Marshal(x)` / `json.Unmarshal(b, &x)`).
var json = struct {
	Marshal   func(any) ([]byte, error)
	Unmarshal func([]byte, any) error
}{
	Marshal:   jsonMarshal,
	Unmarshal: jsonUnmarshal,
}

var (
	// globalDB is the cache file's database the store reads and writes. It
	// is swapped when a reloaded box reopens the cache file; see rebindDB.
	globalDB         atomic.Pointer[bbolt.DB]
	bucketSmartStats = []byte(BucketName)

	globalStoreOnce sync.Once
	globalStore     *Store

	// Global write queue for bbolt batch flushing, guarded by globalQueueMu:
	//
	//   globalQueueOps — pending operations in arrival order, one per key
	//   globalQueueIdx — key → position in globalQueueOps (O(1) dedup and
	//                    exact-key reads)
	//   inflightOps / inflightIdx — the batch the flusher is committing.
	//                    Readers keep consulting it until the commit lands,
	//                    so a write is never invisible between leaving the
	//                    queue and reaching bbolt.
	//
	// Readers hold the read lock and look keys up in place — exact keys via
	// the indexes, prefixes by walking the two slices — instead of copying
	// the queue.
	globalQueueMu  sync.RWMutex
	globalQueueOps []queuedOp
	globalQueueIdx map[string]int
	inflightOps    []queuedOp
	inflightIdx    map[string]int

	// Write generations for dbResultCache validity, guarded by
	// globalQueueMu. Every bbolt write bumps scanAnyGen and the generation
	// of the group scope it touches ("smart/<type>/<cfg>/<grp>"); writes
	// wider than one group bump scanEpoch. A cached scan is served only
	// while the stamp it was read under is still current.
	scanEpoch     uint64
	scanAnyGen    uint64
	scanGroupGens map[string]uint64

	// flushMu serialises queue drains, so at most one batch is in flight
	// and callers that must not race a commit (StoreFlushNow, FlushByLevel,
	// RemoveNodesData) can wait for it.
	flushMu sync.Mutex
	// flushSignal wakes the store's single background flusher once the
	// queue crosses BatchSaveThreshold; the one-slot buffer coalesces
	// signals that arrive while a drain is running.
	flushSignal chan struct{}

	globalCacheParams struct {
		BatchSaveThreshold int
		MaxTargets         int
		IndexBudget        int64 // byte budget shared by all decoded stats indexes
		LastMemoryUsage    float64
		mu                 sync.RWMutex
	}

	targetCache       *lruCache[string, string]
	unwrapCache       *lruCache[string, UnwrapMap]
	recordCache       *lruCache[string, *AtomicStatsRecord]
	dbResultCache     *lruCache[string, dbScan]
	blockedNodesCache *lruCache[string, map[string]bool]
)

// queuedOp is a pending write together with its bbolt key.
type queuedOp struct {
	key string
	op  StoreOperation
}

// scanStamp identifies the write generation a scan was read at.
type scanStamp struct {
	epoch, gen uint64
}

// dbScan is a cached bbolt prefix scan and the stamp it was read under.
type dbScan struct {
	stamp scanStamp
	rows  map[string][]byte
}

// Store is a singleton that wraps bbolt + in-memory caches.
type Store struct{}

// BucketName is the top-level cache file bucket holding all Smart data.
const BucketName = "smart_stats"

// SmartDBProvider is implemented by the cache file service to hand its
// database to the Smart store.
type SmartDBProvider interface {
	SmartDB() *bbolt.DB
}

// GetOrInitStore returns the global Store bound to db, initializing the
// process-wide caches and flusher on first call. A later call with another
// db — the cache file reopened after a SIGHUP / Clash API reload or a
// restarted platform service — rebinds the store to it.
func GetOrInitStore(db *bbolt.DB) *Store {
	globalStoreOnce.Do(func() {
		globalDB.Store(db)
		initCaches()
		initQueue()
		globalStore = &Store{}
		go globalStore.runFlusher()
	})
	if globalDB.Load() != db {
		rebindDB(db)
	}
	return globalStore
}

// rebindDB points the store at db and drops everything derived from the
// previous database. That database belonged to the previous box, which
// closed it after its Smart groups flushed; writes still queued for it are
// discarded with it, and caches and stats indexes reload lazily from db.
func rebindDB(db *bbolt.DB) {
	flushMu.Lock()
	defer flushMu.Unlock()
	if globalDB.Load() == db {
		return
	}
	globalQueueMu.Lock()
	clear(globalQueueOps)
	globalQueueOps = globalQueueOps[:0]
	clear(globalQueueIdx)
	globalDB.Store(db)
	scanEpoch++
	globalQueueMu.Unlock()

	targetCache.Clear()
	unwrapCache.Clear()
	recordCache.Clear()
	dbResultCache.Clear()
	blockedNodesCache.Clear()
	invalidateStatsIndexes(FormatDBKey())
}

func initCaches() {
	sz, bytesPer, batch := resolveCacheBudget()

	globalCacheParams.mu.Lock()
	globalCacheParams.BatchSaveThreshold = batch
	globalCacheParams.MaxTargets = sz * 4
	globalCacheParams.IndexBudget = bytesPer
	globalCacheParams.mu.Unlock()

	// Byte-budgeted caches: MaxCost is real memory, cost fns return each
	// value's heap footprint. The configured SMART_CACHE_BUDGET_MB is thus
	// a true ceiling instead of an entry count derived from a 2 KiB/entry
	// guess that the actual values rarely match.
	targetCache = newLRUBytes[string, string](bytesPer, costString)
	unwrapCache = newLRUBytes[string, UnwrapMap](bytesPer, costUnwrapMap)
	// recordCache reports every departing record to the record index.
	recordCache = newCacheCost[string, *AtomicStatsRecord](bytesPer, 0, byteBudgetCounters(bytesPer), costRecord, unindexRecord)
	dbResultCache = newLRUBytesWithTTL[string, dbScan](bytesPer, 300*time.Second, costDBScan)
	blockedNodesCache = newLRUBytesWithTTL[string, map[string]bool](bytesPer, 300*time.Second, costBlocked)
}

// Per-entry overhead folded into every cost estimate: the bbolt-style key
// string (≈ "smart/stats/<cfg>/<grp>/<target>/<node>", 40–90 B), the
// keysIndex map slot, and ristretto's row bookkeeping. Approximate but
// keeps small entries from being costed as near-free.
const cacheEntryOverhead = 96

// atomicRecordCost is the representative footprint charged for one
// *AtomicStatsRecord at insert time: the struct (~330 B), its four EWMA
// trackers and the weights map once it holds a few entries. ristretto
// cannot re-cost a record after insertion (records are mutated in place),
// so this is the steady-state size rather than the size at creation.
const atomicRecordCost = 768

// cacheBudgetShares splits SMART_CACHE_BUDGET_MB between the five caches
// and the decoded stats indexes.
const cacheBudgetShares = 6

func costString(v string) int64 { return int64(len(v)) + cacheEntryOverhead }

func costUnwrapMap(v UnwrapMap) int64 {
	n := int64(len(v.RefTCP) + len(v.RefUDP))
	for _, s := range v.TCP {
		n += int64(len(s)) + 16 // string header + bytes
	}
	for _, s := range v.UDP {
		n += int64(len(s)) + 16
	}
	return n + cacheEntryOverhead
}

func costRecord(*AtomicStatsRecord) int64 { return atomicRecordCost }

func costDBResult(v map[string][]byte) int64 {
	n := int64(0)
	for k, b := range v {
		n += int64(len(k)) + int64(len(b)) + 24 // key + value + map-bucket overhead
	}
	return n + cacheEntryOverhead
}

func costDBScan(v dbScan) int64 { return costDBResult(v.rows) }

func costBlocked(v map[string]bool) int64 {
	n := int64(0)
	for k := range v {
		n += int64(len(k)) + 9 // key + bool + bucket overhead
	}
	return n + cacheEntryOverhead
}

// resolveCacheBudget returns (per-cache entry budget for scan/prefetch
// limits, per-cache BYTE budget for the ristretto MaxCost, batch-save
// threshold). It honours one env-var override:
//
//   - SMART_CACHE_BUDGET_MB: total memory budget across the five caches
//     and the decoded stats indexes. This is a REAL byte ceiling: each
//     gets mb/6 MiB and evicts by measured value footprint (see the cost
//     fns in initCaches), so the configured number tracks actual RSS
//     instead of an entry count derived from a 2 KiB/entry assumption
//     that the live values rarely match.
//
// perCacheEntries is retained ONLY to size MaxTargets (the prefetch /
// bbolt-scan target cap), which is a count, not a memory figure.
//
// Defaults: desktop 32 MB, Android/iOS 8 MB, split six ways.
func resolveCacheBudget() (perCacheEntries int, perCacheBytes int64, batchThreshold int) {
	mb := defaultCacheBudgetMB()
	if raw := os.Getenv("SMART_CACHE_BUDGET_MB"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			mb = v
		}
	}

	// Real byte budget per cache.
	perCacheBytes = int64(mb) * 1024 * 1024 / cacheBudgetShares

	// Entry budget (for MaxTargets only): ~2 KiB per entry, 5 caches share.
	entriesTotal := (mb * 1024) / 2
	perCacheEntries = entriesTotal / 5
	if perCacheEntries < MinTargetsLimit/4 {
		perCacheEntries = MinTargetsLimit / 4
	}
	if perCacheEntries > MaxTargetsLimit/4 {
		perCacheEntries = MaxTargetsLimit / 4
	}

	// Batch threshold scales linearly between Min/Max bounds proportional
	// to the cache size (bigger cache → larger batches amortise bbolt
	// transaction cost better).
	span := MaxTargetsLimit/4 - MinTargetsLimit/4
	frac := 0.0
	if span > 0 {
		frac = float64(perCacheEntries-MinTargetsLimit/4) / float64(span)
	}
	batchThreshold = MinBatchThreshLimit + int(float64(MaxBatchThreshLimit-MinBatchThreshLimit)*frac)
	if batchThreshold < MinBatchThreshLimit {
		batchThreshold = MinBatchThreshLimit
	}
	if batchThreshold > MaxBatchThreshLimit {
		batchThreshold = MaxBatchThreshLimit
	}
	return perCacheEntries, perCacheBytes, batchThreshold
}

// defaultCacheBudgetMB returns the platform-default cache budget. Android
// (and other constrained mobile runtimes) picks a smaller number because
// the OS aggressively kills background processes exceeding RSS caps.
func defaultCacheBudgetMB() int {
	if runtime.GOOS == "android" || runtime.GOOS == "ios" {
		return 8
	}
	return 32
}

func initQueue() {
	globalQueueOps = make([]queuedOp, 0, 128)
	globalQueueIdx = make(map[string]int, 128)
	inflightIdx = make(map[string]int, 128)
	scanGroupGens = make(map[string]uint64)
	flushSignal = make(chan struct{}, 1)
}

func getBatchSaveThreshold() int {
	globalCacheParams.mu.RLock()
	defer globalCacheParams.mu.RUnlock()
	if globalCacheParams.BatchSaveThreshold <= 0 {
		return MinBatchThreshLimit
	}
	return globalCacheParams.BatchSaveThreshold
}

// AppendToGlobalQueue deduplicates by operation key and wakes the
// background flusher once the queue crosses BatchSaveThreshold. O(1)
// amortised per insert — a persistent `key → index` map sits alongside
// the queue slice, so dedup never rebuilds anything. Stats writes are
// also handed to their group's stats index (when one is tracked) so it
// stays current without re-reading the group.
func (s *Store) AppendToGlobalQueue(operations ...StoreOperation) {
	if len(operations) == 0 {
		return
	}
	threshold := getBatchSaveThreshold()

	globalQueueMu.Lock()
	if globalQueueIdx == nil {
		globalQueueIdx = make(map[string]int, 64)
	}
	for i := range operations {
		key := FormatOperationKey(&operations[i])
		if key == "" {
			continue
		}
		if pos, ok := globalQueueIdx[key]; ok {
			// Overwrite in place — preserves slot, no slice growth.
			globalQueueOps[pos].op = operations[i]
		} else {
			globalQueueIdx[key] = len(globalQueueOps)
			globalQueueOps = append(globalQueueOps, queuedOp{key: key, op: operations[i]})
		}
		if operations[i].Type == OpSaveStats {
			feedStatsIndex(key, operations[i].Data)
		}
	}
	full := len(globalQueueOps) >= threshold
	globalQueueMu.Unlock()

	if full {
		select {
		case flushSignal <- struct{}{}:
		default:
		}
	}
}

// runFlusher is the store's single background writer. It drains the queue
// whenever AppendToGlobalQueue reports it over threshold; signals arriving
// mid-drain coalesce in the channel, so bursts never stack goroutines or
// concurrent bbolt write transactions.
func (s *Store) runFlusher() {
	for range flushSignal {
		s.FlushQueue(false)
	}
}

// removeFromQueue filters the queue in place and rebuilds the index. Its
// callers (FlushByLevel, RemoveNodesData) hold flushMu, so no batch is in
// flight that the filter would miss.
func removeFromQueue(shouldRemove func(StoreOperation) bool) {
	globalQueueMu.Lock()
	kept := globalQueueOps[:0]
	for _, q := range globalQueueOps {
		if !shouldRemove(q.op) {
			kept = append(kept, q)
		}
	}
	clear(globalQueueOps[len(kept):])
	globalQueueOps = kept
	clear(globalQueueIdx)
	for i := range globalQueueOps {
		globalQueueIdx[globalQueueOps[i].key] = i
	}
	globalQueueMu.Unlock()
}

func removeNodesFromQueue(group, config string, nodes []string) {
	nodeSet := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		nodeSet[n] = true
	}
	removeFromQueue(func(op StoreOperation) bool {
		return op.Group == group && op.Config == config && nodeSet[op.Node]
	})
}

func filterQueueByGroup(group, config string) {
	removeFromQueue(func(op StoreOperation) bool {
		return op.Group == group && op.Config == config
	})
}

func filterQueueByConfig(config string) {
	removeFromQueue(func(op StoreOperation) bool {
		return op.Config == config
	})
}

// FlushQueue writes buffered operations to bbolt; force=false only drains
// a queue at or above BatchSaveThreshold. The drained batch stays readable
// as the in-flight batch until its commit lands. Drains are serialised by
// flushMu, so a call that finds one running waits for it first.
func (s *Store) FlushQueue(force bool) {
	threshold := getBatchSaveThreshold()
	flushMu.Lock()
	defer flushMu.Unlock()

	globalQueueMu.Lock()
	if n := len(globalQueueOps); n == 0 || (!force && n < threshold) {
		globalQueueMu.Unlock()
		return
	}
	// Swap the queue into the in-flight slot; new appends continue on the
	// previous batch's (cleared) storage.
	batch := globalQueueOps
	globalQueueOps, inflightOps = inflightOps[:0], batch
	globalQueueIdx, inflightIdx = inflightIdx, globalQueueIdx
	globalQueueMu.Unlock()

	// A failed commit drops the batch, as before: retrying against a
	// closed or broken database would only grow the queue.
	err := commitBatch(batch)

	var lost []string
	globalQueueMu.Lock()
	for i := range batch {
		noteWriteLocked(batch[i].key)
		if err != nil && batch[i].op.Type == OpSaveStats {
			lost = append(lost, batch[i].key)
		}
	}
	clear(batch)
	inflightOps = batch[:0]
	clear(inflightIdx)
	globalQueueMu.Unlock()
	// Stats indexes already applied the dropped writes; rebuild them.
	noteDBMutation(lost...)
}

// commitBatch writes a deduplicated batch in one bbolt transaction.
// Tombstone ops (OpDelete*) delete their key. bbolt fsyncs every commit
// unless the database was opened with NoSync, so there is no extra Sync
// per batch; StoreFlushNow adds the explicit one shutdown paths rely on.
func commitBatch(batch []queuedOp) error {
	return globalDB.Load().Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketSmartStats)
		if err != nil {
			return err
		}
		for i := range batch {
			q := &batch[i]
			if isDeleteOp(q.op.Type) {
				err = bucket.Delete([]byte(q.key))
			} else {
				err = bucket.Put([]byte(q.key), q.op.Data)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// BatchSave persists operations to bbolt in a single transaction,
// bypassing the queue. Tombstone ops (OpDelete*) delete their key; when
// several operations share a key the last one wins.
func (s *Store) BatchSave(operations []StoreOperation) error {
	if len(operations) == 0 {
		return nil
	}
	batch := make([]queuedOp, 0, len(operations))
	pos := make(map[string]int, len(operations))
	for i := range operations {
		key := FormatOperationKey(&operations[i])
		if key == "" {
			continue
		}
		if p, ok := pos[key]; ok {
			batch[p].op = operations[i]
			continue
		}
		pos[key] = len(batch)
		batch = append(batch, queuedOp{key: key, op: operations[i]})
	}
	err := commitBatch(batch)
	keys := make([]string, len(batch))
	for i := range batch {
		keys[i] = batch[i].key
	}
	noteDBMutation(keys...)
	return err
}

// StoreFlushNow drains every pending queue entry — first waiting out any
// batch the background flusher is committing — then issues one explicit
// fsync on the bbolt store.
//
// Call this from shutdown / SIGTERM / cache-reset paths where you need
// the "everything the Smart group has observed is on disk" guarantee.
// Idempotent and safe to call concurrently.
func (s *Store) StoreFlushNow() error {
	if s == nil || globalDB.Load() == nil {
		return nil
	}
	s.FlushQueue(true)
	return globalDB.Load().Sync()
}

// noteWriteLocked bumps the write generations covering key (a full key or
// a prefix). Caller holds globalQueueMu for writing.
func noteWriteLocked(key string) {
	scanAnyGen++
	scope, ok := groupScope(key)
	if !ok {
		scanEpoch++
		return
	}
	if scanGroupGens == nil {
		scanGroupGens = make(map[string]uint64)
	}
	if _, seen := scanGroupGens[scope]; !seen {
		// Don't pin the whole key string behind the map entry.
		scope = strings.Clone(scope)
	}
	scanGroupGens[scope]++
}

// scanStampLocked returns the generation a scan of prefix reads at.
// Caller holds globalQueueMu.
func scanStampLocked(prefix string) scanStamp {
	if scope, ok := groupScope(prefix); ok {
		return scanStamp{scanEpoch, scanGroupGens[scope]}
	}
	return scanStamp{scanEpoch, scanAnyGen}
}

// noteDBMutation records bbolt writes that bypassed the queue (deletes,
// direct puts) under each key or prefix: cached scans covering them stop
// being served and stats indexes covering them are rebuilt on next use.
func noteDBMutation(prefixes ...string) {
	if len(prefixes) == 0 {
		return
	}
	globalQueueMu.Lock()
	for _, p := range prefixes {
		noteWriteLocked(p)
	}
	globalQueueMu.Unlock()
	seen := make(map[string]struct{}, 1)
	for _, p := range prefixes {
		if scope, ok := groupScope(p); ok {
			p = scope
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		invalidateStatsIndexes(p)
	}
}

// groupScope returns the "smart/<type>/<cfg>/<grp>" head of a key or
// prefix, or false when it is shallower than a group.
func groupScope(key string) (string, bool) {
	if !strings.HasPrefix(key, "smart/") {
		return "", false
	}
	slashes := 0
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			slashes++
			if slashes == 4 {
				return key[:i], true
			}
		}
	}
	return key, slashes == 3
}

// hasScanPrefix reports whether key lies under prefix on a segment
// boundary: equal to it, or prefix followed by '/'.
func hasScanPrefix(key, prefix string) bool {
	if len(key) == len(prefix) {
		return key == prefix
	}
	return len(key) > len(prefix) && key[len(prefix)] == '/' && key[:len(prefix)] == prefix
}

// scanPrefixShape returns the key type and segment count of a
// "smart/<type>/..." prefix.
func scanPrefixShape(prefix string) (keyType string, depth int, ok bool) {
	if !strings.HasPrefix(prefix, "smart/") {
		return "", 0, false
	}
	keyType = prefix[len("smart/"):]
	if i := strings.IndexByte(keyType, '/'); i >= 0 {
		keyType = keyType[:i]
	}
	return keyType, strings.Count(prefix, "/") + 1, true
}

// isLeafKey reports whether a prefix with depth segments is a complete key
// of its type (the depth FormatOperationKey produces).
func isLeafKey(keyType string, depth int) bool {
	switch keyType {
	case KeyTypeStats:
		return depth == 6
	case KeyTypeRanking, KeyTypeManualPin, KeyTypeRegionState:
		return depth == 4
	case KeyTypeNode, KeyTypePrefetch, KeyTypeHostFailures, KeyTypeKnownDead, KeyTypeBreaker, KeyTypePinEndorsement, KeyTypeExitGeo:
		return depth == 5
	}
	return false
}

// queuedLocked returns the pending write for key, preferring the queue
// over the in-flight batch. Caller holds globalQueueMu.
func queuedLocked(key string) (queuedOp, bool) {
	if pos, ok := globalQueueIdx[key]; ok {
		return globalQueueOps[pos], true
	}
	if pos, ok := inflightIdx[key]; ok {
		return inflightOps[pos], true
	}
	return queuedOp{}, false
}

// GetSubBytesByPath returns all records under a key prefix: queued and
// in-flight writes overlaid on bbolt — a queued value wins over the
// stored one and a queued tombstone hides it. Prefixes match whole
// segments, so group "HK" never picks up "HK-Auto" rows.
func (s *Store) GetSubBytesByPath(prefix string) (map[string][]byte, error) {
	result := make(map[string][]byte)
	keyType, depth, ok := scanPrefixShape(prefix)
	if !ok {
		return result, nil
	}
	exact := isLeafKey(keyType, depth)

	globalCacheParams.mu.RLock()
	configMaxTargets := globalCacheParams.MaxTargets / 2
	globalCacheParams.mu.RUnlock()

	var tombstoned map[string]struct{}
	globalQueueMu.RLock()
	stamp := scanStampLocked(prefix)
	if exact {
		// A pending value or tombstone for an exact key is authoritative;
		// bbolt is not consulted.
		if q, found := queuedLocked(prefix); found {
			globalQueueMu.RUnlock()
			if !isDeleteOp(q.op.Type) {
				result[prefix] = q.op.Data
			}
			return result, nil
		}
	} else {
		// In-flight first, so newer queued writes override it.
		for _, ops := range [2][]queuedOp{inflightOps, globalQueueOps} {
			for i := range ops {
				q := &ops[i]
				if !hasScanPrefix(q.key, prefix) {
					continue
				}
				if isDeleteOp(q.op.Type) {
					delete(result, q.key)
					if tombstoned == nil {
						tombstoned = make(map[string]struct{})
					}
					tombstoned[q.key] = struct{}{}
				} else {
					result[q.key] = q.op.Data
					delete(tombstoned, q.key)
				}
			}
		}
	}
	globalQueueMu.RUnlock()

	maxResults := -1
	if configMaxTargets > 1 {
		maxResults = configMaxTargets
	}
	// Stats scans stay uncached: the decoded stats index serves every hot
	// stats read, a raw group scan would crowd hundreds of small entries
	// out of the budget, and exact stats reads (record hydration) are
	// one-offs.
	cacheable := maxResults > 0 && keyType != KeyTypeStats
	merge := func(rows map[string][]byte) {
		for k, v := range rows {
			if _, gone := tombstoned[k]; gone {
				continue
			}
			if _, exists := result[k]; !exists {
				result[k] = v
			}
		}
	}
	if cacheable {
		if cached, hit := dbResultCache.Get(prefix); hit && cached.stamp == stamp {
			merge(cached.rows)
			return result, nil
		}
	}
	dbResult, err := s.DBViewPrefixScan(prefix, maxResults, true)
	if err != nil {
		return result, nil
	}
	if cacheable {
		dbResultCache.Set(prefix, dbScan{stamp: stamp, rows: dbResult})
	}
	merge(dbResult)
	return result, nil
}

// DBViewPrefixScan scans bbolt for keys with the given prefix.
// maxResults=-1 means unlimited; reservoir sampling applied when over limit.
//
// The reservoir is maintained ONLINE (Algorithm R) while the cursor walks:
// only entries currently inside the reservoir hold copied key/value bytes.
// The previous implementation materialised EVERY matching entry first and
// sampled afterwards — on a stats table with hundreds of nodes × hundreds
// of targets that was a multi-hundred-MB allocation spike per scan, fired
// every ranking/prefetch cycle, and the dominant GC-pressure source users
// observed as sustained CPU heat on large subscriptions.
func (s *Store) DBViewPrefixScan(prefix string, maxResults int, strict bool) (map[string][]byte, error) {
	type kv struct {
		key string
		val []byte
	}
	var reservoir []kv
	seen := 0

	err := globalDB.Load().View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSmartStats)
		if bucket == nil {
			return nil
		}
		cursor := bucket.Cursor()
		prefixBytes := []byte(prefix)
		for k, v := cursor.Seek(prefixBytes); k != nil && bytes.HasPrefix(k, prefixBytes); k, v = cursor.Next() {
			if strict && len(k) > len(prefixBytes) && k[len(prefixBytes)] != '/' {
				continue
			}
			if maxResults < 0 || len(reservoir) < maxResults {
				valCopy := make([]byte, len(v))
				copy(valCopy, v)
				reservoir = append(reservoir, kv{string(k), valCopy})
			} else if j := rand.Intn(seen + 1); j < maxResults {
				valCopy := make([]byte, len(v))
				copy(valCopy, v)
				reservoir[j] = kv{string(k), valCopy}
			}
			seen++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte, len(reservoir))
	for _, item := range reservoir {
		result[item.key] = item.val
	}
	return result, nil
}

// deleteChunkSize bounds the keys one delete transaction removes, so a
// huge wipe never builds a single giant bbolt transaction.
const deleteChunkSize = 8192

// DBBatchDeletePrefix deletes all keys matching a prefix (strict: whole
// segments only, so "node-1" never takes "node-10" with it).
func (s *Store) DBBatchDeletePrefix(prefix string, strict bool) error {
	_, err := deletePrefix(prefix, strict)
	return err
}

// deletePrefix deletes every key under prefix and returns how many it
// removed. Keys are collected and deleted inside the same write
// transaction (keys only — values are never copied), chunked by
// deleteChunkSize.
func deletePrefix(prefix string, strict bool) (int, error) {
	head := []byte(prefix)
	total := 0
	var err error
	for {
		var keys [][]byte
		more := false
		err = globalDB.Load().Update(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket(bucketSmartStats)
			if bucket == nil {
				return nil
			}
			c := bucket.Cursor()
			for k, _ := c.Seek(head); k != nil && bytes.HasPrefix(k, head); k, _ = c.Next() {
				if strict && len(k) > len(head) && k[len(head)] != '/' {
					continue
				}
				if len(keys) == deleteChunkSize {
					more = true
					break
				}
				keys = append(keys, bytes.Clone(k))
			}
			return deleteKeysTx(bucket, keys)
		})
		if err != nil {
			break
		}
		total += len(keys)
		if !more {
			break
		}
	}
	if total > 0 {
		if strict {
			noteDBMutation(prefix)
		} else {
			// A non-strict prefix can cut across group scopes.
			noteDBMutation(FormatDBKey())
		}
	}
	return total, err
}

// deleteKeys deletes exact keys, deleteChunkSize per transaction.
func deleteKeys(keys [][]byte) error {
	for len(keys) > 0 {
		chunk := keys[:min(len(keys), deleteChunkSize)]
		keys = keys[len(chunk):]
		err := globalDB.Load().Update(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket(bucketSmartStats)
			if bucket == nil {
				return nil
			}
			return deleteKeysTx(bucket, chunk)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func deleteKeysTx(bucket *bbolt.Bucket, keys [][]byte) error {
	for _, k := range keys {
		if err := bucket.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// walkKeys calls fn for every bbolt key under prefix + "/" (keys only).
func walkKeys(prefix string, fn func(k []byte)) error {
	head := []byte(prefix + "/")
	return globalDB.Load().View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSmartStats)
		if bucket == nil {
			return nil
		}
		c := bucket.Cursor()
		for k, _ := c.Seek(head); k != nil && bytes.HasPrefix(k, head); k, _ = c.Next() {
			fn(k)
		}
		return nil
	})
}

// queuedKeys calls fn for every queued or in-flight key under prefix + "/".
func queuedKeys(prefix string, fn func(key string)) {
	globalQueueMu.RLock()
	defer globalQueueMu.RUnlock()
	for _, ops := range [2][]queuedOp{inflightOps, globalQueueOps} {
		for i := range ops {
			if len(ops[i].key) > len(prefix) && hasScanPrefix(ops[i].key, prefix) {
				fn(ops[i].key)
			}
		}
	}
}

func (s *Store) DBBatchPutItem(key string, value []byte) error {
	err := globalDB.Load().Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketSmartStats)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(key), value)
	})
	noteDBMutation(key)
	return err
}

// IterateAtomicRecords walks every cached AtomicStatsRecord under the
// given (group, config) namespace. The callback receives the parsed
// (target, node) tuple plus the live record so callers can read the
// most-recent atomic counters WITHOUT going through bbolt — that
// avoids the BatchSave-flush latency window where in-memory
// success/failure increments aren't yet visible to GetAllStats.
//
// Order is unspecified. Returning false from the callback stops the
// walk early.
func (s *Store) IterateAtomicRecords(group, config string, cb func(target, node string, rec *AtomicStatsRecord) bool) {
	if cb == nil {
		return
	}
	for _, rec := range groupRecords(group, config) {
		if !cb(rec.target, rec.node, rec) {
			return
		}
	}
}

// LookupAnyAtomicRecord returns the most recently created or used cached
// AtomicStatsRecord for (group, config, proxy), regardless of target.
//
// Used by node-level signal queries (e.g. ShortRTT for the
// fastest-recent algorithm) where the caller wants the EWMA reading on
// a node tag without knowing which target most recently dialled it.
// O(1) through the per-group record index.
//
// Returns nil when no cached record exists. Callers MUST treat nil as
// "no signal yet" rather than "node is bad".
func (s *Store) LookupAnyAtomicRecord(group, config, proxy string) *AtomicStatsRecord {
	if proxy == "" {
		return nil
	}
	return latestRecord(group, config, proxy)
}

// LookupAtomicRecord returns the in-memory AtomicStatsRecord for the
// exact cacheKey, or nil if absent. Unlike GetOrCreateAtomicRecord
// this does NOT hydrate from bbolt and does NOT allocate — it's a
// strict steady-state cache peek. Callers that merely need to CHECK
// per-(target, node) health without creating ghost records use this.
// Expected to be called from hot-path filter code (selectProxies)
// hundreds of times per second, so it must stay O(1) and alloc-free.
func (s *Store) LookupAtomicRecord(cacheKey string) *AtomicStatsRecord {
	if recordCache == nil || cacheKey == "" {
		return nil
	}
	if r, ok := recordCache.Get(cacheKey); ok {
		return r
	}
	return nil
}

// GetOrCreateAtomicRecord fetches or creates an in-memory AtomicStatsRecord,
// seeding it from bbolt if available.
func (s *Store) GetOrCreateAtomicRecord(cacheKey, group, config, target, proxy string) *AtomicStatsRecord {
	if r, ok := recordCache.Get(cacheKey); ok {
		touchRecord(r)
		return r
	}

	record := NewAtomicStatsRecord()
	record.config, record.group, record.target, record.node = config, group, target, proxy

	existingData, err := s.GetStatsForTarget(group, config, target, proxy)
	if err == nil {
		if data, exists := existingData[proxy]; exists {
			var sr StatsRecord
			if UnmarshalStatsRecord(data, &sr) == nil {
				record.success.Store(sr.Success)
				record.failure.Store(sr.Failure)
				record.connectTime.Store(sr.ConnectTime)
				record.latency.Store(sr.Latency)
				record.lastUsed.Store(sr.LastUsed)
				record.storeFloat(&record.uploadTotal, sr.UploadTotal)
				record.storeFloat(&record.downloadTotal, sr.DownloadTotal)
				record.storeFloat(&record.duration, sr.ConnectionDuration)
				record.storeFloat(&record.maxUploadRate, sr.MaxUploadRate)
				record.storeFloat(&record.maxDownloadRate, sr.MaxDownloadRate)
				record.cumulSent.Store(sr.CumulSent)
				record.cumulRetrans.Store(sr.CumulRetrans)
				if sr.Weights != nil {
					record.weightsMu.Lock()
					for k, v := range sr.Weights {
						record.weights[k] = v
					}
					record.weightsMu.Unlock()
				}
			}
		}
	}

	// Index before offering it to the cache: an immediate rejection or
	// eviction then finds it in the index and removes it again.
	indexRecord(record)
	recordCache.Set(cacheKey, record)
	return record
}

// GetStatsForTarget returns node-keyed stats bytes for a given target.
func (s *Store) GetStatsForTarget(group, config, target, proxy string) (map[string][]byte, error) {
	var pathPrefix string
	if proxy != "" {
		pathPrefix = FormatDBKey(KeyTypeStats, config, group, target, proxy)
	} else {
		pathPrefix = FormatDBKey(KeyTypeStats, config, group, target)
	}

	rawResult, err := s.GetSubBytesByPath(pathPrefix)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte, len(rawResult))
	if proxy != "" {
		for _, data := range rawResult {
			result[proxy] = data
		}
	} else {
		for fullPath, data := range rawResult {
			result[lastKeyPart(fullPath)] = data
		}
	}
	return result, nil
}

// lastKeyPart returns the unescaped final segment of a key.
func lastKeyPart(key string) string {
	return UnescapeKeyPart(key[strings.LastIndexByte(key, '/')+1:])
}

// GetAllStats returns map[target]map[nodeName]rawJSON for a group.
func (s *Store) GetAllStats(group, config string) (map[string]map[string][]byte, error) {
	pathPrefix := FormatDBKey(KeyTypeStats, config, group)
	rawResult, err := s.GetSubBytesByPath(pathPrefix)
	if err != nil {
		return nil, err
	}

	result := make(map[string]map[string][]byte)
	for fullPath, data := range rawResult {
		parts := strings.Split(fullPath, "/")
		if len(parts) < 6 {
			continue
		}
		// unescape because FormatDBKey percent-escaped the user-
		// supplied bits (target hostname / outbound tag) so a `/`
		// inside e.g. "ENET/🇳🇿 Base 新西兰" doesn't fragment the
		// path. Without this, target / node end up as the wrong
		// substring and the wantSet match in callers always misses.
		target := UnescapeKeyPart(parts[len(parts)-2])
		node := UnescapeKeyPart(parts[len(parts)-1])
		if _, ok := result[target]; !ok {
			result[target] = make(map[string][]byte)
		}
		result[target][node] = data
	}
	return result, nil
}

// GetNodeStates returns map[nodeName]rawJSON from bbolt+queue.
func (s *Store) GetNodeStates(group, config string) (map[string][]byte, error) {
	pathPrefix := FormatDBKey(KeyTypeNode, config, group)
	rawResult, err := s.GetSubBytesByPath(pathPrefix)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte, len(rawResult))
	for fullPath, data := range rawResult {
		result[lastKeyPart(fullPath)] = data
	}
	return result, nil
}

// GetBlockedNodes returns the set of currently blocked node names.
func (s *Store) GetBlockedNodes(group, config string) (map[string]bool, error) {
	cacheKey := FormatDBKey(config, group)
	if blocked, ok := blockedNodesCache.Get(cacheKey); ok {
		return blocked, nil
	}

	stateData, err := s.GetNodeStates(group, config)
	if err != nil {
		return nil, err
	}

	blocked := make(map[string]bool)
	now := time.Now().Unix()
	for nodeName, data := range stateData {
		var state NodeState
		if json.Unmarshal(data, &state) == nil {
			if state.BlockedUntil > 0 && state.BlockedUntil > now {
				blocked[nodeName] = true
			}
		}
	}

	blockedNodesCache.Set(cacheKey, blocked)
	return blocked, nil
}

// ClearBlockedNodesCache removes the cached blocked-node entry for a group.
func ClearBlockedNodesCache(group, config string) {
	if blockedNodesCache == nil {
		return
	}
	blockedNodesCache.Delete(FormatDBKey(config, group))
}

// GetBestProxyForTarget returns nodes sorted by weight for a target (and
// optional ASN). Served from the group's decoded stats index, so a call
// costs the target's rows (or the ASN's candidates), not a decode of the
// whole group — it runs on the dial path (tier-3 selection) as well as
// once per prefetched target.
func (s *Store) GetBestProxyForTarget(group, config, target, asnNumber string, isUDP bool) ([]string, []float64, error) {
	if target == "" {
		return nil, nil, errors.New("empty target")
	}
	var (
		nodes   []string
		weights []float64
	)
	err := withStatsIndex(group, config, func(ix *statsIndex) {
		nodes, weights = ix.bestFor(target, asnNumber, isUDP, time.Now().Unix())
	})
	if err != nil {
		return nil, nil, err
	}
	if len(nodes) == 0 {
		return nil, nil, errors.New("no best node with enough weight")
	}
	return nodes, weights, nil
}

// StorePrefetchResult persists a prefetch result for a target (and optionally ASN).
func (s *Store) StorePrefetchResult(group, config, target, asnNumber string, isUDP bool, proxyNames []string, weights []float64) {
	if target == "" || len(proxyNames) == 0 {
		return
	}

	targetCacheKey := FormatDBKey(KeyTypePrefetch, config, group, target)
	nodeWeight := NodesWithWeights{Nodes: proxyNames, Weights: weights}

	var pm PrefetchMap
	if isUDP {
		pm.UDP = nodeWeight
	} else {
		pm.TCP = nodeWeight
	}
	pm.UpdatedTime = time.Now().Unix()

	ops := make([]StoreOperation, 0, 2)
	if data, err := json.Marshal(pm); err == nil {
		ops = append(ops, StoreOperation{
			Type:   OpSavePrefetch,
			Group:  group,
			Config: config,
			Target: target,
			Data:   data,
		})
	}

	if asnNumber != "" && !CdnASNs[asnNumber] {
		var asnPm PrefetchMap
		if isUDP {
			asnPm.RefUDP = targetCacheKey
		} else {
			asnPm.RefTCP = targetCacheKey
		}
		asnPm.UpdatedTime = time.Now().Unix()
		if asnData, err := json.Marshal(asnPm); err == nil {
			ops = append(ops, StoreOperation{
				Type:   OpSavePrefetch,
				Group:  group,
				Config: config,
				Target: asnNumber,
				Data:   asnData,
			})
		}
	}

	if len(ops) > 0 {
		s.AppendToGlobalQueue(ops...)
	}
}

// GetPrefetchResult retrieves a cached prefetch result.
func (s *Store) GetPrefetchResult(group, config, target, asnNumber string, isUDP bool) ([]string, []float64) {
	if target == "" {
		return nil, nil
	}

	findResult := func(pm PrefetchMap) ([]string, []float64) {
		var res NodesWithWeights
		if isUDP {
			res = pm.UDP
		} else {
			res = pm.TCP
		}
		if len(res.Nodes) > 0 && len(res.Weights) == len(res.Nodes) {
			return res.Nodes, res.Weights
		}
		return nil, nil
	}

	getPrefetchMap := func(pathPrefix string) (PrefetchMap, bool) {
		rawResult, err := s.GetSubBytesByPath(pathPrefix)
		if err != nil {
			return PrefetchMap{}, false
		}
		for _, data := range rawResult {
			var pm PrefetchMap
			if json.Unmarshal(data, &pm) == nil {
				return pm, true
			}
		}
		return PrefetchMap{}, false
	}

	getRefKey := func(pm PrefetchMap) string {
		if isUDP {
			return pm.RefUDP
		}
		return pm.RefTCP
	}

	if asnNumber != "" && !CdnASNs[asnNumber] {
		asnPath := FormatDBKey(KeyTypePrefetch, config, group, asnNumber)
		if pm, ok := getPrefetchMap(asnPath); ok {
			if refKey := getRefKey(pm); refKey != "" {
				parts := strings.Split(refKey, "/")
				if len(parts) >= 5 {
					parsedTarget := strings.Join(parts[4:], "/")
					targetPath := FormatDBKey(KeyTypePrefetch, config, group, parsedTarget)
					if refPm, ok := getPrefetchMap(targetPath); ok {
						if nodes, weights := findResult(refPm); nodes != nil {
							return nodes, weights
						}
					}
				}
			}
		}
	}

	pathPrefix := FormatDBKey(KeyTypePrefetch, config, group, target)
	if pm, ok := getPrefetchMap(pathPrefix); ok {
		if nodes, weights := findResult(pm); nodes != nil {
			return nodes, weights
		}
	}

	return nil, nil
}

// StoreUnwrapResult caches the node list selected for a target into memory LRU.
func (s *Store) StoreUnwrapResult(group, config, target, asnNumber string, isUDP bool, names []string) {
	if target == "" || len(names) == 0 {
		return
	}

	targetKey := FormatDBKey(config, group, target)

	if asnNumber != "" && !CdnASNs[asnNumber] {
		asnKey := FormatDBKey(config, group, asnNumber)
		if um, ok := unwrapCache.Get(asnKey); ok {
			if isUDP {
				if len(um.UDP) == 0 {
					um.UDP = names
					unwrapCache.Set(asnKey, um)
				}
			} else {
				if len(um.TCP) == 0 {
					um.TCP = names
					unwrapCache.Set(asnKey, um)
				}
			}
		} else {
			um := UnwrapMap{}
			if isUDP {
				um.UDP = names
			} else {
				um.TCP = names
			}
			unwrapCache.Set(asnKey, um)
		}

		if um, ok := unwrapCache.Get(targetKey); ok {
			if isUDP {
				if um.RefUDP == "" {
					um.RefUDP = asnKey
					unwrapCache.Set(targetKey, um)
				}
			} else {
				if um.RefTCP == "" {
					um.RefTCP = asnKey
					unwrapCache.Set(targetKey, um)
				}
			}
		} else {
			um := UnwrapMap{}
			if isUDP {
				um.RefUDP = asnKey
			} else {
				um.RefTCP = asnKey
			}
			unwrapCache.Set(targetKey, um)
		}
	} else {
		if um, ok := unwrapCache.Get(targetKey); ok {
			if isUDP {
				um.UDP = names
			} else {
				um.TCP = names
			}
			unwrapCache.Set(targetKey, um)
		} else {
			um := UnwrapMap{}
			if isUDP {
				um.UDP = names
			} else {
				um.TCP = names
			}
			unwrapCache.Set(targetKey, um)
		}
	}
}

// GetUnwrapResult retrieves cached node list for a target.
func (s *Store) GetUnwrapResult(group, config, target, asnNumber string, isUDP bool) []string {
	if target == "" {
		return nil
	}

	targetKey := FormatDBKey(config, group, target)

	if um, ok := unwrapCache.Get(targetKey); ok {
		var refKey string
		if isUDP {
			refKey = um.RefUDP
		} else {
			refKey = um.RefTCP
		}
		if refKey != "" {
			if refUm, ok := unwrapCache.Get(refKey); ok {
				if isUDP {
					return refUm.UDP
				}
				return refUm.TCP
			}
		} else {
			if isUDP {
				return um.UDP
			}
			return um.TCP
		}
	}

	if asnNumber != "" && !CdnASNs[asnNumber] {
		asnKey := FormatDBKey(config, group, asnNumber)
		if um, ok := unwrapCache.Get(asnKey); ok {
			if isUDP {
				return um.UDP
			}
			return um.TCP
		}
	}

	return nil
}

// ClearUnwrapByGroup drops every unwrap-cache entry scoped to (group, config).
// Used by Smart.ClearSelection so a freshly unpinned group re-evaluates
// every target on its next dial instead of riding the stale pin-era cache.
// The unwrap LRU is process-global (to share entries across groups that map
// the same target), so we scope the clear by FormatDBKey's group prefix
// rather than the nuclear Clear() that would evict other groups too. The
// trailing separator keeps "HK" from clearing "HK-Auto".
func (s *Store) ClearUnwrapByGroup(group, config string) {
	if group == "" {
		return
	}
	unwrapCache.RemoveByPrefix(FormatDBKey(config, group) + "/")
}

// DeleteUnwrapResult removes a cached unwrap entry.
func (s *Store) DeleteUnwrapResult(group, config, target, asnNumber string, isUDP bool) {
	if target == "" {
		return
	}

	targetKey := FormatDBKey(config, group, target)
	if um, ok := unwrapCache.Get(targetKey); ok {
		if isUDP {
			um.UDP = nil
			um.RefUDP = ""
		} else {
			um.TCP = nil
			um.RefTCP = ""
		}
		if len(um.TCP) == 0 && len(um.UDP) == 0 && um.RefTCP == "" && um.RefUDP == "" {
			unwrapCache.Delete(targetKey)
		} else {
			unwrapCache.Set(targetKey, um)
		}
	}

	if asnNumber != "" && !CdnASNs[asnNumber] {
		asnKey := FormatDBKey(config, group, asnNumber)
		if um, ok := unwrapCache.Get(asnKey); ok {
			if isUDP {
				um.UDP = nil
			} else {
				um.TCP = nil
			}
			if len(um.TCP) == 0 && len(um.UDP) == 0 {
				unwrapCache.Delete(asnKey)
			} else {
				unwrapCache.Set(asnKey, um)
			}
		}
	}
}

// GetHostStatus returns failure count and lastUsed for a host.
func (s *Store) GetHostStatus(group, config, host string) (int, int64) {
	pathPrefix := FormatDBKey(KeyTypeHostFailures, config, group, host)
	rawResult, err := s.GetSubBytesByPath(pathPrefix)
	if err != nil {
		return 0, 0
	}
	for _, data := range rawResult {
		var hs HostStatus
		if json.Unmarshal(data, &hs) == nil {
			return hs.FailureCount, hs.LastUsed
		}
	}
	return 0, 0
}

// UpdateHostStatus increments or decrements the failure counter for a host.
func (s *Store) UpdateHostStatus(group, config, host string, failure, needLastUsedUpdate bool) {
	pathPrefix := FormatDBKey(KeyTypeHostFailures, config, group, host)
	rawResult, _ := s.GetSubBytesByPath(pathPrefix)

	var hs HostStatus
	for _, data := range rawResult {
		if json.Unmarshal(data, &hs) == nil {
			break
		}
	}

	if !failure && hs.FailureCount <= 0 && !needLastUsedUpdate {
		return
	}

	if failure {
		hs.FailureCount++
		hs.LastFailure = time.Now().Unix()
	} else {
		if hs.FailureCount > 0 {
			hs.FailureCount--
		}
	}
	hs.LastUsed = time.Now().Unix()

	data, err := json.Marshal(hs)
	if err != nil {
		return
	}
	s.AppendToGlobalQueue(StoreOperation{
		Type:   OpSaveHostFailures,
		Group:  group,
		Config: config,
		Target: host,
		Data:   data,
	})
}

// TargetWeightEntry is the per-(target, node) raw weight readout used by
// the /proxies/{name}/weights?target=... diagnostic endpoint. Every field
// mirrors an exact bbolt stats row so operators can line up API output
// against debug logs one-to-one (no aggregation, no normalisation).
type TargetWeightEntry struct {
	Target      string             `json:"target"`
	Node        string             `json:"node"`
	WeightTCP   float64            `json:"weight_tcp,omitempty"`
	WeightUDP   float64            `json:"weight_udp,omitempty"`
	WeightsByT  map[string]float64 `json:"weights_by_type,omitempty"`
	Success     int64              `json:"success"`
	Failure     int64              `json:"failure"`
	ConnectTime int64              `json:"connect_time_ms,omitempty"`
	Latency     int64              `json:"latency_ms,omitempty"`
	LastUsed    int64              `json:"last_used"`
	Upload      float64            `json:"upload_mb,omitempty"`
	Download    float64            `json:"download_mb,omitempty"`
}

// GetPerTargetWeights returns every (target, node) weight row for the group,
// straight from bbolt stats — no aggregation, no normalisation. This is
// the authoritative ground truth that `selectProxiesTraced` tier 3
// (GetBestProxyForTarget) sees at dial time. Exposed for the ClashAPI
// `/proxies/{name}/weights?target=...&full=1` diagnostic path so users can
// verify the API weight display matches the internal selection values.
func (s *Store) GetPerTargetWeights(group, config string) []TargetWeightEntry {
	allStats, err := s.GetAllStats(group, config)
	if err != nil || len(allStats) == 0 {
		return nil
	}
	out := make([]TargetWeightEntry, 0, 64)
	for target, nodes := range allStats {
		for node, data := range nodes {
			var record StatsRecord
			if UnmarshalStatsRecord(data, &record) != nil {
				continue
			}
			entry := TargetWeightEntry{
				Target:      target,
				Node:        node,
				Success:     record.Success,
				Failure:     record.Failure,
				ConnectTime: record.ConnectTime,
				Latency:     record.Latency,
				LastUsed:    record.LastUsed,
				Upload:      record.UploadTotal,
				Download:    record.DownloadTotal,
			}
			if record.Weights != nil {
				entry.WeightTCP = record.Weights[WeightTypeTCP]
				entry.WeightUDP = record.Weights[WeightTypeUDP]
				// Full weight map (including ASN-scoped entries) so power
				// users can audit per-ASN weight divergence.
				entry.WeightsByT = make(map[string]float64, len(record.Weights))
				for k, v := range record.Weights {
					entry.WeightsByT[k] = math.Round(v*10000) / 10000
				}
				entry.WeightTCP = math.Round(entry.WeightTCP*10000) / 10000
				entry.WeightUDP = math.Round(entry.WeightUDP*10000) / 10000
			}
			out = append(out, entry)
		}
	}
	// Sort by (target, weight descending) so UI rendering is stable.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		wi := out[i].WeightTCP + out[i].WeightUDP
		wj := out[j].WeightTCP + out[j].WeightUDP
		return wi > wj
	})
	return out
}

// GetLiveNodeRanking aggregates NODE-level weights directly from raw stats —
// bypassing the prefetch→ranking pipeline that takes minutes to warm up on a
// fresh config. Sums each node's per-target WeightTypeTCP + WeightTypeUDP
// scores, then normalises to percentages and assigns rank categories.
//
// Used as a fallback in WeightRanking when the precomputed ranking cache is
// empty — mihomo-style "live weights" behaviour so /proxies/<tag>/weights
// returns data the moment the first connection stats land in bbolt, without
// waiting for the (intentionally slow) prefetch cycle.
func (s *Store) GetLiveNodeRanking(group, config string, isAlive func(tag string) bool, allTags []string) []NodeRank {
	if len(allTags) == 0 {
		return nil
	}

	// Per-node accumulators. Switched from SUM to AVG-per-target so the
	// output Weight matches the internal CalculateWeight scale (typically
	// 0.3–3 range) regardless of how many targets a node has seen. The
	// previous SUM aggregation inflated high-coverage nodes' display
	// weight by 10× or more vs. their true per-dial scale.
	type acc struct {
		weightSum   float64
		targetCount int
		sampleCount int
		lastUsed    int64
	}
	// Set-based membership test — the previous contains() linear scan made
	// this loop O(records × N): with 300 tags over a 150k-record stats
	// table that's ~45M string compares per ranking refresh.
	wantSet := make(map[string]struct{}, len(allTags))
	for _, t := range allTags {
		wantSet[t] = struct{}{}
	}
	accs := make(map[string]*acc, len(allTags))
	err := withStatsIndex(group, config, func(ix *statsIndex) {
		ix.forEachRow(func(_, nodeName string, r *statsRow) {
			if _, want := wantSet[nodeName]; !want {
				return
			}
			// Real-data gate: count this (node, target) pair only when the
			// node has actually been dialled to that target. Pure tombstones
			// or weight-only rows would otherwise inflate TargetCount with
			// fake coverage. SampleCount uses the same gate so the two
			// confidence numbers move together.
			samples := int(r.samples)
			if samples <= 0 {
				return
			}
			a := accs[nodeName]
			if a == nil {
				a = &acc{}
				accs[nodeName] = a
			}
			// Both counters increment per real (node, target) pair —
			// TargetCount is the genuine breadth of dial coverage. Weight
			// might still be zero for a target where every dial failed;
			// that's a real signal worth keeping in the average rather
			// than silently filtering out.
			a.targetCount++
			a.sampleCount += samples
			a.weightSum += r.tcp + r.udp
			if r.lastUsed > a.lastUsed {
				a.lastUsed = r.lastUsed
			}
		})
	})
	if err != nil || len(accs) == 0 {
		return nil
	}

	// Raw average weight per node, in the same scale as internal selection.
	rawWeights := make(map[string]float64, len(accs))
	targetCounts := make(map[string]int, len(accs))
	sampleCounts := make(map[string]int, len(accs))
	maxRaw := 0.0
	for name, a := range accs {
		avg := a.weightSum / float64(a.targetCount)
		rawWeights[name] = avg
		targetCounts[name] = a.targetCount
		sampleCounts[name] = a.sampleCount
		if avg > maxRaw {
			maxRaw = avg
		}
	}
	if maxRaw == 0 {
		return nil
	}

	now := time.Now().Unix()
	result := make([]NodeRank, 0, len(allTags))
	for _, tag := range allTags {
		raw := rawWeights[tag]
		score := 0.0
		if maxRaw > 0 {
			score = math.Round(raw/maxRaw*100*100) / 100
		}
		result = append(result, NodeRank{
			Name:        tag,
			Weight:      math.Round(raw*10000) / 10000, // 4 dp precision
			Score:       score,
			TargetCount: targetCounts[tag],
			SampleCount: sampleCounts[tag],
			LastUpdated: now,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		ai := isAlive(result[i].Name)
		aj := isAlive(result[j].Name)
		if ai != aj {
			return ai
		}
		return result[i].Weight > result[j].Weight
	})
	assignRankCategories(result, isAlive)
	return result
}

// assignRankCategories fills in NodeRank.Rank using a 20/50 split — top 20%
// of alive nodes with a non-zero weight are MostUsed, the next 50% are
// OccasionalUsed, the remainder are RarelyUsed. Dead nodes are always
// RarelyUsed regardless of weight. Shared helper so every ranking
// source (prefetch / live-stats / delay) categorises identically.
func assignRankCategories(result []NodeRank, isAlive func(tag string) bool) {
	aliveCount := 0
	for _, r := range result {
		if isAlive(r.Name) {
			aliveCount++
		}
	}
	if aliveCount == 0 {
		for i := range result {
			result[i].Rank = RankRarelyUsed
		}
		return
	}
	result[0].Rank = RankMostUsed
	if aliveCount == 2 {
		if result[1].Weight > 0 {
			result[1].Rank = RankOccasional
		} else {
			result[1].Rank = RankRarelyUsed
		}
	} else if aliveCount >= 3 {
		mostUsedBound := int(float64(aliveCount) * 0.2)
		if mostUsedBound < 1 {
			mostUsedBound = 1
		}
		occasionalBound := mostUsedBound + int(float64(aliveCount)*0.5)
		for i := 1; i < mostUsedBound && i < aliveCount; i++ {
			if result[i].Weight > 0 {
				result[i].Rank = RankMostUsed
			} else {
				result[i].Rank = RankRarelyUsed
			}
		}
		for i := mostUsedBound; i < occasionalBound && i < aliveCount; i++ {
			if result[i].Weight > 0 {
				result[i].Rank = RankOccasional
			} else {
				result[i].Rank = RankRarelyUsed
			}
		}
		for i := occasionalBound; i < aliveCount; i++ {
			result[i].Rank = RankRarelyUsed
		}
	}
	for i := 0; i < aliveCount; i++ {
		if result[i].Rank == "" {
			result[i].Rank = RankRarelyUsed
		}
	}
	for i := aliveCount; i < len(result); i++ {
		result[i].Rank = RankRarelyUsed
	}
}

// GetNodeWeightRankingCache returns cached ranking without recomputing.
//
// Stale-schema guard: cached entries written by older builds (before
// the TargetCount + SampleCount fields existed) deserialise with both
// counters zero across every entry. We treat that pattern as a stale
// schema and return empty so WeightRanking falls through to the live
// recompute path — otherwise the API would keep echoing a cached zero
// indefinitely (GitHub issue: "TargetCount always 0"). Dial-real
// rankings always populate at least TargetCount, so this can't false-
// positive a genuinely-warm cache.
func (s *Store) GetNodeWeightRankingCache(group, config string) ([]NodeRank, error) {
	pathPrefix := FormatDBKey(KeyTypeRanking, config, group)
	rawResult, err := s.GetSubBytesByPath(pathPrefix)
	if err != nil {
		return nil, err
	}
	for _, data := range rawResult {
		var ranking []NodeRank
		if json.Unmarshal(data, &ranking) != nil || len(ranking) == 0 {
			continue
		}
		// Try to repair stale entries in place — succeeds whenever the
		// stats table still has the data needed to recompute the
		// counts. Failure to repair (no stats yet, or every record has
		// zero samples) means the entry is genuinely empty in the
		// modern schema sense; we drop it and let the caller fall
		// through to GetLiveNodeRanking instead of echoing zeros.
		if isLegacyZeroCountRanking(ranking) {
			repaired := s.EnrichRankingCounts(group, config, ranking)
			if isLegacyZeroCountRanking(ranking) {
				// Still broken after enrichment — abandon the entry.
				continue
			}
			if repaired {
				// Persist the patched ranking so the next restart
				// reads a clean copy instead of repairing every time.
				s.StoreNodeWeightRanking(group, config, ranking)
			}
		}
		return ranking, nil
	}
	return []NodeRank{}, nil
}

// isLegacyZeroCountRanking reports whether the deserialised ranking
// breaks the "Weight > 0 ↔ TargetCount > 0" invariant — fresh code
// from every ranking source guarantees that pairing, so any entry
// with positive weight but zero TargetCount is unambiguous evidence
// of stale schema or a write that pre-dated the TargetCount fix.
//
// Earlier versions of this function only flagged rankings where
// EVERY entry had TC==0; a single non-zero TC entry could "save" a
// payload that otherwise contained dozens of weight>0 / TC=0 rows,
// letting the bbolt cache re-publish those broken rows indefinitely
// (the visible "TargetCount always 0 in /smart/weights" symptom).
//
// The strict invariant catches the mixed case too — callers can drop
// the ranking and recompute, or call EnrichRankingCounts to repair it
// in place.
func isLegacyZeroCountRanking(ranking []NodeRank) bool {
	for i := range ranking {
		if ranking[i].Weight > 0 && ranking[i].TargetCount == 0 {
			return true
		}
	}
	return false
}

// EnrichRankingCounts force-recomputes TargetCount and SampleCount
// for every entry in the supplied ranking by walking BOTH the in-memory
// atomic recordCache AND the bbolt stats table, deduplicating any
// (node, target) pair seen in both sources. Atomic records win on
// conflict because they reflect the freshest state — bbolt is the
// lagging copy after BatchSave.
//
// Returns true when at least one entry's count actually changed.
func (s *Store) EnrichRankingCounts(group, config string, ranking []NodeRank) bool {
	if len(ranking) == 0 {
		return false
	}
	wantSet := make(map[string]struct{}, len(ranking))
	for i := range ranking {
		wantSet[ranking[i].Name] = struct{}{}
	}
	tc := make(map[string]int, len(wantSet))
	sc := make(map[string]int, len(wantSet))
	seen := make(map[string]map[string]struct{}, len(wantSet))

	addPair := func(node, target string, count int) {
		if count <= 0 {
			return
		}
		ts := seen[node]
		if ts == nil {
			ts = make(map[string]struct{}, 4)
			seen[node] = ts
		}
		if _, dup := ts[target]; dup {
			return
		}
		ts[target] = struct{}{}
		tc[node]++
		sc[node] += count
	}

	// Source 1: in-memory atomic records — freshest data, reflects
	// recordStats writes immediately without waiting for BatchSave.
	s.IterateAtomicRecords(group, config, func(target, node string, rec *AtomicStatsRecord) bool {
		if _, want := wantSet[node]; !want {
			return true
		}
		addPair(node, target, int(rec.GetInt64("success")+rec.GetInt64("failure")))
		return true
	})

	// Source 2: persisted stats — covers entries evicted from recordCache.
	_ = withStatsIndex(group, config, func(ix *statsIndex) {
		ix.forEachRow(func(target, nodeName string, r *statsRow) {
			if _, want := wantSet[nodeName]; want {
				addPair(nodeName, target, int(r.samples))
			}
		})
	})

	changed := false
	for i := range ranking {
		newTC := tc[ranking[i].Name]
		newSC := sc[ranking[i].Name]
		// Don't overwrite a non-zero count with zero — both sources
		// can transiently come up empty (cache eviction crossed with
		// read). Preserving the previous count means "couldn't
		// refresh, last known good wins".
		if newTC > 0 && ranking[i].TargetCount != newTC {
			ranking[i].TargetCount = newTC
			changed = true
		}
		if newSC > 0 && ranking[i].SampleCount != newSC {
			ranking[i].SampleCount = newSC
			changed = true
		}
	}
	return changed
}

// GetNodeWeightRanking computes a fresh ranking using prefetch data AND
// raw stats. Prefetch gives us "this node is in the top-N for target X"
// signal (high-confidence, but summarized); stats give us the actual
// weight magnitude. Combining both means the returned Weight field matches
// the internal selection scale (raw CalculateWeight output) while the
// rank ordering still benefits from prefetch's accumulated history.
//
// Previous version returned position-based scores (100 - i*10) normalised
// to 0-100. That caused the "API weight != debug log weight" confusion —
// users comparing the two saw wildly different numbers.
func (s *Store) GetNodeWeightRanking(group, config, testURL string, isAlive func(tag string) bool, allTags []string) ([]NodeRank, error) {
	if len(allTags) == 0 {
		return nil, fmt.Errorf("no proxies provided")
	}

	globalCacheParams.mu.RLock()
	prefetchLimit := globalCacheParams.MaxTargets / 2
	globalCacheParams.mu.RUnlock()

	activeTargets := s.GetActiveTargets(group, config, prefetchLimit)

	// Prefetch gives us a position-based signal of "which nodes tend to
	// rank well across targets". Aggregate as (weightSum, targetCount)
	// per node, using the ACTUAL prefetched weights (not synthetic position
	// scores) so the final Weight matches the internal scale.
	type acc struct {
		weightSum   float64
		targetCount int
	}
	// Set lookup instead of contains() — avoids O(targets × 10 × N)
	// string compares on large subscriptions.
	wantSet := make(map[string]struct{}, len(allTags))
	for _, t := range allTags {
		wantSet[t] = struct{}{}
	}
	accs := make(map[string]*acc, len(allTags))
	for _, ad := range activeTargets {
		nodes, weights := s.GetPrefetchResult(group, config, ad.Target, ad.ASN, ad.IsUDP)
		for i := 0; i < len(nodes) && i < 10; i++ {
			if _, want := wantSet[nodes[i]]; !want {
				continue
			}
			w := 0.0
			if i < len(weights) {
				w = weights[i]
			}
			if w <= 0 {
				continue
			}
			a := accs[nodes[i]]
			if a == nil {
				a = &acc{}
				accs[nodes[i]] = a
			}
			a.weightSum += w
			a.targetCount++
		}
	}

	if len(accs) == 0 {
		return []NodeRank{}, nil
	}

	rawWeights := make(map[string]float64, len(accs))
	targetCounts := make(map[string]int, len(accs))
	maxRaw := 0.0
	for name, a := range accs {
		avg := a.weightSum / float64(a.targetCount)
		rawWeights[name] = avg
		targetCounts[name] = a.targetCount
		if avg > maxRaw {
			maxRaw = avg
		}
	}
	if maxRaw == 0 {
		return []NodeRank{}, nil
	}

	// TargetCount and SampleCount come from the raw stats table — the
	// prefetch tally above only records "this node placed in the top-N
	// for target X" and would under-report coverage for any node whose
	// real dial history extends beyond the prefetched targets. Walk
	// allStats once and overwrite both maps with the genuine numbers
	// so this function and GetLiveNodeRanking and delayBasedRanking
	// all agree on the same real-data semantic.
	targetCoverage := make(map[string]int, len(accs))
	sampleCounts := make(map[string]int, len(accs))
	_ = withStatsIndex(group, config, func(ix *statsIndex) {
		ix.forEachRow(func(_, nodeName string, r *statsRow) {
			if _, want := accs[nodeName]; !want || r.samples <= 0 {
				return
			}
			targetCoverage[nodeName]++
			sampleCounts[nodeName] += int(r.samples)
		})
	})
	// Fall back to the prefetch-derived count only when stats are
	// unavailable — better a partial number than an empty field.
	for name, cov := range targetCounts {
		if _, ok := targetCoverage[name]; !ok {
			targetCoverage[name] = cov
		}
	}

	now := time.Now().Unix()
	result := make([]NodeRank, 0, len(allTags))
	for _, tag := range allTags {
		raw := rawWeights[tag]
		score := 0.0
		if maxRaw > 0 {
			score = math.Round(raw/maxRaw*100*100) / 100
		}
		result = append(result, NodeRank{
			Name:        tag,
			Weight:      math.Round(raw*10000) / 10000,
			Score:       score,
			TargetCount: targetCoverage[tag],
			SampleCount: sampleCounts[tag],
			LastUpdated: now,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		ai := isAlive(result[i].Name)
		aj := isAlive(result[j].Name)
		if ai != aj {
			return ai
		}
		return result[i].Weight > result[j].Weight
	})
	assignRankCategories(result, isAlive)

	s.StoreNodeWeightRanking(group, config, result)
	return result, nil
}

func (s *Store) StoreNodeWeightRanking(group, config string, ranking []NodeRank) {
	data, err := json.Marshal(ranking)
	if err != nil {
		return
	}
	s.AppendToGlobalQueue(StoreOperation{
		Type:   OpSaveRanking,
		Group:  group,
		Config: config,
		Data:   data,
	})
}

// GetActiveTargets returns the most recently used target/ASN/UDP combinations.
func (s *Store) GetActiveTargets(group, config string, limit int) []ActiveTarget {
	var result []ActiveTarget
	if err := withStatsIndex(group, config, func(ix *statsIndex) {
		result = ix.activeTargets(limit)
	}); err != nil {
		return nil
	}
	return result
}

// RunPrefetch pre-calculates best nodes for frequently accessed targets.
// Every target is ranked from one decoded stats index in a single pass,
// instead of re-reading and re-decoding the whole group per target.
func (s *Store) RunPrefetch(group, config string, proxyMap map[string]string) int {
	blockedNodes, _ := s.GetBlockedNodes(group, config)

	availableProxyMap := make(map[string]string, len(proxyMap))
	for name, v := range proxyMap {
		if !blockedNodes[name] {
			availableProxyMap[name] = v
		}
	}

	if len(availableProxyMap) == 0 {
		return 0
	}

	globalCacheParams.mu.RLock()
	prefetchLimit := globalCacheParams.MaxTargets / 2
	globalCacheParams.mu.RUnlock()

	type asnKey struct {
		asn   string
		isUDP bool
	}
	type asnVal struct {
		nodes   []string
		weights []float64
	}

	type prefetchItem struct {
		target      string
		asnNumber   string
		isUDP       bool
		bestNodes   []string
		bestWeights []float64
	}

	var items []prefetchItem
	err := withStatsIndex(group, config, func(ix *statsIndex) {
		now := time.Now().Unix()
		// ASN rankings span every target, so each (ASN, UDP) pair is
		// ranked and filtered once per pass.
		asnCache := make(map[asnKey]asnVal)
		for _, active := range ix.activeTargets(prefetchLimit) {
			isASN := active.ASN != "" && !CdnASNs[active.ASN]
			k := asnKey{active.ASN, active.IsUDP}
			v, cached := asnCache[k]
			if !isASN || !cached {
				bestNodes, bestWeights := ix.bestFor(active.Target, active.ASN, active.IsUDP, now)
				v = asnVal{make([]string, 0, len(bestNodes)), make([]float64, 0, len(bestWeights))}
				for i, node := range bestNodes {
					if _, exists := availableProxyMap[node]; exists {
						v.nodes = append(v.nodes, node)
						v.weights = append(v.weights, bestWeights[i])
					}
				}
				if isASN {
					asnCache[k] = v
				}
			}
			if len(v.nodes) > 0 {
				items = append(items, prefetchItem{active.Target, active.ASN, active.IsUDP, v.nodes, v.weights})
			}
		}
	})
	if err != nil {
		return 0
	}

	asnCache := make(map[asnKey]asnVal)
	prefetchCount := 0

	for _, item := range items {
		var sortedNodes []string
		var sortedWeights []float64
		var needUpdate bool

		cacheHit := false
		if item.asnNumber != "" && !CdnASNs[item.asnNumber] {
			k := asnKey{item.asnNumber, item.isUDP}
			if v, ok := asnCache[k]; ok {
				sortedNodes = v.nodes
				sortedWeights = v.weights
				cacheHit = true
			}
		}

		if !cacheHit {
			// The stored result only matters when merging; an ASN cache
			// hit reuses this pass's ranking without reading it back.
			oldNodes, oldWeights := s.GetPrefetchResult(group, config, item.target, item.asnNumber, item.isUDP)
			if len(oldNodes) == 0 {
				needUpdate = true
				sortedNodes = item.bestNodes
				sortedWeights = item.bestWeights
			} else {
				finalNodeMap := make(map[string]float64, len(oldNodes))
				for i, node := range oldNodes {
					finalNodeMap[node] = oldWeights[i]
				}
				for i, newNode := range item.bestNodes {
					newW := item.bestWeights[i]
					if oldW, exists := finalNodeMap[newNode]; exists {
						if math.Abs(newW-oldW)/oldW > 0.1 {
							finalNodeMap[newNode] = newW
							needUpdate = true
						}
					} else {
						finalNodeMap[newNode] = newW
						needUpdate = true
					}
				}
				if needUpdate {
					nodeList := make([]NodeWithWeight, 0, len(finalNodeMap))
					for node, weight := range finalNodeMap {
						nodeList = append(nodeList, NodeWithWeight{node, weight})
					}
					sort.Slice(nodeList, func(i, j int) bool {
						if nodeList[i].Weight != nodeList[j].Weight {
							return nodeList[i].Weight > nodeList[j].Weight
						}
						return nodeList[i].Node < nodeList[j].Node
					})
					sortedNodes = make([]string, len(nodeList))
					sortedWeights = make([]float64, len(nodeList))
					for i, nw := range nodeList {
						sortedNodes[i] = nw.Node
						sortedWeights[i] = nw.Weight
					}
				} else {
					sortedNodes = item.bestNodes
					sortedWeights = item.bestWeights
				}
			}

			if item.asnNumber != "" && !CdnASNs[item.asnNumber] {
				asnCache[asnKey{item.asnNumber, item.isUDP}] = asnVal{sortedNodes, sortedWeights}
			}
		}

		if needUpdate || (cacheHit && len(sortedNodes) > 0) {
			s.StorePrefetchResult(group, config, item.target, item.asnNumber, item.isUDP, sortedNodes, sortedWeights)
		}
		prefetchCount++
	}

	return prefetchCount
}

// RemoveNodesData cleans up stats, prefetch, ranking, and node-state entries
// for removed nodes in a single bbolt transaction. Stats rows are found by
// key alone; only prefetch and ranking values (which list nodes) are read.
func (s *Store) RemoveNodesData(group, config string, nodes []string) error {
	if len(nodes) == 0 {
		return nil
	}

	// Hold off the flusher so an in-flight batch can't re-add rows for
	// these nodes after they are deleted.
	flushMu.Lock()
	defer flushMu.Unlock()
	removeNodesFromQueue(group, config, nodes)

	nodeSet := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		nodeSet[n] = struct{}{}
	}

	statsScope := FormatDBKey(KeyTypeStats, config, group)
	prefetchScope := FormatDBKey(KeyTypePrefetch, config, group)
	rankingKey := FormatDBKey(KeyTypeRanking, config, group)
	nodeScope := FormatDBKey(KeyTypeNode, config, group)

	err := globalDB.Load().Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSmartStats)
		if bucket == nil {
			return nil
		}
		var (
			deletes [][]byte
			puts    []struct{ key, value []byte }
		)
		c := bucket.Cursor()

		statsHead := []byte(statsScope + "/")
		for k, _ := c.Seek(statsHead); k != nil && bytes.HasPrefix(k, statsHead); k, _ = c.Next() {
			rest := k[len(statsHead):]
			if i := bytes.LastIndexByte(rest, '/'); i >= 0 {
				if _, ok := nodeSet[UnescapeKeyPart(string(rest[i+1:]))]; ok {
					deletes = append(deletes, bytes.Clone(k))
				}
			}
		}

		prefetchHead := []byte(prefetchScope + "/")
		for k, v := c.Seek(prefetchHead); k != nil && bytes.HasPrefix(k, prefetchHead); k, v = c.Next() {
			var pm PrefetchMap
			if json.Unmarshal(v, &pm) != nil {
				continue
			}
			changed := false
			pm.TCP.Nodes, pm.TCP.Weights = removeFromNodesWeights(pm.TCP.Nodes, pm.TCP.Weights, nodeSet, &changed)
			pm.UDP.Nodes, pm.UDP.Weights = removeFromNodesWeights(pm.UDP.Nodes, pm.UDP.Weights, nodeSet, &changed)
			if !changed {
				continue
			}
			if len(pm.TCP.Nodes) == 0 && len(pm.UDP.Nodes) == 0 && pm.RefTCP == "" && pm.RefUDP == "" {
				deletes = append(deletes, bytes.Clone(k))
			} else if newData, err := json.Marshal(pm); err == nil {
				puts = append(puts, struct{ key, value []byte }{bytes.Clone(k), newData})
			}
		}

		if data := bucket.Get([]byte(rankingKey)); data != nil {
			var ranking []NodeRank
			if json.Unmarshal(data, &ranking) == nil {
				kept := ranking[:0]
				for _, r := range ranking {
					if _, toRemove := nodeSet[r.Name]; !toRemove {
						kept = append(kept, r)
					}
				}
				if len(kept) < len(ranking) {
					if len(kept) == 0 {
						deletes = append(deletes, []byte(rankingKey))
					} else if newData, err := json.Marshal(kept); err == nil {
						puts = append(puts, struct{ key, value []byte }{[]byte(rankingKey), newData})
					}
				}
			}
		}

		for _, n := range nodes {
			deletes = append(deletes, []byte(FormatDBKey(KeyTypeNode, config, group, n)))
		}

		if err := deleteKeysTx(bucket, deletes); err != nil {
			return err
		}
		for _, p := range puts {
			if err := bucket.Put(p.key, p.value); err != nil {
				return err
			}
		}
		return nil
	})
	noteDBMutation(statsScope, prefetchScope, rankingKey, nodeScope)
	return err
}

func removeFromNodesWeights(nodes []string, weights []float64, nodeSet map[string]struct{}, changed *bool) ([]string, []float64) {
	newNodes := nodes[:0]
	newWeights := weights[:0]
	for i, node := range nodes {
		if _, toRemove := nodeSet[node]; toRemove {
			*changed = true
			continue
		}
		newNodes = append(newNodes, node)
		if i < len(weights) {
			newWeights = append(newWeights, weights[i])
		}
	}
	return newNodes, newWeights
}

// GetAllGroupsForConfig returns all known group names for a config, from
// stats keys alone: one cursor seek per group, values never read.
func (s *Store) GetAllGroupsForConfig(config string) ([]string, error) {
	scope := FormatDBKey(KeyTypeStats, config)
	groupsMap := make(map[string]bool)
	queuedKeys(scope, func(key string) {
		if g, _, _ := strings.Cut(key[len(scope)+1:], "/"); g != "" {
			groupsMap[UnescapeKeyPart(g)] = true
		}
	})

	head := []byte(scope + "/")
	err := globalDB.Load().View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSmartStats)
		if bucket == nil {
			return nil
		}
		c := bucket.Cursor()
		k, _ := c.Seek(head)
		for k != nil && bytes.HasPrefix(k, head) {
			g, _, deeper := bytes.Cut(k[len(head):], []byte{'/'})
			if len(g) > 0 {
				groupsMap[UnescapeKeyPart(string(g))] = true
			}
			if !deeper || len(g) == 0 {
				k, _ = c.Next()
				continue
			}
			// Skip the rest of this group's rows: every key under
			// head+g+"/" sorts before head+g+"0" ('0' follows '/').
			next := make([]byte, 0, len(head)+len(g)+1)
			next = append(append(append(next, head...), g...), '0')
			k, _ = c.Seek(next)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(groupsMap))
	for g := range groupsMap {
		result = append(result, g)
	}
	return result, nil
}

// GetAllNodesForGroup returns all known node names for a group, from
// node-state and stats keys alone (values are never read).
func (s *Store) GetAllNodesForGroup(group, config string) ([]string, error) {
	nodesMap := make(map[string]bool)
	for i, scope := range []string{FormatDBKey(KeyTypeNode, config, group), FormatDBKey(KeyTypeStats, config, group)} {
		// Node-state keys end in the node; stats keys need a target too.
		needTarget := i == 1
		add := func(rest []byte) {
			j := bytes.LastIndexByte(rest, '/')
			if needTarget && j < 0 {
				return
			}
			node := rest[j+1:]
			switch {
			case len(node) == 0:
			case bytes.IndexByte(node, '%') >= 0:
				nodesMap[UnescapeKeyPart(string(node))] = true
			case !nodesMap[string(node)]:
				nodesMap[string(node)] = true
			}
		}
		queuedKeys(scope, func(key string) { add([]byte(key[len(scope)+1:])) })
		if err := walkKeys(scope, func(k []byte) { add(k[len(scope)+1:]) }); err != nil {
			return nil, err
		}
	}

	result := make([]string, 0, len(nodesMap))
	for node := range nodesMap {
		result = append(result, node)
	}
	return result, nil
}

// cleanupItem is one row considered for trimming by CleanupOldRecords.
type cleanupItem struct {
	key      []byte
	lastTime int64
	value    float64
}

// cleanupLess orders rows for eviction: least valuable first, then oldest.
// The key breaks remaining ties so the selection is deterministic.
func cleanupLess(a, b *cleanupItem) bool {
	if a.value != b.value {
		return a.value < b.value
	}
	if a.lastTime != b.lastTime {
		return a.lastTime < b.lastTime
	}
	return bytes.Compare(a.key, b.key) < 0
}

// selectSmallest partially orders items so items[:k] holds the k smallest
// under cleanupLess (quickselect: O(n) on average instead of a full sort).
func selectSmallest(items []cleanupItem, k int) {
	lo, hi := 0, len(items)-1
	for lo < hi {
		mid := lo + (hi-lo)/2
		pivot := items[mid]
		items[mid], items[hi] = items[hi], items[mid]
		store := lo
		for i := lo; i < hi; i++ {
			if cleanupLess(&items[i], &pivot) {
				items[i], items[store] = items[store], items[i]
				store++
			}
		}
		items[store], items[hi] = items[hi], items[store]
		switch {
		case store == k:
			return
		case store < k:
			lo = store + 1
		default:
			hi = store - 1
		}
	}
}

// cleanupRecord is the part of a stats row CleanupOldRecords ranks by;
// decoding into it skips the weights map and every other field.
type cleanupRecord struct {
	Success  int64 `json:"success"`
	Failure  int64 `json:"failure"`
	LastUsed int64 `json:"last_used"`
}

// CleanupOldRecords removes excess historical data from bbolt. Each key
// type is first counted by key alone; values are decoded only when the
// group is over its cap, and the surplus is deleted in one transaction
// (chunked if huge) instead of one commit per key.
func (s *Store) CleanupOldRecords(group, config string) error {
	globalCacheParams.mu.RLock()
	maxTargets := globalCacheParams.MaxTargets
	globalCacheParams.mu.RUnlock()

	for _, keyType := range []string{KeyTypeStats, KeyTypePrefetch, KeyTypeHostFailures} {
		scope := FormatDBKey(keyType, config, group)
		total := 0
		if walkKeys(scope, func([]byte) { total++ }) != nil || total <= maxTargets*2 {
			continue
		}

		var items []cleanupItem
		head := []byte(scope + "/")
		err := globalDB.Load().View(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket(bucketSmartStats)
			if bucket == nil {
				return nil
			}
			c := bucket.Cursor()
			for k, v := c.Seek(head); k != nil && bytes.HasPrefix(k, head); k, v = c.Next() {
				item := cleanupItem{}
				switch keyType {
				case KeyTypeStats:
					if bytes.IndexByte(k[len(head):], '/') < 0 {
						continue
					}
					var record cleanupRecord
					if unmarshalRecord(v, &record) != nil {
						continue
					}
					item.lastTime = record.LastUsed
					item.value = float64(record.Success + record.Failure)
				case KeyTypePrefetch:
					var pm PrefetchMap
					if json.Unmarshal(v, &pm) != nil {
						continue
					}
					item.lastTime = pm.UpdatedTime
					item.value = float64(len(pm.TCP.Nodes) + len(pm.UDP.Nodes))
				case KeyTypeHostFailures:
					var hs HostStatus
					if json.Unmarshal(v, &hs) != nil {
						continue
					}
					item.lastTime = hs.LastFailure
					item.value = float64(hs.FailureCount)
				}
				item.key = bytes.Clone(k)
				items = append(items, item)
			}
			return nil
		})
		if err != nil || len(items) <= maxTargets*2 {
			continue
		}

		// Rows without a timestamp go first, then the least valuable /
		// oldest of the rest.
		toDelete := len(items) - maxTargets
		invalid := 0
		for i := range items {
			if items[i].lastTime <= 0 {
				items[i], items[invalid] = items[invalid], items[i]
				invalid++
			}
		}
		victims := items[:min(invalid, toDelete)]
		if remaining := toDelete - len(victims); remaining > 0 {
			valid := items[invalid:]
			selectSmallest(valid, remaining)
			victims = items[:invalid+min(remaining, len(valid))]
		}

		keys := make([][]byte, len(victims))
		for i := range victims {
			keys[i] = victims[i].key
		}
		err = deleteKeys(keys)
		noteDBMutation(scope)
		if err != nil {
			return err
		}
	}

	return nil
}

// AdjustCacheParameters applies the cache-budget policy.
//
// Background: the previous implementation called runtime.ReadMemStats on
// every invocation to infer heap pressure and dynamically resize all five
// caches. That was a cumulative 16 STW passes per 5-minute cycle (once
// per Smart group) which showed up as UI-visible jitter on Android. Since
// switching the caches to ristretto, cost-based admission + TinyLFU
// eviction handle overflow on their own — we no longer need per-cycle
// heap introspection to pick a capacity.
//
// The function still exists because a handful of management paths
// (including the Clash API cache/smart/flush endpoint) historically
// invoked it to "refresh" cache sizing. It now just applies the static
// budget derived from the SMART_CACHE_BUDGET_MB env var (Android
// defaults to a smaller cap than desktops) to ristretto via
// UpdateMaxCost. Idempotent and allocation-free.
func (s *Store) AdjustCacheParameters() {
	sz, bytesPer, batch := resolveCacheBudget()

	globalCacheParams.mu.Lock()
	globalCacheParams.MaxTargets = sz * 4 // legacy consumers expect MaxTargets ≈ 4×per-cache capacity
	globalCacheParams.BatchSaveThreshold = batch
	globalCacheParams.IndexBudget = bytesPer
	globalCacheParams.mu.Unlock()

	// Resize the byte budget — cost fns are unchanged, so eviction keeps
	// honouring real footprint at the new ceiling.
	if bytesPer < 1 {
		bytesPer = 1
	}
	if targetCache != nil {
		targetCache.ResizeBytes(bytesPer)
	}
	if unwrapCache != nil {
		unwrapCache.ResizeBytes(bytesPer)
	}
	if recordCache != nil {
		recordCache.ResizeBytes(bytesPer)
	}
	if dbResultCache != nil {
		dbResultCache.ResizeBytes(bytesPer)
	}
	if blockedNodesCache != nil {
		blockedNodesCache.ResizeBytes(bytesPer)
	}
}

// FlushStats holds per-key-type deletion counts returned by FlushByLevel.
// Zero values mean "nothing matched" — NOT "skipped". Callers surface this
// to operators so `POST /cache/smart/flush/{name}` is visibly effective.
type FlushStats struct {
	Stats          int `json:"stats"`
	Nodes          int `json:"nodes"`
	Ranking        int `json:"ranking"`
	Prefetch       int `json:"prefetch"`
	Failures       int `json:"failures"`
	Queue          int `json:"queue"`
	ManualPin      int `json:"manual_pin"`
	KnownDead      int `json:"known_dead"`
	Breakers       int `json:"breakers"`
	PinEndorsement int `json:"pin_endorsement"`
	RegionState    int `json:"region_state"`
	ExitGeo        int `json:"exit_geo"`
}

// Total sums every deletion bucket — convenient for "nothing happened" checks.
func (f FlushStats) Total() int {
	return f.Stats + f.Nodes + f.Ranking + f.Prefetch + f.Failures + f.Queue +
		f.ManualPin + f.KnownDead + f.Breakers + f.PinEndorsement + f.RegionState + f.ExitGeo
}

// FlushByLevel clears queue and DB data at the given level and returns the
// per-bucket deletion counts + the first error (if any). Previous versions
// silently swallowed errors via `_ = ...` which masked failures in logs.
// Group-level deletes now use strict=true so "HK" doesn't accidentally
// purge "HK-Backup" (prefix-collision bug with non-strict matching).
func (s *Store) FlushByLevel(level, config, group string) (FlushStats, error) {
	// Wait out any in-flight batch so it can't re-create purged rows.
	flushMu.Lock()
	defer flushMu.Unlock()

	var stats FlushStats
	stats.Queue = snapshotQueueDepth(level, config, group)

	switch level {
	case "all":
		globalQueueMu.Lock()
		clear(globalQueueOps)
		globalQueueOps = globalQueueOps[:0]
		clear(globalQueueIdx)
		globalQueueMu.Unlock()
	case "config":
		filterQueueByConfig(config)
	case "group":
		filterQueueByGroup(group, config)
	}

	// Clear in-memory caches (process-wide — cheap to rebuild lazily).
	targetCache.Clear()
	unwrapCache.Clear()
	recordCache.Clear()
	dbResultCache.Clear()
	blockedNodesCache.Clear()

	var firstErr error
	deleteCount := func(prefix string, strict bool) int {
		n, err := deletePrefix(prefix, strict)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		return n
	}
	switch level {
	case "all":
		stats.Stats = deleteCount(FormatDBKey(KeyTypeStats), false)
		stats.Nodes = deleteCount(FormatDBKey(KeyTypeNode), false)
		stats.Ranking = deleteCount(FormatDBKey(KeyTypeRanking), false)
		stats.Prefetch = deleteCount(FormatDBKey(KeyTypePrefetch), false)
		stats.Failures = deleteCount(FormatDBKey(KeyTypeHostFailures), false)
		stats.ManualPin = deleteCount(FormatDBKey(KeyTypeManualPin), false)
		stats.KnownDead = deleteCount(FormatDBKey(KeyTypeKnownDead), false)
		stats.Breakers = deleteCount(FormatDBKey(KeyTypeBreaker), false)
		stats.PinEndorsement = deleteCount(FormatDBKey(KeyTypePinEndorsement), false)
		stats.RegionState = deleteCount(FormatDBKey(KeyTypeRegionState), false)
		stats.ExitGeo = deleteCount(FormatDBKey(KeyTypeExitGeo), false)
	case "config":
		stats.Stats = deleteCount(FormatDBKey(KeyTypeStats, config), true)
		stats.Nodes = deleteCount(FormatDBKey(KeyTypeNode, config), true)
		stats.Ranking = deleteCount(FormatDBKey(KeyTypeRanking, config), true)
		stats.Prefetch = deleteCount(FormatDBKey(KeyTypePrefetch, config), true)
		stats.Failures = deleteCount(FormatDBKey(KeyTypeHostFailures, config), true)
		stats.ManualPin = deleteCount(FormatDBKey(KeyTypeManualPin, config), true)
		stats.KnownDead = deleteCount(FormatDBKey(KeyTypeKnownDead, config), true)
		stats.Breakers = deleteCount(FormatDBKey(KeyTypeBreaker, config), true)
		stats.PinEndorsement = deleteCount(FormatDBKey(KeyTypePinEndorsement, config), true)
		stats.RegionState = deleteCount(FormatDBKey(KeyTypeRegionState, config), true)
		stats.ExitGeo = deleteCount(FormatDBKey(KeyTypeExitGeo, config), true)
	case "group":
		stats.Stats = deleteCount(FormatDBKey(KeyTypeStats, config, group), true)
		stats.Nodes = deleteCount(FormatDBKey(KeyTypeNode, config, group), true)
		stats.Ranking = deleteCount(FormatDBKey(KeyTypeRanking, config, group), true)
		stats.Prefetch = deleteCount(FormatDBKey(KeyTypePrefetch, config, group), true)
		stats.Failures = deleteCount(FormatDBKey(KeyTypeHostFailures, config, group), true)
		stats.ManualPin = deleteCount(FormatDBKey(KeyTypeManualPin, config, group), true)
		stats.KnownDead = deleteCount(FormatDBKey(KeyTypeKnownDead, config, group), true)
		stats.Breakers = deleteCount(FormatDBKey(KeyTypeBreaker, config, group), true)
		stats.PinEndorsement = deleteCount(FormatDBKey(KeyTypePinEndorsement, config, group), true)
		stats.RegionState = deleteCount(FormatDBKey(KeyTypeRegionState, config, group), true)
		stats.ExitGeo = deleteCount(FormatDBKey(KeyTypeExitGeo, config, group), true)
	}
	// Purged queue entries may have fed stats indexes that no bbolt delete
	// covered; drop the affected indexes regardless.
	switch level {
	case "all":
		invalidateStatsIndexes(FormatDBKey(KeyTypeStats))
	case "config":
		invalidateStatsIndexes(FormatDBKey(KeyTypeStats, config))
	case "group":
		invalidateStatsIndexes(FormatDBKey(KeyTypeStats, config, group))
	}
	return stats, firstErr
}

// snapshotQueueDepth counts pending queue items that match a flush scope,
// captured BEFORE the queue is filtered so the stats output reflects what
// was actually purged (not the residual).
func snapshotQueueDepth(level, config, group string) int {
	globalQueueMu.RLock()
	defer globalQueueMu.RUnlock()
	n := 0
	for i := range globalQueueOps {
		op := &globalQueueOps[i].op
		switch level {
		case "all":
			n++
		case "config":
			if op.Config == config {
				n++
			}
		case "group":
			if op.Config == config && op.Group == group {
				n++
			}
		}
	}
	return n
}

func (s *Store) FlushAll() (FlushStats, error) {
	return s.FlushByLevel("all", "", "")
}
func (s *Store) FlushByConfig(c string) (FlushStats, error) {
	return s.FlushByLevel("config", c, "")
}
func (s *Store) FlushByGroup(g, c string) (FlushStats, error) {
	return s.FlushByLevel("group", c, g)
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// weightTypeASNPrefix returns the ASN-scoped weight-type prefix.
func weightTypeASNPrefix(isUDP bool) string {
	if isUDP {
		return WeightTypeUDPASN
	}
	return WeightTypeTCPASN
}

// asnWeightKey builds the weight key for an ASN.
func asnWeightKey(isUDP bool, asnNumber string) string {
	return weightTypeASNPrefix(isUDP) + ":" + asnNumber
}

// strconv shim for strconv.FormatInt
var _ = strconv.FormatInt
