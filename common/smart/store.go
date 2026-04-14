package smart

import (
	"bytes"
	"container/heap"
	"errors"
	"fmt"
	"math"
	"math/rand"
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
	globalDB         *bbolt.DB
	bucketSmartStats = []byte("smart_stats")

	globalStoreOnce sync.Once
	globalStore     *Store

	// Global write queue for bbolt batch flushing. The queue is a (slice,
	// index map) tandem protected by globalQueueMu:
	//
	//   globalQueueOps    — ordered list of pending StoreOperations
	//   globalQueueIdx    — map[key] → position in globalQueueOps
	//   globalQueueDirty  — set when the publicly-visible snapshot is stale
	//
	// The index keeps AppendToGlobalQueue at O(1) amortised per insert.
	// The dirty flag keeps snapshot publishing O(1) on reads too — we
	// only refresh the atomic.Value snapshot when a reader actually needs
	// it (in getGlobalQueueSnapshot), not on every write. Writes just
	// flip the dirty bit.
	globalQueue      atomic.Value // holds []StoreOperation (read-only)
	globalQueueOps   []StoreOperation
	globalQueueIdx   map[string]int
	globalQueueDirty atomic.Bool
	globalQueueMu    sync.Mutex

	globalCacheParams struct {
		BatchSaveThreshold int
		MaxTargets         int
		LastMemoryUsage    float64
		mu                 sync.RWMutex
	}

	targetCache       *lruCache[string, string]
	unwrapCache       *lruCache[string, UnwrapMap]
	recordCache       *lruCache[string, *AtomicStatsRecord]
	dbResultCache     *lruCache[string, map[string][]byte]
	blockedNodesCache *lruCache[string, map[string]bool]
)

// Store is a singleton that wraps bbolt + in-memory caches.
type Store struct{}

// GetOrInitStore returns the global Store, initializing it with db on first call.
func GetOrInitStore(db *bbolt.DB) *Store {
	globalStoreOnce.Do(func() {
		globalDB = db
		initCaches()
		initQueue()
		globalStore = &Store{}
	})
	return globalStore
}

func initCaches() {
	sz := MinTargetsLimit / 4

	globalCacheParams.mu.Lock()
	globalCacheParams.BatchSaveThreshold = MinBatchThreshLimit
	globalCacheParams.MaxTargets = MinTargetsLimit
	globalCacheParams.mu.Unlock()

	targetCache = newLRU[string, string](sz)
	unwrapCache = newLRU[string, UnwrapMap](sz)
	recordCache = newLRU[string, *AtomicStatsRecord](sz)
	dbResultCache = newLRUWithTTL[string, map[string][]byte](sz, 300*time.Second)
	blockedNodesCache = newLRUWithTTL[string, map[string]bool](sz, 300*time.Second)
}

func initQueue() {
	globalQueueOps = make([]StoreOperation, 0, 128)
	globalQueueIdx = make(map[string]int, 128)
	globalQueue.Store([]StoreOperation{})
}

func getBatchSaveThreshold() int {
	globalCacheParams.mu.RLock()
	defer globalCacheParams.mu.RUnlock()
	if globalCacheParams.BatchSaveThreshold <= 0 {
		return MinBatchThreshLimit
	}
	return globalCacheParams.BatchSaveThreshold
}

// AppendToGlobalQueue deduplicates by operation key and auto-flushes when
// over threshold. O(1) amortised per insert — we maintain a persistent
// `key → index` map alongside the queue slice, so dedup doesn't require
// rebuilding the map from the whole queue on every call.
//
// The exported snapshot (via globalQueue atomic.Value) is republished
// lazily only when callers need it — see getGlobalQueueSnapshot.
func (s *Store) AppendToGlobalQueue(operations ...StoreOperation) {
	if len(operations) == 0 {
		return
	}

	var shouldFlush bool
	var snapshot []StoreOperation

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
			globalQueueOps[pos] = operations[i]
			continue
		}
		globalQueueIdx[key] = len(globalQueueOps)
		globalQueueOps = append(globalQueueOps, operations[i])
	}

	threshold := getBatchSaveThreshold()
	if len(globalQueueOps) >= threshold {
		shouldFlush = true
		// Hand the accumulated ops to the flusher; reset the queue. We
		// copy into a fresh slice so the flusher can work in parallel
		// with new inserts without holding globalQueueMu.
		snapshot = make([]StoreOperation, len(globalQueueOps))
		copy(snapshot, globalQueueOps)
		globalQueueOps = globalQueueOps[:0]
		// Clear map keys instead of reallocating — preserves capacity.
		for k := range globalQueueIdx {
			delete(globalQueueIdx, k)
		}
	}

	// Mark the snapshot dirty — actual publish deferred until a reader
	// calls getGlobalQueueSnapshot. Keeps the append hot path allocation-
	// free for the steady-state (non-threshold) case.
	globalQueueDirty.Store(true)
	globalQueueMu.Unlock()

	if shouldFlush && len(snapshot) > 0 {
		go func() {
			_ = s.BatchSave(snapshot)
		}()
	}
}

// publishQueueSnapshotLocked copies globalQueueOps into the atomic.Value
// so lock-free readers (GetSubBytesByPath) see a consistent view without
// contending on globalQueueMu. Must be called with globalQueueMu held.
func publishQueueSnapshotLocked() {
	snap := make([]StoreOperation, len(globalQueueOps))
	copy(snap, globalQueueOps)
	globalQueue.Store(snap)
	globalQueueDirty.Store(false)
}

// getGlobalQueueSnapshot returns the most recent view of the queue.
// Republishes the snapshot if the append path has flagged it dirty —
// this defers the O(n) copy until a reader actually needs the data,
// keeping AppendToGlobalQueue O(1) in the common case.
func getGlobalQueueSnapshot() []StoreOperation {
	if globalQueueDirty.Load() {
		globalQueueMu.Lock()
		if globalQueueDirty.Load() {
			publishQueueSnapshotLocked()
		}
		globalQueueMu.Unlock()
	}
	v, _ := globalQueue.Load().([]StoreOperation)
	return v
}

// removeFromQueue filters the queue in-place and rebuilds the index. Used
// by FlushByLevel → filterQueueByGroup / filterQueueByConfig which run on
// cache-maintenance operations (infrequent, so the O(n) cost is fine).
func removeFromQueue(shouldRemove func(StoreOperation) bool) {
	globalQueueMu.Lock()
	kept := globalQueueOps[:0]
	for _, op := range globalQueueOps {
		if !shouldRemove(op) {
			kept = append(kept, op)
		}
	}
	globalQueueOps = kept
	// Rebuild the index — cheaper than incremental delete because filter
	// operations are bulk and we'd do O(n) deletes anyway.
	if globalQueueIdx == nil {
		globalQueueIdx = make(map[string]int, len(kept))
	} else {
		for k := range globalQueueIdx {
			delete(globalQueueIdx, k)
		}
	}
	for i := range globalQueueOps {
		if key := FormatOperationKey(&globalQueueOps[i]); key != "" {
			globalQueueIdx[key] = i
		}
	}
	publishQueueSnapshotLocked()
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

// FlushQueue writes buffered operations to bbolt. Swaps the in-memory
// queue atomically with globalQueueMu so concurrent Append calls don't
// race against the flusher — the caller gets a consistent snapshot to
// BatchSave while new inserts start on a fresh slice.
func (s *Store) FlushQueue(force bool) {
	globalQueueMu.Lock()
	if len(globalQueueOps) == 0 {
		globalQueueMu.Unlock()
		return
	}
	if !force && len(globalQueueOps) < getBatchSaveThreshold() {
		globalQueueMu.Unlock()
		return
	}
	ops := make([]StoreOperation, len(globalQueueOps))
	copy(ops, globalQueueOps)
	globalQueueOps = globalQueueOps[:0]
	for k := range globalQueueIdx {
		delete(globalQueueIdx, k)
	}
	publishQueueSnapshotLocked()
	globalQueueMu.Unlock()
	_ = s.BatchSave(ops)
}

// BatchSave persists a list of operations to bbolt in a single Batch transaction.
func (s *Store) BatchSave(operations []StoreOperation) error {
	if len(operations) == 0 {
		return nil
	}

	writeMap := make(map[string][]byte, len(operations))
	for i := range operations {
		key := FormatOperationKey(&operations[i])
		if key != "" {
			writeMap[key] = operations[i].Data
		}
	}

	return globalDB.Batch(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketSmartStats)
		if err != nil {
			return err
		}
		for key, data := range writeMap {
			if err := bucket.Put([]byte(key), data); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetSubBytesByPath returns all bbolt records matching a key prefix.
func (s *Store) GetSubBytesByPath(prefix string) (map[string][]byte, error) {
	result := make(map[string][]byte)

	globalCacheParams.mu.RLock()
	configMaxTargets := globalCacheParams.MaxTargets / 2
	globalCacheParams.mu.RUnlock()

	pathParts := strings.Split(prefix, "/")
	if len(pathParts) < 2 || pathParts[0] != "smart" {
		return result, nil
	}

	keyType := pathParts[1]
	config := ""
	group := ""
	if len(pathParts) >= 3 {
		config = pathParts[2]
	}
	if len(pathParts) >= 4 {
		group = pathParts[3]
	}

	strict := false
	switch keyType {
	case KeyTypeNode, KeyTypePrefetch, KeyTypeHostFailures:
		if len(pathParts) == 5 {
			strict = true
		}
	case KeyTypeRanking:
		if len(pathParts) == 4 {
			strict = true
		}
	case KeyTypeStats:
		if len(pathParts) == 6 {
			strict = true
		}
	}

	// Pull from write-queue first (in-flight data takes precedence)
	for _, op := range getGlobalQueueSnapshot() {
		if op.Config != config || op.Group != group {
			continue
		}
		var key string
		switch keyType {
		case KeyTypeNode:
			if op.Type == OpSaveNodeState && op.Node != "" {
				key = FormatDBKey(KeyTypeNode, op.Config, op.Group, op.Node)
				result[key] = op.Data
			}
		case KeyTypeStats:
			if op.Type == OpSaveStats && op.Target != "" && op.Node != "" {
				if len(pathParts) >= 5 && pathParts[4] != op.Target {
					continue
				}
				key = FormatDBKey(KeyTypeStats, op.Config, op.Group, op.Target, op.Node)
				result[key] = op.Data
			}
		case KeyTypePrefetch:
			if op.Type == OpSavePrefetch && op.Target != "" {
				if len(pathParts) >= 5 && pathParts[4] != op.Target {
					continue
				}
				key = FormatDBKey(KeyTypePrefetch, op.Config, op.Group, op.Target)
				result[key] = op.Data
			}
		case KeyTypeRanking:
			if op.Type == OpSaveRanking {
				key = FormatDBKey(KeyTypeRanking, op.Config, op.Group)
				result[key] = op.Data
			}
		case KeyTypeHostFailures:
			if op.Type == OpSaveHostFailures && op.Target != "" {
				if len(pathParts) >= 5 && pathParts[4] != op.Target {
					continue
				}
				key = FormatDBKey(KeyTypeHostFailures, op.Config, op.Group, op.Target)
				result[key] = op.Data
			}
		}
	}

	if strict && len(result) > 0 {
		return result, nil
	}

	maxResults := -1
	if configMaxTargets > 1 {
		maxResults = configMaxTargets
	}

	if cached, ok := dbResultCache.Get(prefix); ok && maxResults > 0 {
		for k, v := range cached {
			if _, exists := result[k]; !exists {
				result[k] = v
			}
		}
	} else {
		dbResult, err := s.DBViewPrefixScan(prefix, maxResults, strict)
		if err != nil {
			return result, nil
		}
		if maxResults > 0 && !(keyType == KeyTypeStats && strict) {
			dbResultCache.Set(prefix, dbResult)
		}
		for k, v := range dbResult {
			if _, exists := result[k]; !exists {
				result[k] = v
			}
		}
	}

	return result, nil
}

// DBViewPrefixScan scans bbolt for keys with the given prefix.
// maxResults=-1 means unlimited; reservoir sampling applied when over limit.
func (s *Store) DBViewPrefixScan(prefix string, maxResults int, strict bool) (map[string][]byte, error) {
	type kv struct {
		key string
		val []byte
	}
	var kvs []kv

	err := globalDB.View(func(tx *bbolt.Tx) error {
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
			valCopy := make([]byte, len(v))
			copy(valCopy, v)
			kvs = append(kvs, kv{string(k), valCopy})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte)
	if maxResults < 0 || len(kvs) <= maxResults {
		for _, item := range kvs {
			result[item.key] = item.val
		}
	} else {
		reservoir := kvs[:maxResults]
		for i := maxResults; i < len(kvs); i++ {
			j := rand.Intn(i + 1)
			if j < maxResults {
				reservoir[j] = kvs[i]
			}
		}
		for _, item := range reservoir {
			result[item.key] = item.val
		}
	}
	return result, nil
}

// DBBatchDeletePrefix deletes all keys matching a prefix.
func (s *Store) DBBatchDeletePrefix(prefix string, strict bool) error {
	var keysToDelete [][]byte

	err := globalDB.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSmartStats)
		if bucket == nil {
			return nil
		}
		cursor := bucket.Cursor()
		prefixBytes := []byte(prefix)
		for k, _ := cursor.Seek(prefixBytes); k != nil && bytes.HasPrefix(k, prefixBytes); k, _ = cursor.Next() {
			if strict && len(k) > len(prefixBytes) && k[len(prefixBytes)] != '/' {
				continue
			}
			keyCopy := make([]byte, len(k))
			copy(keyCopy, k)
			keysToDelete = append(keysToDelete, keyCopy)
		}
		return nil
	})
	if err != nil {
		return err
	}

	const batchSize = 200
	for i := 0; i < len(keysToDelete); i += batchSize {
		end := i + batchSize
		if end > len(keysToDelete) {
			end = len(keysToDelete)
		}
		batch := keysToDelete[i:end]
		if err := globalDB.Batch(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket(bucketSmartStats)
			if bucket == nil {
				return nil
			}
			for _, k := range batch {
				if err := bucket.Delete(k); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) DBBatchPutItem(key string, value []byte) error {
	return globalDB.Batch(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketSmartStats)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(key), value)
	})
}

// GetOrCreateAtomicRecord fetches or creates an in-memory AtomicStatsRecord,
// seeding it from bbolt if available.
func (s *Store) GetOrCreateAtomicRecord(cacheKey, group, config, target, proxy string) *AtomicStatsRecord {
	if r, ok := recordCache.Get(cacheKey); ok {
		return r
	}

	record := NewAtomicStatsRecord()

	existingData, err := s.GetStatsForTarget(group, config, target, proxy)
	if err == nil {
		if data, exists := existingData[proxy]; exists {
			var sr StatsRecord
			if json.Unmarshal(data, &sr) == nil {
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
			parts := strings.Split(fullPath, "/")
			if len(parts) > 0 {
				result[parts[len(parts)-1]] = data
			}
		}
	}
	return result, nil
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
		target := parts[len(parts)-2]
		node := parts[len(parts)-1]
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
		parts := strings.Split(fullPath, "/")
		if len(parts) > 0 {
			result[parts[len(parts)-1]] = data
		}
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

// ClearBlockedNodesCache removes cached blocked-node entries for a group.
func ClearBlockedNodesCache(group, config string) {
	if blockedNodesCache == nil {
		return
	}
	prefix := FormatDBKey(config, group)
	blockedNodesCache.RemoveByPrefix(prefix)
}

// GetBestProxyForTarget returns nodes sorted by weight for a target (and optional ASN).
func (s *Store) GetBestProxyForTarget(group, config, target, asnNumber string, isUDP bool) ([]string, []float64, error) {
	if target == "" {
		return nil, nil, errors.New("empty target")
	}

	now := time.Now().Unix()
	getDecay := func(lastUsed int64) float64 {
		return GetTimeDecay(lastUsed, now, 0.4)
	}

	allStatsMap, err := s.GetAllStats(group, config)
	if err != nil {
		return nil, nil, err
	}

	weightType := WeightTypeTCP
	if isUDP {
		weightType = WeightTypeUDP
	}

	nodesWithWeight := make(map[string]float64)

	if asnNumber != "" && !CdnASNs[asnNumber] {
		asnWeightType := WeightTypeTCPASN + ":" + asnNumber
		if isUDP {
			asnWeightType = WeightTypeUDPASN + ":" + asnNumber
		}

		nodeWeights := make(map[string][]float64)
		for _, mapStats := range allStatsMap {
			for nodeName, data := range mapStats {
				var record StatsRecord
				if json.Unmarshal(data, &record) != nil || record.Weights == nil {
					continue
				}
				if weight, ok := record.Weights[asnWeightType]; ok && weight > 0 {
					decay := getDecay(record.LastUsed)
					nodeWeights[nodeName] = append(nodeWeights[nodeName], weight*decay)
				}
			}
		}
		for nodeName, weights := range nodeWeights {
			sort.Float64s(weights)
			if weights[0] < AllowedWeight {
				nodesWithWeight[nodeName] = weights[0]
			} else {
				nodesWithWeight[nodeName] = weights[len(weights)-1]
			}
		}
	} else {
		var mapStats map[string][]byte
		if stats, ok := allStatsMap[target]; ok {
			mapStats = stats
		} else if stats, err := s.GetStatsForTarget(group, config, target, ""); err == nil {
			mapStats = stats
		}

		for nodeName, data := range mapStats {
			var record StatsRecord
			if json.Unmarshal(data, &record) != nil || record.Weights == nil {
				continue
			}
			if weight := record.Weights[weightType]; weight > 0 {
				nodesWithWeight[nodeName] = weight * getDecay(record.LastUsed)
			}
		}
	}

	if len(nodesWithWeight) == 0 {
		return nil, nil, errors.New("no best node with enough weight")
	}

	nodeList := make([]NodeWithWeight, 0, len(nodesWithWeight))
	for node, weight := range nodesWithWeight {
		nodeList = append(nodeList, NodeWithWeight{node, weight})
	}

	sort.Slice(nodeList, func(i, j int) bool {
		if nodeList[i].Weight != nodeList[j].Weight {
			return nodeList[i].Weight > nodeList[j].Weight
		}
		return nodeList[i].Node < nodeList[j].Node
	})

	bestNodes := make([]string, len(nodeList))
	bestWeights := make([]float64, len(nodeList))
	for i, nw := range nodeList {
		bestNodes[i] = nw.Node
		bestWeights[i] = nw.Weight
	}
	return bestNodes, bestWeights, nil
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
// rather than the nuclear Clear() that would evict other groups too.
func (s *Store) ClearUnwrapByGroup(group, config string) {
	if group == "" {
		return
	}
	unwrapCache.RemoveByPrefix(FormatDBKey(config, group))
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
			if json.Unmarshal(data, &record) != nil {
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
	allStats, err := s.GetAllStats(group, config)
	if err != nil || len(allStats) == 0 {
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
		lastUsed    int64
	}
	accs := make(map[string]*acc, len(allTags))
	for _, nodeStats := range allStats {
		for nodeName, data := range nodeStats {
			if !contains(allTags, nodeName) {
				continue
			}
			var record StatsRecord
			if json.Unmarshal(data, &record) != nil || record.Weights == nil {
				continue
			}
			// Sum tcp + udp weights for THIS target (scalar per target),
			// then average over targets in the final pass.
			tcp := record.Weights[WeightTypeTCP]
			udp := record.Weights[WeightTypeUDP]
			w := tcp + udp
			if w <= 0 {
				continue
			}
			a := accs[nodeName]
			if a == nil {
				a = &acc{}
				accs[nodeName] = a
			}
			a.weightSum += w
			a.targetCount++
			if record.LastUsed > a.lastUsed {
				a.lastUsed = record.LastUsed
			}
		}
	}

	if len(accs) == 0 {
		return nil
	}

	// Raw average weight per node, in the same scale as internal selection.
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
func (s *Store) GetNodeWeightRankingCache(group, config string) ([]NodeRank, error) {
	pathPrefix := FormatDBKey(KeyTypeRanking, config, group)
	rawResult, err := s.GetSubBytesByPath(pathPrefix)
	if err != nil {
		return nil, err
	}
	for _, data := range rawResult {
		var ranking []NodeRank
		if json.Unmarshal(data, &ranking) == nil && len(ranking) > 0 {
			return ranking, nil
		}
	}
	return []NodeRank{}, nil
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
	accs := make(map[string]*acc, len(allTags))
	for _, ad := range activeTargets {
		nodes, weights := s.GetPrefetchResult(group, config, ad.Target, ad.ASN, ad.IsUDP)
		for i := 0; i < len(nodes) && i < 10; i++ {
			if !contains(allTags, nodes[i]) {
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
			TargetCount: targetCounts[tag],
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
type targetMinHeap []ActiveTarget

func (h targetMinHeap) Len() int            { return len(h) }
func (h targetMinHeap) Less(i, j int) bool  { return h[i].LastUsed < h[j].LastUsed }
func (h targetMinHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *targetMinHeap) Push(x interface{}) { *h = append(*h, x.(ActiveTarget)) }
func (h *targetMinHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func (s *Store) GetActiveTargets(group, config string, limit int) []ActiveTarget {
	allStats, err := s.GetAllStats(group, config)
	if err != nil || len(allStats) == 0 {
		return nil
	}

	h := &targetMinHeap{}
	heap.Init(h)
	seen := make(map[string]int64)

	for target, nodeStats := range allStats {
		activeCombinations := make(map[string]int64)
		hasASN := false

		for _, data := range nodeStats {
			var record StatsRecord
			if json.Unmarshal(data, &record) != nil || record.Weights == nil {
				continue
			}

			if w, ok := record.Weights[WeightTypeTCP]; ok && w > 0 {
				key := ":false"
				if last, exists := activeCombinations[key]; !exists || record.LastUsed > last {
					activeCombinations[key] = record.LastUsed
				}
			}
			if w, ok := record.Weights[WeightTypeUDP]; ok && w > 0 {
				key := ":true"
				if last, exists := activeCombinations[key]; !exists || record.LastUsed > last {
					activeCombinations[key] = record.LastUsed
				}
			}

			for key, weight := range record.Weights {
				// Weight keys are "tcp_asn:13335" or "udp_asn:13335" — exactly one
				// ':' separator between the prefix and the ASN number. Previous
				// code used SplitN(..., 3) with len(parts) >= 3 which is
				// unreachable (the string produces 2 parts, not 3). The ASN
				// therefore never propagated to activeCombinations, so
				// RunPrefetch + GetNodeWeightRanking never received any ASN
				// data — breaking the /weights Clash API endpoints entirely
				// for users with use_asn: true.
				//
				// Match mihomo exactly: strings.Split (no N cap) with parts[1].
				if strings.HasPrefix(key, WeightTypeTCPASN) && weight > 0 {
					parts := strings.Split(key, ":")
					if len(parts) >= 2 {
						asn := parts[1]
						ck := asn + ":false"
						if last, exists := activeCombinations[ck]; !exists || record.LastUsed > last {
							activeCombinations[ck] = record.LastUsed
							hasASN = true
						}
					}
				} else if strings.HasPrefix(key, WeightTypeUDPASN) && weight > 0 {
					parts := strings.Split(key, ":")
					if len(parts) >= 2 {
						asn := parts[1]
						ck := asn + ":true"
						if last, exists := activeCombinations[ck]; !exists || record.LastUsed > last {
							activeCombinations[ck] = record.LastUsed
							hasASN = true
						}
					}
				}
			}
		}

		for combKey, lastUsed := range activeCombinations {
			parts := strings.SplitN(combKey, ":", 2)
			asn := parts[0]
			isUDP := len(parts) >= 2 && parts[1] == "true"

			if asn == "" && hasASN {
				continue
			}

			recordKey := fmt.Sprintf("%s:%s:%t", target, asn, isUDP)
			if existingLast, exists := seen[recordKey]; !exists || lastUsed > existingLast {
				seen[recordKey] = lastUsed
				heap.Push(h, ActiveTarget{
					Target:   target,
					ASN:      asn,
					IsUDP:    isUDP,
					LastUsed: lastUsed,
				})
				if h.Len() > limit {
					heap.Pop(h)
				}
			}
		}
	}

	sorted := make([]ActiveTarget, 0, h.Len())
	for h.Len() > 0 {
		sorted = append(sorted, heap.Pop(h).(ActiveTarget))
	}

	result := make([]ActiveTarget, 0, len(sorted))
	for i := len(sorted) - 1; i >= 0; i-- {
		result = append(result, sorted[i])
	}
	return result
}

// RunPrefetch pre-calculates best nodes for frequently accessed targets.
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

	activeTargets := s.GetActiveTargets(group, config, prefetchLimit)

	type asnKey struct {
		asn   string
		isUDP bool
	}
	type asnVal struct {
		nodes   []string
		weights []float64
	}
	asnCache := make(map[asnKey]asnVal)

	type prefetchItem struct {
		target      string
		asnNumber   string
		isUDP       bool
		bestNodes   []string
		bestWeights []float64
	}

	var items []prefetchItem
	for _, active := range activeTargets {
		var (
			bestNodes   []string
			bestWeights []float64
			err         error
		)

		if active.ASN != "" && !CdnASNs[active.ASN] {
			k := asnKey{active.ASN, active.IsUDP}
			if v, ok := asnCache[k]; ok {
				bestNodes = v.nodes
				bestWeights = v.weights
			} else {
				bestNodes, bestWeights, err = s.GetBestProxyForTarget(group, config, active.Target, active.ASN, active.IsUDP)
				asnCache[k] = asnVal{bestNodes, bestWeights}
			}
		} else {
			bestNodes, bestWeights, err = s.GetBestProxyForTarget(group, config, active.Target, active.ASN, active.IsUDP)
		}

		if err != nil || len(bestNodes) == 0 {
			continue
		}

		nodes := make([]string, 0, len(bestNodes))
		weights := make([]float64, 0, len(bestWeights))
		for i, node := range bestNodes {
			if _, exists := availableProxyMap[node]; exists {
				nodes = append(nodes, node)
				weights = append(weights, bestWeights[i])
			}
		}
		if len(nodes) > 0 {
			items = append(items, prefetchItem{active.Target, active.ASN, active.IsUDP, nodes, weights})
		}
	}

	asnCache = make(map[asnKey]asnVal)
	prefetchCount := 0

	for _, item := range items {
		oldNodes, oldWeights := s.GetPrefetchResult(group, config, item.target, item.asnNumber, item.isUDP)

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

// RemoveNodesData cleans up stats, prefetch, ranking, and node-state entries for removed nodes.
func (s *Store) RemoveNodesData(group, config string, nodes []string) error {
	if len(nodes) == 0 {
		return nil
	}

	removeNodesFromQueue(group, config, nodes)

	nodeSet := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		nodeSet[n] = struct{}{}
	}

	var firstErr error

	statsPrefix := FormatDBKey(KeyTypeStats, config, group)
	statsResults, err := s.DBViewPrefixScan(statsPrefix, -1, false)
	if err != nil {
		return err
	}
	for path := range statsResults {
		parts := strings.Split(path, "/")
		if len(parts) >= 6 {
			node := parts[len(parts)-1]
			if _, ok := nodeSet[node]; ok {
				if delErr := s.DBBatchDeletePrefix(path, true); delErr != nil && firstErr == nil {
					firstErr = delErr
				}
			}
		}
	}

	prefetchPrefix := FormatDBKey(KeyTypePrefetch, config, group)
	prefetchResults, err := s.DBViewPrefixScan(prefetchPrefix, -1, false)
	if err != nil {
		if firstErr == nil {
			firstErr = err
		}
		return firstErr
	}
	for path, data := range prefetchResults {
		var pm PrefetchMap
		if err := json.Unmarshal(data, &pm); err != nil {
			continue
		}
		changed := false
		pm.TCP.Nodes, pm.TCP.Weights = removeFromNodesWeights(pm.TCP.Nodes, pm.TCP.Weights, nodeSet, &changed)
		pm.UDP.Nodes, pm.UDP.Weights = removeFromNodesWeights(pm.UDP.Nodes, pm.UDP.Weights, nodeSet, &changed)
		if changed {
			if len(pm.TCP.Nodes) == 0 && len(pm.UDP.Nodes) == 0 && pm.RefTCP == "" && pm.RefUDP == "" {
				_ = s.DBBatchDeletePrefix(path, true)
			} else if newData, merr := json.Marshal(pm); merr == nil {
				_ = s.DBBatchPutItem(path, newData)
			}
		}
	}

	rankingPrefix := FormatDBKey(KeyTypeRanking, config, group)
	rankingResults, _ := s.DBViewPrefixScan(rankingPrefix, -1, true)
	for path, data := range rankingResults {
		var ranking []NodeRank
		if err := json.Unmarshal(data, &ranking); err != nil {
			continue
		}
		newRanking := ranking[:0]
		changed := false
		for _, r := range ranking {
			if _, toRemove := nodeSet[r.Name]; toRemove {
				changed = true
				continue
			}
			newRanking = append(newRanking, r)
		}
		if changed {
			if len(newRanking) == 0 {
				_ = s.DBBatchDeletePrefix(path, true)
			} else if newData, merr := json.Marshal(newRanking); merr == nil {
				_ = s.DBBatchPutItem(path, newData)
			}
		}
	}

	for _, nodeName := range nodes {
		_ = s.DBBatchDeletePrefix(FormatDBKey(KeyTypeNode, config, group, nodeName), true)
	}

	return firstErr
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

// GetAllGroupsForConfig returns all known group names for a config.
func (s *Store) GetAllGroupsForConfig(config string) ([]string, error) {
	groupsMap := make(map[string]bool)

	statsPath := FormatDBKey(KeyTypeStats, config)
	raw, err := s.GetSubBytesByPath(statsPath)
	if err == nil {
		for fullPath := range raw {
			parts := strings.Split(fullPath, "/")
			if len(parts) >= 4 && parts[3] != "" {
				groupsMap[parts[3]] = true
			}
		}
	} else {
		scanResults, err2 := s.DBViewPrefixScan(statsPath, -1, false)
		if err2 != nil {
			return nil, err2
		}
		for path := range scanResults {
			parts := strings.Split(path, "/")
			if len(parts) >= 4 && parts[3] != "" {
				groupsMap[parts[3]] = true
			}
		}
	}

	result := make([]string, 0, len(groupsMap))
	for g := range groupsMap {
		result = append(result, g)
	}
	return result, nil
}

// GetAllNodesForGroup returns all known node names for a group.
func (s *Store) GetAllNodesForGroup(group, config string) ([]string, error) {
	nodesMap := make(map[string]bool)

	nodesPath := FormatDBKey(KeyTypeNode, config, group)
	if nodeStatesData, err := s.GetSubBytesByPath(nodesPath); err == nil {
		for key := range nodeStatesData {
			parts := strings.Split(key, "/")
			if len(parts) > 0 && parts[len(parts)-1] != "" {
				nodesMap[parts[len(parts)-1]] = true
			}
		}
	}

	statsPath := FormatDBKey(KeyTypeStats, config, group)
	if statsData, err := s.GetSubBytesByPath(statsPath); err == nil {
		for key := range statsData {
			parts := strings.Split(key, "/")
			if len(parts) >= 6 && parts[len(parts)-1] != "" {
				nodesMap[parts[len(parts)-1]] = true
			}
		}
	}

	result := make([]string, 0, len(nodesMap))
	for node := range nodesMap {
		result = append(result, node)
	}
	return result, nil
}

// CleanupOldRecords removes excess historical data from bbolt.
func (s *Store) CleanupOldRecords(group, config string) error {
	globalCacheParams.mu.RLock()
	maxTargets := globalCacheParams.MaxTargets
	globalCacheParams.mu.RUnlock()

	for _, keyType := range []string{KeyTypeStats, KeyTypePrefetch, KeyTypeHostFailures} {
		pathPrefix := FormatDBKey(keyType, config, group)
		rawData, err := s.DBViewPrefixScan(pathPrefix, -1, false)
		if err != nil {
			continue
		}

		type targetInfo struct {
			lastTime int64
			value    float64
			path     string
		}
		targetMap := make(map[string]*targetInfo, len(rawData))

		for path, data := range rawData {
			parts := strings.Split(path, "/")
			if len(parts) < 5 {
				continue
			}

			var lastTime int64
			var value float64

			switch keyType {
			case KeyTypeStats:
				if len(parts) < 6 {
					continue
				}
				var record StatsRecord
				if err := json.Unmarshal(data, &record); err != nil {
					continue
				}
				lastTime = record.LastUsed
				value = float64(record.Success + record.Failure)
			case KeyTypePrefetch:
				var pm PrefetchMap
				if err := json.Unmarshal(data, &pm); err != nil {
					continue
				}
				lastTime = pm.UpdatedTime
				value = float64(len(pm.TCP.Nodes) + len(pm.UDP.Nodes))
			case KeyTypeHostFailures:
				var hs HostStatus
				if err := json.Unmarshal(data, &hs); err != nil {
					continue
				}
				lastTime = hs.LastFailure
				value = float64(hs.FailureCount)
			}

			targetMap[path] = &targetInfo{lastTime, value, path}
		}

		totalRecords := len(targetMap)
		if totalRecords <= maxTargets*2 {
			continue
		}

		toDeleteCount := totalRecords - maxTargets
		deleted := 0

		var invalidPaths, validPaths []string
		for path, info := range targetMap {
			if info.lastTime <= 0 {
				invalidPaths = append(invalidPaths, path)
			} else {
				validPaths = append(validPaths, path)
			}
		}

		for _, path := range invalidPaths {
			if deleted >= toDeleteCount {
				break
			}
			if err := s.DBBatchDeletePrefix(path, false); err == nil {
				deleted++
			}
		}

		if deleted < toDeleteCount {
			remaining := toDeleteCount - deleted
			sort.Slice(validPaths, func(i, j int) bool {
				ii := targetMap[validPaths[i]]
				jj := targetMap[validPaths[j]]
				if ii.value != jj.value {
					return ii.value < jj.value
				}
				return ii.lastTime < jj.lastTime
			})
			for i := 0; i < remaining && i < len(validPaths); i++ {
				if err := s.DBBatchDeletePrefix(validPaths[i], false); err == nil {
					deleted++
				}
			}
		}

		dbResultCache.RemoveByPrefix(pathPrefix)
	}

	return nil
}

// AdjustCacheParameters dynamically resizes caches based on system memory.
func (s *Store) AdjustCacheParameters() {
	memUsage := getSystemMemoryUsage()

	globalCacheParams.mu.Lock()
	defer globalCacheParams.mu.Unlock()

	isFirst := globalCacheParams.LastMemoryUsage == 0
	needAdjust := isFirst

	if !isFirst {
		memChanged := math.Abs(memUsage-globalCacheParams.LastMemoryUsage) > 0.05
		needAdjust = memChanged || memUsage > 0.5
	}

	globalCacheParams.LastMemoryUsage = memUsage
	if !needAdjust && !isFirst {
		return
	}

	if memUsage > 0.9 {
		globalCacheParams.MaxTargets = MinTargetsLimit
		globalCacheParams.BatchSaveThreshold = MinBatchThreshLimit
	} else {
		factor := (1 - memUsage) * 0.5
		globalCacheParams.MaxTargets = MinTargetsLimit + int(float64(MaxTargetsLimit-MinTargetsLimit)*factor)
		globalCacheParams.BatchSaveThreshold = MinBatchThreshLimit + int(float64(MaxBatchThreshLimit-MinBatchThreshLimit)*factor)
	}

	sz := globalCacheParams.MaxTargets / 4
	targetCache.Resize(sz)
	unwrapCache.Resize(sz)
	recordCache.Resize(sz)
	dbResultCache.Resize(sz)
	blockedNodesCache.Resize(sz)
}

func getSystemMemoryUsage() float64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	// Use heap alloc as a proxy for pressure (no OS-level call)
	if ms.Sys > 0 {
		return math.Min(float64(ms.HeapInuse)/float64(ms.Sys), 1.0)
	}
	return 0.5
}

// FlushStats holds per-key-type deletion counts returned by FlushByLevel.
// Zero values mean "nothing matched" — NOT "skipped". Callers surface this
// to operators so `POST /cache/smart/flush/{name}` is visibly effective.
type FlushStats struct {
	Stats    int `json:"stats"`
	Nodes    int `json:"nodes"`
	Ranking  int `json:"ranking"`
	Prefetch int `json:"prefetch"`
	Failures int `json:"failures"`
	Queue    int `json:"queue"`
}

// Total sums every deletion bucket — convenient for "nothing happened" checks.
func (f FlushStats) Total() int {
	return f.Stats + f.Nodes + f.Ranking + f.Prefetch + f.Failures + f.Queue
}

// FlushByLevel clears queue and DB data at the given level and returns the
// per-bucket deletion counts + the first error (if any). Previous versions
// silently swallowed errors via `_ = ...` which masked failures in logs.
// Group-level deletes now use strict=true so "HK" doesn't accidentally
// purge "HK-Backup" (prefix-collision bug with non-strict matching).
func (s *Store) FlushByLevel(level, config, group string) (FlushStats, error) {
	var stats FlushStats
	stats.Queue = snapshotQueueDepth(level, config, group)

	switch level {
	case "all":
		globalQueueMu.Lock()
		globalQueueOps = globalQueueOps[:0]
		for k := range globalQueueIdx {
			delete(globalQueueIdx, k)
		}
		publishQueueSnapshotLocked()
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
	deletePrefix := func(prefix string, strict bool) int {
		n, err := s.dbDeletePrefixCount(prefix, strict)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		return n
	}
	switch level {
	case "all":
		stats.Stats = deletePrefix(FormatDBKey(KeyTypeStats), false)
		stats.Nodes = deletePrefix(FormatDBKey(KeyTypeNode), false)
		stats.Ranking = deletePrefix(FormatDBKey(KeyTypeRanking), false)
		stats.Prefetch = deletePrefix(FormatDBKey(KeyTypePrefetch), false)
		stats.Failures = deletePrefix(FormatDBKey(KeyTypeHostFailures), false)
	case "config":
		stats.Stats = deletePrefix(FormatDBKey(KeyTypeStats, config), true)
		stats.Nodes = deletePrefix(FormatDBKey(KeyTypeNode, config), true)
		stats.Ranking = deletePrefix(FormatDBKey(KeyTypeRanking, config), true)
		stats.Prefetch = deletePrefix(FormatDBKey(KeyTypePrefetch, config), true)
		stats.Failures = deletePrefix(FormatDBKey(KeyTypeHostFailures, config), true)
	case "group":
		stats.Stats = deletePrefix(FormatDBKey(KeyTypeStats, config, group), true)
		stats.Nodes = deletePrefix(FormatDBKey(KeyTypeNode, config, group), true)
		stats.Ranking = deletePrefix(FormatDBKey(KeyTypeRanking, config, group), true)
		stats.Prefetch = deletePrefix(FormatDBKey(KeyTypePrefetch, config, group), true)
		stats.Failures = deletePrefix(FormatDBKey(KeyTypeHostFailures, config, group), true)
	}
	return stats, firstErr
}

// snapshotQueueDepth counts pending queue items that match a flush scope,
// captured BEFORE the queue is filtered so the stats output reflects what
// was actually purged (not the residual).
func snapshotQueueDepth(level, config, group string) int {
	ops, _ := globalQueue.Load().([]StoreOperation)
	if len(ops) == 0 {
		return 0
	}
	n := 0
	for _, op := range ops {
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

// dbDeletePrefixCount deletes by prefix and returns how many keys matched.
// Mirrors DBBatchDeletePrefix but preserves the deletion count so callers
// (notably FlushByLevel) can surface "how much did we actually wipe" to
// operators hitting /cache/smart/flush/*.
func (s *Store) dbDeletePrefixCount(prefix string, strict bool) (int, error) {
	var keysToDelete [][]byte
	err := globalDB.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSmartStats)
		if bucket == nil {
			return nil
		}
		cursor := bucket.Cursor()
		prefixBytes := []byte(prefix)
		for k, _ := cursor.Seek(prefixBytes); k != nil && bytes.HasPrefix(k, prefixBytes); k, _ = cursor.Next() {
			if strict && len(k) > len(prefixBytes) && k[len(prefixBytes)] != '/' {
				continue
			}
			keyCopy := make([]byte, len(k))
			copy(keyCopy, k)
			keysToDelete = append(keysToDelete, keyCopy)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if len(keysToDelete) == 0 {
		return 0, nil
	}
	const batchSize = 200
	for i := 0; i < len(keysToDelete); i += batchSize {
		end := i + batchSize
		if end > len(keysToDelete) {
			end = len(keysToDelete)
		}
		batch := keysToDelete[i:end]
		if err := globalDB.Batch(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket(bucketSmartStats)
			if bucket == nil {
				return nil
			}
			for _, k := range batch {
				if err := bucket.Delete(k); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return 0, err
		}
	}
	return len(keysToDelete), nil
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
