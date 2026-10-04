package smart

import (
	"bytes"
	"fmt"
	"math/rand"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
)

func putRaw(t *testing.T, key string, value []byte) {
	t.Helper()
	err := globalDB.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketSmartStats)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(key), value)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func rawExists(t *testing.T, key string) bool {
	t.Helper()
	found := false
	err := globalDB.View(func(tx *bbolt.Tx) error {
		if bucket := tx.Bucket(bucketSmartStats); bucket != nil {
			found = bucket.Get([]byte(key)) != nil
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func rawCount(t *testing.T, prefix string) int {
	t.Helper()
	n := 0
	if err := walkKeys(prefix, func([]byte) { n++ }); err != nil {
		t.Fatal(err)
	}
	return n
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// TestGroupPrefixIsolation: group "HK" must never see or touch rows of
// group "HK-Auto", whose keys share the "smart/<type>/<cfg>/HK" prefix.
func TestGroupPrefixIsolation(t *testing.T) {
	s := freshStore(t)
	const cfg = "cfg-prefix"
	setMaxTargets(t, 2)
	for _, g := range []string{"HK", "HK-Auto"} {
		stageStats(t, s, g, cfg, "only-"+g+".example", "node-"+g, 10, 1, 1.5)
		s.AppendToGlobalQueue(
			StoreOperation{Type: OpSaveNodeState, Group: g, Config: cfg, Node: "node-" + g, Data: []byte(`{"name":"x","failure_count":1}`)},
			StoreOperation{Type: OpSaveKnownDead, Group: g, Config: cfg, Node: "node-" + g, Data: []byte(`{"dead_at":1}`)},
		)
	}
	for i := 0; i < 10; i++ {
		stageStats(t, s, "HK-Auto", cfg, fmt.Sprintf("auto-%d.example", i), "node-HK-Auto", 1, 0, 1)
	}

	check := func(phase string) {
		t.Helper()
		stats, _ := s.GetAllStats("HK", cfg)
		if len(stats) != 1 || stats["only-HK.example"] == nil {
			t.Fatalf("%s: GetAllStats(HK) = %v", phase, stats)
		}
		states, _ := s.GetNodeStates("HK", cfg)
		if len(states) != 1 || states["node-HK"] == nil {
			t.Fatalf("%s: GetNodeStates(HK) = %v", phase, states)
		}
		dead, _ := s.GetSubBytesByPath(FormatDBKey(KeyTypeKnownDead, cfg, "HK"))
		if len(dead) != 1 {
			t.Fatalf("%s: dead rows for HK = %v", phase, dead)
		}
		if active := s.GetActiveTargets("HK", cfg, 100); len(active) != 1 || active[0].Target != "only-HK.example" {
			t.Fatalf("%s: GetActiveTargets(HK) = %v", phase, active)
		}
		if nodes, _ := s.GetAllNodesForGroup("HK", cfg); fmt.Sprint(nodes) != "[node-HK]" {
			t.Fatalf("%s: GetAllNodesForGroup(HK) = %v", phase, nodes)
		}
		if _, _, err := s.GetBestProxyForTarget("HK", cfg, "only-HK-Auto.example", "", false); err == nil {
			t.Fatalf("%s: HK must not rank HK-Auto targets", phase)
		}
		if groups, _ := s.GetAllGroupsForConfig(cfg); fmt.Sprint(sortedStrings(groups)) != "[HK HK-Auto]" {
			t.Fatalf("%s: GetAllGroupsForConfig = %v", phase, groups)
		}
	}
	check("queued")
	s.FlushQueue(true)
	check("flushed")

	// HK holds one stats row (under the 2×MaxTargets trigger); HK-Auto's
	// eleven rows must not be counted against it, let alone deleted.
	if err := s.CleanupOldRecords("HK", cfg); err != nil {
		t.Fatal(err)
	}
	if n := rawCount(t, FormatDBKey(KeyTypeStats, cfg, "HK-Auto")); n != 11 {
		t.Fatalf("CleanupOldRecords(HK) touched HK-Auto: %d rows left", n)
	}
	if err := s.RemoveNodesData("HK", cfg, []string{"node-HK-Auto"}); err != nil {
		t.Fatal(err)
	}
	if n := rawCount(t, FormatDBKey(KeyTypeStats, cfg, "HK-Auto")); n != 11 {
		t.Fatalf("RemoveNodesData(HK) touched HK-Auto: %d rows left", n)
	}

	s.StoreUnwrapResult("HK", cfg, "a.example", "", false, []string{"x"})
	s.StoreUnwrapResult("HK-Auto", cfg, "a.example", "", false, []string{"y"})
	unwrapCache.Wait()
	s.ClearUnwrapByGroup("HK", cfg)
	if got := s.GetUnwrapResult("HK-Auto", cfg, "a.example", "", false); fmt.Sprint(got) != "[y]" {
		t.Fatalf("ClearUnwrapByGroup(HK) cleared HK-Auto: %v", got)
	}
	if got := s.GetUnwrapResult("HK", cfg, "a.example", "", false); got != nil {
		t.Fatalf("ClearUnwrapByGroup(HK) left %v", got)
	}
}

// TestCleanupOldRecordsDeletesExactKeys: trimming node-1's row must not
// take node-10's row (same target) with it.
func TestCleanupOldRecordsDeletesExactKeys(t *testing.T) {
	s := freshStore(t)
	const g, cfg = "g-cleanup", "cfg-cleanup"
	setMaxTargets(t, 2)
	now := time.Now().Unix()
	put := func(target, node string, success, lastUsed int64) {
		data, _ := MarshalStatsRecord(&StatsRecord{Success: success, LastUsed: lastUsed})
		putRaw(t, FormatDBKey(KeyTypeStats, cfg, g, target, node), data)
	}
	put("t.example", "node-1", 1000, 0) // no timestamp: trimmed first
	put("t.example", "node-10", 1000, now)
	for i := int64(1); i <= 4; i++ {
		put(fmt.Sprintf("f%d.example", i), "filler", i, now)
	}

	if err := s.CleanupOldRecords(g, cfg); err != nil {
		t.Fatal(err)
	}
	if rawExists(t, FormatDBKey(KeyTypeStats, cfg, g, "t.example", "node-1")) {
		t.Fatal("node-1 row should have been trimmed")
	}
	if !rawExists(t, FormatDBKey(KeyTypeStats, cfg, g, "t.example", "node-10")) {
		t.Fatal("node-10 row deleted along with node-1")
	}
	if !rawExists(t, FormatDBKey(KeyTypeStats, cfg, g, "f4.example", "filler")) {
		t.Fatal("most valuable filler row should survive")
	}
	if n := rawCount(t, FormatDBKey(KeyTypeStats, cfg, g)); n != 2 {
		t.Fatalf("%d rows left, want MaxTargets=2", n)
	}
	// The index must reflect the deletion.
	if _, _, err := s.GetBestProxyForTarget(g, cfg, "f1.example", "", false); err == nil {
		t.Fatal("trimmed row still served by the stats index")
	}
}

// TestRemoveNodesDataEscapedTags: tags containing '/' or '%' are matched
// by their real name, and only the removed nodes' rows go.
func TestRemoveNodesDataEscapedTags(t *testing.T) {
	s := freshStore(t)
	const g, cfg = "g-remove", "cfg-remove"
	gone, kept := "ENET/🇳🇿 NZ", "50% off"
	for _, n := range []string{gone, kept} {
		stageStats(t, s, g, cfg, "a.example", n, 5, 0, 1)
		s.AppendToGlobalQueue(StoreOperation{Type: OpSaveNodeState, Group: g, Config: cfg, Node: n, Data: []byte(`{}`)})
	}
	s.StorePrefetchResult(g, cfg, "a.example", "", false, []string{gone, kept}, []float64{2, 1})
	s.FlushQueue(true)

	nodes, _ := s.GetAllNodesForGroup(g, cfg)
	if fmt.Sprint(sortedStrings(nodes)) != fmt.Sprint(sortedStrings([]string{gone, kept})) {
		t.Fatalf("GetAllNodesForGroup = %q", nodes)
	}
	if err := s.RemoveNodesData(g, cfg, []string{gone}); err != nil {
		t.Fatal(err)
	}
	if rawExists(t, FormatDBKey(KeyTypeStats, cfg, g, "a.example", gone)) || rawExists(t, FormatDBKey(KeyTypeNode, cfg, g, gone)) {
		t.Fatal("removed node's rows survived")
	}
	if !rawExists(t, FormatDBKey(KeyTypeStats, cfg, g, "a.example", kept)) || !rawExists(t, FormatDBKey(KeyTypeNode, cfg, g, kept)) {
		t.Fatal("kept node's rows were deleted")
	}
	if nodes, _ := s.GetPrefetchResult(g, cfg, "a.example", "", false); fmt.Sprint(nodes) != "[50% off]" {
		t.Fatalf("prefetch after removal = %q", nodes)
	}
}

// TestQueuedWritesOverlayStore covers exact and prefix reads against
// queued values, tombstones, and a batch that is mid-commit.
func TestQueuedWritesOverlayStore(t *testing.T) {
	s := freshStore(t)
	const g, cfg = "g-overlay", "cfg-overlay"
	keyA := FormatDBKey(KeyTypeKnownDead, cfg, g, "A")
	keyB := FormatDBKey(KeyTypeKnownDead, cfg, g, "B")
	scope := FormatDBKey(KeyTypeKnownDead, cfg, g)
	putRaw(t, keyA, []byte(`{"dead_at":1}`))
	putRaw(t, keyB, []byte(`{"dead_at":2}`))

	// Warm the cache so the overlay must win over a cached scan too.
	_, _ = s.GetSubBytesByPath(scope)
	dbResultCache.Wait()

	s.AppendToGlobalQueue(
		StoreOperation{Type: OpSaveKnownDead, Group: g, Config: cfg, Node: "A", Data: []byte(`{"dead_at":10}`)},
		StoreOperation{Type: OpDeleteKnownDead, Group: g, Config: cfg, Node: "B"},
	)
	if rows, _ := s.GetSubBytesByPath(keyA); string(rows[keyA]) != `{"dead_at":10}` {
		t.Fatalf("exact read ignored queued value: %q", rows)
	}
	if rows, _ := s.GetSubBytesByPath(keyB); len(rows) != 0 {
		t.Fatalf("exact read ignored tombstone: %q", rows)
	}
	rows, _ := s.GetSubBytesByPath(scope)
	if len(rows) != 1 || string(rows[keyA]) != `{"dead_at":10}` {
		t.Fatalf("prefix read = %q", rows)
	}

	// Stall the commit by holding bbolt's writer lock: the drained batch
	// must stay visible while it is in flight.
	held, release := make(chan struct{}), make(chan struct{})
	go func() {
		_ = globalDB.Update(func(*bbolt.Tx) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	flushed := make(chan struct{})
	go func() {
		s.FlushQueue(true)
		close(flushed)
	}()
	waitFor(t, "batch in flight", func() bool {
		globalQueueMu.RLock()
		defer globalQueueMu.RUnlock()
		return len(inflightOps) == 2
	})
	if rows, _ := s.GetSubBytesByPath(keyA); string(rows[keyA]) != `{"dead_at":10}` {
		t.Fatalf("in-flight value invisible: %q", rows)
	}
	if rows, _ := s.GetSubBytesByPath(scope); len(rows) != 1 {
		t.Fatalf("in-flight tombstone invisible: %q", rows)
	}
	dbResultCache.Wait()
	close(release)
	<-flushed

	rows, _ = s.GetSubBytesByPath(scope)
	if len(rows) != 1 || string(rows[keyA]) != `{"dead_at":10}` {
		t.Fatalf("after commit = %q", rows)
	}
	if rawExists(t, keyB) {
		t.Fatal("tombstone not applied")
	}
}

// TestReadModifyWriteAcrossFlushes: counters updated read-modify-write
// must see their own flushed writes, not a cached pre-write scan.
func TestReadModifyWriteAcrossFlushes(t *testing.T) {
	s := freshStore(t)
	const g, cfg = "g-rmw", "cfg-rmw"
	for i := 0; i < 3; i++ {
		s.UpdateHostStatus(g, cfg, "host.example", true, false)

		states, _ := s.GetNodeStates(g, cfg)
		var st NodeState
		if data, ok := states["N/1"]; ok {
			_ = json.Unmarshal(data, &st)
		}
		st.FailureCount++
		data, _ := json.Marshal(&st)
		s.AppendToGlobalQueue(StoreOperation{Type: OpSaveNodeState, Group: g, Config: cfg, Node: "N/1", Data: data})

		dbResultCache.Wait()
		s.FlushQueue(true)
	}
	if fails, _ := s.GetHostStatus(g, cfg, "host.example"); fails != 3 {
		t.Fatalf("host failure count = %d, want 3", fails)
	}
	states, _ := s.GetNodeStates(g, cfg)
	var st NodeState
	if err := json.Unmarshal(states["N/1"], &st); err != nil || st.FailureCount != 3 {
		t.Fatalf("node failure count = %d (%v), want 3", st.FailureCount, err)
	}
}

// TestBackgroundFlusher: crossing the threshold drains through the single
// flusher (no goroutine per batch); StoreFlushNow drains the rest.
func TestBackgroundFlusher(t *testing.T) {
	s := freshStore(t)
	const g, cfg = "g-flusher", "cfg-flusher"
	threshold := getBatchSaveThreshold()
	before := runtime.NumGoroutine()
	for i := 0; i < 10*threshold; i++ {
		s.AppendToGlobalQueue(StoreOperation{Type: OpSaveHostFailures, Group: g, Config: cfg, Target: fmt.Sprintf("h%d", i), Data: []byte(`{}`)})
	}
	if after := runtime.NumGoroutine(); after > before+1 {
		t.Fatalf("goroutines grew from %d to %d while appending", before, after)
	}
	waitFor(t, "background drain", func() bool {
		globalQueueMu.RLock()
		defer globalQueueMu.RUnlock()
		return len(globalQueueOps) < threshold && len(inflightOps) == 0
	})

	s.AppendToGlobalQueue(StoreOperation{Type: OpSaveHostFailures, Group: g, Config: cfg, Target: "last", Data: []byte(`{}`)})
	if err := s.StoreFlushNow(); err != nil {
		t.Fatal(err)
	}
	if n := rawCount(t, FormatDBKey(KeyTypeHostFailures, cfg, g)); n != 10*threshold+1 {
		t.Fatalf("%d rows on disk, want %d", n, 10*threshold+1)
	}
	globalQueueMu.RLock()
	pending := len(globalQueueOps) + len(inflightOps)
	globalQueueMu.RUnlock()
	if pending != 0 {
		t.Fatalf("%d ops still pending after StoreFlushNow", pending)
	}
}

// TestLRUKeysIndexTracksResidency: keys leave the index when ristretto
// evicts or rejects them, and the remove hook sees every departure.
func TestLRUKeysIndexTracksResidency(t *testing.T) {
	var removed atomic.Int64
	c := newCacheCost[string, string](16*1024, 0, byteBudgetCounters(16*1024), costString, func(string) { removed.Add(1) })
	defer c.Close()
	const inserted = 5000
	value := strings.Repeat("x", 512)
	for i := 0; i < inserted; i++ {
		c.Set(keyN(i), value)
	}
	c.Wait()

	resident := 0
	c.keysIndex.Range(func(k string, _ uint64) bool {
		if _, ok := c.Get(k); ok {
			resident++
		}
		return true
	})
	if size := c.keysIndex.Size(); size != resident || size == 0 || size > 64 {
		t.Fatalf("keysIndex holds %d keys for %d resident entries", size, resident)
	}
	if got := removed.Load() + int64(resident); got != inserted {
		t.Fatalf("removed %d + resident %d != inserted %d", removed.Load(), resident, inserted)
	}

	c.RemoveByPrefix("k")
	c.Wait()
	if c.keysIndex.Size() != 0 {
		t.Fatalf("RemoveByPrefix left %d keys", c.keysIndex.Size())
	}

	// A second Set racing the first one's admission must leave the key
	// indexed under whichever entry survived.
	big := newLRUBytes[string, string](1<<20, costString)
	defer big.Close()
	big.Set("dup", "a")
	big.Set("dup", "b")
	big.Wait()
	if _, ok := big.Get("dup"); ok {
		if _, indexed := big.keysIndex.Load("dup"); !indexed {
			t.Fatal("resident key dropped from keysIndex")
		}
	}
	big.RemoveByPrefix("dup")
	big.Wait()
	if _, ok := big.Get("dup"); ok {
		t.Fatal("RemoveByPrefix missed a resident key")
	}
}

// TestLookupAnyAtomicRecord: O(1) per-node lookup returns the node's most
// recently used record and falls back as records leave the cache.
func TestLookupAnyAtomicRecord(t *testing.T) {
	s := freshStore(t)
	const cfg = "cfg-lookup"
	get := func(g, target string) (string, *AtomicStatsRecord) {
		key := FormatDBKey(KeyTypeStats, cfg, g, target, "n/1")
		return key, s.GetOrCreateAtomicRecord(key, g, cfg, target, "n/1")
	}
	k1, r1 := get("HK", "a.example")
	k2, r2 := get("HK", "b.example")
	_, r3 := get("HK-Auto", "a.example")
	recordCache.Wait()

	if got := s.LookupAnyAtomicRecord("HK", cfg, "n/1"); got != r2 {
		t.Fatal("want the most recently created record")
	}
	if _, again := get("HK", "a.example"); again != r1 {
		t.Fatal("cache hit returned a different record")
	}
	if got := s.LookupAnyAtomicRecord("HK", cfg, "n/1"); got != r1 {
		t.Fatal("want the most recently used record")
	}
	if got := s.LookupAnyAtomicRecord("HK-Auto", cfg, "n/1"); got != r3 {
		t.Fatal("HK-Auto lookup crossed groups")
	}
	var targets []string
	s.IterateAtomicRecords("HK", cfg, func(target, node string, rec *AtomicStatsRecord) bool {
		targets = append(targets, target+"|"+node)
		return true
	})
	if fmt.Sprint(sortedStrings(targets)) != "[a.example|n/1 b.example|n/1]" {
		t.Fatalf("IterateAtomicRecords(HK) = %v", targets)
	}

	recordCache.Delete(k1)
	if got := s.LookupAnyAtomicRecord("HK", cfg, "n/1"); got != r2 {
		t.Fatal("lookup should fall back to the remaining record")
	}
	recordCache.Delete(k2)
	if got := s.LookupAnyAtomicRecord("HK", cfg, "n/1"); got != nil {
		t.Fatal("lookup should be empty once every record left the cache")
	}
}

// TestLegacyDigestRows: rows carrying the retired rtt_digest blob still
// load everywhere, and new snapshots no longer write it.
func TestLegacyDigestRows(t *testing.T) {
	s := freshStore(t)
	const g, cfg = "g-legacy", "cfg-legacy"
	legacy := []byte(`{"success":5,"failure":1,"last_used":123,"weights":{"tcp":1.5},"rtt_digest":"AAECAwQFBgcICQ=="}`)
	key := FormatDBKey(KeyTypeStats, cfg, g, "a.example", "n1")
	putRaw(t, key, legacy)

	rec := s.GetOrCreateAtomicRecord(key, g, cfg, "a.example", "n1")
	if rec.GetInt64("success") != 5 || rec.GetWeight(WeightTypeTCP) != 1.5 {
		t.Fatalf("legacy row not hydrated: success=%d", rec.GetInt64("success"))
	}
	if nodes, _, err := s.GetBestProxyForTarget(g, cfg, "a.example", "", false); err != nil || fmt.Sprint(nodes) != "[n1]" {
		t.Fatalf("legacy row not indexed: %v %v", nodes, err)
	}
	for i := 0; i < 100; i++ {
		rec.UpdateLatencySample(int64(20 + i))
	}
	snap := rec.CreateStatsSnapshot()
	data, err := MarshalStatsRecord(snap)
	ReleaseStatsRecord(snap)
	if err != nil || bytes.Contains(data, []byte("rtt_digest")) {
		t.Fatalf("snapshot still carries a digest: %s (%v)", data, err)
	}
}

// TestStatsIndexOverflowAndEviction: an index that missed too many writes
// rebuilds, and an index dropped for budget rebuilds on demand.
func TestStatsIndexOverflowAndEviction(t *testing.T) {
	s := freshStore(t)
	const cfg = "cfg-evict"
	now := time.Now().Unix()
	r := rand.New(rand.NewSource(3))
	stageEquivalenceData(t, s, "A", cfg, r, now)
	stageEquivalenceData(t, s, "B", cfg, r, now)
	assertIndexMatchesOracle(t, s, "A", cfg, now)

	queueEquivalenceWrites(s, "A", cfg, r, now, statsIndexMaxPending+100)
	assertIndexMatchesOracle(t, s, "A", cfg, now)

	globalCacheParams.mu.Lock()
	prev := globalCacheParams.IndexBudget
	globalCacheParams.IndexBudget = 1
	globalCacheParams.mu.Unlock()
	t.Cleanup(func() {
		globalCacheParams.mu.Lock()
		globalCacheParams.IndexBudget = prev
		globalCacheParams.mu.Unlock()
	})
	assertIndexMatchesOracle(t, s, "B", cfg, now)
	if sl, _ := statsSlots.Load(FormatDBKey(KeyTypeStats, cfg, "A")); sl.resident.Load() {
		t.Fatal("over budget: the idle index should have been dropped")
	}
	assertIndexMatchesOracle(t, s, "A", cfg, now)
}

// TestStoreConcurrentAccess exercises writers, readers, flushes and
// prefetch together (meaningful under -race).
func TestStoreConcurrentAccess(t *testing.T) {
	s := freshStore(t)
	const g, cfg = "g-concurrent", "cfg-concurrent"
	// The writers can push the group past GetAllStats' reservoir-sampling
	// cap; lift it so the oracle sees every row (the index always does).
	setMaxTargets(t, 1<<20)
	now := time.Now().Unix()
	stageEquivalenceData(t, s, g, cfg, rand.New(rand.NewSource(5)), now)
	proxies := map[string]string{}
	for _, n := range equivalenceNodes() {
		proxies[n] = n
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	run := func(fn func(r *rand.Rand)) {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed))
			for {
				select {
				case <-stop:
					return
				default:
					fn(r)
				}
			}
		}(rand.Int63())
	}
	run(func(r *rand.Rand) { queueEquivalenceWrites(s, g, cfg, r, now, 20) })
	run(func(r *rand.Rand) {
		_, _, _ = s.GetBestProxyForTarget(g, cfg, fmt.Sprintf("*.t%d.example.com", r.Intn(140)), equivalenceASNs[r.Intn(len(equivalenceASNs))], r.Intn(2) == 0)
	})
	run(func(r *rand.Rand) { _ = s.RunPrefetch(g, cfg, proxies) })
	run(func(r *rand.Rand) { s.FlushQueue(r.Intn(2) == 0) })
	run(func(r *rand.Rand) {
		key := FormatDBKey(KeyTypeStats, cfg, g, "a.example", fmt.Sprintf("n-%02d", r.Intn(36)))
		rec := s.GetOrCreateAtomicRecord(key, g, cfg, "a.example", fmt.Sprintf("n-%02d", r.Intn(36)))
		rec.UpdateLatencySample(int64(r.Intn(200) + 1))
		_ = s.LookupAnyAtomicRecord(g, cfg, fmt.Sprintf("n-%02d", r.Intn(36)))
	})
	run(func(r *rand.Rand) { _, _ = s.GetNodeStates(g, cfg) })
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	if err := s.StoreFlushNow(); err != nil {
		t.Fatal(err)
	}
	assertIndexMatchesOracle(t, s, g, cfg, now)
}
