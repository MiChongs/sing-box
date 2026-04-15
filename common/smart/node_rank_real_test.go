package smart

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/bbolt"
)

// helper: stage one stats record with a custom (success, failure)
// pair into bbolt so we can drive the ranking functions without
// running a real dial. Returns the (group, config) it wrote under.
func stageStats(t *testing.T, store *Store, group, config, target, node string, success, failure int64, weight float64) {
	t.Helper()
	rec := StatsRecord{
		Success: success,
		Failure: failure,
		Weights: map[string]float64{WeightTypeTCP: weight},
	}
	data, err := MarshalStatsRecord(&rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	store.AppendToGlobalQueue(StoreOperation{
		Type:   OpSaveStats,
		Group:  group,
		Config: config,
		Target: target,
		Node:   node,
		Data:   data,
	})
}

// freshStore spins up an isolated bbolt + Store under t.TempDir so each
// test owns its DB and doesn't see pollution from earlier runs through
// the package-global singletons. Cleans up automatically.
func freshStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	db, err := bbolt.Open(filepath.Join(dir, "test.db"), 0600, nil)
	if err != nil {
		t.Fatalf("open bbolt: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.RemoveAll(dir)
	})
	// GetOrInitStore is a sync.Once singleton — first caller wins. On
	// the SECOND test that calls freshStore, the singleton still holds
	// the previous test's (now-closed) db handle and would silently
	// return empty results from every read. Force the swap by writing
	// globalDB directly; package-internal access lets us bypass the
	// sync.Once for tests without touching production semantics.
	s := GetOrInitStore(db)
	globalDB = db
	s.FlushQueue(true)
	if dbResultCache != nil {
		dbResultCache.Clear()
	}
	if recordCache != nil {
		recordCache.Clear()
	}
	if blockedNodesCache != nil {
		blockedNodesCache.Clear()
	}
	if unwrapCache != nil {
		unwrapCache.Clear()
	}
	if targetCache != nil {
		targetCache.Clear()
	}
	return s
}

// TestGetLiveNodeRanking_RealCoverageOnly verifies that TargetCount
// reflects only (node, target) pairs with REAL dial samples, and that
// SampleCount aggregates success+failure across them. A target where
// every dial failed (weight=0 but samples>0) MUST still count toward
// TargetCount — this is real coverage.
func TestGetLiveNodeRanking_RealCoverageOnly(t *testing.T) {
	store := freshStore(t)
	const grp, cfg = "g_real_cov", "c_real_cov"

	// Node A: 2 targets, both with samples + non-zero weight.
	stageStats(t, store, grp, cfg, "a.example", "A", 50, 1, 1.5)
	stageStats(t, store, grp, cfg, "b.example", "A", 30, 0, 1.2)
	// Node B: 1 target with samples but weight=0 (all failures).
	//          Should still count toward TargetCount (real coverage).
	stageStats(t, store, grp, cfg, "c.example", "B", 0, 20, 0)
	// Node B: 1 weight-only "ghost" target (zero samples). Must NOT
	//          inflate TargetCount — it's not real coverage.
	stageStats(t, store, grp, cfg, "d.example", "B", 0, 0, 0.9)

	// Force the queue to flush so GetAllStats sees the rows.
	store.FlushQueue(true)
	// Pump the bbolt cache so subsequent reads see the writes.
	store.StoreFlushNow()

	alive := func(_ string) bool { return true }
	ranking := store.GetLiveNodeRanking(grp, cfg, alive, []string{"A", "B"})

	got := make(map[string]NodeRank, len(ranking))
	for _, r := range ranking {
		got[r.Name] = r
	}

	if got["A"].TargetCount != 2 {
		t.Errorf("A TargetCount = %d, want 2 (two real targets)", got["A"].TargetCount)
	}
	if got["A"].SampleCount != 81 {
		t.Errorf("A SampleCount = %d, want 81 (50+1+30+0)", got["A"].SampleCount)
	}
	// Node B: only the all-failures target counts (samples > 0). The
	// weight-only ghost target must NOT contribute.
	if got["B"].TargetCount != 1 {
		t.Errorf("B TargetCount = %d, want 1 (only the sampled target)", got["B"].TargetCount)
	}
	if got["B"].SampleCount != 20 {
		t.Errorf("B SampleCount = %d, want 20 (failures only)", got["B"].SampleCount)
	}
}

// TestGetLiveNodeRanking_NoStatsZeroCoverage confirms a node referenced
// in allTags but with no stats rows ends up with TargetCount=0 and
// SampleCount=0 — the honest "no data yet" answer.
func TestGetLiveNodeRanking_NoStatsZeroCoverage(t *testing.T) {
	store := freshStore(t)
	const grp, cfg = "g_nostats", "c_nostats"
	// Only stage stats for A; B has no rows.
	stageStats(t, store, grp, cfg, "a.example", "A", 5, 0, 1.0)
	store.FlushQueue(true)
	store.StoreFlushNow()

	alive := func(_ string) bool { return true }
	ranking := store.GetLiveNodeRanking(grp, cfg, alive, []string{"A", "B"})
	for _, r := range ranking {
		if r.Name == "B" {
			if r.TargetCount != 0 || r.SampleCount != 0 {
				t.Fatalf("B with no stats: TC=%d SC=%d, want 0/0",
					r.TargetCount, r.SampleCount)
			}
		}
	}
}
