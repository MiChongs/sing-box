package smart

import (
	"encoding/base64"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
)

// perfDataset describes a synthetic stats table shaped like a large
// production subscription: many targets, a handful of nodes dialled per
// target out of a big node pool, TCP + ASN-scoped weights.
type perfDataset struct {
	targets        int
	nodesPerTarget int
	totalNodes     int
	// legacyDigest appends a serialized t-digest blob to every row, the
	// way records written by older builds look on disk.
	legacyDigest bool
}

// perfASNs mixes non-CDN ASNs (prefetch computes them) with one CDN ASN
// (ignored by selection) so both branches are exercised.
var perfASNs = []string{"4134", "4837", "9808", "45102", "13335"}

func perfNode(i int) string { return "node-" + strconv.Itoa(i) }

func perfTarget(i int) string { return "*.host" + strconv.Itoa(i) + ".example.com" }

// stagePerfStats writes the dataset straight into bbolt (bypassing the
// queue) and returns the proxy map RunPrefetch expects.
func stagePerfStats(tb testing.TB, group, config string, ds perfDataset) map[string]string {
	tb.Helper()
	now := time.Now().Unix()
	r := rand.New(rand.NewSource(1))
	digest := ""
	if ds.legacyDigest {
		blob := make([]byte, 1600)
		r.Read(blob)
		digest = `,"rtt_digest":"` + base64.StdEncoding.EncodeToString(blob) + `"`
	}
	err := globalDB.Load().Update(func(tx *bbolt.Tx) error {
		bk, err := tx.CreateBucketIfNotExists(bucketSmartStats)
		if err != nil {
			return err
		}
		for t := 0; t < ds.targets; t++ {
			asn := perfASNs[t%len(perfASNs)]
			for k := 0; k < ds.nodesPerTarget; k++ {
				rec := StatsRecord{
					Success:  int64(1 + r.Intn(50)),
					Failure:  int64(r.Intn(5)),
					LastUsed: now - int64(r.Intn(7*24*3600)),
					Weights: map[string]float64{
						WeightTypeTCP:                r.Float64() * 3,
						WeightTypeTCPASN + ":" + asn: r.Float64() * 3,
						WeightTypeUDPASN + ":" + perfASNs[(t+1)%len(perfASNs)]: r.Float64(),
					},
				}
				if t%3 == 0 {
					rec.Weights[WeightTypeUDP] = r.Float64() * 2
				}
				data, err := MarshalStatsRecord(&rec)
				if err != nil {
					return err
				}
				if digest != "" {
					data = append(data[:len(data)-1:len(data)-1], digest+"}"...)
				}
				key := FormatDBKey(KeyTypeStats, config, group, perfTarget(t), perfNode(r.Intn(ds.totalNodes)))
				if err := bk.Put([]byte(key), data); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		tb.Fatal(err)
	}
	proxies := make(map[string]string, ds.totalNodes)
	for i := 0; i < ds.totalNodes; i++ {
		proxies[perfNode(i)] = perfNode(i)
	}
	return proxies
}

var perfDatasets = []struct {
	name string
	ds   perfDataset
}{
	{"legacyDigestRows", perfDataset{targets: 800, nodesPerTarget: 6, totalNodes: 300, legacyDigest: true}},
	{"compactRows", perfDataset{targets: 800, nodesPerTarget: 6, totalNodes: 300}},
}

// BenchmarkRunPrefetch measures one prefetch pass for a single group —
// the work every Smart group repeats on its prefetch timer.
func BenchmarkRunPrefetch(b *testing.B) {
	for _, c := range perfDatasets {
		b.Run(c.name, func(b *testing.B) {
			s := freshStore(b)
			proxies := stagePerfStats(b, "g", "cfg", c.ds)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = s.RunPrefetch("g", "cfg", proxies)
				b.StopTimer()
				s.FlushQueue(true)
				b.StartTimer()
			}
		})
	}
}

// BenchmarkGetBestProxyForTarget measures the dial-path tier-3 lookup
// (selection straight from stats when unwrap/prefetch caches miss).
func BenchmarkGetBestProxyForTarget(b *testing.B) {
	for _, c := range perfDatasets {
		b.Run(c.name, func(b *testing.B) {
			s := freshStore(b)
			stagePerfStats(b, "g", "cfg", c.ds)
			for _, mode := range []struct {
				name string
				asn  string
			}{{"target", ""}, {"asn", "4134"}} {
				b.Run(mode.name, func(b *testing.B) {
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						_, _, _ = s.GetBestProxyForTarget("g", "cfg", perfTarget(i%c.ds.targets), mode.asn, false)
					}
				})
			}
		})
	}
}

// BenchmarkBuildStatsIndex measures one full decode of a group into its
// stats index — the cost a rebuild (TTL backstop, invalidation, budget
// eviction) pays.
func BenchmarkBuildStatsIndex(b *testing.B) {
	for _, c := range perfDatasets {
		b.Run(c.name, func(b *testing.B) {
			freshStore(b)
			stagePerfStats(b, "g", "cfg", c.ds)
			scope := FormatDBKey(KeyTypeStats, "cfg", "g")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := buildStatsIndex(scope); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkLookupAnyAtomicRecord measures the node-level record lookup
// used by the fastest-recent algorithm on every dial, with a record
// cache populated across many groups.
func BenchmarkLookupAnyAtomicRecord(b *testing.B) {
	s := freshStore(b)
	const groups, nodes, targetsPerNode = 16, 100, 3
	for g := 0; g < groups; g++ {
		group := "group-" + strconv.Itoa(g)
		for n := 0; n < nodes; n++ {
			for t := 0; t < targetsPerNode; t++ {
				target := perfTarget(n*targetsPerNode + t)
				key := FormatDBKey(KeyTypeStats, "cfg", group, target, perfNode(n))
				s.GetOrCreateAtomicRecord(key, group, "cfg", target, perfNode(n))
			}
		}
	}
	recordCache.Wait()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.LookupAnyAtomicRecord("group-"+strconv.Itoa(i%groups), "cfg", perfNode(i%nodes))
	}
}

// BenchmarkHostStatusWithQueuedWrites models the per-close read path:
// one queued write followed by an exact-key read while the write queue
// holds a steady-state backlog.
func BenchmarkHostStatusWithQueuedWrites(b *testing.B) {
	s := freshStore(b)
	backlog := make([]StoreOperation, 250)
	for i := range backlog {
		backlog[i] = StoreOperation{
			Type: OpSaveStats, Group: "g", Config: "cfg",
			Target: perfTarget(i), Node: perfNode(i), Data: []byte(`{"success":1}`),
		}
	}
	s.AppendToGlobalQueue(backlog...)
	op := StoreOperation{Type: OpSaveHostFailures, Group: "g", Config: "cfg", Target: perfTarget(1), Data: []byte(`{"failure_count":1}`)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.AppendToGlobalQueue(op)
		_, _ = s.GetHostStatus("g", "cfg", perfTarget(i%64))
	}
}

// BenchmarkAtomicRecordLatencySamples measures the per-record memory a
// busy (target, node) pair accretes plus one snapshot encode — the
// write path every closed connection takes.
func BenchmarkAtomicRecordLatencySamples(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := NewAtomicStatsRecord()
		for j := 0; j < 64; j++ {
			r.UpdateLatencySample(int64(40 + j))
		}
		r.SetWeight(WeightTypeTCP, 1.2, false)
		snap := r.CreateStatsSnapshot()
		if _, err := MarshalStatsRecord(snap); err != nil {
			b.Fatal(err)
		}
		ReleaseStatsRecord(snap)
	}
}

// setMaxTargets temporarily overrides the cleanup / prefetch target cap.
func setMaxTargets(tb testing.TB, n int) {
	globalCacheParams.mu.Lock()
	prev := globalCacheParams.MaxTargets
	globalCacheParams.MaxTargets = n
	globalCacheParams.mu.Unlock()
	tb.Cleanup(func() {
		globalCacheParams.mu.Lock()
		globalCacheParams.MaxTargets = prev
		globalCacheParams.mu.Unlock()
	})
}

// BenchmarkCleanupOldRecords trims a 600-row stats table down to the
// configured cap (100 rows), i.e. ~500 deletions per pass.
func BenchmarkCleanupOldRecords(b *testing.B) {
	s := freshStore(b)
	setMaxTargets(b, 100)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		_, _ = s.FlushByGroup("g", "cfg")
		stagePerfStats(b, "g", "cfg", perfDataset{targets: 100, nodesPerTarget: 6, totalNodes: 300})
		b.StartTimer()
		if err := s.CleanupOldRecords("g", "cfg"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRemoveNodesData drops 30 of 300 nodes from a 4800-row group.
func BenchmarkRemoveNodesData(b *testing.B) {
	s := freshStore(b)
	removed := make([]string, 30)
	for i := range removed {
		removed[i] = perfNode(i * 10)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		_, _ = s.FlushByGroup("g", "cfg")
		stagePerfStats(b, "g", "cfg", perfDataset{targets: 800, nodesPerTarget: 6, totalNodes: 300})
		b.StartTimer()
		if err := s.RemoveNodesData("g", "cfg", removed); err != nil {
			b.Fatal(err)
		}
	}
}
