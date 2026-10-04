package smart

import (
	"bytes"
	"container/heap"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/vmihailenco/msgpack/v5"
)

// The oracle* functions are the pre-index implementations, kept verbatim
// apart from taking the GetAllStats map and `now` as parameters. They
// pin the decoded stats index to the exact results of the algorithm it
// replaced.

func oracleBestProxy(allStatsMap map[string]map[string][]byte, target, asnNumber string, isUDP bool, now int64) ([]string, []float64) {
	getDecay := func(lastUsed int64) float64 {
		return GetTimeDecay(lastUsed, now, 0.4)
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
				if UnmarshalStatsRecord(data, &record) != nil || record.Weights == nil {
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
		for nodeName, data := range allStatsMap[target] {
			var record StatsRecord
			if UnmarshalStatsRecord(data, &record) != nil || record.Weights == nil {
				continue
			}
			if weight := record.Weights[weightType]; weight > 0 {
				nodesWithWeight[nodeName] = weight * getDecay(record.LastUsed)
			}
		}
	}
	if len(nodesWithWeight) == 0 {
		return nil, nil
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
	return bestNodes, bestWeights
}

type oracleTargetHeap []ActiveTarget

func (h oracleTargetHeap) Len() int            { return len(h) }
func (h oracleTargetHeap) Less(i, j int) bool  { return h[i].LastUsed < h[j].LastUsed }
func (h oracleTargetHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *oracleTargetHeap) Push(x interface{}) { *h = append(*h, x.(ActiveTarget)) }
func (h *oracleTargetHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func oracleActiveTargets(allStats map[string]map[string][]byte, limit int) []ActiveTarget {
	h := &oracleTargetHeap{}
	heap.Init(h)
	seen := make(map[string]int64)
	for target, nodeStats := range allStats {
		activeCombinations := make(map[string]int64)
		hasASN := false
		for _, data := range nodeStats {
			var record StatsRecord
			if UnmarshalStatsRecord(data, &record) != nil || record.Weights == nil {
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
				if strings.HasPrefix(key, WeightTypeTCPASN) && weight > 0 {
					parts := strings.Split(key, ":")
					if len(parts) >= 2 {
						ck := parts[1] + ":false"
						if last, exists := activeCombinations[ck]; !exists || record.LastUsed > last {
							activeCombinations[ck] = record.LastUsed
							hasASN = true
						}
					}
				} else if strings.HasPrefix(key, WeightTypeUDPASN) && weight > 0 {
					parts := strings.Split(key, ":")
					if len(parts) >= 2 {
						ck := parts[1] + ":true"
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
				heap.Push(h, ActiveTarget{Target: target, ASN: asn, IsUDP: isUDP, LastUsed: lastUsed})
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

// oracleNodeCoverage is the per-node aggregation GetLiveNodeRanking,
// GetNodeWeightRanking and EnrichRankingCounts performed over GetAllStats.
type oracleCoverage struct {
	targets, samples int
	weightSum        float64
	lastUsed         int64
}

func oracleNodeCoverage(allStats map[string]map[string][]byte) map[string]*oracleCoverage {
	out := make(map[string]*oracleCoverage)
	for _, nodeStats := range allStats {
		for nodeName, data := range nodeStats {
			var record StatsRecord
			if UnmarshalStatsRecord(data, &record) != nil {
				continue
			}
			samples := int(record.Success + record.Failure)
			if samples <= 0 {
				continue
			}
			a := out[nodeName]
			if a == nil {
				a = &oracleCoverage{}
				out[nodeName] = a
			}
			a.targets++
			a.samples += samples
			if record.Weights != nil {
				a.weightSum += record.Weights[WeightTypeTCP] + record.Weights[WeightTypeUDP]
			}
			if record.LastUsed > a.lastUsed {
				a.lastUsed = record.LastUsed
			}
		}
	}
	return out
}

// equivalenceASNs mixes non-CDN and CDN ASNs.
var equivalenceASNs = []string{"4134", "4837", "9808", "13335", "45102"}

// equivalenceNodes includes tags that need key escaping.
func equivalenceNodes() []string {
	nodes := []string{"ENET/🇳🇿 Base 新西兰", "50% off", "node-1", "node-10"}
	for i := 0; i < 36; i++ {
		nodes = append(nodes, fmt.Sprintf("n-%02d", i))
	}
	return nodes
}

// randomStatsValue produces a stored stats value covering the shapes found
// in real databases: JSON and msgpack rows, legacy digest blobs, nil and
// odd weight maps, non-positive weights and undecodable bytes.
func randomStatsValue(r *rand.Rand, now int64) []byte {
	if r.Intn(40) == 0 {
		return []byte("{not json")
	}
	rec := StatsRecord{
		Success:  int64(r.Intn(30)),
		Failure:  int64(r.Intn(4)),
		LastUsed: now - int64(r.Intn(30*24*3600)),
	}
	if r.Intn(25) == 0 {
		rec.LastUsed = 0
	}
	if r.Intn(15) != 0 {
		rec.Weights = map[string]float64{WeightTypeTCP: r.Float64()*3.5 - 0.5}
		if r.Intn(3) == 0 {
			rec.Weights[WeightTypeUDP] = r.Float64()*2 - 0.2
		}
		for i := r.Intn(3); i > 0; i-- {
			asn := equivalenceASNs[r.Intn(len(equivalenceASNs))]
			prefix := WeightTypeTCPASN
			if r.Intn(3) == 0 {
				prefix = WeightTypeUDPASN
			}
			rec.Weights[prefix+":"+asn] = r.Float64()*2.5 - 0.2
		}
		switch r.Intn(30) {
		case 0:
			rec.Weights[WeightTypeTCPASN] = 1
		case 1:
			rec.Weights[WeightTypeTCPASN+":"] = 1.1
		}
	}
	if r.Intn(10) == 0 {
		var buf bytes.Buffer
		enc := msgpack.NewEncoder(&buf)
		enc.SetCustomStructTag("json")
		if err := enc.Encode(&rec); err != nil {
			panic(err)
		}
		return buf.Bytes()
	}
	data, err := MarshalStatsRecord(&rec)
	if err != nil {
		panic(err)
	}
	if r.Intn(4) == 0 {
		data = append(data[:len(data)-1:len(data)-1], `,"rtt_digest":"AAAAAQIDBAUGBwgJ"}`...)
	}
	return data
}

// stageEquivalenceData writes rows for group g (and a decoy group sharing
// its prefix) to bbolt, then queues overlay writes that update existing
// rows and add new ones.
func stageEquivalenceData(t *testing.T, s *Store, group, config string, r *rand.Rand, now int64) {
	t.Helper()
	nodes := equivalenceNodes()
	err := globalDB.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketSmartStats)
		if err != nil {
			return err
		}
		for _, g := range []string{group, group + "-Auto"} {
			for ti := 0; ti < 120; ti++ {
				for k := 0; k < 6; k++ {
					key := FormatDBKey(KeyTypeStats, config, g, fmt.Sprintf("*.t%d.example.com", ti), nodes[r.Intn(len(nodes))])
					if err := bucket.Put([]byte(key), randomStatsValue(r, now)); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	queueEquivalenceWrites(s, group, config, r, now, 80)
}

func queueEquivalenceWrites(s *Store, group, config string, r *rand.Rand, now int64, n int) {
	nodes := equivalenceNodes()
	ops := make([]StoreOperation, 0, n)
	for i := 0; i < n; i++ {
		ops = append(ops, StoreOperation{
			Type: OpSaveStats, Group: group, Config: config,
			Target: fmt.Sprintf("*.t%d.example.com", r.Intn(140)),
			Node:   nodes[r.Intn(len(nodes))],
			Data:   randomStatsValue(r, now),
		})
	}
	s.AppendToGlobalQueue(ops...)
}

// assertIndexMatchesOracle compares every index-backed computation with
// the oracle over the current GetAllStats view.
func assertIndexMatchesOracle(t *testing.T, s *Store, group, config string, now int64) {
	t.Helper()
	allStats, err := s.GetAllStats(group, config)
	if err != nil {
		t.Fatal(err)
	}
	if len(allStats) == 0 {
		t.Fatal("empty dataset")
	}
	var queries []ActiveTarget
	for target := range allStats {
		queries = append(queries, ActiveTarget{Target: target}, ActiveTarget{Target: target, IsUDP: true})
	}
	queries = append(queries, ActiveTarget{Target: "*.missing.example.com"})
	for _, asn := range append(equivalenceASNs, "", "64512") {
		queries = append(queries, ActiveTarget{Target: "*.t1.example.com", ASN: asn}, ActiveTarget{Target: "*.t1.example.com", ASN: asn, IsUDP: true})
	}

	err = withStatsIndex(group, config, func(ix *statsIndex) {
		answered, asnAnswered := 0, 0
		for _, q := range queries {
			wantNodes, wantWeights := oracleBestProxy(allStats, q.Target, q.ASN, q.IsUDP, now)
			gotNodes, gotWeights := ix.bestFor(q.Target, q.ASN, q.IsUDP, now)
			if fmt.Sprint(gotNodes) != fmt.Sprint(wantNodes) || fmt.Sprint(gotWeights) != fmt.Sprint(wantWeights) {
				t.Fatalf("bestFor(%+v):\n got  %v %v\n want %v %v", q, gotNodes, gotWeights, wantNodes, wantWeights)
			}
			if len(gotNodes) > 0 {
				answered++
				if q.ASN != "" && !CdnASNs[q.ASN] {
					asnAnswered++
				}
			}
		}
		if answered < len(queries)/2 || asnAnswered < 6 {
			t.Fatalf("degenerate dataset: %d/%d queries answered, %d by ASN", answered, len(queries), asnAnswered)
		}

		const unlimited = 1 << 30
		want := oracleActiveTargets(allStats, unlimited)
		got := ix.activeTargets(unlimited)
		sortActive(want)
		sortActive(got)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("activeTargets mismatch:\n got  %v\n want %v", got, want)
		}
		// With a cap, the selected recency profile must match exactly
		// (only the choice among equal timestamps may differ).
		for _, limit := range []int{1, 7, 50} {
			wantCut := oracleActiveTargets(allStats, limit)
			gotCut := ix.activeTargets(limit)
			if len(gotCut) != len(wantCut) {
				t.Fatalf("limit %d: got %d targets, want %d", limit, len(gotCut), len(wantCut))
			}
			for i := range gotCut {
				if gotCut[i].LastUsed != wantCut[i].LastUsed {
					t.Fatalf("limit %d: LastUsed[%d] = %d, want %d", limit, i, gotCut[i].LastUsed, wantCut[i].LastUsed)
				}
			}
		}

		wantCov := oracleNodeCoverage(allStats)
		gotCov := make(map[string]*oracleCoverage)
		ix.forEachRow(func(_, node string, r *statsRow) {
			if r.samples <= 0 {
				return
			}
			a := gotCov[node]
			if a == nil {
				a = &oracleCoverage{}
				gotCov[node] = a
			}
			a.targets++
			a.samples += int(r.samples)
			a.weightSum += r.tcp + r.udp
			if r.lastUsed > a.lastUsed {
				a.lastUsed = r.lastUsed
			}
		})
		if len(gotCov) != len(wantCov) {
			t.Fatalf("coverage: %d nodes, want %d", len(gotCov), len(wantCov))
		}
		for node, w := range wantCov {
			g := gotCov[node]
			if g == nil || g.targets != w.targets || g.samples != w.samples || g.lastUsed != w.lastUsed ||
				math.Abs(g.weightSum-w.weightSum) > 1e-9 {
				t.Fatalf("coverage[%s] = %+v, want %+v", node, g, w)
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}

func sortActive(a []ActiveTarget) {
	sort.Slice(a, func(i, j int) bool {
		if a[i].Target != a[j].Target {
			return a[i].Target < a[j].Target
		}
		if a[i].ASN != a[j].ASN {
			return a[i].ASN < a[j].ASN
		}
		return !a[i].IsUDP && a[j].IsUDP
	})
}

// TestStatsIndexMatchesLegacyAlgorithm pins the index-backed selection,
// active-target and coverage computations to the pre-index algorithm,
// both on a fresh build and after incremental updates.
func TestStatsIndexMatchesLegacyAlgorithm(t *testing.T) {
	s := freshStore(t)
	const group, config = "HK", "cfg-equivalence"
	now := time.Now().Unix()
	r := rand.New(rand.NewSource(7))
	stageEquivalenceData(t, s, group, config, r, now)
	assertIndexMatchesOracle(t, s, group, config, now)

	// Incremental path: queued writes after the index was built, a flush,
	// and more writes on top.
	queueEquivalenceWrites(s, group, config, r, now, 150)
	assertIndexMatchesOracle(t, s, group, config, now)
	s.FlushQueue(true)
	assertIndexMatchesOracle(t, s, group, config, now)
	queueEquivalenceWrites(s, group, config, r, now, 40)
	assertIndexMatchesOracle(t, s, group, config, now)

	// Direct bbolt mutations invalidate the index.
	if err := s.RemoveNodesData(group, config, []string{"n-01", "ENET/🇳🇿 Base 新西兰"}); err != nil {
		t.Fatal(err)
	}
	assertIndexMatchesOracle(t, s, group, config, now)
}

// TestGetBestProxyForTargetPublicAPI checks the exported entry point
// against the oracle (weights within decay drift of a second).
func TestGetBestProxyForTargetPublicAPI(t *testing.T) {
	s := freshStore(t)
	const group, config = "g-public", "cfg-public"
	now := time.Now().Unix()
	r := rand.New(rand.NewSource(11))
	stageEquivalenceData(t, s, group, config, r, now)
	allStats, _ := s.GetAllStats(group, config)
	for _, q := range []ActiveTarget{{Target: "*.t3.example.com"}, {Target: "*.t3.example.com", ASN: "4134"}, {Target: "*.t9.example.com", IsUDP: true}} {
		wantNodes, wantWeights := oracleBestProxy(allStats, q.Target, q.ASN, q.IsUDP, time.Now().Unix())
		gotNodes, gotWeights, err := s.GetBestProxyForTarget(group, config, q.Target, q.ASN, q.IsUDP)
		if len(wantNodes) == 0 {
			if err == nil {
				t.Fatalf("%+v: expected error, got %v", q, gotNodes)
			}
			continue
		}
		if err != nil || len(gotNodes) != len(wantNodes) {
			t.Fatalf("%+v: got %v (%v), want %v", q, gotNodes, err, wantNodes)
		}
		for i := range gotNodes {
			if math.Abs(gotWeights[i]-wantWeights[i]) > 1e-5*wantWeights[i] {
				t.Fatalf("%+v: weight[%d] = %v, want %v", q, i, gotWeights[i], wantWeights[i])
			}
		}
	}
	if _, _, err := s.GetBestProxyForTarget(group, config, "", "", false); err == nil {
		t.Fatal("empty target must error")
	}
}
