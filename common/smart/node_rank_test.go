package smart

import (
	stdjson "encoding/json"
	"testing"
)

// TestNodeRank_JSONFieldNames pins the camelCase wire contract so a
// future field reorder can't silently break dashboard consumers. The
// keys are the public ClashAPI surface — changing them is a breaking
// change.
func TestNodeRank_JSONFieldNames(t *testing.T) {
	in := NodeRank{
		Name:        "n1",
		Rank:        "MostUsed",
		Weight:      1.5,
		Score:       80,
		TargetCount: 3,
		SampleCount: 50,
		LastUpdated: 1700000000,
	}
	blob, err := stdjson.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(blob)
	for _, key := range []string{
		`"name":"n1"`,
		`"rank":"MostUsed"`,
		`"weight":1.5`,
		`"score":80`,
		`"targetCount":3`,
		`"sampleCount":50`,
		`"lastUpdated":1700000000`,
	} {
		if !contains([]string{got}, got) || !containsSubstring(got, key) {
			t.Errorf("missing key in JSON: %s\nfull: %s", key, got)
		}
	}
}

// TestNodeRank_LegacyDecoding confirms a NodeRank serialised by an
// older build (no targetCount field at all, PascalCase keys) still
// deserialises into the new struct without losing any populated
// fields. This is the wire-compat guarantee for in-flight bbolt rows.
func TestNodeRank_LegacyDecoding(t *testing.T) {
	legacy := []byte(`{"Name":"n1","Rank":"MostUsed","Weight":1.5,"Score":80,"LastUpdated":1700000000}`)
	var got NodeRank
	if err := stdjson.Unmarshal(legacy, &got); err != nil {
		t.Fatalf("legacy unmarshal: %v", err)
	}
	if got.Name != "n1" || got.Weight != 1.5 || got.Score != 80 {
		t.Fatalf("legacy fields lost: %+v", got)
	}
	if got.TargetCount != 0 || got.SampleCount != 0 {
		t.Fatalf("new fields should default to zero on legacy data, got TC=%d SC=%d",
			got.TargetCount, got.SampleCount)
	}
}

// TestIsLegacyZeroCountRanking covers the strict invariant guard:
// any (Weight > 0, TargetCount == 0) entry trips it — the older
// "all-zero" check let mixed payloads slip through and republish
// stale TargetCount==0 rows on every /smart/weights call.
func TestIsLegacyZeroCountRanking(t *testing.T) {
	cases := []struct {
		name string
		in   []NodeRank
		want bool
	}{
		{
			name: "fresh_with_counts",
			in: []NodeRank{
				{Name: "n1", Weight: 1.5, TargetCount: 3},
				{Name: "n2", Weight: 0.8, TargetCount: 1},
			},
			want: false,
		},
		{
			name: "all_zero_weight",
			in: []NodeRank{
				{Name: "n1", Weight: 0, TargetCount: 0},
				{Name: "n2", Weight: 0, TargetCount: 0},
			},
			want: false, // no weight signal — nothing to repair, keep
		},
		{
			name: "all_weight_no_counts",
			in: []NodeRank{
				{Name: "n1", Weight: 1.5, TargetCount: 0},
				{Name: "n2", Weight: 0.8, TargetCount: 0},
			},
			want: true,
		},
		{
			name: "mixed_must_now_trip",
			in: []NodeRank{
				{Name: "n1", Weight: 1.5, TargetCount: 0}, // BAD entry
				{Name: "n2", Weight: 0.8, TargetCount: 5},
			},
			want: true, // strict invariant: ANY broken entry is enough
		},
		{
			name: "weight_zero_tc_zero_ok",
			in: []NodeRank{
				{Name: "dead", Weight: 0, TargetCount: 0},
				{Name: "n1", Weight: 1.0, TargetCount: 2},
			},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isLegacyZeroCountRanking(c.in); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestEnrichRankingCounts_RepairsMixed: feed a ranking with a
// (Weight>0, TargetCount=0) entry plus real stats data; the
// repair pass must populate TargetCount/SampleCount from the bbolt
// stats while leaving the already-correct entries untouched.
func TestEnrichRankingCounts_RepairsMixed(t *testing.T) {
	store := freshStore(t)
	const grp, cfg = "g_enrich", "c_enrich"
	stageStats(t, store, grp, cfg, "a.example", "broken-tc", 30, 0, 1.2)
	stageStats(t, store, grp, cfg, "b.example", "broken-tc", 20, 5, 1.0)
	store.FlushQueue(true)
	store.StoreFlushNow()

	in := []NodeRank{
		{Name: "broken-tc", Weight: 1.1, TargetCount: 0, SampleCount: 0},
		{Name: "already-good", Weight: 0.9, TargetCount: 7, SampleCount: 99},
		{Name: "dead", Weight: 0, TargetCount: 0, SampleCount: 0},
	}
	repaired := store.EnrichRankingCounts(grp, cfg, in)
	if !repaired {
		t.Fatalf("expected enrich to report repaired=true; in=%+v", in)
	}
	if in[0].TargetCount != 2 || in[0].SampleCount != 55 {
		t.Errorf("broken entry not repaired: %+v", in[0])
	}
	// Pre-populated entries must be untouched.
	if in[1].TargetCount != 7 || in[1].SampleCount != 99 {
		t.Errorf("good entry mutated: %+v", in[1])
	}
	// Dead entries left as-is — they have nothing to repair.
	if in[2].TargetCount != 0 {
		t.Errorf("dead entry mutated: %+v", in[2])
	}
}

// TestEnrichRankingCounts_NoStatsNoOp: when the stats table has
// nothing for the broken entries (or no stats at all), the function
// must be a no-op so callers don't fabricate counts.
func TestEnrichRankingCounts_NoStatsNoOp(t *testing.T) {
	store := freshStore(t)
	const grp, cfg = "g_enrich_empty", "c_enrich_empty"
	in := []NodeRank{
		{Name: "broken", Weight: 1.0, TargetCount: 0},
	}
	repaired := store.EnrichRankingCounts(grp, cfg, in)
	if repaired {
		t.Fatal("repaired=true with empty stats — should have been no-op")
	}
	if in[0].TargetCount != 0 {
		t.Fatalf("TargetCount fabricated to %d", in[0].TargetCount)
	}
}

// containsSubstring is a tiny helper to keep the JSON-key assertion
// readable. The stdlib `strings.Contains` would do, but importing it
// for one call doubles the import block; the inline byte loop costs
// nothing at test speed.
func containsSubstring(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
