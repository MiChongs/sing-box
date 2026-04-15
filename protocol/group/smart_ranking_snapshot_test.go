package group

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/smart"
)

// TestPublishRankingSnapshot_BasicRoundtrip pushes a ranking, reads it
// back through the in-process snapshot, and verifies the read returns
// the same values plus a fresh computedAt timestamp. This is the
// fast-path WeightRanking now uses to avoid the bbolt write→flush→read
// window that previously made the API serve fallback data.
func TestPublishRankingSnapshot_BasicRoundtrip(t *testing.T) {
	s := &Smart{}
	in := []smart.NodeRank{
		{Name: "n1", Weight: 1.5, Score: 80, TargetCount: 3, SampleCount: 50},
		{Name: "n2", Weight: 0.8, Score: 40, TargetCount: 1, SampleCount: 5},
	}
	s.publishRankingSnapshot(in)
	got := s.rankingSnapshot.Load()
	if got == nil {
		t.Fatal("snapshot should be non-nil after publish")
	}
	if len(got.ranking) != len(in) {
		t.Fatalf("snapshot length = %d, want %d", len(got.ranking), len(in))
	}
	for i := range in {
		if got.ranking[i].Name != in[i].Name ||
			got.ranking[i].Weight != in[i].Weight ||
			got.ranking[i].TargetCount != in[i].TargetCount {
			t.Fatalf("snapshot[%d] = %+v, want %+v", i, got.ranking[i], in[i])
		}
	}
	if time.Since(got.computedAt) > time.Second {
		t.Fatalf("computedAt too stale: %v", time.Since(got.computedAt))
	}
}

// TestPublishRankingSnapshot_DefensiveCopy mutates the source slice
// after publishing and confirms the snapshot doesn't observe the
// mutation. Without the copy, a concurrent sort.Slice in
// updateNodeRanking could tear the snapshot mid-read.
func TestPublishRankingSnapshot_DefensiveCopy(t *testing.T) {
	s := &Smart{}
	src := []smart.NodeRank{
		{Name: "n1", Weight: 1.0, TargetCount: 1},
	}
	s.publishRankingSnapshot(src)
	// Mutate the source — snapshot must NOT change.
	src[0].Name = "MUTATED"
	src[0].Weight = 99
	src[0].TargetCount = 99

	got := s.rankingSnapshot.Load()
	if got == nil || len(got.ranking) != 1 {
		t.Fatal("snapshot lost after publish")
	}
	if got.ranking[0].Name != "n1" || got.ranking[0].Weight != 1.0 {
		t.Fatalf("snapshot leaked source mutation: %+v", got.ranking[0])
	}
}

// TestPublishRankingSnapshot_EmptyNoOp verifies an empty publish
// doesn't overwrite an existing snapshot — the API path explicitly
// relies on this so transient empty results from updateNodeRanking
// don't blow away the last good ranking.
func TestPublishRankingSnapshot_EmptyNoOp(t *testing.T) {
	s := &Smart{}
	good := []smart.NodeRank{{Name: "n1", Weight: 1.0, TargetCount: 1}}
	s.publishRankingSnapshot(good)

	// Empty publish must be ignored.
	s.publishRankingSnapshot(nil)
	s.publishRankingSnapshot([]smart.NodeRank{})

	got := s.rankingSnapshot.Load()
	if got == nil || len(got.ranking) != 1 || got.ranking[0].Name != "n1" {
		t.Fatalf("good snapshot was clobbered by empty publish: %+v", got)
	}
}
