package group

import (
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/common/urltest"
)

func newFillTestMembers(names ...string) ([]adapter.Outbound, map[string]adapter.Outbound) {
	all := make([]adapter.Outbound, 0, len(names))
	byName := make(map[string]adapter.Outbound, len(names))
	for _, name := range names {
		ob := &preMatchTestOutbound{tag: name}
		all = append(all, ob)
		byName[name] = ob
	}
	return all, byName
}

// TestSupplementalCandidates_RankingThenDelay: a ranking that covers only
// some nodes is followed by the measured nodes, fastest first, before any
// unmeasured node is considered.
func TestSupplementalCandidates_RankingThenDelay(t *testing.T) {
	all, byName := newFillTestMembers("unmeasured-a", "slow", "ranked", "unmeasured-b", "fast", "ineligible")
	s := &Smart{store: &smart.Store{}, history: urltest.NewHistoryStorage()}
	s.rankingHydrated.Store(true)
	s.publishRankingSnapshot([]smart.NodeRank{{Name: "ranked", Weight: 10}})
	s.history.StoreURLTestHistory("slow", &adapter.URLTestHistory{Time: time.Now(), Delay: 50})
	s.history.StoreURLTestHistory("fast", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	s.history.StoreURLTestHistory("ineligible", &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	eligible := func(ob adapter.Outbound) bool { return ob.Tag() != "ineligible" }

	got := outboundTagsOf(s.supplementalCandidates(all, byName, eligible, 3))
	if want := []string{"ranked", "fast", "slow"}; !equalStrings(got, want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	got = outboundTagsOf(s.supplementalCandidates(all, byName, eligible, 10))
	if len(got) != 5 || !equalStrings(got[:3], []string{"ranked", "fast", "slow"}) {
		t.Fatalf("candidates = %v, want ranked, fast, slow then both unmeasured nodes", got)
	}
}

// TestSupplementalCandidates_RandomSampleIsUniform: the random fallback
// must sample the whole group, not a contiguous run from a random offset —
// subscriptions list nodes of one provider (often dead together) next to
// each other.
func TestSupplementalCandidates_RandomSampleIsUniform(t *testing.T) {
	names := make([]string, 100)
	for i := range names {
		names[i] = strconv.Itoa(i)
	}
	all, byName := newFillTestMembers(names...)
	s := &Smart{}
	eligible := func(adapter.Outbound) bool { return true }
	adjacent := 0
	const runs = 500
	for range runs {
		got := s.supplementalCandidates(all, byName, eligible, 2)
		if len(got) != 2 || got[0] == got[1] {
			t.Fatalf("expected two distinct candidates, got %v", outboundTagsOf(got))
		}
		a, _ := strconv.Atoi(got[0].Tag())
		b, _ := strconv.Atoi(got[1].Tag())
		if a-b == 1 || b-a == 1 {
			adjacent++
		}
	}
	// A uniform pair is adjacent ~2% of the time; a contiguous walk always.
	if adjacent > runs/10 {
		t.Fatalf("%d of %d samples were adjacent nodes", adjacent, runs)
	}
}

// TestSupplementalCandidates_SkipsIneligible: whatever the path, only
// eligible nodes come back, each once.
func TestSupplementalCandidates_SkipsIneligible(t *testing.T) {
	names := make([]string, 40)
	for i := range names {
		names[i] = strconv.Itoa(i)
	}
	all, byName := newFillTestMembers(names...)
	s := &Smart{}
	eligible := func(ob adapter.Outbound) bool {
		i, _ := strconv.Atoi(ob.Tag())
		return i%10 == 0
	}
	got := outboundTagsOf(s.supplementalCandidates(all, byName, eligible, 10))
	if len(got) != 4 {
		t.Fatalf("candidates = %v, want the 4 eligible nodes", got)
	}
	seen := make(map[string]bool)
	for _, tag := range got {
		i, _ := strconv.Atoi(tag)
		if i%10 != 0 || seen[tag] {
			t.Fatalf("candidates = %v contain an ineligible or repeated node", got)
		}
		seen[tag] = true
	}
}

func outboundTagsOf(outbounds []adapter.Outbound) []string {
	tags := make([]string, 0, len(outbounds))
	for _, ob := range outbounds {
		tags = append(tags, ob.Tag())
	}
	return tags
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
