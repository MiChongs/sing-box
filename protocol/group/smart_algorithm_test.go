package group

import (
	"context"
	"net"
	"sort"
	"testing"

	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// setAlgo wires the algorithm atomic on a test-constructed Smart.
// Required because the live field is atomic.Pointer[string] and
// can't be assigned from a struct literal — the wrapper keeps the
// per-test setup readable while the production runtime gets the
// lock-free swap path it needs.
func setAlgo(s *Smart, algo string) *Smart {
	a := algo
	s.algorithm.Store(&a)
	return s
}

// stubOutbound satisfies adapter.Outbound just enough for the
// algorithm tests — only Tag()/Type()/Network() are read by the
// reorder code paths. Dial methods panic so a regression that
// accidentally invokes them surfaces immediately.
type stubOutbound struct{ tag string }

func (s *stubOutbound) Tag() string             { return s.tag }
func (s *stubOutbound) Type() string            { return "stub" }
func (s *stubOutbound) Network() []string       { return []string{N.NetworkTCP} }
func (s *stubOutbound) Dependencies() []string  { return nil }
func (s *stubOutbound) DialContext(_ context.Context, _ string, _ metadata.Socksaddr) (net.Conn, error) {
	panic("stubOutbound dial unexpected")
}
func (s *stubOutbound) ListenPacket(_ context.Context, _ metadata.Socksaddr) (net.PacketConn, error) {
	panic("stubOutbound listen unexpected")
}

func makeStubs(tags ...string) []adapter.Outbound {
	out := make([]adapter.Outbound, len(tags))
	for i, t := range tags {
		out[i] = &stubOutbound{tag: t}
	}
	return out
}

// TestNormalizeAlgorithm covers the user-facing canonicalisation —
// case, separators, common synonyms ("auto" / "best" / "load") all
// resolve to the documented constants. Unknown strings collapse to
// strict-best so a typo doesn't break the dial path.
func TestNormalizeAlgorithm(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", smartAlgoStrictBest},
		{"auto", smartAlgoStrictBest},
		{"BEST", smartAlgoStrictBest},
		{"strict_best", smartAlgoStrictBest},
		{"weighted-random", smartAlgoWeightedRandom},
		{"weighted_random", smartAlgoWeightedRandom},
		{"random", smartAlgoWeightedRandom},
		{" Least Loaded ", smartAlgoLeastLoaded},
		{"least-load", smartAlgoLeastLoaded},
		{"fastest-recent", smartAlgoFastestRecent},
		{"recent", smartAlgoFastestRecent},
		{"sticky", smartAlgoStickySession},
		{"unknown-thing", smartAlgoStrictBest}, // safe default
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := normalizeAlgorithm(c.in); got != c.want {
				t.Errorf("normalize(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestReorder_StrictBestNoOp: the default path must not touch ordering.
// Critical contract — every previously-shipped build relied on this.
func TestReorder_StrictBestNoOp(t *testing.T) {
	s := setAlgo(&Smart{nodeLoad: newNodeLoadCounter()}, smartAlgoStrictBest)
	in := makeStubs("a", "b", "c", "d", "e")
	got := s.reorderForAlgorithm(in, "example.com", false)
	for i, ob := range got {
		if want := []string{"a", "b", "c", "d", "e"}[i]; ob.Tag() != want {
			t.Fatalf("position %d = %q, want %q (strict-best should be no-op)", i, ob.Tag(), want)
		}
	}
}

// TestReorder_LeastLoaded swaps in the lowest-load candidate within
// the swap budget. We seed three candidates with distinct loads and
// verify the lightest gets promoted to position 0.
func TestReorder_LeastLoaded(t *testing.T) {
	s := setAlgo(&Smart{nodeLoad: newNodeLoadCounter()}, smartAlgoLeastLoaded)
	// Heavy first, light second, medium third.
	for i := 0; i < 10; i++ {
		s.nodeLoad.inc("heavy")
	}
	s.nodeLoad.inc("light")
	for i := 0; i < 5; i++ {
		s.nodeLoad.inc("medium")
	}
	in := makeStubs("heavy", "light", "medium")
	got := s.reorderForAlgorithm(in, "example.com", false)
	if got[0].Tag() != "light" {
		t.Fatalf("position 0 = %q, want light", got[0].Tag())
	}
}

// TestReorder_LeastLoaded_BudgetCap proves the algorithm never looks
// past leastLoadedSwapBudget candidates — a far-back light node
// shouldn't be pulled to the front.
func TestReorder_LeastLoaded_BudgetCap(t *testing.T) {
	s := setAlgo(&Smart{nodeLoad: newNodeLoadCounter()}, smartAlgoLeastLoaded)
	for i := 0; i < 10; i++ {
		s.nodeLoad.inc("front-heavy")
	}
	for i := 0; i < 9; i++ {
		s.nodeLoad.inc("front-medium")
	}
	for i := 0; i < 8; i++ {
		s.nodeLoad.inc("front-medium2")
	}
	// A super-light candidate well past the swap budget must NOT be
	// promoted (proves the budget guard is honoured).
	in := makeStubs("front-heavy", "front-medium", "front-medium2", "far-light", "far-light2")
	// far-light has zero load; if budget were unlimited it would jump.
	got := s.reorderForAlgorithm(in, "example.com", false)
	if got[0].Tag() == "far-light" || got[0].Tag() == "far-light2" {
		t.Fatalf("budget cap broken — far candidate %q jumped to position 0", got[0].Tag())
	}
}

// TestReorder_StickySession promotes the previously-recorded node for
// the target. We seed sticky for one target, ask for it, and check
// the wanted node lands in position 0.
func TestReorder_StickySession(t *testing.T) {
	s := setAlgo(&Smart{stickyByTarget: xsync.NewMapOf[stickyKey, string]()}, smartAlgoStickySession)
	s.rememberStickyChoice("example.com", "node-pref", false)

	in := makeStubs("node-a", "node-b", "node-pref", "node-d")
	got := s.reorderForAlgorithm(in, "example.com", false)
	if got[0].Tag() != "node-pref" {
		t.Fatalf("position 0 = %q, want node-pref", got[0].Tag())
	}
}

// TestReorder_StickySession_NoMemoryNoOp: sticky algorithm with no
// recorded choice for the target leaves ordering untouched.
func TestReorder_StickySession_NoMemoryNoOp(t *testing.T) {
	s := setAlgo(&Smart{stickyByTarget: xsync.NewMapOf[stickyKey, string]()}, smartAlgoStickySession)
	in := makeStubs("a", "b", "c")
	got := s.reorderForAlgorithm(in, "untouched.com", false)
	for i, want := range []string{"a", "b", "c"} {
		if got[i].Tag() != want {
			t.Fatalf("sticky no-mem reordered position %d = %q, want %q", i, got[i].Tag(), want)
		}
	}
}

// TestReorder_StickySession_UDPDistinct verifies UDP and TCP sticky
// memories are separate — a TCP success on target T must not pull
// the same node to the front of a UDP request to T.
func TestReorder_StickySession_UDPDistinct(t *testing.T) {
	s := setAlgo(&Smart{stickyByTarget: xsync.NewMapOf[stickyKey, string]()}, smartAlgoStickySession)
	s.rememberStickyChoice("example.com", "tcp-only", false)
	in := makeStubs("a", "b", "tcp-only")
	udp := s.reorderForAlgorithm(in, "example.com", true) // UDP
	if udp[0].Tag() == "tcp-only" {
		t.Fatalf("TCP sticky leaked into UDP path — UDP should be untouched")
	}
}

// TestReorder_WeightedRandom_Distribution asserts the sampler honours
// the rank-derived bias: across many trials, position 0 wins more
// often than later positions, but later positions still get picked
// at least sometimes (otherwise it would be strict-best).
func TestReorder_WeightedRandom_Distribution(t *testing.T) {
	s := setAlgo(&Smart{nodeLoad: newNodeLoadCounter()}, smartAlgoWeightedRandom)
	wins := map[string]int{}
	const trials = 1000
	for i := 0; i < trials; i++ {
		in := makeStubs("a", "b", "c", "d", "e")
		got := s.reorderForAlgorithm(in, "example.com", false)
		wins[got[0].Tag()]++
	}
	// "a" should be the modal winner (top of synthetic-weight scale).
	type entry struct {
		tag string
		n   int
	}
	es := make([]entry, 0, len(wins))
	for k, v := range wins {
		es = append(es, entry{k, v})
	}
	sort.Slice(es, func(i, j int) bool { return es[i].n > es[j].n })
	if es[0].tag != "a" {
		t.Fatalf("expected 'a' to be modal winner, got %v", es)
	}
	// At least 3 distinct positions should win across 1000 trials —
	// otherwise the algorithm collapsed to strict-best.
	if len(wins) < 3 {
		t.Fatalf("only %d distinct winners across %d trials — distribution too narrow", len(wins), trials)
	}
}

// TestNodeLoadCounter_Lifecycle covers inc/dec/get and the
// "decrement an unknown node is a no-op" safety contract.
func TestNodeLoadCounter_Lifecycle(t *testing.T) {
	n := newNodeLoadCounter()
	if n.get("missing") != 0 {
		t.Fatal("unknown node should report 0")
	}
	n.inc("a")
	n.inc("a")
	n.inc("b")
	if got := n.get("a"); got != 2 {
		t.Fatalf("a count = %d, want 2", got)
	}
	if got := n.get("b"); got != 1 {
		t.Fatalf("b count = %d, want 1", got)
	}
	n.dec("a")
	if got := n.get("a"); got != 1 {
		t.Fatalf("a count after dec = %d, want 1", got)
	}
	// Decrementing a never-seen node must NOT panic or create the entry.
	n.dec("never-existed")
	if n.get("never-existed") != 0 {
		t.Fatal("dec of unknown node should not create the entry")
	}
}
