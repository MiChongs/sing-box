package group

import (
	"testing"
)

// TestSetAlgorithm_RuntimeSwap verifies the atomic swap path works
// without needing a full Smart construction: change algorithm, query
// the live value, observe the change. Mirrors the ClashAPI PUT path.
func TestSetAlgorithm_RuntimeSwap(t *testing.T) {
	s := &Smart{}
	if got := s.CurrentAlgorithm(); got != smartAlgoStrictBest {
		t.Fatalf("zero-value Smart should report %q, got %q", smartAlgoStrictBest, got)
	}
	if got := s.SetAlgorithm("p2c"); got != smartAlgoP2C {
		t.Fatalf("SetAlgorithm(p2c) returned %q, want %q", got, smartAlgoP2C)
	}
	if got := s.CurrentAlgorithm(); got != smartAlgoP2C {
		t.Fatalf("after swap CurrentAlgorithm = %q, want %q", got, smartAlgoP2C)
	}
	// Unknown name → strict-best (safe default), same as parser.
	if got := s.SetAlgorithm("does-not-exist"); got != smartAlgoStrictBest {
		t.Fatalf("unknown name didn't fall back: %q", got)
	}
}

// TestSetAlgorithm_LazyAllocates confirms the runtime swap allocates
// the bookkeeping the new algorithm needs (sticky map, RR counters)
// — otherwise the algorithm would silently degrade to no-op when
// switched onto from a different starting point.
func TestSetAlgorithm_LazyAllocates(t *testing.T) {
	s := &Smart{}
	s.SetAlgorithm("round-robin")
	if s.rrCounter == nil {
		t.Fatal("round-robin swap did not allocate rrCounter")
	}
	s.SetAlgorithm("weighted-rr")
	if s.wrrCounter == nil {
		t.Fatal("weighted-rr swap did not allocate wrrCounter")
	}
	s.SetAlgorithm("sticky")
	if s.stickyByTarget == nil {
		t.Fatal("sticky swap did not allocate stickyByTarget")
	}
	// Switch back to strict-best — counters stay (lazy alloc is
	// one-way; cheap to keep them around for the next swap).
	s.SetAlgorithm("strict-best")
	if s.rrCounter == nil || s.wrrCounter == nil || s.stickyByTarget == nil {
		t.Fatal("post-swap-back: allocations should persist for future re-swaps")
	}
}

// TestAlgoRound0Width_PerAlgorithm pins the race-width contract:
// selection-style algorithms (sticky / round-robin / etc) MUST get
// width=1 so dialWithRetry doesn't second-guess the algorithm's
// choice; ranking-style algorithms keep the legacy 2-wide race.
func TestAlgoRound0Width_PerAlgorithm(t *testing.T) {
	cases := []struct {
		algo string
		want int
	}{
		// Selection-style → 1
		{smartAlgoStickySession, 1},
		{smartAlgoRoundRobin, 1},
		{smartAlgoWeightedRR, 1},
		{smartAlgoP2C, 1},
		{smartAlgoWeightedRandom, 1},
		// Ranking-style → race
		{smartAlgoStrictBest, smartRound0Parallel},
		{smartAlgoLeastLoaded, smartRound0Parallel},
		{smartAlgoFastestRecent, smartRound0Parallel},
		{smartAlgoLatencyBanded, smartRound0Parallel},
	}
	for _, c := range cases {
		t.Run(c.algo, func(t *testing.T) {
			s := &Smart{}
			s.SetAlgorithm(c.algo)
			if got := s.algoRound0Width(); got != c.want {
				t.Fatalf("algoRound0Width(%s) = %d, want %d", c.algo, got, c.want)
			}
		})
	}
}

// TestCurrentAlgorithm_NilSafe: a brand-new Smart whose algorithm
// atomic was never Stored must still report the safe default. Critical
// for early-init code paths that call algoRound0Width before NewSmart
// has finished wiring everything up.
func TestCurrentAlgorithm_NilSafe(t *testing.T) {
	s := &Smart{}
	if got := s.CurrentAlgorithm(); got != smartAlgoStrictBest {
		t.Fatalf("nil-safe default broken: got %q", got)
	}
	if got := s.algoRound0Width(); got != smartRound0Parallel {
		t.Fatalf("nil-safe race width broken: got %d", got)
	}
}
