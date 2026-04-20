package group

import (
	"testing"
)

// TestNormalizeAlgorithm_ConsistentHashing covers the aliases we
// accept for the new algorithm. Users copy/paste from docs or from
// mihomo/clash configs so we accept both the canonical form and the
// common shorthand.
func TestNormalizeAlgorithm_ConsistentHashing(t *testing.T) {
	cases := []string{
		"consistent-hashing",
		"consistent_hashing",
		"Consistent-Hashing",
		"  CONSISTENT-HASHING  ",
		"consistent-hash",
		"chash",
		"ch",
		"consistent",
		"jump-hash",
	}
	for _, raw := range cases {
		got := normalizeAlgorithm(raw)
		if got != smartAlgoConsistentHashing {
			t.Errorf("normalizeAlgorithm(%q) = %q, want %q",
				raw, got, smartAlgoConsistentHashing)
		}
	}
}

// TestReorderConsistentHashing_SameTargetStable verifies the core
// property: two dials to the same target pick the same candidate.
// We pick a target + candidate list, run the reorder, record the
// winner, then re-run on a fresh copy and confirm the winner is the
// same.
func TestReorderConsistentHashing_SameTargetStable(t *testing.T) {
	s := &Smart{}

	tags := []string{"A", "B", "C", "D", "E", "F", "G"}
	target := "example.com:443"

	first := makeStubs(tags...)
	s.reorderConsistentHashing(first, target, false)
	winner := first[0].Tag()

	// Run again on a fresh identical candidate list.
	second := makeStubs(tags...)
	s.reorderConsistentHashing(second, target, false)

	if second[0].Tag() != winner {
		t.Fatalf("instability: first=%s second=%s", winner, second[0].Tag())
	}

	// Run once more for paranoia.
	third := makeStubs(tags...)
	s.reorderConsistentHashing(third, target, false)
	if third[0].Tag() != winner {
		t.Fatalf("instability on 3rd call: got %s want %s", third[0].Tag(), winner)
	}
}

// TestReorderConsistentHashing_UDPDiffersFromTCP ensures that UDP
// and TCP dials to the same host don't forcibly land on the same
// node. They CAN (if the hashes collide), but the key is different
// so at least one (target, isUDP) pair out of a small set must pick
// differently — otherwise the isUDP fold in the key is broken.
func TestReorderConsistentHashing_UDPDiffersFromTCP(t *testing.T) {
	s := &Smart{}
	tags := []string{"A", "B", "C", "D", "E", "F", "G", "H"}

	targets := []string{"foo.com:443", "bar.com:443", "baz.com:443", "qux.com:443"}
	differed := 0
	for _, target := range targets {
		tcp := makeStubs(tags...)
		s.reorderConsistentHashing(tcp, target, false)

		udp := makeStubs(tags...)
		s.reorderConsistentHashing(udp, target, true)

		if tcp[0].Tag() != udp[0].Tag() {
			differed++
		}
	}
	if differed == 0 {
		t.Fatal("TCP and UDP hash keys collapsed to same slot for every target — isUDP fold not working")
	}
}

// TestReorderConsistentHashing_DifferentTargetsSpread: given 100
// distinct targets and 8 candidates, the hashed picks should use
// more than one candidate. A deterministic-choice algorithm that
// always picked candidate[0] would pass every other test but fail
// this smoke check.
func TestReorderConsistentHashing_DifferentTargetsSpread(t *testing.T) {
	s := &Smart{}
	tags := []string{"A", "B", "C", "D", "E", "F", "G", "H"}

	picked := make(map[string]int)
	for i := 0; i < 100; i++ {
		target := randomTargetForTest(i)
		cs := makeStubs(tags...)
		s.reorderConsistentHashing(cs, target, false)
		picked[cs[0].Tag()]++
	}
	if len(picked) < 3 {
		t.Fatalf("spread too narrow: used only %d distinct nodes out of 8 (%v)", len(picked), picked)
	}
}

// TestReorderConsistentHashing_EmptyTargetNoop: the algorithm must
// not touch the candidate ordering when no target signal is
// available (direct-IP dial without sniff). Tier-logic's choice at
// position 0 stays.
func TestReorderConsistentHashing_EmptyTargetNoop(t *testing.T) {
	s := &Smart{}
	cs := makeStubs("A", "B", "C")
	s.reorderConsistentHashing(cs, "", false)
	if cs[0].Tag() != "A" {
		t.Fatalf("empty target disturbed order: got %s, want A", cs[0].Tag())
	}
}

// TestReorderConsistentHashing_SingleCandidate: len<=1 is a no-op.
func TestReorderConsistentHashing_SingleCandidate(t *testing.T) {
	s := &Smart{}
	cs := makeStubs("solo")
	s.reorderConsistentHashing(cs, "anything:443", false)
	if len(cs) != 1 || cs[0].Tag() != "solo" {
		t.Fatalf("single-element list disturbed: %+v", cs)
	}
}

// TestReorderConsistentHashing_AlgoRound0Width1 verifies the dial
// pipeline treats consistent-hashing as a selection-style algorithm
// (width=1), not a ranking-style one — racing a second candidate
// would defeat the "deterministic single pick" contract.
func TestReorderConsistentHashing_AlgoRound0Width1(t *testing.T) {
	s := setAlgo(&Smart{}, smartAlgoConsistentHashing)
	if got := s.algoRound0Width(); got != 1 {
		t.Fatalf("consistent-hashing algoRound0Width = %d, want 1", got)
	}
}

// randomTargetForTest returns a deterministic pseudo-random target
// derived from an index — we want the same sequence across runs so
// TestReorderConsistentHashing_DifferentTargetsSpread is reproducible
// without pulling in math/rand seeds.
func randomTargetForTest(i int) string {
	// Mix the index into a dotted-quad style string. Avoids actual
	// randomness so test runs are deterministic.
	b := [4]byte{
		byte(17*i + 3),
		byte(23*i + 5),
		byte(31*i + 7),
		byte(37*i + 11),
	}
	return formatTargetForTest(b)
}

func formatTargetForTest(b [4]byte) string {
	s := [24]byte{}
	n := 0
	for i := 0; i < 4; i++ {
		v := b[i]
		if v >= 100 {
			s[n] = '0' + v/100
			n++
			v %= 100
			s[n] = '0' + v/10
			n++
			s[n] = '0' + v%10
			n++
		} else if v >= 10 {
			s[n] = '0' + v/10
			n++
			s[n] = '0' + v%10
			n++
		} else {
			s[n] = '0' + v
			n++
		}
		if i < 3 {
			s[n] = '.'
			n++
		}
	}
	s[n] = ':'
	n++
	s[n] = '4'
	n++
	s[n] = '4'
	n++
	s[n] = '3'
	n++
	return string(s[:n])
}
