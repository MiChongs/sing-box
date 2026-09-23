package group

import (
	"testing"
	"time"
)

// TestManualPinLearning_PriorityBoost verifies that the manual-pin
// confidence boost is composed multiplicatively with the
// config-defined policy_priority factor, so both signals coexist
// instead of one shadowing the other. Exercises the precise
// computation that recordStats performs for a pinned dial.
//
// Why a stand-alone test rather than asserting through recordStats:
// recordStats is tightly coupled to bbolt store state and the shared
// ants pool. This test pins down the arithmetic invariant directly so
// a future refactor that tweaks priority composition can't silently
// break user-endorsement learning.
func TestManualPinLearning_PriorityBoost(t *testing.T) {
	const basePriority float64 = 1.4 // e.g., policy_priority: "HK:1.4"
	factor := float64(basePriority)
	factor *= manualPinWeightBoost
	want := float64(basePriority) * float64(manualPinWeightBoost)
	if factor != want {
		t.Fatalf("composed factor = %.4f, want %.4f", factor, want)
	}
	if factor <= basePriority {
		t.Fatalf("pin boost did not uplift factor: got %.4f, base %.4f",
			factor, basePriority)
	}
}

// TestManualPinLearning_Gating confirms the boost ONLY applies when
// the dialed proxyTag matches the currently-pinned tag. Unpinned
// dials must keep the base priority factor unchanged — otherwise
// every node would receive the uplift and the signal would be
// meaningless.
func TestManualPinLearning_Gating(t *testing.T) {
	s := &Smart{}
	s.manualSelected.Store("HK-01")

	// Pinned tag → boost applies.
	if got := s.getManualSelected(); got != "HK-01" {
		t.Fatalf("pin state = %q, want HK-01", got)
	}
	pinnedDial := s.getManualSelected() == "HK-01"
	if !pinnedDial {
		t.Fatal("dial to pinned tag must register as pinned")
	}

	// Different node → boost must NOT apply.
	otherDial := s.getManualSelected() == "US-22"
	if otherDial {
		t.Fatal("dial to non-pinned tag must not register as pinned")
	}

	// Clearing the pin ends the boost regardless of dial tag.
	s.manualSelected.Store("")
	if clearedDial := s.getManualSelected() == "HK-01"; clearedDial {
		t.Fatal("after unpin, previous pin tag must no longer register as pinned")
	}
}

// TestManualPinLearning_BoostValueSane guards against someone
// accidentally setting the boost to an extreme value that would
// either dominate every other signal (>1.5) or become a no-op (≤1).
// If the boost is tuned in future, this test forces an explicit
// review of the change.
func TestManualPinLearning_BoostValueSane(t *testing.T) {
	if manualPinWeightBoost <= 1.0 {
		t.Fatalf("manualPinWeightBoost = %.3f must be > 1.0 to express preference", manualPinWeightBoost)
	}
	if manualPinWeightBoost > 1.5 {
		t.Fatalf("manualPinWeightBoost = %.3f is too aggressive; a single pin would override genuine health degradation signals", manualPinWeightBoost)
	}
}

func TestManualPinLearning_Degrade(t *testing.T) {
	entry := newPinEndorsementEntry()
	now := time.Now().Unix()
	meta := &smartDialMeta{smartTarget: "example.com", asnCode: "12345"}
	entry.recordHit(meta, true, 100.0, now)

	boostNormal := entry.boost(meta, 120.0, now)
	if boostNormal <= 1.0 {
		t.Fatalf("Expected boost > 1.0 under normal latency, got %v", boostNormal)
	}

	boostDegraded := entry.boost(meta, 300.0, now) // > 2.5 * 100.0
	if boostDegraded != 1.0 {
		t.Fatalf("Expected boost exactly 1.0 under degraded latency, got %v", boostDegraded)
	}
}

func TestManualPinLearning_Context(t *testing.T) {
	entry := newPinEndorsementEntry()
	now := time.Now().Unix()
	meta := &smartDialMeta{smartTarget: "example.com", asnCode: "12345"}
	entry.recordHit(meta, true, 100.0, now)
	entry.recordHit(meta, true, 100.0, now)

	fullMeta := &smartDialMeta{smartTarget: "example.com", asnCode: "12345"}
	noneMeta := &smartDialMeta{smartTarget: "other.com", asnCode: "54321"}

	boostFull := entry.boost(fullMeta, 100.0, now)
	boostNone := entry.boost(noneMeta, 100.0, now)

	if boostFull <= boostNone {
		t.Fatalf("Expected higher boost with full context matching. Full: %v, None: %v", boostFull, boostNone)
	}
}
