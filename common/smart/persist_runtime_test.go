package smart

import (
	"testing"
)

// TestPersistRuntime_FormatOperationKey ensures Save and Delete ops for
// the three runtime-state key types map to the SAME key, so queue dedup
// collapses a save-then-delete (or vice-versa) into one tombstone slot.
func TestPersistRuntime_FormatOperationKey(t *testing.T) {
	cases := []struct {
		name       string
		save, del  int
		group      string
		node       string
		expectNode bool // true when the key includes the node segment
	}{
		{"ManualPin", OpSaveManualPin, OpDeleteManualPin, "g1", "", false},
		{"KnownDead", OpSaveKnownDead, OpDeleteKnownDead, "g1", "N1", true},
		{"Breaker", OpSaveBreaker, OpDeleteBreaker, "g1", "N1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opSave := &StoreOperation{Type: tc.save, Config: "c1", Group: tc.group, Node: tc.node}
			opDel := &StoreOperation{Type: tc.del, Config: "c1", Group: tc.group, Node: tc.node}
			ks := FormatOperationKey(opSave)
			kd := FormatOperationKey(opDel)
			if ks == "" {
				t.Fatalf("save op returned empty key")
			}
			if ks != kd {
				t.Fatalf("save and delete keys must match for dedup: save=%q del=%q", ks, kd)
			}
			if tc.expectNode && tc.node != "" {
				// Expect the node segment to appear in the key.
				if !containsTail(ks, tc.node) {
					t.Fatalf("expected node %q in key %q", tc.node, ks)
				}
			}
		})
	}
}

// TestPersistRuntime_IsDeleteOp covers the helper BatchSave depends on.
func TestPersistRuntime_IsDeleteOp(t *testing.T) {
	deletes := []int{OpDeleteManualPin, OpDeleteKnownDead, OpDeleteBreaker}
	saves := []int{OpSaveManualPin, OpSaveKnownDead, OpSaveBreaker, OpSaveStats, OpSaveNodeState}
	for _, d := range deletes {
		if !isDeleteOp(d) {
			t.Fatalf("op %d should be classified as delete", d)
		}
	}
	for _, s := range saves {
		if isDeleteOp(s) {
			t.Fatalf("op %d should NOT be classified as delete", s)
		}
	}
}

// TestPersistRuntime_RecordRoundtrip ensures the three serialisation
// structs survive JSON marshal / unmarshal losslessly — the hydrate
// path depends on this.
func TestPersistRuntime_RecordRoundtrip(t *testing.T) {
	pin := &ManualPinRecord{Tag: "HK-01", UpdatedAt: 1700000000}
	data, _ := jsonMarshal(pin)
	var pinOut ManualPinRecord
	if err := jsonUnmarshal(data, &pinOut); err != nil || pinOut != *pin {
		t.Fatalf("ManualPinRecord roundtrip failed: err=%v got=%+v", err, pinOut)
	}

	dead := &KnownDeadRecord{DeadAt: 1700000001}
	data, _ = jsonMarshal(dead)
	var deadOut KnownDeadRecord
	if err := jsonUnmarshal(data, &deadOut); err != nil || deadOut != *dead {
		t.Fatalf("KnownDeadRecord roundtrip failed: err=%v got=%+v", err, deadOut)
	}

	brk := &BreakerRecord{ConsecFails: 2, FirstFailAt: 1e18, OpenUntil: 2e18}
	data, _ = jsonMarshal(brk)
	var brkOut BreakerRecord
	if err := jsonUnmarshal(data, &brkOut); err != nil || brkOut != *brk {
		t.Fatalf("BreakerRecord roundtrip failed: err=%v got=%+v", err, brkOut)
	}
}

// containsTail reports whether haystack ends with "/" + needle.
func containsTail(haystack, needle string) bool {
	if len(needle) == 0 || len(haystack) <= len(needle) {
		return haystack == needle
	}
	tail := haystack[len(haystack)-len(needle)-1:]
	return tail == "/"+needle
}
