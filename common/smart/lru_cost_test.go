package smart

import (
	"strings"
	"testing"
)

// TestByteBudgetEvictsBySize verifies the cache honours a byte budget:
// once the summed value cost exceeds MaxCost, ristretto admits/evicts so
// the resident set stays near the ceiling instead of growing with entry
// count. We size the budget to hold roughly a handful of large values and
// assert the cache never retains far more than that.
func TestByteBudgetEvictsBySize(t *testing.T) {
	const (
		valueBytes = 10 * 1024  // 10 KiB per value
		budget     = 100 * 1024 // 100 KiB → ~10 values worth
		inserted   = 2000       // way more than fit
	)
	c := newLRUBytes[string, string](budget, costString)
	defer c.Close()

	big := strings.Repeat("x", valueBytes)
	for i := 0; i < inserted; i++ {
		c.Set(keyN(i), big)
	}
	c.Wait()

	// Count survivors via the key index (bounded by admission). The live
	// set must be on the order of budget/valueBytes (~10), not `inserted`.
	survivors := 0
	c.keysIndex.Range(func(k string, _ struct{}) bool {
		if _, ok := c.Get(k); ok {
			survivors++
		}
		return true
	})
	maxExpected := (budget / valueBytes) * 4 // generous slack for sampling
	if survivors > maxExpected {
		t.Fatalf("byte budget not enforced: %d survivors, expected <= %d", survivors, maxExpected)
	}
	if survivors == 0 {
		t.Fatalf("expected some entries to be admitted, got 0")
	}
}

// TestCostFunctionsPositive guards against a cost fn returning <1 (which
// would let ristretto treat an entry as free and break the budget).
func TestCostFunctionsPositive(t *testing.T) {
	if costString("") < 1 {
		t.Fatal("costString(empty) < 1")
	}
	if costUnwrapMap(UnwrapMap{}) < 1 {
		t.Fatal("costUnwrapMap(zero) < 1")
	}
	if costRecord(nil) < 1 {
		t.Fatal("costRecord(nil) < 1")
	}
	if costDBResult(map[string][]byte{}) < 1 {
		t.Fatal("costDBResult(empty) < 1")
	}
	if costBlocked(map[string]bool{}) < 1 {
		t.Fatal("costBlocked(empty) < 1")
	}
	// A larger value must cost strictly more than a smaller one so eviction
	// can discriminate by footprint.
	if costDBResult(map[string][]byte{"k": make([]byte, 4096)}) <= costDBResult(map[string][]byte{"k": make([]byte, 16)}) {
		t.Fatal("costDBResult not monotonic in value size")
	}
}

func keyN(i int) string {
	// Distinct keys so each Set is a separate entry.
	const digits = "0123456789"
	if i == 0 {
		return "k0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{digits[i%10]}, b...)
		i /= 10
	}
	return "k" + string(b)
}
