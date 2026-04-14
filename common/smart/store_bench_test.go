package smart

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/bbolt"
)

// BenchmarkAppendToGlobalQueue_Churn models a busy-config workload:
// 1 Smart group × 100 active targets × 10 nodes = 1000 distinct (target, node)
// pairs cycling through recordStats. Prior to the O(n) → O(1) rewrite the
// dedup map was rebuilt on every insert; for a queue of size 1000 this was
// ~1000 allocs and ~16 µs per insert. With the persistent index we should
// see single-digit allocs and sub-µs per insert.
func BenchmarkAppendToGlobalQueue_Churn(b *testing.B) {
	dir := b.TempDir()
	db, err := bbolt.Open(filepath.Join(dir, "bench.db"), 0600, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	defer os.RemoveAll(dir)

	store := GetOrInitStore(db)

	// Pre-populate queue with 500 entries (simulating steady state).
	ops := make([]StoreOperation, 500)
	for i := range ops {
		ops[i] = StoreOperation{
			Type: OpSaveStats, Group: "g1", Config: "c1",
			Target: "*.example" + itoa(i) + ".com",
			Node:   "N" + itoa(i),
			Data:   []byte("x"),
		}
	}
	store.AppendToGlobalQueue(ops...)

	// Pre-build the op templates so the benchmark measures only the
	// append-path cost (not the test-harness string construction).
	templates := make([]StoreOperation, 500)
	for i := range templates {
		templates[i] = StoreOperation{
			Type: OpSaveStats, Group: "g1", Config: "c1",
			Target: "*.example" + itoa(i) + ".com",
			Node:   "N" + itoa(i),
			Data:   []byte("y"),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Alternate between existing-key (update path) and new-key paths.
		// In the update case the old O(n) implementation would still do
		// full map rebuild; the new impl is O(1).
		store.AppendToGlobalQueue(templates[i%500])
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
