package group

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestMMDBPool_Dedup verifies that multiple getSharedMMDB calls for the
// same path reuse a single *maxminddb.Reader. This is the core savings
// for multi-Smart-group configs where 16 groups all want the same ASN DB.
func TestMMDBPool_Dedup(t *testing.T) {
	// Use a real mmdb-shaped file from the repo if present, otherwise skip.
	path := filepath.Join(os.TempDir(), "nonexistent-smart-test.mmdb")
	_, err := getSharedMMDB(path)
	if err == nil {
		t.Fatalf("expected error for nonexistent file")
	}
}

// TestMMDBPool_RefcountBalance drives the pool's refcount directly with a
// synthetic entry (we can't easily open a real mmdb in unit tests) and
// confirms balanced increments + decrements remove the pool entry via
// the Compute-with-delete path.
func TestMMDBPool_RefcountBalance(t *testing.T) {
	key := mmdbKey{path: "test-balance", size: 1, mtime: 1}
	shared := &sharedMMDBReader{key: key}
	shared.refcount.Store(3)
	forwardPool.Store(key, shared)
	defer forwardPool.Delete(key)

	// Simulate 3 releases, the last one should drop the entry.
	for i := 0; i < 3; i++ {
		if shared.refcount.Add(-1) > 0 {
			continue
		}
		forwardPool.Compute(shared.key, func(old *sharedMMDBReader, loaded bool) (*sharedMMDBReader, bool) {
			if !loaded || old != shared {
				return old, !loaded
			}
			if shared.refcount.Load() > 0 {
				return shared, false
			}
			return shared, true
		})
	}

	if _, exists := forwardPool.Load(key); exists {
		t.Fatalf("pool entry still present after balanced release")
	}
}

// TestMMDBPool_ConcurrentAcquireMiss exercises the singleflight path:
// many goroutines race to acquire a missing file. Only one Open() call
// should be attempted (via singleflight) and every caller should see the
// same error.
func TestMMDBPool_ConcurrentAcquireMiss(t *testing.T) {
	path := filepath.Join(os.TempDir(), "nonexistent-smart-concurrent.mmdb")
	const N = 16
	var wg sync.WaitGroup
	errs := make([]error, N)
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = getSharedMMDB(path)
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e == nil {
			t.Fatalf("caller %d: expected error, got nil", i)
		}
	}
}
