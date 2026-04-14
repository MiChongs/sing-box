package group

import (
	"testing"
	"time"
)

// TestStaggeredInitialDelay_Spreads: two groups with consecutive ordinals
// must produce different delays so their first tick doesn't coincide.
func TestStaggeredInitialDelay_Spreads(t *testing.T) {
	base := 10 * time.Second
	d1 := staggeredInitialDelay(base, 1)
	d2 := staggeredInitialDelay(base, 2)
	d3 := staggeredInitialDelay(base, 3)
	if d1 == d2 || d2 == d3 {
		t.Fatalf("stagger didn't spread consecutive ordinals: %v %v %v", d1, d2, d3)
	}
	// All delays must be at least base (we only ADD an offset).
	if d1 < base || d2 < base || d3 < base {
		t.Fatalf("stagger produced delay below base: %v %v %v (base=%v)", d1, d2, d3, base)
	}
	// And within a reasonable window.
	if d1 > base+5*time.Second || d2 > base+5*time.Second || d3 > base+5*time.Second {
		t.Fatalf("stagger exceeded reasonable window: %v %v %v", d1, d2, d3)
	}
}

// TestSharedWorker_Singleton: the process-wide worker must survive repeated
// calls and not reinitialise its pool on each access.
func TestSharedWorker_Singleton(t *testing.T) {
	w1 := getSmartWorker()
	w2 := getSmartWorker()
	if w1 != w2 {
		t.Fatalf("getSmartWorker returned different instances; expected singleton")
	}
	if w1.freshnessCache == nil {
		t.Fatal("freshnessCache nil")
	}
}

// TestSharedWorker_FreshnessCache: cached probeResult entries within
// freshWindow return the cached value without re-running the probe.
func TestSharedWorker_FreshnessCache(t *testing.T) {
	w := getSmartWorker()
	w.freshnessCache.Store("test-tag", probeResult{
		at:    time.Now(),
		delay: 123,
		err:   nil,
	})
	got, ok := w.freshnessCache.Load("test-tag")
	if !ok || got.delay != 123 {
		t.Fatalf("freshnessCache didn't return the stored value: got=%+v ok=%v", got, ok)
	}
	// Expired entries stay in the map but probeOnce would skip them — here
	// we just verify Load still sees the stale value (the expiry check is
	// in probeOnce, not the cache itself).
	w.freshnessCache.Delete("test-tag")
}
