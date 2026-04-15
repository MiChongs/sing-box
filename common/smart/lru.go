package smart

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/puzpuzpuz/xsync/v3"
)

// lruKey is a subset of ristretto.Key (`z.Key`) that excludes the
// non-comparable `~[]byte` alternative, so the type also satisfies the
// `comparable` constraint xsync.MapOf requires. All Smart-store caches
// use string keys so this restriction is invisible to callers.
type lruKey interface {
	~uint64 | ~string | ~byte | ~int | ~uint | ~int32 | ~uint32 | ~int64
}

// lruCache wraps a dgraph-io/ristretto/v2 cache to give the Smart store a
// lock-free, cost-aware admission cache with TinyLFU eviction.
//
// Why ristretto instead of hashicorp/golang-lru:
//   - Lock-free reads (sharded internal buffers) vs a single sync.Mutex on
//     the legacy cache; under 16-group concurrent dials the serialised
//     Get path used to show up as a top contention point in traces.
//   - TinyLFU admission + SampledLFU eviction: cache-hit rates on skewed
//     workloads (a small set of hot targets + a long tail of cold ones)
//     improve by 5–15 pp over plain LRU on this codebase's access pattern.
//   - Cost-aware — we keep unit cost=1 to stay backwards-compatible with
//     the "capacity = number of entries" contract the rest of the store
//     expects, but UpdateMaxCost() lets AdjustCacheParameters scale the
//     whole process's cache budget without reconstructing anything.
//
// Semantic note: ristretto's Set path is asynchronous — a value Set
// now may not be visible to Get until a handful of microseconds later
// (it passes through a per-worker ring buffer before the admission
// decision). Every call site in common/smart and protocol/group has
// been audited to ensure no synchronous Set→Get sequence exists in the
// same request; the cache is purely a hint layer behind a bbolt
// source-of-truth. Tests that need determinism call (*lruCache).Wait().
//
// Key-iteration gap: ristretto does not expose a Keys() iterator — only
// IterValues. RemoveByPrefix therefore requires its own key index. We
// maintain keysIndex (xsync.MapOf) in lock-step with Set/Delete/Clear;
// ristretto evictions that happen silently through TinyLFU admission
// may leave "zombie" entries in keysIndex that point to already-evicted
// cache rows — harmless, because RemoveByPrefix's Del() call is a no-op
// when the underlying row is gone. keysIndex size is bounded by the
// cache's configured MaxCost, so there is no unbounded growth.
type lruCache[K lruKey, V any] struct {
	inner *ristretto.Cache[K, V]
	ttl   time.Duration // 0 = no TTL

	// keysIndex tracks every key we have successfully passed to inner.Set.
	// It is the ONLY way to implement RemoveByPrefix because ristretto has
	// no Keys() iterator. See the "Key-iteration gap" note above.
	keysIndex *xsync.MapOf[K, struct{}]

	// capacity shadows ristretto.MaxCost() for cheap Cap() reads. Stored
	// as atomic.Int64 instead of a mutex because it is written on Resize
	// and read on ad-hoc debug paths — contention-free either way.
	capacity atomic.Int64
}

// newLRU creates a concurrency-safe cache without TTL. The capacity is
// interpreted as the MAX NUMBER OF ENTRIES (unit cost per entry), matching
// the legacy hashicorp/golang-lru semantics callers assume.
func newLRU[K lruKey, V any](capacity int) *lruCache[K, V] {
	return newCache[K, V](capacity, 0)
}

// newLRUWithTTL creates a concurrency-safe cache with per-entry expiration.
// A Get on an expired entry returns miss (ristretto's GC tick reclaims the
// row in the background).
func newLRUWithTTL[K lruKey, V any](capacity int, ttl time.Duration) *lruCache[K, V] {
	return newCache[K, V](capacity, ttl)
}

func newCache[K lruKey, V any](capacity int, ttl time.Duration) *lruCache[K, V] {
	if capacity <= 0 {
		capacity = 1
	}
	// NumCounters: ristretto recommends ~10× expected cache size for good
	// TinyLFU admission accuracy. We clamp below to avoid pathological 0/1
	// cases on tiny caches.
	numCounters := int64(capacity) * 10
	if numCounters < 128 {
		numCounters = 128
	}
	c, err := ristretto.NewCache(&ristretto.Config[K, V]{
		NumCounters: numCounters,
		MaxCost:     int64(capacity),
		BufferItems: 64,
		// IgnoreInternalCost: ristretto normally adds ~56 B per entry to
		// account for its own bookkeeping; our callers pass Cost=1 and
		// treat MaxCost as "number of entries", so we turn the internal
		// accounting off to preserve that contract.
		IgnoreInternalCost: true,
	})
	if err != nil {
		// ristretto.NewCache only errors on invalid config; with the
		// constants above that is impossible, but keep a defensive panic
		// so a future refactor that breaks invariants surfaces loudly
		// instead of returning a nil cache.
		panic("smart: ristretto init failed: " + err.Error())
	}
	lc := &lruCache[K, V]{
		inner:     c,
		ttl:       ttl,
		keysIndex: xsync.NewMapOf[K, struct{}](),
	}
	lc.capacity.Store(int64(capacity))
	return lc
}

// Get returns (value, true) on hit, (zero, false) on miss.
func (c *lruCache[K, V]) Get(key K) (V, bool) {
	return c.inner.Get(key)
}

// Set inserts or updates an entry. ristretto may reject the Set if the
// admission policy deems the key not hot enough; we still record the key
// in keysIndex so RemoveByPrefix can find and clear it.
//
// Asynchronous: the value becomes visible after ristretto's internal
// ring buffer drains (sub-millisecond). Call Wait() if you need sync.
func (c *lruCache[K, V]) Set(key K, value V) {
	c.keysIndex.Store(key, struct{}{})
	if c.ttl > 0 {
		c.inner.SetWithTTL(key, value, 1, c.ttl)
		return
	}
	c.inner.Set(key, value, 1)
}

// Delete removes an entry; no-op when missing.
func (c *lruCache[K, V]) Delete(key K) {
	c.inner.Del(key)
	c.keysIndex.Delete(key)
}

// Clear empties the cache and the key index. Internally ristretto
// rebuilds its state, which is cheap relative to the per-key churn the
// Smart store already performs on a group-wide flush.
func (c *lruCache[K, V]) Clear() {
	c.inner.Clear()
	// xsync.MapOf has no Clear on v3 ≤ 3.0.x and a Clear on 3.1+; the
	// Range-Delete loop works on both versions and costs O(N) with
	// N ≤ MaxCost, which is bounded by design.
	c.keysIndex.Range(func(k K, _ struct{}) bool {
		c.keysIndex.Delete(k)
		return true
	})
}

// Resize changes the cost budget. ristretto evicts in the background
// until the total cost drops under the new ceiling.
func (c *lruCache[K, V]) Resize(newCapacity int) {
	if newCapacity <= 0 {
		newCapacity = 1
	}
	c.capacity.Store(int64(newCapacity))
	c.inner.UpdateMaxCost(int64(newCapacity))
}

// Cap returns the current configured capacity. Surfaced for ops/debug.
func (c *lruCache[K, V]) Cap() int {
	return int(c.capacity.Load())
}

// Wait blocks until every Set queued so far has been processed by the
// ristretto worker. Only useful in tests that need read-your-write
// semantics; production code should treat the cache as best-effort.
func (c *lruCache[K, V]) Wait() {
	c.inner.Wait()
}

// Close releases background resources. Kept for completeness — the Smart
// store's caches are process-scoped and Close is not part of the hot
// lifecycle, but unit tests and cache-swap code paths need it.
func (c *lruCache[K, V]) Close() {
	if c.inner != nil {
		c.inner.Close()
	}
}

// RemoveByPrefix removes all entries whose string key has the given prefix.
// Implemented by walking keysIndex (bounded by MaxCost) rather than the
// underlying ristretto, which has no key iterator. Zombie entries — keys
// evicted by the admission policy but still in keysIndex — are cleaned up
// incidentally.
func (c *lruCache[K, V]) RemoveByPrefix(prefix string) {
	// Collect first so we don't mutate while Range is walking.
	var drop []K
	c.keysIndex.Range(func(k K, _ struct{}) bool {
		if s, ok := any(k).(string); ok && strings.HasPrefix(s, prefix) {
			drop = append(drop, k)
		}
		return true
	})
	if len(drop) == 0 {
		return
	}
	for _, k := range drop {
		c.inner.Del(k)
		c.keysIndex.Delete(k)
	}
}

// sinkMu exists so tests that care about the ordering of Set visibility
// can serialise Set→Wait→Get sequences across goroutines without
// depending on the cache's own synchronization internals. Exported
// getter (`sinkLock`) kept unexported for the same reason — it's a
// test affordance, not a public API.
var sinkMu sync.Mutex

// sinkLock returns the test-only serialisation mutex. Unexported.
//
//nolint:unused
func sinkLock() *sync.Mutex { return &sinkMu }
