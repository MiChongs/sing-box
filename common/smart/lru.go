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

// lruEntry is what the cache actually stores: the caller's value plus the
// original key and a per-Set id. ristretto hands only key hashes to its
// eviction callbacks, so carrying the key in the value is what lets those
// callbacks keep keysIndex exact.
type lruEntry[K lruKey, V any] struct {
	key K
	id  uint64
	val V
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
// IterValues. RemoveByPrefix therefore requires its own key index.
// keysIndex is kept exact: Set/Delete/Clear maintain it directly, and the
// ristretto OnExit/OnReject callbacks drop a key once the entry that last
// claimed it is evicted, expires, loses admission or is dropped from the
// set buffer. Without the callbacks every key ever Set stayed indexed for
// the life of the process.
type lruCache[K lruKey, V any] struct {
	inner *ristretto.Cache[K, lruEntry[K, V]]
	ttl   time.Duration // 0 = no TTL

	// cost computes the byte cost of a value so ristretto's MaxCost budget
	// is a TRUE memory ceiling rather than an entry count. nil → every
	// entry costs 1 (the legacy "MaxCost = number of entries" contract,
	// kept for callers that genuinely want count-based bounding). When set,
	// MaxCost is interpreted as a byte budget and eviction tracks real
	// heap footprint, so a few large entries correctly displace many small
	// ones instead of all five caches silently overshooting the configured
	// SMART_CACHE_BUDGET_MB by the variance between assumed and actual
	// entry size.
	cost func(V) int64

	// keysIndex maps every key that is cached or awaiting admission to the
	// id of the newest entry Set for it. Callbacks only remove a key when
	// the departing entry still owns it, so a stale eviction never drops a
	// key that a later Set re-claimed. See the "Key-iteration gap" note.
	keysIndex *xsync.MapOf[K, uint64]
	nextID    atomic.Uint64

	// onRemove, when set, observes every value that leaves the cache or
	// never makes it in: eviction, expiry, admission rejection, set-buffer
	// drop, replacement by a newer Set, Delete and Clear. It runs on
	// ristretto's goroutines, sometimes under internal shard locks, so it
	// must not call back into this cache.
	onRemove func(V)

	// capacity shadows ristretto.MaxCost() for cheap Cap() reads. Stored
	// as atomic.Int64 instead of a mutex because it is written on Resize
	// and read on ad-hoc debug paths — contention-free either way. Holds
	// the byte budget when a cost fn is set, else the entry count.
	capacity atomic.Int64
}

// newLRUBytes creates a byte-budgeted cache: maxBytes is a real memory
// ceiling and costFn returns each value's approximate heap footprint.
func newLRUBytes[K lruKey, V any](maxBytes int64, costFn func(V) int64) *lruCache[K, V] {
	return newCacheCost[K, V](maxBytes, 0, byteBudgetCounters(maxBytes), costFn, nil)
}

// newLRUBytesWithTTL is newLRUBytes with per-entry expiration. A Get on an
// expired entry returns miss (ristretto's GC tick reclaims the row in the
// background).
func newLRUBytesWithTTL[K lruKey, V any](maxBytes int64, ttl time.Duration, costFn func(V) int64) *lruCache[K, V] {
	return newCacheCost[K, V](maxBytes, ttl, byteBudgetCounters(maxBytes), costFn, nil)
}

// byteBudgetCounters picks a TinyLFU counter count for a byte budget.
// ristretto wants ~10× the expected item count; we estimate item count
// from a conservative ~256 B average so admission accuracy stays high
// without over-allocating the 4-bit counter sketch.
func byteBudgetCounters(maxBytes int64) int64 {
	n := maxBytes / 26 // ≈ (maxBytes/256)*10
	if n < 1024 {
		n = 1024
	}
	return n
}

func newCacheCost[K lruKey, V any](maxCost int64, ttl time.Duration, numCounters int64, costFn func(V) int64, onRemove func(V)) *lruCache[K, V] {
	if maxCost <= 0 {
		maxCost = 1
	}
	if numCounters < 128 {
		numCounters = 128
	}
	lc := &lruCache[K, V]{
		ttl:       ttl,
		cost:      costFn,
		keysIndex: xsync.NewMapOf[K, uint64](),
		onRemove:  onRemove,
	}
	c, err := ristretto.NewCache(&ristretto.Config[K, lruEntry[K, V]]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: 64,
		// IgnoreInternalCost: ristretto normally adds ~56 B per entry for
		// its own bookkeeping. In entry-count mode (costFn==nil) callers
		// pass Cost=1 and treat MaxCost as "number of entries", so we keep
		// the internal accounting OFF to preserve that contract. In
		// byte-budget mode our cost fn already folds a per-entry overhead
		// into the returned cost, so we likewise keep it off and own the
		// full accounting ourselves — keeps the math predictable.
		IgnoreInternalCost: true,
		OnReject:           lc.onReject,
		OnExit:             lc.onExit,
	})
	if err != nil {
		// ristretto.NewCache only errors on invalid config; with the
		// constants above that is impossible, but keep a defensive panic
		// so a future refactor that breaks invariants surfaces loudly
		// instead of returning a nil cache.
		panic("smart: ristretto init failed: " + err.Error())
	}
	lc.inner = c
	lc.capacity.Store(maxCost)
	return lc
}

// onExit runs for every value ristretto lets go of. The key leaves
// keysIndex only when this entry was the last one Set for it — an entry
// replaced in place exits while its newer sibling keeps the key.
func (c *lruCache[K, V]) onExit(e lruEntry[K, V]) {
	if e.id == 0 {
		// Zero value: delete markers and misses carry no entry.
		return
	}
	c.forgetKey(e.key, e.id)
	if c.onRemove != nil {
		c.onRemove(e.val)
	}
}

// onReject handles the admission race where two Sets of a key that is not
// yet resident both enter the set buffer: the first is admitted, the
// second is rejected as a duplicate even though it was the latest Set.
// The key must stay indexed under the surviving entry, which a Get here
// (outside any shard lock) can see. onExit runs right after and finds the
// id no longer matches.
func (c *lruCache[K, V]) onReject(item *ristretto.Item[lruEntry[K, V]]) {
	e := item.Value
	if e.id == 0 {
		return
	}
	stored, ok := c.inner.Get(e.key)
	if !ok {
		return
	}
	c.keysIndex.Compute(e.key, func(cur uint64, loaded bool) (uint64, bool) {
		if loaded && cur == e.id {
			return stored.id, false
		}
		return cur, !loaded
	})
}

// forgetKey removes key from keysIndex if id is still its current owner.
func (c *lruCache[K, V]) forgetKey(key K, id uint64) {
	c.keysIndex.Compute(key, func(cur uint64, loaded bool) (uint64, bool) {
		if loaded && cur != id {
			return cur, false
		}
		return 0, true
	})
}

// Get returns (value, true) on hit, (zero, false) on miss.
func (c *lruCache[K, V]) Get(key K) (V, bool) {
	e, ok := c.inner.Get(key)
	return e.val, ok
}

// Set inserts or updates an entry. The key is indexed immediately so
// RemoveByPrefix can reach it while it awaits admission; the callbacks
// above un-index it if ristretto ends up not keeping it.
//
// Asynchronous: the value becomes visible after ristretto's internal
// ring buffer drains (sub-millisecond). Call Wait() if you need sync.
func (c *lruCache[K, V]) Set(key K, value V) {
	cost := int64(1)
	if c.cost != nil {
		cost = c.cost(value)
		if cost < 1 {
			cost = 1
		}
	}
	id := c.nextID.Add(1)
	c.keysIndex.Store(key, id)
	if !c.inner.SetWithTTL(key, lruEntry[K, V]{key: key, id: id, val: value}, cost, c.ttl) {
		// Dropped before reaching the admission policy (set buffer full);
		// ristretto fires no callback for these.
		c.forgetKey(key, id)
		if c.onRemove != nil {
			c.onRemove(value)
		}
	}
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
	c.keysIndex.Clear()
}

// Resize changes the cost budget (entry-count mode). ristretto evicts in
// the background until the total cost drops under the new ceiling.
func (c *lruCache[K, V]) Resize(newCapacity int) {
	c.ResizeBytes(int64(newCapacity))
}

// ResizeBytes changes the MaxCost budget using an int64 so byte budgets
// that exceed an int on 32-bit platforms are handled cleanly. Same effect
// as Resize otherwise.
func (c *lruCache[K, V]) ResizeBytes(newMaxCost int64) {
	if newMaxCost <= 0 {
		newMaxCost = 1
	}
	c.capacity.Store(newMaxCost)
	c.inner.UpdateMaxCost(newMaxCost)
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
// Implemented by walking keysIndex (exactly the resident and pending keys)
// rather than the underlying ristretto, which has no key iterator.
func (c *lruCache[K, V]) RemoveByPrefix(prefix string) {
	// Collect first so we don't mutate while Range is walking.
	var drop []K
	c.keysIndex.Range(func(k K, _ uint64) bool {
		if s, ok := any(k).(string); ok && strings.HasPrefix(s, prefix) {
			drop = append(drop, k)
		}
		return true
	})
	for _, k := range drop {
		c.Delete(k)
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
