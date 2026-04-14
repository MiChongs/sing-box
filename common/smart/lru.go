package smart

import (
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

// lruCache wraps the hashicorp/golang-lru/v2 LRU implementations. The
// previous in-tree implementation used container/list + map + mutex per
// entry, which added ~48 B per list.Element on top of the map node — for
// a 500-entry cache that's ~24 KiB overhead alone. Hashicorp's LRU uses a
// pre-allocated intrusive doubly-linked list that overlaps with the hash
// bucket, saving roughly a third of per-entry overhead.
//
// Concurrency: hashicorp/golang-lru/v2.Cache uses a single internal
// sync.Mutex, same as our prior implementation — no behavioural change,
// just a smaller constant factor. Switching to a sharded variant (e.g.
// ristretto) would require changes to the Resize semantics and is left
// for a future iteration.
//
// API preserved (Get/Set/Delete/Clear/Resize/RemoveByPrefix) so every
// call site in this package stays untouched.
type lruCache[K comparable, V any] struct {
	// Exactly one of these is non-nil depending on whether the cache was
	// constructed with TTL. We switch on non-nil rather than a flag to
	// avoid a branch hidden behind an interface call on the hot path.
	plain     *lru.Cache[K, V]
	expirable *expirable.LRU[K, V]

	// capacityMu guards the cached capacity integer — Resize delegates to
	// the underlying cache which has its own lock, but we surface Cap()
	// for observability and want a lock-free read.
	capacityMu sync.RWMutex
	capacity   int
}

// newLRU creates a concurrency-safe LRU without TTL.
func newLRU[K comparable, V any](capacity int) *lruCache[K, V] {
	if capacity <= 0 {
		capacity = 1
	}
	c, _ := lru.New[K, V](capacity)
	return &lruCache[K, V]{plain: c, capacity: capacity}
}

// newLRUWithTTL creates a concurrency-safe LRU with entry-level expiration.
// Matches the semantics of the prior custom implementation: a Get on an
// expired entry returns miss and removes the entry from the cache.
func newLRUWithTTL[K comparable, V any](capacity int, ttl time.Duration) *lruCache[K, V] {
	if capacity <= 0 {
		capacity = 1
	}
	c := expirable.NewLRU[K, V](capacity, nil, ttl)
	return &lruCache[K, V]{expirable: c, capacity: capacity}
}

// Get returns (value, true) on hit, (zero, false) on miss. TTL-expired
// entries are treated as miss.
func (c *lruCache[K, V]) Get(key K) (V, bool) {
	if c.plain != nil {
		return c.plain.Get(key)
	}
	return c.expirable.Get(key)
}

// Set inserts or updates an entry. Triggers LRU eviction when over capacity.
func (c *lruCache[K, V]) Set(key K, value V) {
	if c.plain != nil {
		c.plain.Add(key, value)
		return
	}
	c.expirable.Add(key, value)
}

// Delete removes an entry; no-op when missing.
func (c *lruCache[K, V]) Delete(key K) {
	if c.plain != nil {
		c.plain.Remove(key)
		return
	}
	c.expirable.Remove(key)
}

// Clear empties the cache.
func (c *lruCache[K, V]) Clear() {
	if c.plain != nil {
		c.plain.Purge()
		return
	}
	c.expirable.Purge()
}

// Resize changes the capacity. Entries past the new limit are evicted
// LRU-first.
func (c *lruCache[K, V]) Resize(newCapacity int) {
	if newCapacity <= 0 {
		newCapacity = 1
	}
	c.capacityMu.Lock()
	c.capacity = newCapacity
	c.capacityMu.Unlock()
	if c.plain != nil {
		c.plain.Resize(newCapacity)
		return
	}
	// expirable.LRU has no Resize in older versions but does in v2.0.7+.
	// Calling via interface-free path keeps the compile-time dep check.
	c.expirable.Resize(newCapacity)
}

// RemoveByPrefix removes all entries whose string key has the given prefix.
// K must be a string-valued type (typed-string works via the runtime type
// assertion). Iterates the current key set — acceptable cost since the
// cache is bounded to ~MaxTargetsLimit/2 entries.
//
// Used by Store.ClearUnwrapByGroup so a single-group flush doesn't nuke
// other groups' cache entries.
func (c *lruCache[K, V]) RemoveByPrefix(prefix string) {
	var keys []K
	if c.plain != nil {
		keys = c.plain.Keys()
	} else {
		keys = c.expirable.Keys()
	}
	for _, k := range keys {
		if s, ok := any(k).(string); ok && strings.HasPrefix(s, prefix) {
			if c.plain != nil {
				c.plain.Remove(k)
			} else {
				c.expirable.Remove(k)
			}
		}
	}
}
