package smart

import (
	"container/list"
	"sync"
	"time"
)

type lruEntry[K comparable, V any] struct {
	key       K
	value     V
	expiresAt time.Time
}

// lruCache is a simple goroutine-safe LRU cache with optional TTL.
type lruCache[K comparable, V any] struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	items    map[K]*list.Element
	order    *list.List
}

func newLRU[K comparable, V any](capacity int) *lruCache[K, V] {
	return &lruCache[K, V]{
		capacity: capacity,
		items:    make(map[K]*list.Element),
		order:    list.New(),
	}
}

func newLRUWithTTL[K comparable, V any](capacity int, ttl time.Duration) *lruCache[K, V] {
	return &lruCache[K, V]{
		capacity: capacity,
		ttl:      ttl,
		items:    make(map[K]*list.Element),
		order:    list.New(),
	}
}

func (c *lruCache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	entry := el.Value.(*lruEntry[K, V])
	if c.ttl > 0 && !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		c.order.Remove(el)
		delete(c.items, key)
		var zero V
		return zero, false
	}
	c.order.MoveToFront(el)
	return entry.value, true
}

func (c *lruCache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.MoveToFront(el)
		entry := el.Value.(*lruEntry[K, V])
		entry.value = value
		if c.ttl > 0 {
			entry.expiresAt = time.Now().Add(c.ttl)
		}
		return
	}
	entry := &lruEntry[K, V]{key: key, value: value}
	if c.ttl > 0 {
		entry.expiresAt = time.Now().Add(c.ttl)
	}
	el := c.order.PushFront(entry)
	c.items[key] = el
	if c.order.Len() > c.capacity && c.capacity > 0 {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.items, oldest.Value.(*lruEntry[K, V]).key)
		}
	}
}

func (c *lruCache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
}

func (c *lruCache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[K]*list.Element)
	c.order.Init()
}

func (c *lruCache[K, V]) Resize(newCapacity int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.capacity = newCapacity
	for c.order.Len() > newCapacity && newCapacity > 0 {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*lruEntry[K, V]).key)
	}
}

// RemoveByPrefix removes all entries whose string key has the given prefix.
// K must be string to use this method (called via type assertion internally).
func (c *lruCache[K, V]) RemoveByPrefix(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var toRemove []*list.Element
	for el := c.order.Front(); el != nil; el = el.Next() {
		entry := el.Value.(*lruEntry[K, V])
		if k, ok := any(entry.key).(string); ok {
			if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
				toRemove = append(toRemove, el)
			}
		}
	}
	for _, el := range toRemove {
		entry := el.Value.(*lruEntry[K, V])
		c.order.Remove(el)
		delete(c.items, entry.key)
	}
}
