package smart

import "sync"

// stringCache is a bounded string map that drops a random half when full;
// it memoizes pure functions, so losing entries only costs recomputation.
type stringCache struct {
	access sync.RWMutex
	limit  int
	values map[string]string
}

func newStringCache(limit int) *stringCache {
	return &stringCache{limit: limit, values: make(map[string]string)}
}

func (c *stringCache) get(key string) (string, bool) {
	c.access.RLock()
	v, ok := c.values[key]
	c.access.RUnlock()
	return v, ok
}

func (c *stringCache) put(key, value string) {
	c.access.Lock()
	if len(c.values) >= c.limit {
		n := 0
		for k := range c.values {
			delete(c.values, k)
			n++
			if n >= c.limit/2 {
				break
			}
		}
	}
	c.values[key] = value
	c.access.Unlock()
}
