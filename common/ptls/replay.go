package ptls

import (
	"sync"
	"time"
)

type ReplayCache struct {
	shards     [16]sync.Mutex
	current    [16]map[[24]byte]struct{}
	previous   [16]map[[24]byte]struct{}
	lastRotate [16]time.Time
	maxSize    int
	tolerance  time.Duration
}

func NewReplayCache(maxSize int, tolerance time.Duration) *ReplayCache {
	if maxSize <= 0 {
		maxSize = 65536
	}
	shardMax := maxSize / 16
	if shardMax < 1 {
		shardMax = 1
	}
	c := &ReplayCache{
		maxSize:   shardMax,
		tolerance: tolerance,
	}
	now := time.Now()
	for i := 0; i < 16; i++ {
		c.current[i] = make(map[[24]byte]struct{})
		c.previous[i] = make(map[[24]byte]struct{})
		c.lastRotate[i] = now
	}
	return c
}

func (c *ReplayCache) CheckAndAdd(tag []byte, now time.Time) bool {
	if len(tag) != 24 {
		return false
	}
	var key [24]byte
	copy(key[:], tag)

	shard := key[0] & 0x0F
	c.shards[shard].Lock()
	defer c.shards[shard].Unlock()

	if now.Before(c.lastRotate[shard]) {
		c.lastRotate[shard] = now
	} else {
		elapsed := now.Sub(c.lastRotate[shard])
		if elapsed >= c.tolerance*2 {
			c.previous[shard] = make(map[[24]byte]struct{})
			c.current[shard] = make(map[[24]byte]struct{})
			c.lastRotate[shard] = now
		} else if elapsed >= c.tolerance || len(c.current[shard]) >= c.maxSize {
			c.previous[shard] = c.current[shard]
			c.current[shard] = make(map[[24]byte]struct{})
			c.lastRotate[shard] = now
		}
	}

	if _, exists := c.current[shard][key]; exists {
		return false
	}
	if _, exists := c.previous[shard][key]; exists {
		return false
	}

	c.current[shard][key] = struct{}{}
	return true
}