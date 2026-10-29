package smart

import (
	"sync"
	"sync/atomic"
)

// Layer names one level of the evidence hierarchy. A score blends global,
// family, site and exact evidence, each overriding its parent in proportion
// to its own useful completions.
type Layer uint8

const (
	LayerGlobal Layer = iota // (group, network, node)
	LayerFamily              // + target address family
	LayerSite                // + site: eTLD+1, or the target ASN with prefer_asn
	LayerExact               // + normalized target host:port
)

// Key identifies one cell. Scope is 0 for global and family cells, the
// site hash for site cells and the target hash for exact cells.
type Key struct {
	Group   uint32
	Node    uint32
	Scope   uint64
	Network Network
	Family  Family
	Layer   Layer
}

func (k Key) shard() uint64 {
	h := uint64(k.Group)*0x9E3779B97F4A7C15 ^ uint64(k.Node)*0xC2B2AE3D27D4EB4F ^ k.Scope ^ uint64(k.Layer)<<56 ^ uint64(k.Network)<<48 ^ uint64(k.Family)<<40
	h ^= h >> 31
	return h % tableShards
}

type tableShard struct {
	access sync.Mutex
	cells  map[Key]*Cell
	_      [40]byte // keep shards on separate cache lines
}

// Table is a sharded, bounded map of cells with approximate LRU eviction:
// a full shard evicts the least recently touched of a few sampled cells,
// so reads never take a write path just to bump recency.
type Table struct {
	shards   [tableShards]tableShard
	perShard int
	size     atomic.Int64
	evicted  atomic.Uint64
}

func NewTable(capacity int) *Table {
	t := &Table{perShard: max(capacity/tableShards, 8)}
	for i := range t.shards {
		t.shards[i].cells = make(map[Key]*Cell)
	}
	return t
}

// Peek calls fn with the cell for key under the shard lock, or with nil.
func (t *Table) Peek(key Key, now Mono, fn func(*Cell)) {
	s := &t.shards[key.shard()]
	s.access.Lock()
	c := s.cells[key]
	if c != nil {
		c.touched = now
	}
	fn(c)
	s.access.Unlock()
}

// Update calls fn with the cell for key under the shard lock, creating it
// when absent.
func (t *Table) Update(key Key, now Mono, fn func(*Cell)) {
	s := &t.shards[key.shard()]
	s.access.Lock()
	c := s.cells[key]
	if c == nil {
		if len(s.cells) >= t.perShard {
			t.evictLocked(s)
		}
		c = &Cell{}
		s.cells[key] = c
		t.size.Add(1)
	}
	c.touched = now
	fn(c)
	s.access.Unlock()
}

const evictSample = 8

func (t *Table) evictLocked(s *tableShard) {
	var (
		victim  Key
		oldest  Mono
		sampled int
	)
	// Map iteration order is randomized, so the first entries are a sample.
	for key, c := range s.cells {
		if sampled == 0 || c.touched < oldest {
			victim, oldest = key, c.touched
		}
		sampled++
		if sampled == evictSample {
			break
		}
	}
	if sampled > 0 {
		delete(s.cells, victim)
		t.size.Add(-1)
		t.evicted.Add(1)
	}
}

// Range calls fn for every cell. fn runs under the shard lock and must not
// call back into the table.
func (t *Table) Range(fn func(Key, *Cell) bool) {
	for i := range t.shards {
		s := &t.shards[i]
		s.access.Lock()
		for key, c := range s.cells {
			if !fn(key, c) {
				s.access.Unlock()
				return
			}
		}
		s.access.Unlock()
	}
}

// DeleteFunc removes every cell for which fn returns true.
func (t *Table) DeleteFunc(fn func(Key, *Cell) bool) int {
	var removed int
	for i := range t.shards {
		s := &t.shards[i]
		s.access.Lock()
		for key, c := range s.cells {
			if fn(key, c) {
				delete(s.cells, key)
				removed++
			}
		}
		s.access.Unlock()
	}
	t.size.Add(-int64(removed))
	return removed
}

func (t *Table) Len() int        { return int(t.size.Load()) }
func (t *Table) Evicted() uint64 { return t.evicted.Load() }
