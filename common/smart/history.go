package smart

import "sync"

// historyKey identifies the incumbent of one selection context.
type historyKey struct {
	group   uint32
	target  uint64 // exact target hash, 0 for targetless reads
	network Network
	family  Family
}

type historyEntry struct {
	current   uint32
	previous  uint32
	sinceSwap uint32 // ordinary choices since current replaced previous
	valid     bool
	touched   Mono
}

const historyShards = 16

type historyShard struct {
	access  sync.Mutex
	entries map[historyKey]*historyEntry
}

// history remembers each context's ordinary winner (the incumbent), so a
// trained incumbent is held until a challenger proves a real gain.
type history struct {
	shards   [historyShards]historyShard
	perShard int
}

func newHistory(capacity int) *history {
	h := &history{perShard: max(capacity/historyShards, 8)}
	for i := range h.shards {
		h.shards[i].entries = make(map[historyKey]*historyEntry)
	}
	return h
}

func (h *history) shard(key historyKey) *historyShard {
	x := uint64(key.group)*0x9E3779B97F4A7C15 ^ key.target ^ uint64(key.network)<<60 ^ uint64(key.family)<<56
	x ^= x >> 29
	return &h.shards[x%historyShards]
}

func (h *history) incumbent(key historyKey, now Mono) (uint32, bool) {
	s := h.shard(key)
	s.access.Lock()
	defer s.access.Unlock()
	e := s.entries[key]
	if e == nil || !e.valid {
		return 0, false
	}
	e.touched = now
	return e.current, true
}

// commit records an ordinary choice and reports whether it switched the
// incumbent and whether the switch returned to the previous winner within
// the flap window.
func (h *history) commit(key historyKey, node uint32, now Mono) (switched, flap bool) {
	s := h.shard(key)
	s.access.Lock()
	defer s.access.Unlock()
	e := s.entries[key]
	if e == nil {
		if len(s.entries) >= h.perShard {
			var (
				victim historyKey
				oldest Mono
				n      int
			)
			for k, v := range s.entries {
				if n == 0 || v.touched < oldest {
					victim, oldest = k, v.touched
				}
				n++
				if n == evictSample {
					break
				}
			}
			delete(s.entries, victim)
		}
		e = &historyEntry{}
		s.entries[key] = e
	}
	e.touched = now
	if !e.valid {
		e.current, e.valid = node, true
		return false, false
	}
	if e.current == node {
		if e.sinceSwap < switchFlapWindow {
			e.sinceSwap++
		}
		return false, false
	}
	flap = e.previous == node && e.sinceSwap < switchFlapWindow
	e.previous, e.current, e.sinceSwap = e.current, node, 0
	return true, flap
}

func (h *history) deleteGroup(group uint32) {
	for i := range h.shards {
		s := &h.shards[i]
		s.access.Lock()
		for k := range s.entries {
			if k.group == group {
				delete(s.entries, k)
			}
		}
		s.access.Unlock()
	}
}

func (h *history) deleteNode(group, node uint32) {
	for i := range h.shards {
		s := &h.shards[i]
		s.access.Lock()
		for k, e := range s.entries {
			if k.group == group && e.current == node {
				delete(s.entries, k)
			}
		}
		s.access.Unlock()
	}
}

func (h *history) deleteTarget(group uint32, target uint64) {
	for i := range h.shards {
		s := &h.shards[i]
		s.access.Lock()
		for k := range s.entries {
			if k.group == group && k.target == target {
				delete(s.entries, k)
			}
		}
		s.access.Unlock()
	}
}
