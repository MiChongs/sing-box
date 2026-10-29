package morph

import "sync"

const (
	replayCapacity = 16384
	replayWindow   = 1024
)

// replayRegistry is the in-process Morph TCP replay table for one Portal key
// set. It keeps at most 16384 identities in strict insertion order and a
// 1024-counter window for each. There is no TTL, persistence, or nonce cache.
type replayRegistry struct {
	mu      sync.Mutex
	entries map[uint64]*replayEntry
	order   [replayCapacity]uint64
	start   int
	count   int
}

type replayEntry struct {
	highest uint64
	bitmap  [replayWindow / 64]uint64
}

func newReplayRegistry() *replayRegistry {
	return &replayRegistry{entries: make(map[uint64]*replayEntry)}
}

func (r *replayRegistry) precheck(identity, counter uint64) bool {
	if !counterValid(counter) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.entries[identity]
	if entry == nil {
		return true
	}
	return entry.accepts(counter)
}

func (r *replayRegistry) commit(identity, counter uint64) bool {
	if !counterValid(counter) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry := r.entries[identity]; entry != nil {
		if !entry.accepts(counter) {
			return false
		}
		entry.mark(counter)
		return true
	}
	if r.count == replayCapacity {
		oldest := r.order[r.start]
		delete(r.entries, oldest)
		r.start = (r.start + 1) % replayCapacity
		r.count--
	}
	entry := &replayEntry{highest: counter}
	entry.bitmap[0] = 1
	r.entries[identity] = entry
	r.order[(r.start+r.count)%replayCapacity] = identity
	r.count++
	return true
}

func counterValid(counter uint64) bool {
	return counter >= 1 && counter <= maxCounter
}

func (e *replayEntry) accepts(counter uint64) bool {
	if counter > e.highest {
		return true
	}
	distance := e.highest - counter
	return distance < replayWindow && e.bitmap[distance/64]&(1<<(distance%64)) == 0
}

func (e *replayEntry) mark(counter uint64) {
	if counter > e.highest {
		distance := counter - e.highest
		if distance >= replayWindow {
			for i := range e.bitmap {
				e.bitmap[i] = 0
			}
		} else {
			words := int(distance / 64)
			bits := uint(distance % 64)
			for index := len(e.bitmap) - 1; index >= 0; index-- {
				var value uint64
				if index >= words {
					value = e.bitmap[index-words] << bits
					if bits != 0 && index > words {
						value |= e.bitmap[index-words-1] >> (64 - bits)
					}
				}
				e.bitmap[index] = value
			}
		}
		e.highest = counter
	}
	distance := e.highest - counter
	e.bitmap[distance/64] |= 1 << (distance % 64)
}
