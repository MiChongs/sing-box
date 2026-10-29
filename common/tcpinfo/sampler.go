package tcpinfo

import (
	"sync"
	"time"
)

// The sampler holds increments until the window clears this floor.
const (
	lossWindowMinSegs   = 64
	lossWindowMinBytes  = 64 << 10
	lossSamplerCapacity = 4096
	lossSamplerTTL      = 30 * time.Minute
)

// TotalRetrans is the retransmitted volume in the unit of Sent.
func (i Info) TotalRetrans() uint64 { return i.Retransmitted() }

func (i Info) meetsLossWindowFloor() bool {
	if i.SegsOut > 0 {
		return i.SegsOut >= lossWindowMinSegs
	}
	return i.BytesSent >= lossWindowMinBytes
}

type lossSamplerEntry struct {
	segs         uint64 // counters at the last judged window
	retransSegs  uint64
	bytesSent    uint64
	bytesRetrans uint64
	updated      time.Time
}

// LossSampler judges one socket's counters in windows (vernesong/mihomo
// tcpstats): increments below the window floor are held and accumulate, and
// a judged window is consumed exactly once, so streams multiplexed over one
// socket do not judge the same retransmissions twice.
type LossSampler struct {
	access  sync.Mutex
	entries map[uint64]lossSamplerEntry
}

func NewLossSampler() *LossSampler {
	return &LossSampler{entries: make(map[uint64]lossSamplerEntry)}
}

// Consume returns the judged window this read completes, or false while the
// counters are still below the floor.
func (s *LossSampler) Consume(source uint64, info Info) (Info, bool) {
	if s == nil || source == 0 {
		return info, info.meetsLossWindowFloor()
	}
	now := time.Now()
	s.access.Lock()
	defer s.access.Unlock()
	entry, known := s.entries[source]
	if known && (info.SegsOut < entry.segs ||
		info.RetransSegs < entry.retransSegs ||
		info.BytesSent < entry.bytesSent ||
		info.BytesRetrans < entry.bytesRetrans) {
		// Counters going backwards mean the pointer now holds a fresh socket.
		known = false
	}
	if known && now.Sub(entry.updated) > lossSamplerTTL {
		known = false
	}
	if !known {
		if len(s.entries) >= lossSamplerCapacity {
			s.evictLocked(now)
		}
		entry = lossSamplerEntry{}
	}
	entry.updated = now
	window := Info{
		SegsOut:      info.SegsOut - entry.segs,
		RetransSegs:  info.RetransSegs - entry.retransSegs,
		BytesSent:    info.BytesSent - entry.bytesSent,
		BytesRetrans: info.BytesRetrans - entry.bytesRetrans,
	}
	if !window.meetsLossWindowFloor() {
		s.entries[source] = entry
		return Info{}, false
	}
	s.entries[source] = lossSamplerEntry{
		segs:         info.SegsOut,
		retransSegs:  info.RetransSegs,
		bytesSent:    info.BytesSent,
		bytesRetrans: info.BytesRetrans,
		updated:      now,
	}
	return window, true
}

func (s *LossSampler) evictLocked(now time.Time) {
	for key, entry := range s.entries {
		if now.Sub(entry.updated) > lossSamplerTTL {
			delete(s.entries, key)
		}
	}
	for key := range s.entries {
		if len(s.entries) < lossSamplerCapacity {
			break
		}
		delete(s.entries, key)
	}
}
