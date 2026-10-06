package wire

import (
	"errors"
	"sync"
	"time"
)

// ReassemblyDropReason is why a fragment was dropped during reassembly.
type ReassemblyDropReason int

const (
	// ReassemblyDropNone indicates that no fragment was dropped.
	ReassemblyDropNone ReassemblyDropReason = iota
	// ReassemblyDropMetadataConflict indicates fragment metadata disagrees with the slot.
	ReassemblyDropMetadataConflict
	// ReassemblyDropDuplicateConflict indicates a duplicate fragment has different bytes.
	ReassemblyDropDuplicateConflict
	// ReassemblyDropByteLimit indicates the slot or byte resource limit was reached.
	ReassemblyDropByteLimit
	// ReassemblyDropInvalidLength indicates the declared length conflicts with the payload.
	ReassemblyDropInvalidLength
)

// String returns a stable label for diagnostics.
func (r ReassemblyDropReason) String() string {
	switch r {
	case ReassemblyDropMetadataConflict:
		return "metadata_conflict"
	case ReassemblyDropDuplicateConflict:
		return "duplicate_conflict"
	case ReassemblyDropByteLimit:
		return "byte_limit"
	case ReassemblyDropInvalidLength:
		return "invalid_length"
	default:
		return "none"
	}
}

// ReassemblyConfig bounds application-layer UDP fragment reassembly.
type ReassemblyConfig struct {
	MaxSlots int
	MaxBytes int
	TTL      time.Duration
}

// DefaultReassemblyConfig matches the Rust defaults.
func DefaultReassemblyConfig() ReassemblyConfig {
	return ReassemblyConfig{MaxSlots: 64, MaxBytes: 1024 * 1024, TTL: 10 * time.Second}
}

// ReassemblyOutcome reports the result of pushing one fragment.
type ReassemblyOutcome struct {
	Done           bool
	Payload        []byte
	Reservation    ByteReservation
	EvictedPartial bool
	DropReason     ReassemblyDropReason
}

// ByteReservation owns bytes charged to a shared session budget. Release must
// be idempotent because shutdown and consumer cancellation may race.
type ByteReservation interface {
	Release()
}

// ByteReservationFactory reserves n bytes only when a new reassembly slot is
// created. A false result rejects the slot without retaining fragment data.
type ByteReservationFactory func(n int) (ByteReservation, bool)

type reassemblyKey struct {
	flowID   FlowID
	packetID uint32
}

type reassemblySlot struct {
	createdAt   time.Time
	fragmentCnt uint8
	totalLen    uint16
	fragments   [][]byte
	received    int
	retained    int
	reservation ByteReservation
}

// DatagramReassembler is a bounded, timeout-aware fragment reassembler. The
// zero value is NOT safe; construct with NewDatagramReassembler.
type DatagramReassembler struct {
	cfg   ReassemblyConfig
	mu    sync.Mutex
	slots map[reassemblyKey]*reassemblySlot
	bytes int
}

// NewDatagramReassembler constructs a reassembler with the given config.
func NewDatagramReassembler(cfg ReassemblyConfig) (*DatagramReassembler, error) {
	if cfg.MaxSlots <= 0 {
		return nil, errors.New("nowhere: reassembly MaxSlots must be positive")
	}
	if cfg.MaxBytes <= 0 {
		return nil, errors.New("nowhere: reassembly MaxBytes must be positive")
	}
	if cfg.TTL <= 0 {
		return nil, errors.New("nowhere: reassembly TTL must be positive")
	}
	return &DatagramReassembler{cfg: cfg, slots: make(map[reassemblyKey]*reassemblySlot)}, nil
}

// SlotCount returns the number of in-flight partial packets.
func (r *DatagramReassembler) SlotCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.slots)
}

// ReservedBytes returns the total declared bytes reserved by partial packets.
func (r *DatagramReassembler) ReservedBytes() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bytes
}

// RemoveFlow releases every partial packet belonging to one flow.
func (r *DatagramReassembler) RemoveFlow(flowID FlowID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, slot := range r.slots {
		if key.flowID == flowID {
			r.bytes -= int(slot.totalLen)
			releaseReservation(slot.reservation)
			delete(r.slots, key)
		}
	}
	if r.bytes < 0 {
		r.bytes = 0
	}
}

// Clear releases every partial packet.
func (r *DatagramReassembler) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, slot := range r.slots {
		releaseReservation(slot.reservation)
	}
	r.slots = make(map[reassemblyKey]*reassemblySlot)
	r.bytes = 0
}

// Expire drops slots whose TTL has elapsed as of now. Returns whether any slot
// was dropped.
func (r *DatagramReassembler) Expire(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	dropped := false
	for key, slot := range r.slots {
		if now.Sub(slot.createdAt) > r.cfg.TTL {
			r.bytes -= int(slot.totalLen)
			releaseReservation(slot.reservation)
			delete(r.slots, key)
			dropped = true
		}
	}
	if r.bytes < 0 {
		r.bytes = 0
	}
	return dropped
}

// Push records one fragment. Identical duplicates are ignored; metadata or
// byte conflicts drop the whole slot.
func (r *DatagramReassembler) Push(flowID FlowID, fragment UDPFragment, now time.Time) ReassemblyOutcome {
	fragment.Payload = append([]byte(nil), fragment.Payload...)
	return r.pushOwned(flowID, fragment, now, nil)
}

// PushWithReservation takes ownership of fragment.Payload. For a new slot it
// calls reserve with the declared total packet length. On completion the
// reservation is transferred to the outcome; callers must release it after the
// completed payload is consumed or discarded.
func (r *DatagramReassembler) PushWithReservation(flowID FlowID, fragment UDPFragment, now time.Time, reserve ByteReservationFactory) ReassemblyOutcome {
	return r.pushOwned(flowID, fragment, now, reserve)
}

func (r *DatagramReassembler) pushOwned(flowID FlowID, fragment UDPFragment, now time.Time, reserve ByteReservationFactory) ReassemblyOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()

	if flowID == 0 || fragment.PacketID == 0 {
		return ReassemblyOutcome{DropReason: ReassemblyDropInvalidLength}
	}
	if err := validateFragmentMetadata(fragment); err != nil {
		return ReassemblyOutcome{DropReason: ReassemblyDropInvalidLength}
	}
	if len(fragment.Payload) == 0 ||
		len(fragment.Payload)+int(fragment.FragmentCount)-1 > int(fragment.TotalLen) {
		return ReassemblyOutcome{DropReason: ReassemblyDropInvalidLength}
	}

	key := reassemblyKey{flowID: flowID, packetID: fragment.PacketID}
	outcome := ReassemblyOutcome{EvictedPartial: r.expireLocked(now)}

	if slot, ok := r.slots[key]; ok {
		if slot.fragmentCnt != fragment.FragmentCount || slot.totalLen != fragment.TotalLen {
			r.removeSlotLocked(key)
			return ReassemblyOutcome{EvictedPartial: outcome.EvictedPartial, DropReason: ReassemblyDropMetadataConflict}
		}
		idx := int(fragment.FragmentIndex)
		if existing := slot.fragments[idx]; existing != nil {
			if !equalBytes(existing, fragment.Payload) {
				r.removeSlotLocked(key)
				return ReassemblyOutcome{EvictedPartial: outcome.EvictedPartial, DropReason: ReassemblyDropDuplicateConflict}
			}
			return outcome // identical duplicate ignored
		}
		retained := slot.retained + len(fragment.Payload)
		if retained > int(slot.totalLen) {
			r.removeSlotLocked(key)
			return ReassemblyOutcome{EvictedPartial: outcome.EvictedPartial, DropReason: ReassemblyDropInvalidLength}
		}
		slot.fragments[idx] = fragment.Payload
		slot.received++
		slot.retained = retained
		if slot.received < int(slot.fragmentCnt) {
			return outcome
		}
		// Complete: reassemble and release the slot.
		if slot.retained != int(slot.totalLen) {
			r.removeSlotLocked(key)
			return ReassemblyOutcome{EvictedPartial: outcome.EvictedPartial, DropReason: ReassemblyDropInvalidLength}
		}
		payload := make([]byte, 0, slot.totalLen)
		for _, frag := range slot.fragments {
			if frag == nil {
				r.removeSlotLocked(key)
				return ReassemblyOutcome{EvictedPartial: outcome.EvictedPartial, DropReason: ReassemblyDropInvalidLength}
			}
			payload = append(payload, frag...)
		}
		reservation := r.takeSlotLocked(key)
		outcome.Done = true
		outcome.Payload = payload
		outcome.Reservation = reservation
		return outcome
	}

	// New slot.
	if r.cfg.MaxSlots == 0 || int(fragment.TotalLen) > r.cfg.MaxBytes {
		return ReassemblyOutcome{DropReason: ReassemblyDropByteLimit}
	}
	if len(r.slots) >= r.cfg.MaxSlots {
		// evict the oldest partial
		var oldestKey reassemblyKey
		var oldestHas bool
		var oldestTime time.Time
		for k, s := range r.slots {
			if !oldestHas || s.createdAt.Before(oldestTime) {
				oldestKey, oldestTime, oldestHas = k, s.createdAt, true
			}
		}
		if oldestHas {
			r.removeSlotLocked(oldestKey)
			outcome.EvictedPartial = true
		}
	}
	if r.bytes+int(fragment.TotalLen) > r.cfg.MaxBytes {
		return ReassemblyOutcome{EvictedPartial: outcome.EvictedPartial, DropReason: ReassemblyDropByteLimit}
	}
	var reservation ByteReservation
	if reserve != nil {
		var ok bool
		reservation, ok = reserve(int(fragment.TotalLen))
		if !ok {
			return ReassemblyOutcome{EvictedPartial: outcome.EvictedPartial, DropReason: ReassemblyDropByteLimit}
		}
	}
	slot := &reassemblySlot{
		createdAt:   now,
		fragmentCnt: fragment.FragmentCount,
		totalLen:    fragment.TotalLen,
		fragments:   make([][]byte, fragment.FragmentCount),
		received:    1,
		retained:    len(fragment.Payload),
		reservation: reservation,
	}
	slot.fragments[fragment.FragmentIndex] = fragment.Payload
	r.slots[key] = slot
	r.bytes += int(fragment.TotalLen)
	return outcome
}

func (r *DatagramReassembler) removeSlotLocked(key reassemblyKey) {
	if slot, ok := r.slots[key]; ok {
		r.bytes -= int(slot.totalLen)
		if r.bytes < 0 {
			r.bytes = 0
		}
		releaseReservation(slot.reservation)
		delete(r.slots, key)
	}
}

func (r *DatagramReassembler) takeSlotLocked(key reassemblyKey) ByteReservation {
	slot, ok := r.slots[key]
	if !ok {
		return nil
	}
	r.bytes -= int(slot.totalLen)
	if r.bytes < 0 {
		r.bytes = 0
	}
	delete(r.slots, key)
	return slot.reservation
}

func (r *DatagramReassembler) expireLocked(now time.Time) bool {
	dropped := false
	for key, slot := range r.slots {
		if now.Sub(slot.createdAt) > r.cfg.TTL {
			r.bytes -= int(slot.totalLen)
			releaseReservation(slot.reservation)
			delete(r.slots, key)
			dropped = true
		}
	}
	if r.bytes < 0 {
		r.bytes = 0
	}
	return dropped
}

func releaseReservation(reservation ByteReservation) {
	if reservation != nil {
		reservation.Release()
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
