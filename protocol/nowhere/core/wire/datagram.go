package wire

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

const (
	udpHeaderLen         = 4
	udpFragmentHeaderLen = 12
	udpPacketMax         = 65535

	frameData      = 0
	frameFragment  = 1
	frameClose     = 2
	frameTypeShift = 30
)

// Datagram is one decoded QUIC UDP frame.
type Datagram struct {
	Type     uint8
	FlowID   uint32
	Payload  []byte
	PacketID uint32
	Index    uint8
	Count    uint8
	Total    uint16
}

// EncodeData encodes one complete UDP payload. An empty payload is valid.
func EncodeData(flowID uint32, payload []byte) ([]byte, error) {
	if err := validateFlow(flowID); err != nil {
		return nil, err
	}
	if len(payload) > udpPacketMax {
		return nil, errors.New("nw3: UDP payload too large")
	}
	out := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint32(out[:4], (uint32(frameData)<<frameTypeShift)|flowID)
	copy(out[4:], payload)
	return out, nil
}

// EncodeClose encodes a 4-byte CLOSE frame.
func EncodeClose(flowID uint32) ([]byte, error) {
	if err := validateFlow(flowID); err != nil {
		return nil, err
	}
	var out [udpHeaderLen]byte
	binary.BigEndian.PutUint32(out[:], (uint32(frameClose)<<frameTypeShift)|flowID)
	return out[:], nil
}

// EncodePacket returns DATA when the payload fits, otherwise FRAGMENT frames.
// packetID must be nonzero when fragmentation is required. maxDatagram is the
// peer DATAGRAM limit including headers.
func EncodePacket(flowID, packetID uint32, payload []byte, maxDatagram int) ([][]byte, error) {
	if err := validateFlow(flowID); err != nil {
		return nil, err
	}
	if len(payload) > udpPacketMax {
		return nil, errors.New("nw3: UDP payload too large")
	}
	if maxDatagram < udpHeaderLen {
		return nil, errors.New("nw3: DATAGRAM limit has no payload capacity")
	}
	if len(payload) <= maxDatagram-udpHeaderLen {
		frame, err := EncodeData(flowID, payload)
		if err != nil {
			return nil, err
		}
		return [][]byte{frame}, nil
	}
	if packetID == 0 {
		return nil, errors.New("nw3: zero packet id")
	}
	capacity := maxDatagram - udpFragmentHeaderLen
	if capacity <= 0 {
		return nil, errors.New("nw3: DATAGRAM limit has no fragment payload capacity")
	}
	count := (len(payload) + capacity - 1) / capacity
	if count < 2 || count > 255 {
		return nil, errors.New("nw3: invalid fragment count")
	}
	frames := make([][]byte, 0, count)
	for index := 0; index < count; index++ {
		start := index * capacity
		end := start + capacity
		if end > len(payload) {
			end = len(payload)
		}
		piece := payload[start:end]
		frame := make([]byte, udpFragmentHeaderLen+len(piece))
		binary.BigEndian.PutUint32(frame[:4], (uint32(frameFragment)<<frameTypeShift)|flowID)
		binary.BigEndian.PutUint32(frame[4:8], packetID)
		frame[8] = byte(index)
		frame[9] = byte(count)
		binary.BigEndian.PutUint16(frame[10:12], uint16(len(payload)))
		copy(frame[12:], piece)
		if err := validateFragment(frame[8], frame[9], binary.BigEndian.Uint16(frame[10:12]), piece); err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

// DecodeDatagram decodes one QUIC UDP frame. The payload aliases input.
func DecodeDatagram(input []byte) (Datagram, error) {
	if len(input) < udpHeaderLen {
		return Datagram{}, errors.New("nw3: short datagram header")
	}
	base := binary.BigEndian.Uint32(input[:4])
	frameType := byte((base >> frameTypeShift) & 0b11)
	flowID := base & MaxFlowID
	if err := validateFlow(flowID); err != nil {
		return Datagram{}, err
	}
	switch frameType {
	case frameData:
		payload := input[udpHeaderLen:]
		if len(payload) > udpPacketMax {
			return Datagram{}, errors.New("nw3: UDP payload too large")
		}
		return Datagram{Type: frameData, FlowID: flowID, Payload: payload}, nil
	case frameClose:
		if len(input) != udpHeaderLen {
			return Datagram{}, errors.New("nw3: CLOSE payload")
		}
		return Datagram{Type: frameClose, FlowID: flowID}, nil
	case frameFragment:
		if len(input) < udpFragmentHeaderLen {
			return Datagram{}, errors.New("nw3: short fragment header")
		}
		payload := input[udpFragmentHeaderLen:]
		d := Datagram{
			Type:     frameFragment,
			FlowID:   flowID,
			Payload:  payload,
			PacketID: binary.BigEndian.Uint32(input[4:8]),
			Index:    input[8],
			Count:    input[9],
			Total:    binary.BigEndian.Uint16(input[10:12]),
		}
		if d.PacketID == 0 {
			return Datagram{}, errors.New("nw3: zero packet id")
		}
		if err := validateFragment(d.Index, d.Count, d.Total, payload); err != nil {
			return Datagram{}, err
		}
		return d, nil
	default:
		return Datagram{}, errors.New("nw3: invalid datagram type")
	}
}

func validateFlow(id uint32) error {
	if id == 0 || id > MaxFlowID {
		return errors.New("nw3: flow id out of range")
	}
	return nil
}

func validateFragment(index, count byte, total uint16, payload []byte) error {
	if count < 2 || index >= count || total == 0 || total < uint16(count) {
		return errors.New("nw3: invalid fragment metadata")
	}
	if len(payload) == 0 || len(payload)+int(count)-1 > int(total) {
		return errors.New("nw3: invalid fragment payload length")
	}
	return nil
}

// WriteUoT writes one length-prefixed UDP payload. Zero length is an empty datagram.
func WriteUoT(w io.Writer, payload []byte) error {
	if len(payload) > udpPacketMax {
		return errors.New("nw3: UDP payload too large")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadUoT reads one length-prefixed UDP payload.
// A clean EOF before the length ends the flow. EOF inside a frame is truncation.
func ReadUoT(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	buf := make([]byte, n)
	if n == 0 {
		return buf, nil
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf, nil
}

// Reassembler collects FRAGMENT frames. Slots are bounded.
type Reassembler struct {
	maxSlots int
	maxBytes int
	ttl      time.Duration
	slots    map[reKey]*reSlot
	reserved int
}

type reKey struct {
	flow uint32
	pkt  uint32
}

type reSlot struct {
	created time.Time
	count   int
	total   int
	parts   [][]byte
	got     int
	bytes   int
}

// NewReassembler builds a reassembler. Zero options use 64 slots, 4 MiB and 10s.
func NewReassembler(slots, maxBytes int, ttl time.Duration) *Reassembler {
	if slots <= 0 {
		slots = 64
	}
	if maxBytes <= 0 {
		maxBytes = 4 << 20
	}
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	return &Reassembler{
		maxSlots: slots,
		maxBytes: maxBytes,
		ttl:      ttl,
		slots:    map[reKey]*reSlot{},
	}
}

// Push adds one fragment. A non-nil payload is the completed datagram.
func (r *Reassembler) Push(d Datagram, now time.Time) ([]byte, error) {
	if d.Type != frameFragment {
		return nil, errors.New("nw3: not a fragment")
	}
	r.expire(now)
	key := reKey{d.FlowID, d.PacketID}
	if slot, ok := r.slots[key]; ok {
		if slot.count != int(d.Count) || slot.total != int(d.Total) {
			r.drop(key)
			return nil, errors.New("nw3: fragment metadata conflict")
		}
		idx := int(d.Index)
		if slot.parts[idx] != nil {
			if string(slot.parts[idx]) != string(d.Payload) {
				r.drop(key)
				return nil, errors.New("nw3: conflicting fragment")
			}
			return nil, nil
		}
		if slot.bytes+len(d.Payload) > slot.total {
			r.drop(key)
			return nil, errors.New("nw3: fragment length overflow")
		}
		slot.parts[idx] = append([]byte(nil), d.Payload...)
		slot.got++
		slot.bytes += len(d.Payload)
		if slot.got < slot.count {
			return nil, nil
		}
		if slot.bytes != slot.total {
			r.drop(key)
			return nil, errors.New("nw3: incomplete fragment length")
		}
		out := make([]byte, 0, slot.total)
		for _, part := range slot.parts {
			out = append(out, part...)
		}
		r.drop(key)
		return out, nil
	}
	need := int(d.Total)
	if len(r.slots) >= r.maxSlots {
		r.evictOldest()
	}
	if r.reserved+need > r.maxBytes {
		return nil, errors.New("nw3: reassembly byte limit")
	}
	slot := &reSlot{
		created: now,
		count:   int(d.Count),
		total:   need,
		parts:   make([][]byte, d.Count),
	}
	slot.parts[d.Index] = append([]byte(nil), d.Payload...)
	slot.got = 1
	slot.bytes = len(d.Payload)
	r.slots[key] = slot
	r.reserved += need
	if slot.count == 1 {
		return nil, errors.New("nw3: invalid fragment metadata")
	}
	return nil, nil
}

// RemoveFlow drops every partial packet for a flow.
func (r *Reassembler) RemoveFlow(flow uint32) {
	for key, slot := range r.slots {
		if key.flow == flow {
			r.reserved -= slot.total
			delete(r.slots, key)
		}
	}
	if r.reserved < 0 {
		r.reserved = 0
	}
}

func (r *Reassembler) drop(key reKey) {
	slot := r.slots[key]
	if slot == nil {
		return
	}
	r.reserved -= slot.total
	if r.reserved < 0 {
		r.reserved = 0
	}
	delete(r.slots, key)
}

func (r *Reassembler) expire(now time.Time) {
	for key, slot := range r.slots {
		if now.Sub(slot.created) > r.ttl {
			r.drop(key)
		}
	}
}

func (r *Reassembler) evictOldest() {
	var oldest reKey
	var when time.Time
	first := true
	for key, slot := range r.slots {
		if first || slot.created.Before(when) {
			oldest = key
			when = slot.created
			first = false
		}
	}
	if !first {
		r.drop(oldest)
	}
}
