package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

// MuxMarker is written once on the client-to-Portal TLS half immediately after
// AuthFrame. Portal does not echo it. 0xff cannot be a valid FlowHeader flags
// byte because its role bits are 0b11.
const MuxMarker byte = 0xff

// MuxHeaderLen is the fixed Mux frame header length.
const MuxHeaderLen = 7

// MuxFrameKind is the MuxHeader kind byte.
type MuxFrameKind uint8

const (
	// MuxFrameOpen opens a logical stream and advertises receive-window extension
	// in 1 KiB units.
	MuxFrameOpen MuxFrameKind = 0x01
	// MuxFrameData carries a non-empty payload for one logical stream.
	MuxFrameData MuxFrameKind = 0x02
	// MuxFrameWindow returns credit in 1 KiB units. flow_id 0 is connection-wide.
	MuxFrameWindow MuxFrameKind = 0x03
	// MuxFrameFin half-closes a logical stream.
	MuxFrameFin MuxFrameKind = 0x04
	// MuxFrameReset immediately removes a logical stream.
	MuxFrameReset MuxFrameKind = 0x05
)

// MuxHeader is the 7-byte Mux frame header.
type MuxHeader struct {
	Kind   MuxFrameKind
	Value  uint16
	FlowID FlowID
}

// Validate enforces kind, flow-id, and value invariants.
func (h MuxHeader) Validate() error {
	switch h.Kind {
	case MuxFrameOpen:
		if err := requireMuxFlowID(h.FlowID); err != nil {
			return err
		}
	case MuxFrameData:
		if err := requireMuxFlowID(h.FlowID); err != nil {
			return err
		}
		if h.Value == 0 {
			return ErrInvalidMuxHeader
		}
	case MuxFrameWindow:
		if h.Value == 0 {
			return ErrInvalidMuxHeader
		}
		if h.FlowID != 0 {
			if err := requireMuxFlowID(h.FlowID); err != nil {
				return err
			}
		}
	case MuxFrameFin, MuxFrameReset:
		if err := requireMuxFlowID(h.FlowID); err != nil {
			return err
		}
		if h.Value != 0 {
			return ErrInvalidMuxHeader
		}
	default:
		return ErrInvalidMuxHeader
	}
	return nil
}

func requireMuxFlowID(flowID FlowID) error {
	if flowID == 0 || flowID > MaxFlowID {
		return ErrInvalidMuxHeader
	}
	return nil
}

// OpenMuxHeader builds an OPEN header. extension is the opener receive-window
// extension in 1 KiB units and may be zero.
func OpenMuxHeader(flowID FlowID, extension int) (MuxHeader, error) {
	return newMuxHeader(MuxFrameOpen, extension, flowID)
}

// DataMuxHeader builds a DATA header. payloadLen must be 1..65535.
func DataMuxHeader(flowID FlowID, payloadLen int) (MuxHeader, error) {
	return newMuxHeader(MuxFrameData, payloadLen, flowID)
}

// WindowMuxHeader builds a WINDOW header. credit is in 1 KiB units and must be
// nonzero. flowID 0 replenishes connection credit.
func WindowMuxHeader(flowID FlowID, credit int) (MuxHeader, error) {
	return newMuxHeader(MuxFrameWindow, credit, flowID)
}

// FinMuxHeader builds a FIN header.
func FinMuxHeader(flowID FlowID) (MuxHeader, error) {
	return newMuxHeader(MuxFrameFin, 0, flowID)
}

// ResetMuxHeader builds a RESET header.
func ResetMuxHeader(flowID FlowID) (MuxHeader, error) {
	return newMuxHeader(MuxFrameReset, 0, flowID)
}

func newMuxHeader(kind MuxFrameKind, value int, flowID FlowID) (MuxHeader, error) {
	if value < 0 || value > 0xffff {
		return MuxHeader{}, errors.New("nowhere: mux frame value exceeds u16")
	}
	header := MuxHeader{Kind: kind, Value: uint16(value), FlowID: flowID}
	if err := header.Validate(); err != nil {
		return MuxHeader{}, err
	}
	return header, nil
}

// EncodeMuxHeader writes one validated 7-byte header.
func EncodeMuxHeader(h MuxHeader) ([MuxHeaderLen]byte, error) {
	if err := h.Validate(); err != nil {
		return [MuxHeaderLen]byte{}, err
	}
	var out [MuxHeaderLen]byte
	out[0] = byte(h.Kind)
	binary.BigEndian.PutUint16(out[1:3], h.Value)
	encodeUint32BE(out[3:], h.FlowID)
	return out, nil
}

// DecodeMuxHeader decodes exactly one 7-byte header.
func DecodeMuxHeader(b []byte) (MuxHeader, error) {
	if len(b) != MuxHeaderLen {
		return MuxHeader{}, ErrInvalidMuxHeader
	}
	header := MuxHeader{
		Kind:   MuxFrameKind(b[0]),
		Value:  binary.BigEndian.Uint16(b[1:3]),
		FlowID: decodeUint32BE(b[3:]),
	}
	if err := header.Validate(); err != nil {
		return MuxHeader{}, ErrInvalidMuxHeader
	}
	return header, nil
}

// ReadMuxHeader reads exactly one header, leaving any following payload.
func ReadMuxHeader(r io.Reader) (MuxHeader, error) {
	var buf [MuxHeaderLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return MuxHeader{}, err
	}
	return DecodeMuxHeader(buf[:])
}

// MuxPayloadLen is the number of bytes that follow a header on the wire.
func MuxPayloadLen(h MuxHeader) int {
	if h.Kind == MuxFrameData {
		return int(h.Value)
	}
	return 0
}
