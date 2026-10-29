package wire

import (
	"errors"
	"io"
)

// MaxFlowID is the largest UDP flow identifier, 2^30-1.
const MaxFlowID uint32 = 1<<30 - 1

// FlowKind is the single FlowStart byte. Bit 0 is 0 for TCP and 1 for UDP.
// Senders MUST set bits 1–7 to zero. Receivers MUST ignore them.
type FlowKind uint8

const (
	// FlowTCP is a byte stream.
	FlowTCP FlowKind = 0
	// FlowUDP is a datagram association.
	FlowUDP FlowKind = 1
)

// ParseFlowStart reads the flow type from bit 0 and ignores bits 1–7.
func ParseFlowStart(b byte) (FlowKind, error) {
	if b&1 == 0 {
		return FlowTCP, nil
	}
	return FlowUDP, nil
}

// ReadFlowStart reads one byte. EOF with no byte is a missing flow, not an error.
func ReadFlowStart(r io.Reader) (FlowKind, bool, error) {
	var b [1]byte
	n, err := r.Read(b[:])
	if n == 0 {
		if err == nil {
			err = io.EOF
		}
		if errors.Is(err, io.EOF) {
			return 0, false, nil
		}
		return 0, false, err
	}
	kind, perr := ParseFlowStart(b[0])
	if perr != nil {
		return 0, false, perr
	}
	return kind, true, nil
}

// WriteFlowStart writes the one-byte FlowStart.
func WriteFlowStart(w io.Writer, kind FlowKind) error {
	if kind != FlowTCP && kind != FlowUDP {
		return errors.New("nw3: invalid FlowStart reserved bits")
	}
	_, err := w.Write([]byte{byte(kind)})
	return err
}

// UDPFlowID derives the connection-local UDP id from a bidirectional QUIC stream.
// serverInitiated selects Egress business streams (server-originated).
// Stream 0 derives id 1; callers must not install a route for an auth-only stream.
func UDPFlowID(streamID uint64, serverInitiated bool) (uint32, error) {
	if streamID&2 != 0 || (streamID&1 != 0) != serverInitiated {
		return 0, errors.New("nw3: invalid business stream direction")
	}
	id := (streamID >> 2) + 1
	if id == 0 || id > uint64(MaxFlowID) {
		return 0, errors.New("nw3: business stream id exhausted")
	}
	return uint32(id), nil
}
