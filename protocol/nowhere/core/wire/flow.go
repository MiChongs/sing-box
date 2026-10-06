package wire

import (
	"errors"
	"io"
)

// FlowHeaderLen is the fixed binary flow header length: one flags byte plus a
// big-endian uint32 flow id.
const FlowHeaderLen = 5

// FlowID identifies one logical flow scoped to a session. Nowhere 2 carries
// it as a 30-bit identifier in 1..=MaxFlowID.
type FlowID = uint32

// MaxFlowID is the largest logical-flow identifier representable by every
// nw2 carrier. The upper two bits of the u32 field must be zero.
const MaxFlowID FlowID = 0x3fffffff

// MaxPortalHops is the largest remaining native Portal forwarding budget
// representable in the FLOW header.
const MaxPortalHops uint8 = 7

// FlowRole is the relationship of the current physical lane to a logical flow.
type FlowRole uint8

const (
	// FlowRoleDuplex carries both directions on one symmetric lane.
	FlowRoleDuplex FlowRole = 0
	// FlowRoleOpen is the first half of an asymmetric flow; carries target+uplink.
	FlowRoleOpen FlowRole = 1
	// FlowRoleAttach is the second half of an asymmetric flow; carries the downlink.
	FlowRoleAttach FlowRole = 2
)

// FlowKind is the proxied payload semantics.
type FlowKind uint8

const (
	// FlowKindTCP identifies a logical TCP flow.
	FlowKindTCP FlowKind = 0
	// FlowKindUDP identifies a logical UDP flow.
	FlowKindUDP FlowKind = 1
)

// Carrier is the physical transport selected for one flow direction.
type Carrier uint8

const (
	// CarrierTLSTCP selects TLS 1.3 over TCP.
	CarrierTLSTCP Carrier = 0
	// CarrierQUIC selects QUIC over UDP.
	CarrierQUIC Carrier = 1
)

const (
	flowRoleMask    byte = 0b0000_0011
	flowKindBit     byte = 0b0000_0100
	flowUplinkBit   byte = 0b0000_1000
	flowDownlinkBit byte = 0b0001_0000
	flowHopsShift        = 5
)

// FlowHeader is the fully decoded logical-flow metadata.
type FlowHeader struct {
	Role     FlowRole
	FlowID   FlowID
	Kind     FlowKind
	Uplink   Carrier
	Downlink Carrier
	// Hops is the remaining native Portal forwarding budget. Vector-originated
	// flows use zero; the first forwarding Portal initializes it to seven.
	Hops uint8
}

// Validate enforces role/id/carrier invariants independent of the lane the
// header arrived on.
func (h FlowHeader) Validate() error {
	if h.Hops > MaxPortalHops {
		return errors.New("nowhere: portal hop budget exceeds 7")
	}
	if h.FlowID == 0 || h.FlowID > MaxFlowID {
		return errors.New("nowhere: flow id out of range")
	}
	switch h.Role {
	case FlowRoleDuplex:
		if h.Uplink != h.Downlink {
			return errors.New("nowhere: duplex carrier mismatch")
		}
	case FlowRoleOpen, FlowRoleAttach:
		// Nowhere 2 allows OPEN/ATTACH with equal carriers. Vector still
		// emits DUPLEX when both directions share a carrier.
	default:
		return errors.New("nowhere: invalid flow role")
	}
	if h.Kind != FlowKindTCP && h.Kind != FlowKindUDP {
		return errors.New("nowhere: invalid flow kind")
	}
	if h.Uplink != CarrierTLSTCP && h.Uplink != CarrierQUIC {
		return errors.New("nowhere: invalid uplink carrier")
	}
	if h.Downlink != CarrierTLSTCP && h.Downlink != CarrierQUIC {
		return errors.New("nowhere: invalid downlink carrier")
	}
	return nil
}

// ValidateOn additionally checks that the header arrived on the physical
// carrier its role declares.
func (h FlowHeader) ValidateOn(current Carrier) error {
	if err := h.Validate(); err != nil {
		return err
	}
	var expected Carrier
	switch h.Role {
	case FlowRoleDuplex, FlowRoleOpen:
		expected = h.Uplink
	case FlowRoleAttach:
		expected = h.Downlink
	}
	if current != expected {
		return errors.New("nowhere: flow arrived on the wrong carrier")
	}
	return nil
}

// CarriesTarget reports whether this lane is followed by a binary target.
func (h FlowHeader) CarriesTarget() bool {
	return h.Role == FlowRoleDuplex || h.Role == FlowRoleOpen
}

// WriteFlowHeader encodes the header after validating its invariants.
func WriteFlowHeader(h FlowHeader) ([FlowHeaderLen]byte, error) {
	if err := h.Validate(); err != nil {
		return [FlowHeaderLen]byte{}, err
	}
	return writeFlowHeaderUnchecked(h), nil
}

// EncodeFlowHeader is an alias for WriteFlowHeader returning a slice.
func EncodeFlowHeader(h FlowHeader) ([]byte, error) {
	out, err := WriteFlowHeader(h)
	if err != nil {
		return nil, err
	}
	return out[:], nil
}

func writeFlowHeaderUnchecked(h FlowHeader) [FlowHeaderLen]byte {
	flags := byte(h.Role) |
		(byte(h.Kind) << 2) |
		(byte(h.Uplink) << 3) |
		(byte(h.Downlink) << 4) |
		(byte(h.Hops) << flowHopsShift)
	var out [FlowHeaderLen]byte
	out[0] = flags
	encodeUint32BE(out[1:], h.FlowID)
	return out
}

// DecodeFlowHeader decodes exactly one 5-byte header.
func DecodeFlowHeader(b []byte) (FlowHeader, error) {
	if len(b) != FlowHeaderLen {
		return FlowHeader{}, ErrInvalidFlowHeader
	}
	flags := b[0]
	role := FlowRole(flags & flowRoleMask)
	kind := FlowKindTCP
	if flags&flowKindBit != 0 {
		kind = FlowKindUDP
	}
	uplink := CarrierTLSTCP
	if flags&flowUplinkBit != 0 {
		uplink = CarrierQUIC
	}
	downlink := CarrierTLSTCP
	if flags&flowDownlinkBit != 0 {
		downlink = CarrierQUIC
	}
	h := FlowHeader{
		Role:     role,
		FlowID:   decodeUint32BE(b[1:]),
		Kind:     kind,
		Uplink:   uplink,
		Downlink: downlink,
		Hops:     flags >> flowHopsShift,
	}
	if err := h.Validate(); err != nil {
		return FlowHeader{}, ErrInvalidFlowHeader
	}
	return h, nil
}

// ReadFlowHeader reads exactly one header, leaving any following payload.
func ReadFlowHeader(r io.Reader) (FlowHeader, error) {
	var buf [FlowHeaderLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return FlowHeader{}, err
	}
	return DecodeFlowHeader(buf[:])
}
