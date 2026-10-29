package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// UoTHeaderLen is the fixed UoT packet header length: a big-endian uint16.
const UoTHeaderLen = 2

// UoTPacketMax is the largest packet representable by the UoT length prefix.
const UoTPacketMax = 0xffff

// EncodeUDPPacketHeader encodes only the two-byte packet length header.
func EncodeUDPPacketHeader(payloadLen int) ([UoTHeaderLen]byte, error) {
	if payloadLen < 0 || payloadLen > UoTPacketMax {
		return [UoTHeaderLen]byte{}, errors.New("nowhere: udp packet too large")
	}
	var out [UoTHeaderLen]byte
	binary.BigEndian.PutUint16(out[:], uint16(payloadLen))
	return out, nil
}

// EncodeUDPPacket encodes one complete UoT packet (header + payload).
func EncodeUDPPacket(payload []byte) ([]byte, error) {
	if len(payload) > UoTPacketMax {
		return nil, errors.New("nowhere: udp packet too large")
	}
	out := make([]byte, UoTHeaderLen+len(payload))
	binary.BigEndian.PutUint16(out[:UoTHeaderLen], uint16(len(payload)))
	copy(out[UoTHeaderLen:], payload)
	return out, nil
}

// WriteUDPPacket writes one UoT packet without buffering.
func WriteUDPPacket(w io.Writer, payload []byte) error {
	if len(payload) > UoTPacketMax {
		return errors.New("nowhere: udp packet too large")
	}
	var hdr [UoTHeaderLen]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if err := WriteFull(w, hdr[:]); err != nil {
		return fmt.Errorf("nowhere: write udp packet header: %w", err)
	}
	if len(payload) > 0 {
		if err := WriteFull(w, payload); err != nil {
			return fmt.Errorf("nowhere: write udp packet payload: %w", err)
		}
	}
	return nil
}

// ReadUDPPacket reads one UoT packet. A clean EOF before any header byte
// returns (nil, nil). A zero-length payload is a legal UDP packet and is
// returned as an empty slice, not EOF.
func ReadUDPPacket(r io.Reader) ([]byte, error) {
	var hdr [1]byte
	n, err := io.ReadFull(r, hdr[:])
	if err == io.EOF || (err == io.ErrUnexpectedEOF && n == 0) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var second [1]byte
	if _, err := io.ReadFull(r, second[:]); err != nil {
		return nil, fmt.Errorf("nowhere: truncated udp packet length: %w", err)
	}
	payloadLen := int(binary.BigEndian.Uint16([]byte{hdr[0], second[0]}))
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("nowhere: truncated udp packet payload: %w", err)
	}
	return payload, nil
}
