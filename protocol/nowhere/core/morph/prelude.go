package morph

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

const (
	preludeAuthInfo = "tcp prelude auth"
	preludeMaskInfo = "tcp prelude mask"
	maxCounter      = (1 << 48) - 1
	payloadLen      = 28
	tagLen          = 14
)

var (
	errIdentityRandom   = errors.New("nw3: morph tcp identity randomness unavailable")
	errCounterExhausted = errors.New("nw3: morph tcp prelude counter exhausted")
	// ErrPreludeRejected is an unauthenticated, invalid, or replayed Morph TCP
	// prelude. The Portal must not read any further input after it.
	ErrPreludeRejected = errors.New("nw3: morph tcp prelude rejected")
	// ErrClientHello is a structurally rejected Morph TCP ClientHello. It is
	// returned before any byte reaches crypto/tls, so the Portal writes no alert.
	ErrClientHello = errors.New("nw3: morph tcp client hello rejected")
	// ErrHandshakeDeadline means Vector authentication finished after the
	// deadline captured when the Morph TCP connection was accepted. Linger
	// stays zero.
	ErrHandshakeDeadline = errors.New("nw3: morph tcp authentication deadline expired")
	errPreludeState      = errors.New("nw3: morph tcp client state missing")

	entropyMu sync.Mutex
	entropy   io.Reader = rand.Reader
)

func readEntropy(dst []byte) error {
	entropyMu.Lock()
	defer entropyMu.Unlock()
	_, err := io.ReadFull(entropy, dst)
	return err
}

// preludeState is shared by every copy of one Derive result. The client
// identity and counter belong to one Vector. The replay registry belongs to
// the Portal that first accepts a Morph TCP connection with these keys.
type preludeState struct {
	authKey [32]byte
	maskKey [32]byte

	idOnce sync.Once
	id     uint64
	idErr  error
	ctr    atomic.Uint64

	replayOnce sync.Once
	replay     *replayRegistry
}

func newPreludeState(root [32]byte) *preludeState {
	return &preludeState{
		authKey: expand(root, preludeAuthInfo),
		maskKey: expand(root, preludeMaskInfo),
	}
}

func (s *preludeState) registry() *replayRegistry {
	s.replayOnce.Do(func() { s.replay = newReplayRegistry() })
	return s.replay
}

func (s *preludeState) allocate() (uint64, uint64, error) {
	s.idOnce.Do(func() {
		var raw [8]byte
		if err := readEntropy(raw[:]); err != nil {
			s.idErr = errIdentityRandom
			return
		}
		s.id = binary.BigEndian.Uint64(raw[:])
	})
	if s.idErr != nil {
		return 0, 0, s.idErr
	}
	for {
		previous := s.ctr.Load()
		if previous >= maxCounter {
			return 0, 0, errCounterExhausted
		}
		if s.ctr.CompareAndSwap(previous, previous+1) {
			return s.id, previous + 1, nil
		}
	}
}

func authInput(prelude *[preludeLen]byte, nonce *[nonceLen]byte) [62]byte {
	var input [62]byte
	copy(input[:nonceLen], nonce[:])
	copy(input[nonceLen:nonceLen+32], prelude[:32])
	for index, b := range prelude[32:] {
		input[44+index/8] |= (b >> 7) << (7 - index%8)
	}
	return input
}

func encodePrelude(state *preludeState, prelude *[preludeLen]byte, nonce *[nonceLen]byte, identity, counter uint64) {
	input := authInput(prelude, nonce)
	binary.BigEndian.PutUint64(input[48:56], identity)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	copy(input[56:62], counterBytes[2:])

	tag := hmacSHA256(state.authKey[:], input[:])
	mask := hmacSHA256(state.maskKey[:], input[:48])
	var payload [payloadLen]byte
	copy(payload[:14], input[48:62])
	copy(payload[14:], tag[:tagLen])
	for i := range payload {
		payload[i] ^= mask[i]
	}
	writePayload(prelude, &payload)
}

func decodePrelude(state *preludeState, prelude *[preludeLen]byte, nonce *[nonceLen]byte) (uint64, uint64, bool) {
	input := authInput(prelude, nonce)
	mask := hmacSHA256(state.maskKey[:], input[:48])
	payload := readPayload(prelude)
	for i := range payload {
		payload[i] ^= mask[i]
	}
	copy(input[48:], payload[:14])
	tag := hmacSHA256(state.authKey[:], input[:])
	if !hmac.Equal(tag[:tagLen], payload[14:]) {
		return 0, 0, false
	}
	identity := binary.BigEndian.Uint64(payload[:8])
	var counterBytes [8]byte
	copy(counterBytes[2:], payload[8:14])
	return identity, binary.BigEndian.Uint64(counterBytes[:]), true
}

func writePayload(prelude *[preludeLen]byte, payload *[payloadLen]byte) {
	var acc uint16
	bits := 0
	index := 0
	for _, b := range payload {
		acc = (acc << 8) | uint16(b)
		bits += 8
		for bits >= 7 {
			bits -= 7
			prelude[32+index] = (prelude[32+index] & 0x80) | byte((acc>>uint(bits))&0x7f)
			index++
		}
	}
}

func readPayload(prelude *[preludeLen]byte) [payloadLen]byte {
	var payload [payloadLen]byte
	var acc uint16
	bits := 0
	index := 0
	for _, b := range prelude[32:] {
		acc = (acc << 7) | uint16(b&0x7f)
		bits += 7
		if bits >= 8 {
			bits -= 8
			payload[index] = byte(acc >> uint(bits))
			index++
		}
	}
	return payload
}

// EncodeTCPPrelude authenticates identity and counter into a generated 64-byte
// prelude. Bytes 0 through 31 and the high bit of every byte are preserved.
// shared-key material comes from Derive; nonce is the independent 12-byte
// Morph nonce. The codec accepts counter 0 so test vectors can round-trip.
// Portal admission still rejects it.
func EncodeTCPPrelude(keys Keys, prelude, nonce []byte, identity, counter uint64) error {
	if keys.state == nil || len(prelude) != preludeLen || len(nonce) != nonceLen {
		return errPreludeState
	}
	var p [preludeLen]byte
	var n [nonceLen]byte
	copy(p[:], prelude)
	copy(n[:], nonce)
	encodePrelude(keys.state, &p, &n, identity, counter)
	copy(prelude, p[:])
	return nil
}

// DecodeTCPPrelude reports the identity and counter authenticated by prelude.
// ok is false when the tag does not match. A counter of 0 can still decode;
// callers enforce the Portal window separately.
func DecodeTCPPrelude(keys Keys, prelude, nonce []byte) (identity, counter uint64, ok bool) {
	if keys.state == nil || len(prelude) != preludeLen || len(nonce) != nonceLen {
		return 0, 0, false
	}
	var p [preludeLen]byte
	var n [nonceLen]byte
	copy(p[:], prelude)
	copy(n[:], nonce)
	return decodePrelude(keys.state, &p, &n)
}
