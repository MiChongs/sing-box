package wire

import (
	"crypto/subtle"
	"encoding/binary"
	"io"
)

// AuthTransport is the physical carrier domain separator bound into the
// authentication tag, so an auth frame captured on one transport cannot be
// replayed on another.
type AuthTransport uint8

const (
	// AuthTransportTLSTCP is TLS 1.3 over TCP.
	AuthTransportTLSTCP AuthTransport = 0x01
	// AuthTransportQUIC is QUIC over UDP.
	AuthTransportQUIC AuthTransport = 0x02
)

// Validate rejects transport values that are not defined by Nowhere 2.
func (t AuthTransport) Validate() error {
	switch t {
	case AuthTransportTLSTCP, AuthTransportQUIC:
		return nil
	default:
		return ErrInvalidAuthTransport
	}
}

// TLSExporterLen is the length of a TLS exporter bound to one connection.
const TLSExporterLen = 32

// TLSExporterLabel is the fixed TLS exporter label required by Nowhere 2.
const TLSExporterLabel = "EXPORTER-Nowhere-Auth"

// EmptyTLSExporterContext returns a present empty context for TLS exporter APIs.
// It intentionally allocates a non-nil zero-length slice so callers cannot
// accidentally pass the nil context with different TLS API semantics.
func EmptyTLSExporterContext() []byte { return []byte{} }

// TLSExporter carries the keying material exported from the physical
// connection's TLS 1.3 handshake.
type TLSExporter = [TLSExporterLen]byte

// AuthTagLen is the truncated HMAC tag carried on the wire.
const AuthTagLen = 16

// AuthFrameLen is the fixed authentication frame length: session_id || tag.
const AuthFrameLen = SessionIDLen + AuthTagLen

// AuthFrame is the complete fixed authentication frame.
type AuthFrame = [AuthFrameLen]byte

// EncodeAuthFrame produces the fixed 32-byte authentication frame:
//
//	frame = session_id[16] || tag[16]
//	tag  = HMAC-SHA256(auth_key, transport || exporter || session_id)[0:16]
//
// The frame is bound to the shared key, transport, the connection's TLS
// exporter and the session id, so it cannot be replayed on any other
// connection.
func EncodeAuthFrame(creds *Credentials, transport AuthTransport, exporter TLSExporter, sessionID SessionID) (AuthFrame, error) {
	if creds == nil {
		return AuthFrame{}, ErrMissingCredentials
	}
	if err := transport.Validate(); err != nil {
		return AuthFrame{}, err
	}
	tag := authTag(creds.authKeyBytes(), transport, exporter, sessionID)
	var frame AuthFrame
	copy(frame[:SessionIDLen], sessionID[:])
	copy(frame[SessionIDLen:], tag[:])
	return frame, nil
}

// ValidateAuthFrame checks the fixed-length frame and returns the session id
// embedded in it. The comparison is constant-time and a failure only surfaces
// a coarse error; callers must apply the common auth deadline before closing.
func ValidateAuthFrame(frame []byte, creds *Credentials, transport AuthTransport, exporter TLSExporter) (SessionID, error) {
	if creds == nil {
		return SessionID{}, ErrMissingCredentials
	}
	if err := transport.Validate(); err != nil {
		return SessionID{}, err
	}
	if len(frame) != AuthFrameLen {
		return SessionID{}, ErrInvalidAuthFrame
	}
	var sessionID SessionID
	copy(sessionID[:], frame[:SessionIDLen])
	want := authTag(creds.authKeyBytes(), transport, exporter, sessionID)
	if subtle.ConstantTimeCompare(frame[SessionIDLen:], want[:]) != 1 {
		return SessionID{}, ErrInvalidAuthFrame
	}
	return sessionID, nil
}

// ReadAuthFrame reads exactly one auth frame, leaving any immediately
// following flow bytes buffered on the reader.
func ReadAuthFrame(r io.Reader, creds *Credentials, transport AuthTransport, exporter TLSExporter) (SessionID, error) {
	var frame AuthFrame
	if _, err := io.ReadFull(r, frame[:]); err != nil {
		return SessionID{}, err
	}
	return ValidateAuthFrame(frame[:], creds, transport, exporter)
}

func authTag(authKey AuthKey, transport AuthTransport, exporter TLSExporter, sessionID SessionID) [AuthTagLen]byte {
	mac := newHMAC(authKey[:])
	mac.Write([]byte{byte(transport)})
	mac.Write(exporter[:])
	mac.Write(sessionID[:])
	sum := mac.Sum(nil)
	var tag [AuthTagLen]byte
	copy(tag[:], sum[:AuthTagLen])
	return tag
}

// encodeUint32BE / decodeUint32BE are small helpers used by flow/datagram.
func encodeUint32BE(b []byte, v uint32) { binary.BigEndian.PutUint32(b, v) }
func decodeUint32BE(b []byte) uint32    { return binary.BigEndian.Uint32(b) }
