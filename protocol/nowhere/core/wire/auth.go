package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
)

const (
	// ExporterLabel is the TLS exporter label bound into every authentication tag.
	ExporterLabel = "EXPORTER-Nowhere-nw3-Auth"
	// ExporterLen is the exporter output length.
	ExporterLen = 32
	// AuthFrameLen is the fixed authentication tag length.
	AuthFrameLen = 16
	// MaxSharedKeyLen matches the Rust u8 bound on raw shared-key bytes.
	MaxSharedKeyLen = 255
)

// AuthTransport separates TLS and QUIC authentication tags.
type AuthTransport uint8

const (
	// AuthTLS is TLS 1.3 over TCP.
	AuthTLS AuthTransport = 0x01
	// AuthQUIC is QUIC over UDP.
	AuthQUIC AuthTransport = 0x02
)

// Role is the peer authenticated by a tag. TLS admits Vector only.
type Role uint8

const (
	// RoleVector is a Vector client.
	RoleVector Role = iota + 1
	// RoleEgress is an Egress client. Valid only on QUIC.
	RoleEgress
)

// Exporter is the 32-byte normal TLS exporter. Early exporters are not used.
type Exporter = [ExporterLen]byte

// Credentials are the two role keys derived from one shared key.
type Credentials struct {
	vector [32]byte
	egress [32]byte
}

// NewCredentials derives role keys. sharedKey is raw text, not hex-decoded.
// Service URLs must additionally pass ValidateServiceKey.
func NewCredentials(sharedKey string) (*Credentials, error) {
	return NewCredentialsBytes([]byte(sharedKey))
}

// NewCredentialsBytes derives role keys from raw shared-key bytes.
func NewCredentialsBytes(sharedKey []byte) (*Credentials, error) {
	if len(sharedKey) == 0 {
		return nil, errors.New("nw3: missing shared key")
	}
	if len(sharedKey) > MaxSharedKeyLen {
		return nil, errors.New("nw3: shared key exceeds 255 bytes")
	}
	c := &Credentials{}
	c.vector = deriveRole(sharedKey, "vector-authentication")
	c.egress = deriveRole(sharedKey, "egress-authentication")
	return c, nil
}

// ValidateServiceKey enforces the Portal, Vector and Egress URL rule: exactly
// 32 lowercase hexadecimal characters.
func ValidateServiceKey(key string) error {
	if len(key) != 32 || !lowercaseHex(key) {
		return errors.New("nw3: shared key must be exactly 32 lowercase hexadecimal characters")
	}
	return nil
}

func lowercaseHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func deriveRole(sharedKey []byte, info string) [32]byte {
	salt := sha256.Sum256([]byte("nowhere/nw3/auth-root"))
	root := hmacSHA256(salt[:], sharedKey)
	input := make([]byte, len(info)+1)
	copy(input, info)
	input[len(info)] = 0x01
	return hmacSHA256(root[:], input)
}

func hmacSHA256(key, data []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// RoleKeyHex returns the derived key for tests and lock fixtures.
func (c *Credentials) RoleKey(role Role) ([32]byte, error) {
	if c == nil {
		return [32]byte{}, errors.New("nw3: missing credentials")
	}
	switch role {
	case RoleVector:
		return c.vector, nil
	case RoleEgress:
		return c.egress, nil
	default:
		return [32]byte{}, errors.New("nw3: invalid role")
	}
}

// EncodeAuthFrame returns the 16-byte tag for one role, transport and exporter.
func EncodeAuthFrame(key [32]byte, transport AuthTransport, exporter Exporter) ([AuthFrameLen]byte, error) {
	if err := transport.validate(); err != nil {
		return [AuthFrameLen]byte{}, err
	}
	var input [1 + ExporterLen]byte
	input[0] = byte(transport)
	copy(input[1:], exporter[:])
	sum := hmacSHA256(key[:], input[:])
	var tag [AuthFrameLen]byte
	copy(tag[:], sum[:AuthFrameLen])
	return tag, nil
}

// ValidateAuthFrame reports which role produced the tag.
// Egress is rejected on TLS. Comparison is constant time.
func ValidateAuthFrame(frame []byte, creds *Credentials, transport AuthTransport, exporter Exporter) (Role, error) {
	if creds == nil {
		return 0, errors.New("nw3: missing credentials")
	}
	if err := transport.validate(); err != nil {
		return 0, err
	}
	if len(frame) != AuthFrameLen {
		return 0, errors.New("nw3: invalid authentication frame length")
	}
	vector, err := EncodeAuthFrame(creds.vector, transport, exporter)
	if err != nil {
		return 0, err
	}
	egress, err := EncodeAuthFrame(creds.egress, transport, exporter)
	if err != nil {
		return 0, err
	}
	isVector := subtle.ConstantTimeCompare(frame, vector[:]) == 1
	isEgress := subtle.ConstantTimeCompare(frame, egress[:]) == 1
	switch {
	case isVector && !isEgress:
		return RoleVector, nil
	case !isVector && isEgress && transport == AuthQUIC:
		return RoleEgress, nil
	default:
		return 0, errors.New("nw3: invalid authentication tag or role")
	}
}

// ReadAuthFrame reads one tag from r.
func ReadAuthFrame(r io.Reader, creds *Credentials, transport AuthTransport, exporter Exporter) (Role, error) {
	var frame [AuthFrameLen]byte
	if _, err := io.ReadFull(r, frame[:]); err != nil {
		return 0, err
	}
	return ValidateAuthFrame(frame[:], creds, transport, exporter)
}

// WriteAuthFrame writes the tag for role.
func WriteAuthFrame(w io.Writer, creds *Credentials, role Role, transport AuthTransport, exporter Exporter) error {
	if creds == nil {
		return errors.New("nw3: missing credentials")
	}
	var key [32]byte
	switch role {
	case RoleVector:
		key = creds.vector
	case RoleEgress:
		key = creds.egress
	default:
		return errors.New("nw3: invalid role")
	}
	frame, err := EncodeAuthFrame(key, transport, exporter)
	if err != nil {
		return err
	}
	_, err = w.Write(frame[:])
	return err
}

func (t AuthTransport) validate() error {
	switch t {
	case AuthTLS, AuthQUIC:
		return nil
	default:
		return errors.New("nw3: invalid auth transport")
	}
}
