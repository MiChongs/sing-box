package wire

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrInvalidCertificatePin reports a pin that is not exactly 64 lowercase hex chars.
var ErrInvalidCertificatePin = errors.New("nowhere: certificate pin must be 64 lowercase hex characters")

// ErrCertificatePinMismatch reports that the leaf certificate SHA-256 did not match the pin.
var ErrCertificatePinMismatch = errors.New("nowhere: leaf certificate SHA-256 pin mismatch")

// ParseCertificatePin validates a Nowhere leaf-certificate pin.
// Empty and "none" disable pinning (returns "", nil). Uppercase hex is rejected
// so hosts fail fast the same way Rust Vector rejects uppercase pins at handshake.
func ParseCertificatePin(pin string) (string, error) {
	if pin == "" || pin == "none" {
		return "", nil
	}
	if len(pin) != sha256.Size*2 {
		return "", ErrInvalidCertificatePin
	}
	for i := 0; i < len(pin); i++ {
		c := pin[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", ErrInvalidCertificatePin
		}
	}
	if _, err := hex.DecodeString(pin); err != nil {
		return "", ErrInvalidCertificatePin
	}
	return pin, nil
}

// LeafCertificateSHA256Hex returns the lowercase hex SHA-256 of a DER-encoded certificate.
func LeafCertificateSHA256Hex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// VerifyLeafCertSHA256 checks that rawCerts[0] (the leaf) matches pin.
// pin must already be normalized via ParseCertificatePin (lowercase hex).
// When pin is empty, verification is a no-op (caller decides skip-verify policy).
func VerifyLeafCertSHA256(rawCerts [][]byte, pin string) error {
	if pin == "" {
		return nil
	}
	if len(rawCerts) == 0 || len(rawCerts[0]) == 0 {
		return fmt.Errorf("%w: missing leaf certificate", ErrCertificatePinMismatch)
	}
	if LeafCertificateSHA256Hex(rawCerts[0]) != pin {
		return ErrCertificatePinMismatch
	}
	return nil
}

// PeerCertificatePinVerifier returns a crypto/tls.Config.VerifyPeerCertificate
// callback that pins the leaf certificate DER SHA-256. Hosts should set
// InsecureSkipVerify when installing this verifier so pin overrides SNI/chain
// checks while the TLS stack still verifies the handshake signature.
func PeerCertificatePinVerifier(pin string) (func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error, error) {
	parsed, err := ParseCertificatePin(pin)
	if err != nil {
		return nil, err
	}
	if parsed == "" {
		return nil, errors.New("nowhere: empty certificate pin")
	}
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		return VerifyLeafCertSHA256(rawCerts, parsed)
	}, nil
}
