package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"

	"github.com/sagernet/sing-box/protocol/nowhere/core/internal/hkdf"
)

// AuthKeyLen is the length of the connection-independent authentication key.
const AuthKeyLen = 32

// AuthKey authenticates physical connections; derived once from the shared key.
type AuthKey = [AuthKeyLen]byte

// MaxSharedKeyLen is the largest accepted shared-key length, matching the
// Rust oracle's u8 bound.
const MaxSharedKeyLen = 255

// authRootSaltLabel is the HKDF-Extract salt label: salt = SHA-256(label).
const authRootSaltLabel = "nowhere/nw2/auth-root"

// authKeyInfo is the HKDF-Expand info label for the authentication key.
const authKeyInfo = "authentication"

// Credentials hold the immutable, connection-independent authentication key
// derived from the configured shared key. The shared key itself is not retained
// and no public getter exposes the derived key.
type Credentials struct {
	authKey AuthKey
}

// NewCredentials derives authentication credentials from a shared key.
//
// The shared key is consumed as raw UTF-8 bytes; it is never URL-decoded a
// second time (percent decoding belongs to the Rust URL configuration layer;
// Go product configuration already receives the shared secret value). The key
// must be non-empty and at most MaxSharedKeyLen bytes, matching the Rust
// Credentials::from_shared_key contract.
func NewCredentials(sharedKey string) (*Credentials, error) {
	raw := []byte(sharedKey)
	if len(raw) == 0 {
		return nil, errors.New("nowhere: missing shared key")
	}
	if len(raw) > MaxSharedKeyLen {
		return nil, errors.New("nowhere: shared key exceeds 255 bytes")
	}
	return &Credentials{authKey: DeriveAuthKey(raw)}, nil
}

// authKey returns the derived authentication key for internal callers. It is
// unexported on purpose: the host never reads the raw key.
func (c *Credentials) authKeyBytes() AuthKey {
	return c.authKey
}

// DeriveAuthKey derives the connection-independent authentication key with
// HKDF-SHA256 per the Nowhere 2 spec:
//
//	salt      = SHA-256("nowhere/nw2/auth-root")
//	auth_root = HKDF-Extract-SHA256(salt, shared_key)
//	auth_key  = HKDF-Expand-SHA256(auth_root, "authentication", 32)
//
// The requested output is exactly one SHA-256 block; HKDF-Expand collapses to
// a single HMAC invocation, which the shared hkdf helper materializes.
func DeriveAuthKey(sharedKey []byte) AuthKey {
	salt := sha256.Sum256([]byte(authRootSaltLabel))
	root := hkdf.ExtractSHA256(salt[:], sharedKey)
	var key AuthKey
	hkdf.ExpandSHA256(root, []byte(authKeyInfo), key[:], sha256.New)
	return key
}

// newHMAC constructs an HMAC-SHA256 hasher, factored out for the reassembler.
func newHMAC(key []byte) hash.Hash { return hmac.New(sha256.New, key) }
