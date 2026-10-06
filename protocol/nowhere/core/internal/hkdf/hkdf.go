// Package hkdf implements HKDF-SHA256 (RFC 5869) over the Go standard library,
// so the nowhere wire codec avoids any third-party dependency.
//
// The Expand output length is the responsibility of the caller; no bound is
// enforced here beyond the RFC 5869 hard limit of 255*HashLen.
package hkdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// HashLen is the SHA-256 output length in bytes.
const HashLen = 32

// ExtractSHA256 computes HKDF-Extract with SHA-256: PRK = HMAC(salt, IKM).
func ExtractSHA256(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, HashLen)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// ExpandSHA256 writes HKDF-Expand(PRK, info, len(out)) into out using the
// provided hash constructor (must be sha256.New for SHA-256).
//
// RFC 5869 single-block shortcut: when len(out) <= HashLen, the output is
// HMAC(PRK, info || 0x01) with no iteration loop, matching the Rust oracle.
func ExpandSHA256(prk, info, out []byte, newHash func() hash.Hash) {
	if len(out) == 0 {
		return
	}
	if len(out) > 255*HashLen {
		panic("hkdf: output length exceeds 255*HashLen")
	}
	mac := hmac.New(newHash, prk)
	var counter byte = 1
	var prev []byte
	for i := 0; i < len(out); i += HashLen {
		mac.Reset()
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{counter})
		block := mac.Sum(nil)
		copy(out[i:], block)
		prev = block
		counter++
	}
}
