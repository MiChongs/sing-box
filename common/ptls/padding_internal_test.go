package ptls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// Only P-256 keys get the fixed-length signer: its retry loop targets the
// length of a P-256 signature, so any other key must sign unchanged.
func TestWrapFixedLenSignerPassthrough(t *testing.T) {
	t.Parallel()
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped := wrapFixedLenSigner(p384, 71); wrapped != any(p384) {
		t.Fatalf("P-384 key was wrapped: %T", wrapped)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped := wrapFixedLenSigner(rsaKey, 71); wrapped != any(rsaKey) {
		t.Fatalf("RSA key was wrapped: %T", wrapped)
	}

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, isFixed := wrapFixedLenSigner(p256, 71).(*fixedLenECDSASigner)
	if !isFixed {
		t.Fatal("P-256 key was not wrapped")
	}
	digest := sha256.Sum256([]byte("ptls"))
	for range 32 {
		signature, err := signer.Sign(rand.Reader, digest[:], nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(signature) != 71 {
			t.Fatalf("signature length %d, want 71", len(signature))
		}
		if !ecdsa.VerifyASN1(&p256.PublicKey, digest[:], signature) {
			t.Fatal("fixed-length signature does not verify")
		}
	}
}
