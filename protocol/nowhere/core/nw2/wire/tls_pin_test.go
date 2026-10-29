package wire

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParseCertificatePin(t *testing.T) {
	valid := strings.Repeat("ab", 32)
	got, err := ParseCertificatePin(valid)
	if err != nil || got != valid {
		t.Fatalf("ParseCertificatePin(valid) = %q, %v", got, err)
	}
	for _, pin := range []string{"", "none"} {
		got, err := ParseCertificatePin(pin)
		if err != nil || got != "" {
			t.Fatalf("ParseCertificatePin(%q) = %q, %v", pin, got, err)
		}
	}
	upper := strings.ToUpper(valid)
	if _, err := ParseCertificatePin(upper); !errors.Is(err, ErrInvalidCertificatePin) {
		t.Fatalf("uppercase pin error = %v, want ErrInvalidCertificatePin", err)
	}
	if _, err := ParseCertificatePin("not-a-fingerprint"); !errors.Is(err, ErrInvalidCertificatePin) {
		t.Fatalf("invalid pin error = %v", err)
	}
}

func TestVerifyLeafCertSHA256PinOverridesIdentity(t *testing.T) {
	der := mustSelfSignedDER(t)
	pin := LeafCertificateSHA256Hex(der)
	if err := VerifyLeafCertSHA256([][]byte{der}, pin); err != nil {
		t.Fatal(err)
	}
	wrong := hex.EncodeToString(make([]byte, 32))
	if err := VerifyLeafCertSHA256([][]byte{der}, wrong); !errors.Is(err, ErrCertificatePinMismatch) {
		t.Fatalf("wrong pin = %v", err)
	}
	verifier, err := PeerCertificatePinVerifier(pin)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier([][]byte{der}, nil); err != nil {
		t.Fatal(err)
	}
}

func mustSelfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nowhere-pin-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
