package wire

import (
	"crypto/tls"
	"testing"
)

func TestTLSHandshakeInfoValidation(t *testing.T) {
	valid := TLSHandshakeInfo{TLSVersion: tls.VersionTLS13, NegotiatedALPN: DefaultALPN}
	if err := valid.Validate(""); err != nil {
		t.Fatal(err)
	}
	wrongVersion := valid
	wrongVersion.TLSVersion = tls.VersionTLS12
	if err := wrongVersion.Validate(DefaultALPN); err == nil {
		t.Fatal("TLS 1.2 accepted")
	}
	wrongALPN := valid
	wrongALPN.NegotiatedALPN = "h3"
	if err := wrongALPN.Validate(DefaultALPN); err == nil {
		t.Fatal("wrong ALPN accepted")
	}
	custom := valid
	custom.NegotiatedALPN = "private/1"
	if err := custom.Validate("private/1"); err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeALPN(string(make([]byte, 256))); err == nil {
		t.Fatal("256-byte ALPN accepted")
	}
}
