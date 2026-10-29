package wire

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
)

// TLSHandshakeInfo is the transport-independent subset of TLS state required
// before Nowhere authentication.
type TLSHandshakeInfo struct {
	TLSVersion     uint16
	NegotiatedALPN string
	Exporter       TLSExporter
}

// Validate checks the nw2 TLS 1.3 and exact single-ALPN requirements.
func (i TLSHandshakeInfo) Validate(expectedALPN string) error {
	alpn, err := NormalizeALPN(expectedALPN)
	if err != nil {
		return err
	}
	if i.TLSVersion != tls.VersionTLS13 {
		return fmt.Errorf("nowhere: TLS 1.3 required, negotiated version %#x", i.TLSVersion)
	}
	if i.NegotiatedALPN != alpn {
		return fmt.Errorf("nowhere: negotiated ALPN %q, expected %q", i.NegotiatedALPN, alpn)
	}
	return nil
}

// NormalizeALPN applies the protocol default and validates the one-byte length
// bound used by TLS ALPN identifiers.
func NormalizeALPN(alpn string) (string, error) {
	if alpn == "" {
		alpn = DefaultALPN
	}
	if len(alpn) < 1 || len(alpn) > 255 {
		return "", errors.New("nowhere: ALPN must contain 1..255 bytes")
	}
	return alpn, nil
}

// HandshakedConn pairs a TLS-1.3 connection with the exporter derived from its
// handshake. It is the shared return type for both client (TLSDialer) and
// server (TLSHandshaker) handshakes, so neither carrier nor server needs to
// import the other.
type HandshakedConn struct {
	Conn net.Conn
	TLSHandshakeInfo
}
