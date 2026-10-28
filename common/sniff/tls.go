package sniff

import (
	"context"
	"errors"
	"io"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/crypto/cryptobyte"
)

// Limits and message rules follow crypto/tls (conn.go readRecordOrCCS and
// readHandshake, handshake_messages.go clientHelloMsg.unmarshal), which the
// sniffer previously drove through a full tls.Server handshake. Only the
// ClientHello framing and the server_name extension are decoded here: the
// handshake allocated a Conn, its record buffers and every parsed extension
// for each sniffed connection just to read one string.
const (
	tlsRecordHeaderLength    = 5
	tlsRecordTypeAlert       = 21
	tlsRecordTypeHandshake   = 22
	tlsMaxCiphertext         = 16384 + 2048
	tlsHandshakeHeaderLength = 4
	tlsMaxHandshake          = 65536
	tlsTypeClientHello       = 1
	tlsExtensionServerName   = 0
)

var (
	errTLSNotHandshake       = E.New("tls: first record does not look like a TLS handshake")
	errTLSSSLv2Handshake     = E.New("tls: unsupported SSLv2 handshake received")
	errTLSAlert              = E.New("tls: received alert before ClientHello")
	errTLSOversizedRecord    = E.New("tls: oversized record received")
	errTLSEmptyRecord        = E.New("tls: empty handshake record")
	errTLSUnexpectedMessage  = E.New("tls: first handshake message is not a ClientHello")
	errTLSOversizedHandshake = E.New("tls: handshake message exceeds maximum size")
	errTLSInvalidClientHello = E.New("tls: invalid ClientHello")
)

func TLSClientHello(ctx context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	serverName, err := readTLSClientHelloServerName(reader)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return E.Cause1(ErrNeedMoreData, io.ErrUnexpectedEOF)
		}
		return err
	}
	metadata.Protocol = C.ProtocolTLS
	metadata.SniffHost = M.ParseSocksaddrHostPort(serverName, 0).Fqdn
	return nil
}

// tlsHandshakeReader yields the plaintext handshake bytes carried by the
// leading records of a stream. A ClientHello may be fragmented across any
// number of records.
type tlsHandshakeReader struct {
	reader    io.Reader
	remaining int
}

func (r *tlsHandshakeReader) nextRecord() error {
	var header [tlsRecordHeaderLength]byte
	if _, err := io.ReadFull(r.reader, header[:]); err != nil {
		return err
	}
	recordType := header[0]
	if recordType == 0x80 {
		return errTLSSSLv2Handshake
	}
	version := uint16(header[1])<<8 | uint16(header[2])
	length := int(header[3])<<8 | int(header[4])
	switch {
	case recordType == tlsRecordTypeAlert && version < 0x1000:
		return errTLSAlert
	case recordType != tlsRecordTypeHandshake || version >= 0x1000:
		return errTLSNotHandshake
	case length > tlsMaxCiphertext:
		return errTLSOversizedRecord
	case length == 0:
		return errTLSEmptyRecord
	}
	r.remaining = length
	return nil
}

func (r *tlsHandshakeReader) readFull(p []byte) error {
	for len(p) > 0 {
		if r.remaining == 0 {
			if err := r.nextRecord(); err != nil {
				return err
			}
		}
		n := min(len(p), r.remaining)
		if _, err := io.ReadFull(r.reader, p[:n]); err != nil {
			return err
		}
		r.remaining -= n
		p = p[n:]
	}
	return nil
}

func readTLSClientHelloServerName(reader io.Reader) (string, error) {
	handshakeReader := tlsHandshakeReader{reader: reader}
	var header [tlsHandshakeHeaderLength]byte
	if err := handshakeReader.readFull(header[:]); err != nil {
		return "", err
	}
	if header[0] != tlsTypeClientHello {
		return "", errTLSUnexpectedMessage
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length > tlsMaxHandshake {
		return "", errTLSOversizedHandshake
	}
	if length == 0 {
		return "", errTLSInvalidClientHello
	}
	body := buf.Get(length)
	defer buf.Put(body)
	if err := handshakeReader.readFull(body); err != nil {
		return "", err
	}
	return parseTLSClientHelloServerName(body)
}

// parseTLSClientHelloServerName validates the ClientHello layout and decodes
// server_name with the rules of clientHelloMsg.unmarshal. The contents of
// other extensions are not interpreted.
func parseTLSClientHelloServerName(body []byte) (string, error) {
	s := cryptobyte.String(body)
	var (
		sessionID          cryptobyte.String
		cipherSuites       cryptobyte.String
		compressionMethods cryptobyte.String
	)
	if !s.Skip(2+32) ||
		!s.ReadUint8LengthPrefixed(&sessionID) ||
		!s.ReadUint16LengthPrefixed(&cipherSuites) ||
		len(cipherSuites)%2 != 0 ||
		!s.ReadUint8LengthPrefixed(&compressionMethods) {
		return "", errTLSInvalidClientHello
	}
	if s.Empty() {
		// ClientHello is optionally followed by extension data.
		return "", nil
	}
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return "", errTLSInvalidClientHello
	}
	var (
		seenStorage [32]uint16
		seen        = seenStorage[:0]
		serverName  []byte
	)
	for !extensions.Empty() {
		var (
			extension     uint16
			extensionData cryptobyte.String
		)
		if !extensions.ReadUint16(&extension) || !extensions.ReadUint16LengthPrefixed(&extensionData) {
			return "", errTLSInvalidClientHello
		}
		if slices.Contains(seen, extension) {
			return "", errTLSInvalidClientHello
		}
		seen = append(seen, extension)
		if extension != tlsExtensionServerName {
			continue
		}
		// RFC 6066, Section 3
		var nameList cryptobyte.String
		if !extensionData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() || !extensionData.Empty() {
			return "", errTLSInvalidClientHello
		}
		for !nameList.Empty() {
			var (
				nameType uint8
				name     cryptobyte.String
			)
			if !nameList.ReadUint8(&nameType) || !nameList.ReadUint16LengthPrefixed(&name) || name.Empty() {
				return "", errTLSInvalidClientHello
			}
			if nameType != 0 {
				continue
			}
			// Multiple names of the same name_type are prohibited, and an
			// SNI value may not include a trailing dot.
			if serverName != nil || name[len(name)-1] == '.' {
				return "", errTLSInvalidClientHello
			}
			serverName = name
		}
	}
	// The body is a pooled buffer; the conversion copies the name out of it.
	return string(serverName), nil
}
