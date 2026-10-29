package morph

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/sagernet/sing-box/protocol/nowhere/core/internal/chacha20"
)

const (
	tlsRecordHeader = 5
	tlsHandshake    = 22
	tlsClientHello  = 1
	tlsMaxCipher    = 16384 + 2048
	tlsMaxHandshake = 65536
	tlsMaxRecords   = 64
)

// readClientHello buffers one structurally complete ClientHello from the
// decrypted Morph stream. The returned bytes include every TLS record consumed
// and are later replayed to crypto/tls unchanged.
//
// This is not a rustls Acceptor. A structurally valid ClientHello is handed to
// crypto/tls, which can still emit an alert for a semantic failure such as an
// unsupported version, an empty cipher overlap, or ALPN. Nowhere suppresses
// those alerts when rustls rejects them inside Acceptor, before ServerConfig is
// applied. Incomplete or structurally malformed input returns before any byte
// reaches crypto/tls, so this stack does not emit a PreHello alert for it.
func (c *tcpConn) readClientHello() ([]byte, error) {
	var buf []byte
	var handshake []byte
	messageLen := -1
	consumed := 0
	for records := 0; records < tlsMaxRecords; records++ {
		if messageLen >= 0 && len(handshake) >= 4+messageLen {
			break
		}
		var err error
		buf, err = c.readPlainUntil(buf, consumed+tlsRecordHeader)
		if err != nil {
			return nil, err
		}
		header := buf[consumed : consumed+tlsRecordHeader]
		if records == 0 && (header[0] == 0x80 || header[0] != tlsHandshake || binary.BigEndian.Uint16(header[1:3]) >= 0x1000) {
			return nil, ErrClientHello
		}
		recordLen := int(binary.BigEndian.Uint16(header[3:5]))
		if header[0] != tlsHandshake || recordLen > tlsMaxCipher {
			return nil, ErrClientHello
		}
		total := consumed + tlsRecordHeader + recordLen
		if total > tlsMaxHandshake+tlsMaxRecords*tlsRecordHeader {
			return nil, ErrClientHello
		}
		buf, err = c.readPlainUntil(buf, total)
		if err != nil {
			return nil, err
		}
		handshake = append(handshake, buf[consumed+tlsRecordHeader:total]...)
		consumed = total
		if len(handshake) >= 4 && messageLen < 0 {
			if handshake[0] != tlsClientHello {
				return nil, ErrClientHello
			}
			messageLen = int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if messageLen > tlsMaxHandshake {
				return nil, ErrClientHello
			}
		}
		if messageLen >= 0 && len(handshake) >= 4+messageLen {
			if !clientHelloWellFormed(handshake[:4+messageLen]) {
				return nil, ErrClientHello
			}
			return buf, nil
		}
	}
	return nil, ErrClientHello
}

func (c *tcpConn) readPlainUntil(buf []byte, n int) ([]byte, error) {
	for len(buf) < n {
		if err := checkLimit(c.readOff, n-len(buf)); err != nil {
			return nil, err
		}
		next := make([]byte, n-len(buf))
		if _, err := io.ReadFull(c.Conn, next); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				return nil, ErrClientHello
			}
			return nil, err
		}
		chacha20.XORKeyStreamAt(next, next, &c.readKey, &c.nonce, c.readOff)
		c.readOff += uint64(len(next))
		buf = append(buf, next...)
	}
	return buf, nil
}

func clientHelloWellFormed(message []byte) bool {
	if len(message) < 4 || message[0] != tlsClientHello {
		return false
	}
	n := int(message[1])<<16 | int(message[2])<<8 | int(message[3])
	if n != len(message)-4 {
		return false
	}
	body := message[4:]
	if len(body) < 35 {
		return false
	}
	body = body[34:]
	sessionLen := int(body[0])
	body = body[1:]
	if sessionLen > 32 || len(body) < sessionLen+2 {
		return false
	}
	body = body[sessionLen:]
	suiteLen := int(body[0])<<8 | int(body[1])
	body = body[2:]
	if suiteLen < 2 || suiteLen%2 != 0 || len(body) < suiteLen+1 {
		return false
	}
	body = body[suiteLen:]
	compLen := int(body[0])
	body = body[1:]
	if compLen < 1 || len(body) < compLen {
		return false
	}
	body = body[compLen:]
	if len(body) == 0 {
		return true
	}
	if len(body) < 2 {
		return false
	}
	extLen := int(body[0])<<8 | int(body[1])
	body = body[2:]
	if extLen != len(body) {
		return false
	}
	seen := make(map[uint16]struct{})
	for len(body) > 0 {
		if len(body) < 4 {
			return false
		}
		extType := binary.BigEndian.Uint16(body[:2])
		size := int(binary.BigEndian.Uint16(body[2:4]))
		body = body[4:]
		if _, ok := seen[extType]; ok || len(body) < size {
			return false
		}
		seen[extType] = struct{}{}
		body = body[size:]
	}
	return true
}

func setLinger(conn net.Conn, seconds int) error {
	type linger interface {
		SetLinger(int) error
	}
	if conn, ok := conn.(linger); ok {
		return conn.SetLinger(seconds)
	}
	return nil
}
