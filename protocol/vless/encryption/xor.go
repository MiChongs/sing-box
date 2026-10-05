package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"net"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"

	"lukechampine.com/blake3"
)

func newCTR(key, iv []byte) cipher.Stream {
	k := make([]byte, 32)
	blake3.DeriveKey(k, "VLESS", key) // avoids using key directly
	block, _ := aes.NewCipher(k)
	return cipher.NewCTR(block, iv)
}

// XorConn masks the record headers of the "random" mode, so that everything on
// the wire, including the inner TLS records written by XTLS Vision in direct
// mode, looks fully random.
type XorConn struct {
	net.Conn
	ctr       cipher.Stream
	peerCTR   cipher.Stream
	outSkip   int
	outHeader []byte
	inSkip    int
	inHeader  []byte
}

func newXorConn(conn net.Conn, ctr, peerCTR cipher.Stream, outSkip, inSkip int) *XorConn {
	return &XorConn{
		Conn:      conn,
		ctr:       ctr,
		peerCTR:   peerCTR,
		outSkip:   outSkip,
		outHeader: make([]byte, 0, recordHeaderLen), // important
		inSkip:    inSkip,
		inHeader:  make([]byte, 0, recordHeaderLen), // important
	}
}

// Write masks a copy of b, as callers such as XTLS Vision in direct mode may
// still own the buffer.
func (c *XorConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	buffer := buf.NewSize(len(b))
	defer buffer.Release()
	common.Must1(buffer.Write(b))
	err := c.writeOwned(buffer.Bytes())
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// writeOwned masks b in place and writes it.
func (c *XorConn) writeOwned(b []byte) error {
	for p := b; ; {
		if len(p) <= c.outSkip {
			c.outSkip -= len(p)
			break
		}
		p = p[c.outSkip:]
		c.outSkip = 0
		need := recordHeaderLen - len(c.outHeader)
		if len(p) < need {
			c.outHeader = append(c.outHeader, p...)
			c.ctr.XORKeyStream(p, p)
			break
		}
		c.outSkip, _ = decodeHeader(append(c.outHeader, p[:need]...))
		c.outHeader = c.outHeader[:0]
		c.ctr.XORKeyStream(p[:need], p[:need])
		p = p[need:]
	}
	_, err := c.Conn.Write(b)
	return err
}

func (c *XorConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n, err := c.Conn.Read(b)
	for p := b[:n]; ; {
		if len(p) <= c.inSkip {
			c.inSkip -= len(p)
			break
		}
		p = p[c.inSkip:]
		c.inSkip = 0
		need := recordHeaderLen - len(c.inHeader)
		if len(p) < need {
			c.peerCTR.XORKeyStream(p, p)
			c.inHeader = append(c.inHeader, p...)
			break
		}
		c.peerCTR.XORKeyStream(p[:need], p[:need])
		c.inSkip, _ = decodeHeader(append(c.inHeader, p[:need]...))
		c.inHeader = c.inHeader[:0]
		p = p[need:]
	}
	return n, err
}

// writeOwned writes a buffer owned by the caller of this package, letting
// XorConn mask it in place instead of copying it first.
func writeOwned(conn net.Conn, b []byte) error {
	if xorConn, isXorConn := conn.(*XorConn); isXorConn {
		return xorConn.writeOwned(b)
	}
	_, err := conn.Write(b)
	return err
}
