// Package morph implements the Nowhere 2.1 keyed socket transform below
// TLS/QUIC.
package morph

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/sagernet/sing-box/protocol/nowhere/core/internal/chacha20"
	"github.com/sagernet/sing-box/protocol/nowhere/core/internal/hkdf"
)

const (
	nonceLen      = 12
	preludeLen    = 64
	streamLimit   = (1 << 38) - 64
	tcpC2SInfo    = "tcp c2s"
	tcpS2CInfo    = "tcp s2c"
	udpC2SInfo    = "udp c2s"
	udpS2CInfo    = "udp s2c"
	morphRootSalt = "nowhere/morph"
	preludeEnv    = "NOW_MORPH_TCP_PRELUDE"
)

// Keys are the Morph HKDF outputs for one hop. They must not be logged.
type Keys struct {
	TCPC2S [32]byte
	TCPS2C [32]byte
	UDPC2S [32]byte
	UDPS2C [32]byte
}

// Derive builds Morph keys from the endpoint shared key.
func Derive(sharedKey []byte) Keys {
	root := hkdf.ExtractSHA256([]byte(morphRootSalt), sharedKey)
	var keys Keys
	hkdf.ExpandSHA256(root, []byte(tcpC2SInfo), keys.TCPC2S[:], sha256.New)
	hkdf.ExpandSHA256(root, []byte(tcpS2CInfo), keys.TCPS2C[:], sha256.New)
	hkdf.ExpandSHA256(root, []byte(udpC2SInfo), keys.UDPC2S[:], sha256.New)
	hkdf.ExpandSHA256(root, []byte(udpS2CInfo), keys.UDPS2C[:], sha256.New)
	return keys
}

// The TCP prelude is opaque protocol data sent before the nonce. Receivers
// consume it without interpreting it. The low7 policy clears each random
// byte's high bit; full8 leaves all eight bits unchanged.
type preludePolicy uint8

const (
	preludeLow7 preludePolicy = iota
	preludeFull8
)

func preludePolicyFromEnv() (preludePolicy, error) {
	switch value := os.Getenv(preludeEnv); value {
	case "", "low7":
		return preludeLow7, nil
	case "full8":
		return preludeFull8, nil
	default:
		return 0, fmt.Errorf("nowhere: %s must be low7 or full8", preludeEnv)
	}
}

func generatePrelude(policy preludePolicy) ([preludeLen]byte, error) {
	var prelude [preludeLen]byte
	if _, err := io.ReadFull(rand.Reader, prelude[:]); err != nil {
		return prelude, err
	}
	if policy == preludeLow7 {
		for i := range prelude {
			prelude[i] &= 0x7f
		}
	}
	return prelude, nil
}

// WrapTCPClient writes the 64-byte prelude and the 12-byte nonce, then
// XOR-transforms TLS bytes.
func WrapTCPClient(conn net.Conn, keys Keys) (net.Conn, error) {
	policy, err := preludePolicyFromEnv()
	if err != nil {
		return nil, err
	}
	prelude, err := generatePrelude(policy)
	if err != nil {
		return nil, err
	}
	var nonce [nonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	pref := make([]byte, 0, preludeLen+nonceLen)
	pref = append(pref, prelude[:]...)
	pref = append(pref, nonce[:]...)
	return &tcpConn{
		Conn:      conn,
		readKey:   keys.TCPS2C,
		writeKey:  keys.TCPC2S,
		nonce:     nonce,
		writePref: pref,
	}, nil
}

// WrapTCPServer consumes the client prelude without interpreting it and the
// client nonce, then XOR-transforms TLS bytes.
func WrapTCPServer(conn net.Conn, keys Keys) net.Conn {
	return &tcpConn{
		Conn:        conn,
		readKey:     keys.TCPC2S,
		writeKey:    keys.TCPS2C,
		readDiscard: preludeLen,
		readNeed:    nonceLen,
	}
}

type tcpConn struct {
	net.Conn
	readKey, writeKey [32]byte
	nonce             [nonceLen]byte
	readOff, writeOff uint64
	writePref         []byte
	readDiscard       int
	readNeed          int
	readMu, writeMu   sync.Mutex
}

func (c *tcpConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readDiscard > 0 {
		scratch := make([]byte, c.readDiscard)
		if _, err := io.ReadFull(c.Conn, scratch); err != nil {
			return 0, err
		}
		c.readDiscard = 0
	}
	if c.readNeed > 0 {
		buf := make([]byte, c.readNeed)
		if _, err := io.ReadFull(c.Conn, buf); err != nil {
			return 0, err
		}
		copy(c.nonce[nonceLen-c.readNeed:], buf)
		c.readNeed = 0
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := checkLimit(c.readOff, len(p)); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		chacha20.XORKeyStreamAt(p[:n], p[:n], &c.readKey, &c.nonce, c.readOff)
		c.readOff += uint64(n)
	}
	return n, err
}

func (c *tcpConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	if len(c.writePref) > 0 {
		n, err := c.Conn.Write(c.writePref)
		c.writePref = c.writePref[n:]
		if err != nil {
			return 0, err
		}
		if len(c.writePref) > 0 {
			return 0, io.ErrShortWrite
		}
	}
	if len(p) == 0 {
		return 0, nil
	}
	if err := checkLimit(c.writeOff, len(p)); err != nil {
		return 0, err
	}
	buf := append([]byte(nil), p...)
	chacha20.XORKeyStreamAt(buf, buf, &c.writeKey, &c.nonce, c.writeOff)
	n, err := c.Conn.Write(buf)
	c.writeOff += uint64(n)
	written += n
	return written, err
}

func checkLimit(offset uint64, n int) error {
	if n < 0 {
		return errors.New("nowhere: morph invalid length")
	}
	if offset+uint64(n) > streamLimit {
		return errors.New("nowhere: Morph TCP keystream exhausted")
	}
	return nil
}

// WrapPacketConn XOR-transforms every UDP datagram with a fresh 12-byte
// nonce. Client sockets send under udp c2s and receive under udp s2c; server
// sockets use the reverse pairing.
func WrapPacketConn(pc net.PacketConn, keys Keys, client bool) net.PacketConn {
	txKey, rxKey := keys.UDPC2S, keys.UDPS2C
	if !client {
		txKey, rxKey = keys.UDPS2C, keys.UDPC2S
	}
	return &packetConn{PacketConn: pc, txKey: txKey, rxKey: rxKey}
}

type packetConn struct {
	net.PacketConn
	txKey [32]byte
	rxKey [32]byte
	mu    sync.Mutex
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	var nonce [nonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return 0, err
	}
	buf := make([]byte, nonceLen+len(p))
	copy(buf, nonce[:])
	if len(p) > 0 {
		chacha20.XORKeyStreamAt(buf[nonceLen:], p, &c.txKey, &nonce, 0)
	}
	n, err := c.PacketConn.WriteTo(buf, addr)
	if n < nonceLen {
		return 0, err
	}
	return n - nonceLen, err
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	buf := make([]byte, nonceLen+len(p))
	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	if n <= nonceLen {
		return 0, addr, nil
	}
	var nonce [nonceLen]byte
	copy(nonce[:], buf[:nonceLen])
	payload := buf[nonceLen:n]
	out := p
	if len(out) < len(payload) {
		payload = payload[:len(out)]
	}
	chacha20.XORKeyStreamAt(out, payload, &c.rxKey, &nonce, 0)
	return len(payload), addr, nil
}

var (
	_ net.Conn       = (*tcpConn)(nil)
	_ net.PacketConn = (*packetConn)(nil)
)
