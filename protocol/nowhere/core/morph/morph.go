// Package morph is the Nowhere 3 keyed transform below TLS and QUIC.
// Key derivation uses HMAC with the root label "nowhere/nw3/morph". It does
// not call the Nowhere 2 Morph KDF.
//
// A Morph TCP connection starts with a 64-byte prelude and a 12-byte nonce.
// Since Nowhere 3.2 that prelude must authenticate a Vector identity and a
// counter in 1..=2^48-1. A tag mismatch, a zero counter, a replay, or a
// counter outside the window is rejected before ClientHello parsing and does
// not consult the replay registry. There is no legacy prelude fallback. QUIC
// and non-Morph TCP do not use this prelude.
package morph

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/internal/chacha20"
)

const (
	nonceLen      = 12
	preludeLen    = 64
	streamLimit   = (1 << 38) - 64
	preludeEnv    = "NOW_MORPH_TCP_PRELUDE"
	morphRootSalt = "nowhere/nw3/morph"
)

// Keys are the directional Morph outputs for one shared key.
//
// Copies made from the same Derive call share one Vector prelude identity and
// one Portal replay registry. Keys constructed field by field have neither and
// cannot send or accept an authenticated Morph TCP prelude.
type Keys struct {
	TCPC2S [32]byte
	TCPS2C [32]byte
	UDPC2S [32]byte
	UDPS2C [32]byte
	state  *preludeState
}

// Derive builds Morph keys. sharedKey is the same raw text used for authentication.
func Derive(sharedKey []byte) Keys {
	root := hmacSHA256([]byte(morphRootSalt), sharedKey)
	return Keys{
		TCPC2S: expand(root, "tcp c2s"),
		TCPS2C: expand(root, "tcp s2c"),
		UDPC2S: expand(root, "udp c2s"),
		UDPS2C: expand(root, "udp s2c"),
		state:  newPreludeState(root),
	}
}

func hmacSHA256(key, data []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func expand(root [32]byte, info string) [32]byte {
	input := make([]byte, len(info)+1)
	copy(input, info)
	input[len(info)] = 0x01
	return hmacSHA256(root[:], input)
}

type preludePolicy uint8

const (
	// preludeFade is the Nowhere 3.0.1 default. It is not negotiated.
	preludeFade preludePolicy = iota
	preludeFull8
	preludeLow7
)

func preludePolicyFromEnv() (preludePolicy, error) {
	value, ok := os.LookupEnv(preludeEnv)
	if !ok {
		return preludeFade, nil
	}
	switch value {
	case "fade":
		return preludeFade, nil
	case "full8":
		return preludeFull8, nil
	case "low7":
		return preludeLow7, nil
	default:
		return 0, fmt.Errorf("%s must be fade, full8 or low7", preludeEnv)
	}
}

func generatePrelude(policy preludePolicy) ([preludeLen]byte, error) {
	return generatePreludeWith(policy, readEntropy)
}

func generatePreludeWith(policy preludePolicy, fill func([]byte) error) ([preludeLen]byte, error) {
	var prelude [preludeLen]byte
	if err := fill(prelude[:]); err != nil {
		return prelude, err
	}
	switch policy {
	case preludeFade:
		var boundaries [2]byte
		if err := fill(boundaries[:]); err != nil {
			return prelude, err
		}
		aSample, err := sampleBelow(boundaries[0], 5, fill)
		if err != nil {
			return prelude, err
		}
		bSample, err := sampleBelow(boundaries[1], 17, fill)
		if err != nil {
			return prelude, err
		}
		a := 8 + int(aSample)
		b := 16 + int(bSample)
		for i := 0; i < a; i++ {
			printable, err := sampleBelow(prelude[i], 95, fill)
			if err != nil {
				return prelude, err
			}
			prelude[i] = 0x20 + printable
		}
		for i := a; i < b; i++ {
			prelude[i] &= 0x7f
		}
	case preludeFull8:
	case preludeLow7:
		for i := range prelude {
			prelude[i] &= 0x7f
		}
	default:
		return prelude, fmt.Errorf("%s must be fade, full8 or low7", preludeEnv)
	}
	return prelude, nil
}

// sampleBelow returns a uniform value in [0, upper) from one random byte.
// Bytes at or above 256-256%upper are rejected and replaced, so the modulo
// does not bias the result.
func sampleBelow(b byte, upper byte, fill func([]byte) error) (byte, error) {
	if upper == 0 {
		return 0, errors.New("nw3: empty Morph sample range")
	}
	limit := 256 - 256%int(upper)
	for int(b) >= limit {
		var next [1]byte
		if err := fill(next[:]); err != nil {
			return 0, err
		}
		b = next[0]
	}
	return b % upper, nil
}

// WrapTCPClient allocates this Vector's next prelude counter, writes the
// authenticated 64-byte prelude and 12-byte nonce, then masks TLS bytes.
// The counter is consumed even when prelude generation later fails. QUIC and
// packet Morph never call this and therefore allocate nothing.
func WrapTCPClient(conn net.Conn, keys Keys) (net.Conn, error) {
	if keys.state == nil {
		return nil, errPreludeState
	}
	identity, counter, err := keys.state.allocate()
	if err != nil {
		return nil, err
	}
	policy, err := preludePolicyFromEnv()
	if err != nil {
		return nil, err
	}
	prelude, err := generatePrelude(policy)
	if err != nil {
		return nil, err
	}
	var nonce [nonceLen]byte
	if err := readEntropy(nonce[:]); err != nil {
		return nil, err
	}
	encodePrelude(keys.state, &prelude, &nonce, identity, counter)
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

// WrapTCPServer accepts one Morph TCP connection. The first read requires an
// authenticated prelude with a counter in 1..=2^48-1, checks it against the
// Portal replay window, then buffers one structurally complete ClientHello
// before any byte is exposed to TLS. A tag mismatch or an invalid counter is
// rejected before ClientHello parsing and does not touch the replay registry.
// Linger stays at whatever the caller set until ReleaseAuthenticated.
func WrapTCPServer(conn net.Conn, keys Keys) net.Conn {
	return &tcpConn{
		Conn:     conn,
		readKey:  keys.TCPC2S,
		writeKey: keys.TCPS2C,
		server:   true,
		state:    keys.state,
	}
}

// ReleaseAuthenticated restores normal socket linger after a Morph TCP server
// has authenticated a Vector. deadline is the handshake deadline captured at
// accept. A deadline that has already passed keeps zero linger and returns
// ErrHandshakeDeadline. Non-Morph connections and Morph clients are unchanged.
// Call it only after a complete Vector AuthFrame; every earlier failure must
// leave the abortive close in place.
func ReleaseAuthenticated(conn net.Conn, deadline time.Time) error {
	tcp, ok := conn.(*tcpConn)
	if !ok || !tcp.server {
		return nil
	}
	if !deadline.After(time.Now()) {
		_ = setLinger(tcp.Conn, 0)
		return ErrHandshakeDeadline
	}
	if err := setLinger(tcp.Conn, -1); err != nil {
		return err
	}
	if !deadline.After(time.Now()) {
		_ = setLinger(tcp.Conn, 0)
		return ErrHandshakeDeadline
	}
	return nil
}

type tcpConn struct {
	net.Conn
	readKey, writeKey [32]byte
	nonce             [nonceLen]byte
	readOff, writeOff uint64
	writePref         []byte
	server            bool
	state             *preludeState
	pending           []byte
	bootstrapped      bool
	bootErr           error
	readMu, writeMu   sync.Mutex
}

func (c *tcpConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.server {
		if err := c.bootstrap(); err != nil {
			if errors.Is(err, ErrPreludeRejected) || errors.Is(err, ErrClientHello) {
				// crypto/tls reads the record header before returning a handshake
				// error, and it does not preserve this error. Swap in a reader
				// that fails without touching the socket so the rejected bytes
				// stay unread. The Portal holds the socket until its deadline.
				c.Conn = &silentConn{Conn: c.Conn, err: err}
			}
			return 0, err
		}
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		}
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

func (c *tcpConn) bootstrap() error {
	if c.bootErr != nil {
		return c.bootErr
	}
	if c.bootstrapped {
		return nil
	}
	if err := c.bootstrapOnce(); err != nil {
		c.bootErr = err
		return err
	}
	c.bootstrapped = true
	return nil
}

func (c *tcpConn) bootstrapOnce() error {
	if c.state == nil {
		return errPreludeState
	}
	if err := setLinger(c.Conn, 0); err != nil {
		return err
	}
	var head [preludeLen + nonceLen]byte
	if _, err := io.ReadFull(c.Conn, head[:]); err != nil {
		return err
	}
	var prelude [preludeLen]byte
	copy(prelude[:], head[:preludeLen])
	copy(c.nonce[:], head[preludeLen:])
	identity, counter, matched := decodePrelude(c.state, &prelude, &c.nonce)
	if !matched || !counterValid(counter) {
		return ErrPreludeRejected
	}
	if !c.state.registry().precheck(identity, counter) {
		return ErrPreludeRejected
	}
	pending, err := c.readClientHello()
	if err != nil {
		return err
	}
	if !c.state.registry().commit(identity, counter) {
		return ErrPreludeRejected
	}
	c.pending = pending
	return nil
}

func (c *tcpConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(c.writePref) > 0 {
		n, err := c.Conn.Write(c.writePref)
		c.writePref = c.writePref[n:]
		if err != nil || len(c.writePref) > 0 {
			if err == nil {
				err = io.ErrShortWrite
			}
			return 0, err
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
	return n, err
}

// silentConn keeps a rejected Morph TCP socket from being drained. Reads fail
// with the admission error. Writes and close still reach the underlying socket.
type silentConn struct {
	net.Conn
	err error
}

func (c *silentConn) Read([]byte) (int, error) { return 0, c.err }

func checkLimit(offset uint64, n int) error {
	if n < 0 || offset+uint64(n) > streamLimit {
		return errors.New("nw3: Morph TCP keystream exhausted")
	}
	return nil
}

// WrapPacketConn masks each UDP datagram with a fresh nonce.
// Client sockets send with udp c2s and receive with udp s2c.
// A server socket drops a long-header QUIC datagram whose version is not one
// that Nowhere 3.2's quinn 0.11.19 accepts, before the host QUIC stack can
// answer it. Short headers pass. Clients do not filter.
//
// The result is not a *net.UDPConn, so quic-go does not take its batching path.
// It reads through PacketConn.ReadFrom, which is where the server filter runs.
// No extra socket is opened per peer.
func WrapPacketConn(pc net.PacketConn, keys Keys, client bool) net.PacketConn {
	tx, rx := keys.UDPC2S, keys.UDPS2C
	if !client {
		tx, rx = keys.UDPS2C, keys.UDPC2S
	}
	return &packetConn{PacketConn: pc, txKey: tx, rxKey: rx, server: !client}
}

type packetConn struct {
	net.PacketConn
	txKey   [32]byte
	rxKey   [32]byte
	server  bool
	mu      sync.Mutex
	readBuf []byte
}

// quinnVersions are quinn-proto 0.11.19 DEFAULT_SUPPORTED_VERSIONS, the set
// Nowhere 3.2 uses to suppress Version Negotiation on Morph UDP. quic-go
// negotiates only v1 from this list; draft versions are accepted so a peer
// that speaks them is not answered with a negotiation packet either.
var quinnVersions = []uint32{
	0x00000001,
	0xff00001d,
	0xff00001e,
	0xff00001f,
	0xff000020,
	0xff000021,
	0xff000022,
}

// supportedQUICPacket reports whether one decrypted datagram may be delivered
// to a Morph UDP server. A short header always passes. A long header passes
// only when its 4-byte version is in quinnVersions.
func supportedQUICPacket(packet []byte) bool {
	if len(packet) == 0 {
		return false
	}
	if packet[0]&0x80 == 0 {
		return true
	}
	if len(packet) < 5 {
		return false
	}
	version := binary.BigEndian.Uint32(packet[1:5])
	for _, supported := range quinnVersions {
		if version == supported {
			return true
		}
	}
	return false
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return writeMasked(c.PacketConn, p, addr, &c.txKey)
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cap(c.readBuf) < nonceLen+len(p) {
		c.readBuf = make([]byte, nonceLen+len(p))
	}
	buf := c.readBuf[:nonceLen+len(p)]
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		n, ok := unmaskDatagram(p, buf[:n], &c.rxKey, c.server)
		if !ok {
			continue
		}
		return n, addr, nil
	}
}

func writeMasked(conn interface {
	WriteTo([]byte, net.Addr) (int, error)
}, p []byte, addr net.Addr, key *[32]byte) (int, error) {
	wire, err := maskDatagram(p, key)
	if err != nil {
		return 0, err
	}
	n, err := conn.WriteTo(wire, addr)
	if n < nonceLen {
		return 0, err
	}
	return n - nonceLen, err
}

func maskDatagram(p []byte, key *[32]byte) ([]byte, error) {
	var nonce [nonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, nonceLen+len(p))
	copy(buf, nonce[:])
	if len(p) > 0 {
		chacha20.XORKeyStreamAt(buf[nonceLen:], p, key, &nonce, 0)
	}
	return buf, nil
}

// unmaskDatagram decrypts one datagram into p. ok is false when a server drops
// the datagram, or when it carried no payload. n is the plaintext length.
// The decrypted bytes temporarily overwrite the ciphertext in wire, which the
// caller does not reuse.
func unmaskDatagram(p, wire []byte, key *[32]byte, server bool) (int, bool) {
	if len(wire) <= nonceLen {
		return 0, false
	}
	var nonce [nonceLen]byte
	copy(nonce[:], wire[:nonceLen])
	payload := wire[nonceLen:]
	chacha20.XORKeyStreamAt(payload, payload, key, &nonce, 0)
	if server && !supportedQUICPacket(payload) {
		return 0, false
	}
	n := copy(p, payload)
	return n, true
}
