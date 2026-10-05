// Package encryption implements VLESS Encryption (mlkem768x25519plus), the
// post-quantum layer between the transport and the VLESS header introduced by
// Xray-core. It is wire compatible with Xray-core's proxy/vless/encryption.
package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
	"lukechampine.com/blake3"
)

const (
	recordHeaderLen = 5
	maxRecordData   = 8192
	tagLen          = 16
	// TLS 1.3 max record: 16384 + 256 (RFC 8446 §5.2)
	maxRecordLen = 16640
)

// Keep in sync with crypto/tls/cipher_suites.go, same as Xray-core.
var hasAESGCMHardwareSupport = (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3) ||
	(cpu.ARM64.HasAES && cpu.ARM64.HasPMULL) || (runtime.GOOS == "darwin" && runtime.GOARCH == "arm64") ||
	(cpu.S390X.HasAES && cpu.S390X.HasAESCTR && cpu.S390X.HasGHASH) ||
	runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le"

var (
	errInvalidHeader      = errors.New("invalid header")
	errNewHandshakeNeeded = errors.New("new handshake needed")
)

var outBytesPool = sync.Pool{
	New: func() any {
		return make([]byte, recordHeaderLen+maxRecordData+tagLen)
	},
}

// CommonConn is the encrypted record layer established by a client or server
// handshake. The input and rawInput fields mirror crypto/tls.Conn, XTLS Vision
// locates them by name through reflection to take over the unread data.
type CommonConn struct {
	net.Conn
	useAES      bool
	client      *ClientInstance
	unitedKey   []byte
	preWrite    []byte
	aead        *aeadCipher
	peerAEAD    *aeadCipher
	peerPadding []byte
	rawInput    bytes.Buffer
	input       bytes.Reader
}

func newCommonConn(conn net.Conn, useAES bool) *CommonConn {
	return &CommonConn{
		Conn:   conn,
		useAES: useAES,
	}
}

func (c *CommonConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	outBytes := outBytesPool.Get().([]byte)
	defer outBytesPool.Put(outBytes)
	for n := 0; n < len(b); {
		chunk := b[n:]
		if len(chunk) > maxRecordData {
			chunk = chunk[:maxRecordData] // for avoiding another copy() in peer's Read()
		}
		n += len(chunk)
		headerAndData := outBytes[:recordHeaderLen+len(chunk)+tagLen]
		encodeHeader(headerAndData, len(chunk)+tagLen)
		nonceExhausted := bytes.Equal(c.aead.nonce[:], maxNonce)
		c.aead.Seal(headerAndData[:recordHeaderLen], nil, chunk, headerAndData[:recordHeaderLen])
		if nonceExhausted {
			c.aead = newAEAD(headerAndData, c.unitedKey, c.useAES)
		}
		if c.preWrite != nil {
			headerAndData = append(c.preWrite, headerAndData...)
			c.preWrite = nil
		}
		err := writeOwned(c.Conn, headerAndData)
		if err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

func (c *CommonConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.peerAEAD == nil { // client's 0-RTT
		serverRandom := make([]byte, 16)
		_, err := io.ReadFull(c.Conn, serverRandom)
		if err != nil {
			return 0, err
		}
		c.peerAEAD = newAEAD(serverRandom, c.unitedKey, c.useAES)
		if xorConn, isXorConn := c.Conn.(*XorConn); isXorConn {
			xorConn.peerCTR = newCTR(c.unitedKey, serverRandom)
		}
	}
	if c.peerPadding != nil { // client's 1-RTT
		_, err := io.ReadFull(c.Conn, c.peerPadding)
		if err != nil {
			return 0, err
		}
		_, err = c.peerAEAD.Open(c.peerPadding[:0], nil, c.peerPadding, nil)
		if err != nil {
			return 0, err
		}
		c.peerPadding = nil
	}
	if c.input.Len() > 0 {
		return c.input.Read(b)
	}
	var peerHeader [recordHeaderLen]byte
	_, err := io.ReadFull(c.Conn, peerHeader[:])
	if err != nil {
		return 0, err
	}
	l, err := decodeHeader(peerHeader[:])
	if err != nil {
		if c.client != nil && errors.Is(err, errInvalidHeader) { // client's 0-RTT
			c.client.access.Lock()
			if bytes.HasPrefix(c.unitedKey, c.client.pfsKey) {
				c.client.expire = time.Now() // expired
			}
			c.client.access.Unlock()
			return 0, errNewHandshakeNeeded
		}
		return 0, err
	}
	c.client = nil
	if c.rawInput.Cap() < l {
		c.rawInput.Grow(l) // no need to use sync.Pool, because we are always reading
	}
	peerData := c.rawInput.Bytes()[:l]
	_, err = io.ReadFull(c.Conn, peerData)
	if err != nil {
		return 0, err
	}
	dst := peerData[:l-tagLen]
	if len(dst) <= len(b) {
		dst = b[:len(dst)] // avoids another copy()
	}
	var newPeerAEAD *aeadCipher
	if bytes.Equal(c.peerAEAD.nonce[:], maxNonce) {
		newPeerAEAD = newAEAD(append(peerHeader[:], peerData...), c.unitedKey, c.useAES)
	}
	_, err = c.peerAEAD.Open(dst[:0], nil, peerData, peerHeader[:])
	if newPeerAEAD != nil {
		c.peerAEAD = newPeerAEAD
	}
	if err != nil {
		return 0, err
	}
	if len(dst) > len(b) {
		c.input.Reset(dst[copy(b, dst):])
		dst = b // for len(dst)
	}
	return len(dst), nil
}

type aeadCipher struct {
	cipher.AEAD
	nonce [12]byte
}

func newAEAD(ctx, key []byte, useAES bool) *aeadCipher {
	k := make([]byte, 32)
	blake3.DeriveKey(k, string(ctx), key)
	var aead cipher.AEAD
	if useAES {
		block, _ := aes.NewCipher(k)
		aead, _ = cipher.NewGCM(block)
	} else {
		aead, _ = chacha20poly1305.New(k)
	}
	return &aeadCipher{AEAD: aead}
}

func (a *aeadCipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if nonce == nil {
		nonce = increaseNonce(a.nonce[:])
	}
	return a.AEAD.Seal(dst, nonce, plaintext, additionalData)
}

func (a *aeadCipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if nonce == nil {
		nonce = increaseNonce(a.nonce[:])
	}
	return a.AEAD.Open(dst, nonce, ciphertext, additionalData)
}

func increaseNonce(nonce []byte) []byte {
	for i := range 12 {
		nonce[11-i]++
		if nonce[11-i] != 0 {
			break
		}
	}
	return nonce
}

var maxNonce = bytes.Repeat([]byte{255}, 12)

func encodeLength(l int) []byte {
	return []byte{byte(l >> 8), byte(l)}
}

func decodeLength(b []byte) int {
	return int(b[0])<<8 | int(b[1])
}

func encodeHeader(h []byte, l int) {
	h[0] = 23
	h[1] = 3
	h[2] = 3
	h[3] = byte(l >> 8)
	h[4] = byte(l)
}

func decodeHeader(h []byte) (int, error) {
	l := int(h[3])<<8 | int(h[4])
	if h[0] != 23 || h[1] != 3 || h[2] != 3 {
		l = 0
	}
	if l < 17 || l > maxRecordLen {
		return l, E.Extend(errInvalidHeader, fmt.Sprint(h[:recordHeaderLen]))
	}
	return l, nil
}

func parsePadding(padding string, paddingLens, paddingGaps *[][3]int) error {
	if padding == "" {
		return nil
	}
	maxLen := 0
	for i, s := range strings.Split(padding, ".") {
		x := strings.Split(s, "-")
		if len(x) < 3 || x[0] == "" || x[1] == "" || x[2] == "" {
			return E.New("invalid padding length/gap parameter: ", s)
		}
		var y [3]int
		for j := range y {
			value, err := strconv.Atoi(x[j])
			if err != nil {
				return E.Cause(err, "invalid padding length/gap parameter: ", s)
			}
			y[j] = value
		}
		if i == 0 && (y[0] < 100 || y[1] < 18+17 || y[2] < 18+17) {
			return E.New("first padding length must not be smaller than 35")
		}
		if i%2 == 0 {
			*paddingLens = append(*paddingLens, y)
			maxLen += max(y[1], y[2])
		} else {
			*paddingGaps = append(*paddingGaps, y)
		}
	}
	if maxLen > 18+65535 {
		return E.New("total padding length must not be larger than 65553")
	}
	return nil
}

func createPadding(paddingLens, paddingGaps [][3]int) (length int, lens []int, gaps []time.Duration) {
	if len(paddingLens) == 0 {
		paddingLens = [][3]int{{100, 111, 1111}, {50, 0, 3333}}
		paddingGaps = [][3]int{{75, 0, 111}}
	}
	for _, y := range paddingLens {
		l := 0
		if y[0] >= int(randBetween(0, 100)) {
			l = int(randBetween(int64(y[1]), int64(y[2])))
		}
		lens = append(lens, l)
		length += l
	}
	for _, y := range paddingGaps {
		g := 0
		if y[0] >= int(randBetween(0, 100)) {
			g = int(randBetween(int64(y[1]), int64(y[2])))
		}
		gaps = append(gaps, time.Duration(g)*time.Millisecond)
	}
	return
}

// randBetween returns a uniform random number in [from, to), same as Xray-core's crypto.RandBetween.
func randBetween(from int64, to int64) int64 {
	if from == to {
		return from
	}
	if from > to {
		from, to = to, from
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(to-from))
	return from + bigInt.Int64()
}
