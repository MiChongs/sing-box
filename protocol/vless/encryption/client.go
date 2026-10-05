package encryption

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	"lukechampine.com/blake3"
)

// ClientInstance holds the client configuration and the 0-RTT session shared by
// every connection of an outbound.
type ClientInstance struct {
	nfsPKeys      []any
	nfsPKeysBytes [][]byte
	hash32s       [][32]byte
	relaysLength  int
	xorMode       uint32
	seconds       uint32
	paddingLens   [][3]int
	paddingGaps   [][3]int

	access sync.RWMutex
	expire time.Time
	pfsKey []byte
	ticket []byte
}

func (i *ClientInstance) init(nfsPKeysBytes [][]byte, xorMode, seconds uint32, padding string) error {
	if i.nfsPKeys != nil {
		return E.New("already initialized")
	}
	l := len(nfsPKeysBytes)
	if l == 0 {
		return E.New("empty nfsPKeysBytes")
	}
	i.nfsPKeys = make([]any, l)
	i.nfsPKeysBytes = nfsPKeysBytes
	i.hash32s = make([][32]byte, l)
	for j, k := range nfsPKeysBytes {
		var err error
		if len(k) == X25519PasswordSize {
			i.nfsPKeys[j], err = ecdh.X25519().NewPublicKey(k)
			if err != nil {
				return err
			}
			i.relaysLength += 32 + 32
		} else {
			i.nfsPKeys[j], err = mlkem.NewEncapsulationKey768(k)
			if err != nil {
				return err
			}
			i.relaysLength += mlkem.CiphertextSize768 + 32
		}
		i.hash32s[j] = blake3.Sum256(k)
	}
	i.relaysLength -= 32
	i.xorMode = xorMode
	i.seconds = seconds
	return parsePadding(padding, &i.paddingLens, &i.paddingGaps)
}

// Handshake performs the client handshake on conn. With 0-RTT and a valid
// session, nothing is sent until the first Write.
func (i *ClientInstance) Handshake(conn net.Conn) (*CommonConn, error) {
	if i.nfsPKeys == nil {
		return nil, E.New("uninitialized")
	}
	c := newCommonConn(conn, hasAESGCMHardwareSupport)

	ivAndRelaysLength := 16 + i.relaysLength
	pfsKeyExchangeLength := 18 + mlkem.EncapsulationKeySize768 + 32 + 16
	paddingLength, paddingLens, paddingGaps := createPadding(i.paddingLens, i.paddingGaps)
	clientHello := make([]byte, ivAndRelaysLength+pfsKeyExchangeLength+paddingLength)

	iv := clientHello[:16]
	rand.Read(iv)
	relays := clientHello[16:ivAndRelaysLength]
	var nfsKey []byte
	var lastCTR cipher.Stream
	for j, k := range i.nfsPKeys {
		index := 32
		switch k := k.(type) {
		case *ecdh.PublicKey:
			privateKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
			copy(relays, privateKey.PublicKey().Bytes())
			var err error
			nfsKey, err = privateKey.ECDH(k)
			if err != nil {
				return nil, err
			}
		case *mlkem.EncapsulationKey768:
			var ciphertext []byte
			nfsKey, ciphertext = k.Encapsulate()
			copy(relays, ciphertext)
			index = mlkem.CiphertextSize768
		}
		if i.xorMode > 0 { // this xor can (others can't) be recovered by client's config, revealing an X25519 public key / ML-KEM-768 ciphertext, that's why "native" values
			newCTR(i.nfsPKeysBytes[j], iv).XORKeyStream(relays, relays[:index]) // make X25519 public key / ML-KEM-768 ciphertext distinguishable from random bytes
		}
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:32]) // make this relay irreplaceable
		}
		if j == len(i.nfsPKeys)-1 {
			break
		}
		lastCTR = newCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays[index:], i.hash32s[j+1][:])
		relays = relays[index+32:]
	}
	nfsAEAD := newAEAD(iv, nfsKey, c.useAES)

	if i.seconds > 0 {
		i.access.RLock()
		if time.Now().Before(i.expire) {
			c.client = i
			c.unitedKey = append(i.pfsKey, nfsKey...) // different unitedKey for each connection
			nfsAEAD.Seal(clientHello[:ivAndRelaysLength], nil, encodeLength(32), nil)
			nfsAEAD.Seal(clientHello[:ivAndRelaysLength+18], nil, i.ticket, nil)
			i.access.RUnlock()
			c.preWrite = clientHello[:ivAndRelaysLength+18+32]
			c.aead = newAEAD(clientHello[ivAndRelaysLength+18:ivAndRelaysLength+18+32], c.unitedKey, c.useAES)
			if i.xorMode == 2 {
				c.Conn = newXorConn(conn, newCTR(c.unitedKey, iv), nil, len(c.preWrite), 16)
			}
			return c, nil
		}
		i.access.RUnlock()
	}

	pfsKeyExchange := clientHello[ivAndRelaysLength : ivAndRelaysLength+pfsKeyExchangeLength]
	nfsAEAD.Seal(pfsKeyExchange[:0], nil, encodeLength(pfsKeyExchangeLength-18), nil)
	mlkem768DKey, _ := mlkem.GenerateKey768()
	x25519SKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pfsPublicKey := append(mlkem768DKey.EncapsulationKey().Bytes(), x25519SKey.PublicKey().Bytes()...)
	nfsAEAD.Seal(pfsKeyExchange[:18], nil, pfsPublicKey, nil)

	padding := clientHello[ivAndRelaysLength+pfsKeyExchangeLength:]
	nfsAEAD.Seal(padding[:0], nil, encodeLength(paddingLength-18), nil)
	nfsAEAD.Seal(padding[:18], nil, padding[18:paddingLength-16], nil)

	paddingLens[0] = ivAndRelaysLength + pfsKeyExchangeLength + paddingLens[0]
	for index, l := range paddingLens { // sends padding in a fragmented way, to create variable traffic pattern, before inner VLESS flow takes control
		if l > 0 {
			_, err := conn.Write(clientHello[:l])
			if err != nil {
				return nil, err
			}
			clientHello = clientHello[l:]
		}
		if len(paddingGaps) > index {
			time.Sleep(paddingGaps[index])
		}
	}

	encryptedPfsPublicKey := make([]byte, mlkem.CiphertextSize768+32+16)
	_, err := io.ReadFull(conn, encryptedPfsPublicKey)
	if err != nil {
		return nil, err
	}
	_, err = nfsAEAD.Open(encryptedPfsPublicKey[:0], maxNonce, encryptedPfsPublicKey, nil)
	if err != nil {
		return nil, E.Cause(err, "decrypt server hello")
	}
	mlkem768Key, err := mlkem768DKey.Decapsulate(encryptedPfsPublicKey[:mlkem.CiphertextSize768])
	if err != nil {
		return nil, err
	}
	peerX25519PKey, err := ecdh.X25519().NewPublicKey(encryptedPfsPublicKey[mlkem.CiphertextSize768 : mlkem.CiphertextSize768+32])
	if err != nil {
		return nil, err
	}
	x25519Key, err := x25519SKey.ECDH(peerX25519PKey)
	if err != nil {
		return nil, err
	}
	pfsKey := make([]byte, 32+32) // no more capacity
	copy(pfsKey, mlkem768Key)
	copy(pfsKey[32:], x25519Key)
	c.unitedKey = append(pfsKey, nfsKey...)
	c.aead = newAEAD(pfsPublicKey, c.unitedKey, c.useAES)
	c.peerAEAD = newAEAD(encryptedPfsPublicKey[:mlkem.CiphertextSize768+32], c.unitedKey, c.useAES)

	encryptedTicket := make([]byte, 32)
	_, err = io.ReadFull(conn, encryptedTicket)
	if err != nil {
		return nil, err
	}
	_, err = c.peerAEAD.Open(encryptedTicket[:0], nil, encryptedTicket, nil)
	if err != nil {
		return nil, err
	}
	seconds := decodeLength(encryptedTicket)

	if i.seconds > 0 && seconds > 0 {
		i.access.Lock()
		i.expire = time.Now().Add(time.Duration(seconds) * time.Second)
		i.pfsKey = pfsKey
		i.ticket = encryptedTicket[:16]
		i.access.Unlock()
	}

	encryptedLength := make([]byte, 18)
	_, err = io.ReadFull(conn, encryptedLength)
	if err != nil {
		return nil, err
	}
	_, err = c.peerAEAD.Open(encryptedLength[:0], nil, encryptedLength, nil)
	if err != nil {
		return nil, err
	}
	length := decodeLength(encryptedLength[:2])
	c.peerPadding = make([]byte, length) // important: allows server sends padding slowly, eliminating 1-RTT's traffic pattern

	if i.xorMode == 2 {
		c.Conn = newXorConn(conn, newCTR(c.unitedKey, iv), newCTR(c.unitedKey, encryptedTicket[:16]), 0, length)
	}
	return c, nil
}
