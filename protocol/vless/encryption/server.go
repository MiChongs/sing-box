package encryption

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	"lukechampine.com/blake3"
)

type serverSession struct {
	pfsKey  []byte
	nfsKeys sync.Map
}

// ServerInstance holds the server configuration and the 0-RTT sessions issued
// to clients.
type ServerInstance struct {
	nfsSKeys      []any
	nfsPKeysBytes [][]byte
	hash32s       [][32]byte
	relaysLength  int
	xorMode       uint32
	secondsFrom   int64
	secondsTo     int64
	paddingLens   [][3]int
	paddingGaps   [][3]int

	access    sync.RWMutex
	cleanOnce sync.Once
	done      chan struct{}
	closed    bool
	lasts     map[int64][16]byte
	tickets   [][16]byte
	sessions  map[[16]byte]*serverSession
}

func (i *ServerInstance) init(nfsSKeysBytes [][]byte, xorMode uint32, secondsFrom, secondsTo int64, padding string) error {
	if i.nfsSKeys != nil {
		return E.New("already initialized")
	}
	l := len(nfsSKeysBytes)
	if l == 0 {
		return E.New("empty nfsSKeysBytes")
	}
	i.nfsSKeys = make([]any, l)
	i.nfsPKeysBytes = make([][]byte, l)
	i.hash32s = make([][32]byte, l)
	for j, k := range nfsSKeysBytes {
		if len(k) == X25519PrivateKeySize {
			privateKey, err := ecdh.X25519().NewPrivateKey(k)
			if err != nil {
				return err
			}
			i.nfsSKeys[j] = privateKey
			i.nfsPKeysBytes[j] = privateKey.PublicKey().Bytes()
			i.relaysLength += 32 + 32
		} else {
			decapsulationKey, err := mlkem.NewDecapsulationKey768(k)
			if err != nil {
				return err
			}
			i.nfsSKeys[j] = decapsulationKey
			i.nfsPKeysBytes[j] = decapsulationKey.EncapsulationKey().Bytes()
			i.relaysLength += mlkem.CiphertextSize768 + 32
		}
		i.hash32s[j] = blake3.Sum256(i.nfsPKeysBytes[j])
	}
	i.relaysLength -= 32
	i.xorMode = xorMode
	i.secondsFrom = secondsFrom
	i.secondsTo = secondsTo
	err := parsePadding(padding, &i.paddingLens, &i.paddingGaps)
	if err != nil {
		return err
	}
	if i.secondsFrom > 0 || i.secondsTo > 0 {
		i.lasts = make(map[int64][16]byte)
		i.tickets = make([][16]byte, 0, 1024)
		i.sessions = make(map[[16]byte]*serverSession)
		i.done = make(chan struct{})
	}
	return nil
}

func (i *ServerInstance) cleanSessions() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-i.done:
			return
		case <-ticker.C:
		}
		i.access.Lock()
		minute := time.Now().Unix() / 60
		last := i.lasts[minute]
		delete(i.lasts, minute)
		delete(i.lasts, minute-1) // for insurance
		if last != [16]byte{} {
			for j, ticket := range i.tickets {
				delete(i.sessions, ticket)
				if ticket == last {
					i.tickets = i.tickets[j+1:]
					break
				}
			}
		}
		i.access.Unlock()
	}
}

func (i *ServerInstance) Close() error {
	i.access.Lock()
	defer i.access.Unlock()
	if !i.closed {
		i.closed = true
		if i.done != nil {
			close(i.done)
		}
	}
	return nil
}

// Handshake performs the server handshake on conn.
func (i *ServerInstance) Handshake(conn net.Conn) (*CommonConn, error) {
	if i.nfsSKeys == nil {
		return nil, E.New("uninitialized")
	}
	c := newCommonConn(conn, true)

	ivAndRelays := make([]byte, 16+i.relaysLength)
	_, err := io.ReadFull(conn, ivAndRelays)
	if err != nil {
		return nil, err
	}
	iv := ivAndRelays[:16]
	relays := ivAndRelays[16:]
	var nfsKey []byte
	var lastCTR cipher.Stream
	for j, k := range i.nfsSKeys {
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:32]) // recover this relay
		}
		index := 32
		if _, isMLKEM := k.(*mlkem.DecapsulationKey768); isMLKEM {
			index = mlkem.CiphertextSize768
		}
		if i.xorMode > 0 {
			newCTR(i.nfsPKeysBytes[j], iv).XORKeyStream(relays, relays[:index]) // we don't use buggy elligator2, because we have PSK :)
		}
		switch k := k.(type) {
		case *ecdh.PrivateKey:
			publicKey, err := ecdh.X25519().NewPublicKey(relays[:index])
			if err != nil {
				return nil, err
			}
			if publicKey.Bytes()[31] > 127 { // we just don't want the observer can change even one bit without breaking the connection, though it has nothing to do with security
				return nil, E.New("the highest bit of the last byte of the peer-sent X25519 public key is not 0")
			}
			nfsKey, err = k.ECDH(publicKey)
			if err != nil {
				return nil, err
			}
		case *mlkem.DecapsulationKey768:
			nfsKey, err = k.Decapsulate(relays[:index])
			if err != nil {
				return nil, err
			}
		}
		if j == len(i.nfsSKeys)-1 {
			break
		}
		relays = relays[index:]
		lastCTR = newCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays, relays[:32])
		if !bytes.Equal(relays[:32], i.hash32s[j+1][:]) {
			return nil, E.New("unexpected hash32: ", fmt.Sprint(relays[:32]))
		}
		relays = relays[32:]
	}
	nfsAEAD := newAEAD(iv, nfsKey, c.useAES)

	encryptedLength := make([]byte, 18)
	_, err = io.ReadFull(conn, encryptedLength)
	if err != nil {
		return nil, err
	}
	decryptedLength := make([]byte, 2)
	_, err = nfsAEAD.Open(decryptedLength[:0], nil, encryptedLength, nil)
	if err != nil {
		c.useAES = !c.useAES
		nfsAEAD = newAEAD(iv, nfsKey, c.useAES)
		_, err = nfsAEAD.Open(decryptedLength[:0], nil, encryptedLength, nil)
		if err != nil {
			return nil, err
		}
	}
	length := decodeLength(decryptedLength)

	if length == 32 {
		if i.secondsFrom == 0 && i.secondsTo == 0 {
			return nil, E.New("0-RTT is not allowed")
		}
		encryptedTicket := make([]byte, 32)
		_, err = io.ReadFull(conn, encryptedTicket)
		if err != nil {
			return nil, err
		}
		ticket, err := nfsAEAD.Open(nil, nil, encryptedTicket, nil)
		if err != nil {
			return nil, err
		}
		i.access.RLock()
		s := i.sessions[[16]byte(ticket)]
		i.access.RUnlock()
		if s == nil {
			noises := make([]byte, randBetween(1279, 2279)) // matches 1-RTT's server hello length for "random", though it is not important, just for example
			for {
				rand.Read(noises)
				if _, err = decodeHeader(noises); err != nil {
					break
				}
			}
			conn.Write(noises) // make client do new handshake
			return nil, E.New("expired ticket")
		}
		if _, loaded := s.nfsKeys.LoadOrStore([32]byte(nfsKey), true); loaded { // prevents bad client also
			return nil, E.New("replay detected")
		}
		c.unitedKey = append(s.pfsKey, nfsKey...) // the same nfsKey links the upload & download (prevents server -> client's another request)
		c.preWrite = make([]byte, 16)
		rand.Read(c.preWrite) // always trust yourself, not the client (also prevents being parsed as TLS thus causing false interruption for "native" and "xorpub")
		c.aead = newAEAD(c.preWrite, c.unitedKey, c.useAES)
		c.peerAEAD = newAEAD(encryptedTicket, c.unitedKey, c.useAES) // unchangeable ctx (prevents server -> server), and different ctx length for upload / download (prevents client -> client)
		if i.xorMode == 2 {
			c.Conn = newXorConn(conn, newCTR(c.unitedKey, c.preWrite), newCTR(c.unitedKey, iv), 16, 0) // it doesn't matter if the attacker sends client's iv back to the client
		}
		return c, nil
	}

	if length < mlkem.EncapsulationKeySize768+32+16 { // client may send more public keys in the future's version
		return nil, E.New("too short length")
	}
	encryptedPfsPublicKey := make([]byte, length)
	_, err = io.ReadFull(conn, encryptedPfsPublicKey)
	if err != nil {
		return nil, err
	}
	_, err = nfsAEAD.Open(encryptedPfsPublicKey[:0], nil, encryptedPfsPublicKey, nil)
	if err != nil {
		return nil, err
	}
	mlkem768EKey, err := mlkem.NewEncapsulationKey768(encryptedPfsPublicKey[:mlkem.EncapsulationKeySize768])
	if err != nil {
		return nil, err
	}
	mlkem768Key, encapsulatedPfsKey := mlkem768EKey.Encapsulate()
	peerX25519PKey, err := ecdh.X25519().NewPublicKey(encryptedPfsPublicKey[mlkem.EncapsulationKeySize768 : mlkem.EncapsulationKeySize768+32])
	if err != nil {
		return nil, err
	}
	x25519SKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	x25519Key, err := x25519SKey.ECDH(peerX25519PKey)
	if err != nil {
		return nil, err
	}
	pfsKey := make([]byte, 32+32) // no more capacity
	copy(pfsKey, mlkem768Key)
	copy(pfsKey[32:], x25519Key)
	pfsPublicKey := append(encapsulatedPfsKey, x25519SKey.PublicKey().Bytes()...)
	c.unitedKey = append(pfsKey, nfsKey...)
	c.aead = newAEAD(pfsPublicKey, c.unitedKey, c.useAES)
	c.peerAEAD = newAEAD(encryptedPfsPublicKey[:mlkem.EncapsulationKeySize768+32], c.unitedKey, c.useAES)

	var ticket [16]byte
	rand.Read(ticket[:])
	var seconds int64
	if i.secondsTo == 0 {
		seconds = i.secondsFrom * randBetween(50, 100) / 100
	} else {
		seconds = randBetween(i.secondsFrom, i.secondsTo)
	}
	copy(ticket[:], encodeLength(int(seconds)))
	if seconds > 0 {
		i.access.Lock()
		i.lasts[(time.Now().Unix()+max(i.secondsFrom, i.secondsTo))/60+2] = ticket
		i.tickets = append(i.tickets, ticket)
		i.sessions[ticket] = &serverSession{pfsKey: pfsKey}
		i.access.Unlock()
		i.cleanOnce.Do(func() {
			go i.cleanSessions()
		})
	}

	pfsKeyExchangeLength := mlkem.CiphertextSize768 + 32 + 16
	encryptedTicketLength := 32
	paddingLength, paddingLens, paddingGaps := createPadding(i.paddingLens, i.paddingGaps)
	serverHello := make([]byte, pfsKeyExchangeLength+encryptedTicketLength+paddingLength)
	nfsAEAD.Seal(serverHello[:0], maxNonce, pfsPublicKey, nil)
	c.aead.Seal(serverHello[:pfsKeyExchangeLength], nil, ticket[:], nil)
	padding := serverHello[pfsKeyExchangeLength+encryptedTicketLength:]
	c.aead.Seal(padding[:0], nil, encodeLength(paddingLength-18), nil)
	c.aead.Seal(padding[:18], nil, padding[18:paddingLength-16], nil)

	paddingLens[0] = pfsKeyExchangeLength + encryptedTicketLength + paddingLens[0]
	for index, l := range paddingLens { // sends padding in a fragmented way, to create variable traffic pattern, before inner VLESS flow takes control
		if l > 0 {
			_, err = conn.Write(serverHello[:l])
			if err != nil {
				return nil, err
			}
			serverHello = serverHello[l:]
		}
		if len(paddingGaps) > index {
			time.Sleep(paddingGaps[index])
		}
	}

	// important: allows client sends padding slowly, eliminating 1-RTT's traffic pattern
	_, err = io.ReadFull(conn, encryptedLength)
	if err != nil {
		return nil, err
	}
	_, err = nfsAEAD.Open(encryptedLength[:0], nil, encryptedLength, nil)
	if err != nil {
		return nil, err
	}
	encryptedPadding := make([]byte, decodeLength(encryptedLength[:2]))
	_, err = io.ReadFull(conn, encryptedPadding)
	if err != nil {
		return nil, err
	}
	_, err = nfsAEAD.Open(encryptedPadding[:0], nil, encryptedPadding, nil)
	if err != nil {
		return nil, err
	}

	if i.xorMode == 2 {
		c.Conn = newXorConn(conn, newCTR(c.unitedKey, ticket[:]), newCTR(c.unitedKey, iv), 0, 0)
	}
	return c, nil
}
