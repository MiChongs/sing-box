// Package chacha20 implements IETF ChaCha20 (RFC 8439) over the standard
// library so Morph can stay free of third-party dependencies.
package chacha20

import "encoding/binary"

const (
	// KeySize is the ChaCha20 key length.
	KeySize = 32
	// NonceSize is the IETF 96-bit nonce length.
	NonceSize = 12
	blockSize = 64
)

var sigma = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

// XORKeyStreamAt XORs src with the ChaCha20 keystream at the given byte offset.
// dst and src may alias. The 32-bit block counter starts at offset/64.
func XORKeyStreamAt(dst, src []byte, key *[KeySize]byte, nonce *[NonceSize]byte, offset uint64) {
	if len(dst) < len(src) {
		src = src[:len(dst)]
	}
	var block [blockSize]byte
	counter := uint32(offset / blockSize)
	skip := int(offset % blockSize)
	for len(src) > 0 {
		block64(block[:], key, nonce, counter)
		take := blockSize - skip
		if take > len(src) {
			take = len(src)
		}
		for i := 0; i < take; i++ {
			dst[i] = src[i] ^ block[skip+i]
		}
		dst = dst[take:]
		src = src[take:]
		skip = 0
		counter++
	}
}

func block64(out []byte, key *[KeySize]byte, nonce *[NonceSize]byte, counter uint32) {
	s0, s1, s2, s3 := sigma[0], sigma[1], sigma[2], sigma[3]
	k0 := binary.LittleEndian.Uint32(key[0:4])
	k1 := binary.LittleEndian.Uint32(key[4:8])
	k2 := binary.LittleEndian.Uint32(key[8:12])
	k3 := binary.LittleEndian.Uint32(key[12:16])
	k4 := binary.LittleEndian.Uint32(key[16:20])
	k5 := binary.LittleEndian.Uint32(key[20:24])
	k6 := binary.LittleEndian.Uint32(key[24:28])
	k7 := binary.LittleEndian.Uint32(key[28:32])
	n0 := binary.LittleEndian.Uint32(nonce[0:4])
	n1 := binary.LittleEndian.Uint32(nonce[4:8])
	n2 := binary.LittleEndian.Uint32(nonce[8:12])

	x0, x1, x2, x3 := s0, s1, s2, s3
	x4, x5, x6, x7 := k0, k1, k2, k3
	x8, x9, x10, x11 := k4, k5, k6, k7
	x12, x13, x14, x15 := counter, n0, n1, n2

	for i := 0; i < 10; i++ {
		x0, x4, x8, x12 = quarter(x0, x4, x8, x12)
		x1, x5, x9, x13 = quarter(x1, x5, x9, x13)
		x2, x6, x10, x14 = quarter(x2, x6, x10, x14)
		x3, x7, x11, x15 = quarter(x3, x7, x11, x15)
		x0, x5, x10, x15 = quarter(x0, x5, x10, x15)
		x1, x6, x11, x12 = quarter(x1, x6, x11, x12)
		x2, x7, x8, x13 = quarter(x2, x7, x8, x13)
		x3, x4, x9, x14 = quarter(x3, x4, x9, x14)
	}

	binary.LittleEndian.PutUint32(out[0:4], x0+s0)
	binary.LittleEndian.PutUint32(out[4:8], x1+s1)
	binary.LittleEndian.PutUint32(out[8:12], x2+s2)
	binary.LittleEndian.PutUint32(out[12:16], x3+s3)
	binary.LittleEndian.PutUint32(out[16:20], x4+k0)
	binary.LittleEndian.PutUint32(out[20:24], x5+k1)
	binary.LittleEndian.PutUint32(out[24:28], x6+k2)
	binary.LittleEndian.PutUint32(out[28:32], x7+k3)
	binary.LittleEndian.PutUint32(out[32:36], x8+k4)
	binary.LittleEndian.PutUint32(out[36:40], x9+k5)
	binary.LittleEndian.PutUint32(out[40:44], x10+k6)
	binary.LittleEndian.PutUint32(out[44:48], x11+k7)
	binary.LittleEndian.PutUint32(out[48:52], x12+counter)
	binary.LittleEndian.PutUint32(out[52:56], x13+n0)
	binary.LittleEndian.PutUint32(out[56:60], x14+n1)
	binary.LittleEndian.PutUint32(out[60:64], x15+n2)
}

func quarter(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = d<<16 | d>>16
	c += d
	b ^= c
	b = b<<12 | b>>20
	a += b
	d ^= a
	d = d<<8 | d>>24
	c += d
	b ^= c
	b = b<<7 | b>>25
	return a, b, c, d
}
