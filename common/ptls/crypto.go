package ptls

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"time"
)

var (
	maskDomain = []byte("ptls-v1-whitening-mask")
	authDomain = []byte("ptls-v1-session-auth")
)

func PackSessionID(psk *[32]byte, clientRandom []byte, now time.Time) [32]byte {
	var sessionId [32]byte
	var timestampBytes [8]byte
	binary.BigEndian.PutUint64(timestampBytes[:], uint64(now.Unix()))

	hMask := hmac.New(sha256.New, psk[:])
	hMask.Write(clientRandom)
	hMask.Write(maskDomain)
	mask := hMask.Sum(nil)[:8]

	var maskedTimestamp [8]byte
	for i := 0; i < 8; i++ {
		maskedTimestamp[i] = timestampBytes[i] ^ mask[i]
	}

	hAuth := hmac.New(sha256.New, psk[:])
	hAuth.Write(timestampBytes[:])
	hAuth.Write(clientRandom)
	hAuth.Write(authDomain)
	authTag := hAuth.Sum(nil)[:24]

	for i := 0; i < 8; i++ {
		sessionId[i*4] = maskedTimestamp[i]
		sessionId[i*4+1] = authTag[i*3]
		sessionId[i*4+2] = authTag[i*3+1]
		sessionId[i*4+3] = authTag[i*3+2]
	}

	return sessionId
}

func UnpackSessionID(psk *[32]byte, clientRandom []byte, sessionId []byte) (time.Time, []byte, bool) {
	if len(sessionId) != 32 {
		return time.Time{}, nil, false
	}

	var maskedTimestamp [8]byte
	var authTag [24]byte

	for i := 0; i < 8; i++ {
		maskedTimestamp[i] = sessionId[i*4]
		authTag[i*3] = sessionId[i*4+1]
		authTag[i*3+1] = sessionId[i*4+2]
		authTag[i*3+2] = sessionId[i*4+3]
	}

	hMask := hmac.New(sha256.New, psk[:])
	hMask.Write(clientRandom)
	hMask.Write(maskDomain)
	mask := hMask.Sum(nil)[:8]

	var timestampBytes [8]byte
	for i := 0; i < 8; i++ {
		timestampBytes[i] = maskedTimestamp[i] ^ mask[i]
	}
	ts := int64(binary.BigEndian.Uint64(timestampBytes[:]))
	clientTime := time.Unix(ts, 0)

	hAuth := hmac.New(sha256.New, psk[:])
	hAuth.Write(timestampBytes[:])
	hAuth.Write(clientRandom)
	hAuth.Write(authDomain)
	expectedTag := hAuth.Sum(nil)[:24]

	if subtle.ConstantTimeCompare(authTag[:], expectedTag) != 1 {
		return time.Time{}, nil, false
	}

	return clientTime, authTag[:], true
}