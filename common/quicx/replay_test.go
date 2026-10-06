//go:build with_quic

package quicx

import (
	"testing"
	"time"
)

func replayTestNonce(seed byte) [AuthNonceLen]byte {
	var nonce [AuthNonceLen]byte
	for index := range nonce {
		nonce[index] = seed
	}
	return nonce
}

func newReplayTestCache(size int, ttl time.Duration, now *time.Time) *replayCache {
	cache := newReplayCache(size, ttl)
	cache.now = func() time.Time {
		return *now
	}
	return cache
}

func requireReplay(t *testing.T, cache *replayCache, nonce [AuthNonceLen]byte, sessionID uint64, expected bool, message string) {
	t.Helper()
	if actual := cache.checkAndRecord(nonce, sessionID); actual != expected {
		t.Fatalf("%s: checkAndRecord(session %d) = %v, want %v", message, sessionID, actual, expected)
	}
}

func TestReplayCacheDetectsOtherSession(t *testing.T) {
	now := time.Now()
	cache := newReplayTestCache(16, time.Hour, &now)
	nonce := replayTestNonce(0x11)
	requireReplay(t, cache, nonce, 1, false, "the first use of a nonce is not a replay")
	requireReplay(t, cache, nonce, 2, true, "the same nonce in another session is a replay")
	requireReplay(t, cache, nonce, 3, true, "the replay is reported for every other session")
}

func TestReplayCacheAllowsSameSession(t *testing.T) {
	now := time.Now()
	cache := newReplayTestCache(16, time.Hour, &now)
	nonce := replayTestNonce(0x21)
	requireReplay(t, cache, nonce, 1, false, "the first use of a nonce is not a replay")
	requireReplay(t, cache, nonce, 1, false, "a session may present its own nonce again")
	requireReplay(t, cache, nonce, 2, true, "another session is still rejected")
}

func TestReplayCacheExpiresNonce(t *testing.T) {
	now := time.Now()
	cache := newReplayTestCache(16, time.Hour, &now)
	nonce := replayTestNonce(0x31)
	requireReplay(t, cache, nonce, 1, false, "the first use of a nonce is not a replay")
	now = now.Add(time.Hour - time.Second)
	requireReplay(t, cache, nonce, 2, true, "inside the window the nonce is still known")
	now = now.Add(2 * time.Second)
	requireReplay(t, cache, nonce, 2, false, "an expired nonce is accepted again")
	requireReplay(t, cache, nonce, 3, true, "the expired nonce was recorded again")
}

func TestReplayCacheEvictsOldestNonce(t *testing.T) {
	now := time.Now()
	cache := newReplayTestCache(2, time.Hour, &now)
	first := replayTestNonce(0x41)
	second := replayTestNonce(0x42)
	third := replayTestNonce(0x43)
	requireReplay(t, cache, first, 1, false, "the first use of a nonce is not a replay")
	requireReplay(t, cache, second, 2, false, "the first use of a nonce is not a replay")
	requireReplay(t, cache, third, 3, false, "the first use of a nonce is not a replay")
	requireReplay(t, cache, first, 4, false, "the oldest nonce was evicted")
	requireReplay(t, cache, third, 5, true, "the newest nonce is still known")
}

func TestReplayCacheKeepsRerecordedNonce(t *testing.T) {
	// A nonce recorded again after it expired must stay known while its newer
	// entry is alive, even when the ring position of the older entry is reused.
	now := time.Now()
	cache := newReplayTestCache(2, time.Hour, &now)
	nonce := replayTestNonce(0x51)
	requireReplay(t, cache, nonce, 1, false, "the first use of a nonce is not a replay")
	now = now.Add(2 * time.Hour)
	requireReplay(t, cache, nonce, 2, false, "the expired nonce is recorded for the new session")
	// Fill the ring so the position of the expired entry is overwritten.
	requireReplay(t, cache, replayTestNonce(0x52), 3, false, "the first use of a nonce is not a replay")
	requireReplay(t, cache, nonce, 4, true, "the re-recorded nonce is still a replay")
	requireReplay(t, cache, nonce, 2, false, "the session which recorded it may present it again")
}
