//go:build with_quic

package quicx

import (
	"sync"
	"time"
)

const (
	// defaultReplayCacheSize is how many authentication nonces are remembered.
	// The replay window ends at whichever limit is reached first, this many
	// authenticated sessions or defaultReplayCacheTTL.
	defaultReplayCacheSize = 1 << 16

	// defaultReplayCacheTTL is how long an authentication nonce is remembered.
	// It matches how long crypto/tls keeps the session ticket keys a 0-RTT
	// attempt resumes from.
	defaultReplayCacheTTL = 24 * time.Hour
)

// replayEntry is one remembered authentication nonce. Entries live in the ring
// buffer of replayCache, and entries maps a nonce to its slot so a lookup does
// not have to scan the ring.
type replayEntry struct {
	nonce     [AuthNonceLen]byte
	sessionID uint64
	seenAt    time.Time
}

// replayCache remembers the authentication nonce of recently authenticated
// sessions and reports a nonce another session already used.
//
// QUIC 0-RTT data is not replay protected, so without this check a captured
// 0-RTT flight could be sent to the server again: it would authenticate with
// the password it carries, dial the destination of the CONNECT request it
// carries and deliver the first payload of that request a second time. The
// nonce is the only part of the flight which lets the server tell the copy from
// the original, because it is chosen by the client for exactly one session.
//
// The cache is bounded twice: it keeps at most the configured number of nonces,
// overwriting the oldest one once it is full, and treats entries older than the
// configured TTL as unknown. A replay is therefore rejected within that window,
// which is the usual trade-off of a stateful anti-replay check.
//
// The state is per server instance: a deployment with several QUICX servers
// behind one address only rejects a replay which reaches an instance that saw
// the original session, and a restart forgets the window.
type replayCache struct {
	access  sync.Mutex
	entries map[[AuthNonceLen]byte]*replayEntry
	ring    []replayEntry
	size    int
	next    int
	ttl     time.Duration
	now     func() time.Time
}

func newReplayCache(size int, ttl time.Duration) *replayCache {
	if size <= 0 {
		size = defaultReplayCacheSize
	}
	if ttl <= 0 {
		ttl = defaultReplayCacheTTL
	}
	return &replayCache{
		entries: make(map[[AuthNonceLen]byte]*replayEntry, size),
		ring:    make([]replayEntry, size),
		ttl:     ttl,
		now:     time.Now,
	}
}

// checkAndRecord reports whether nonce was already used by another session
// within the replay window. An unknown or expired nonce is recorded for
// sessionID and reported as not replayed.
//
// A session is allowed to present its own nonce more than once: a client which
// races two authentication streams, or which has to resend its authentication
// after the server rejected the 0-RTT attempt, is not a replay and must not
// tear the session down.
func (c *replayCache) checkAndRecord(nonce [AuthNonceLen]byte, sessionID uint64) bool {
	now := c.now()
	c.access.Lock()
	defer c.access.Unlock()
	if entry, loaded := c.entries[nonce]; loaded {
		if now.Sub(entry.seenAt) < c.ttl {
			return entry.sessionID != sessionID
		}
		// The entry outlived the replay window: it is treated as unknown and
		// recorded again below.
	}
	var slot *replayEntry
	if c.size < len(c.ring) {
		slot = &c.ring[c.size]
		c.size++
	} else {
		slot = &c.ring[c.next]
		c.next = (c.next + 1) % len(c.ring)
		// A slot may have been recorded a second time (an expired nonce which
		// was presented again) after this ring position was filled. In that
		// case entries points at the newer slot and this one must not be
		// removed, otherwise the nonce becomes unknown while it is still
		// inside the replay window.
		if current, loaded := c.entries[slot.nonce]; loaded && current == slot {
			delete(c.entries, slot.nonce)
		}
	}
	slot.nonce = nonce
	slot.sessionID = sessionID
	slot.seenAt = now
	c.entries[nonce] = slot
	return false
}
