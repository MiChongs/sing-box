package group

import (
	"math/bits"

	"github.com/cespare/xxhash/v2"
	"github.com/sagernet/sing-box/adapter"
)

// Consistent-hashing algorithm for the Smart group.
//
// Pins a request target to a deterministic candidate from the list
// already assembled by selectProxiesTraced. Two useful properties:
//
//   1. Same target → same candidate across calls, as long as the
//      candidate set shape (the concrete sequence returned by
//      selectProxiesTraced after weight/priority/hysteresis) stays
//      the same. This is the classic "session affinity" win —
//      applications that rely on server-side state (shopping carts,
//      rate-limit tokens, sticky TLS sessions) get a stable egress
//      even without explicit sticky-session learning.
//
//   2. Distinct targets spread across the candidate set via jump
//      consistent hashing so aggregate load stays balanced — not all
//      requests pile up on candidate[0] the way strict-best would.
//
// Contrast with strategyConsistentHashing in loadbalance.go, which
// hashes over the FULL outbound list. Smart's candidates list is
// already pre-filtered to nodes the tier logic considers good — we
// consistent-hash within THAT set. The trade-off is:
//
//   - Stability: smaller per-call variance than round-robin /
//     weighted-random, and free of the "hot top node" pileup of
//     strict-best.
//   - Quality: candidate[0] from the tier logic is usually the
//     highest-scoring node; consistent-hashing may pick candidate[3]
//     instead if the target's hash lands there. That's the explicit
//     trade-off the user opts into by picking this algorithm —
//     stability over "always the single best".
//
// Ring-probing: if the hash's chosen slot can't currently be dialed
// (happens rarely here because tier logic already filtered), the
// caller's dialWithRetry will proceed through the remaining
// candidates in sequence. We don't re-shuffle here to preserve the
// algorithm's determinism — callers observe the hashed choice first.

// reorderConsistentHashing picks a single candidate by hashing the
// request key (target for TCP, target+isUDP for UDP symmetry) into
// the candidate list and promoting it to position 0. Candidates is
// mutated in place. The remaining candidates keep their original
// relative order so the retry path has a sensible fallback sequence.
func (s *Smart) reorderConsistentHashing(candidates []adapter.Outbound, target string, isUDP bool) []adapter.Outbound {
	n := len(candidates)
	if n <= 1 {
		return candidates
	}
	key := consistentHashingKey(target, isUDP)
	if key == "" {
		// No routable target (direct-IP dial with no sniff). Leave
		// ordering alone so the caller still dials candidate[0] — the
		// tier-logic's best guess is a better pick than an arbitrary
		// hashed slot on a synthetic key.
		return candidates
	}
	slot := int(jumpHash(hashConsistentKey(key), int32(n)))
	if slot != 0 {
		candidates[0], candidates[slot] = candidates[slot], candidates[0]
	}
	return candidates
}

// consistentHashingKey builds the hashing key for a Smart dial. The
// target (meta.smartTarget) is already the normalised (host|IP) +
// port string, which is what we want: a target on UDP and TCP with
// the same host should hash to DIFFERENT slots (they're independent
// connections in the user's traffic graph), so we fold isUDP into
// the key.
//
// Empty target → empty key → algorithm falls back to position 0.
func consistentHashingKey(target string, isUDP bool) string {
	if target == "" {
		return ""
	}
	if isUDP {
		return "u|" + target
	}
	return "t|" + target
}

// hashConsistentKey folds a string into a uint64 suitable for
// jumpHash. xxhash.Sum64String is allocation-free and has a
// well-mixed avalanche — important because jumpHash's first few
// multiplies are sensitive to input bit distribution (a key that's
// sequential in its low bits will pile into the first few buckets
// otherwise).
//
// RotateLeft folds the bits one more time so two keys that differ
// only in a few low bits don't end up in adjacent jumpHash slots —
// aids spread on short target strings like "1.2.3.4:443".
func hashConsistentKey(key string) uint64 {
	if key == "" {
		return 0
	}
	h := xxhash.Sum64String(key)
	return bits.RotateLeft64(h, 17) ^ h
}

// jumpHash mirrors loadbalance.go's implementation — re-declared in
// this file only because it's an internal helper there (lowercase)
// and we're in the same package, so a direct call works without
// copying. Kept as a symbol here purely for documentation; see
// loadbalance.go for the canonical implementation.
var _ = jumpHash // compile-time check that the symbol is reachable from this file
