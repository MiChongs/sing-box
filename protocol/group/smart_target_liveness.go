package group

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart"
	M "github.com/sagernet/sing/common/metadata"
)

// Target-level liveness — "true-alive vs fake-alive" detection.
//
// Classic URLTest only probes a single fixed URL. A node can pass
// URLTest (reaches generate_204) yet fail for the target the user
// actually wants (GFW / ISP / overseas CDN do per-SNI blocking;
// some nodes rate-limit specific ASNs; some have flaky routes to
// particular edges). Without per-target evidence, selectProxies
// keeps re-electing a node that's "alive" on paper but broken for
// the user's actual destination — the user experiences slow /
// stuck / failing dials until the 2× circuit-breaker trips, and
// even then only for dial-level failures; soft-stall (handshake OK
// then never gets first byte) never trips the breaker at all.
//
// This file adds two independent-but-complementary mechanisms:
//
//   A. Pre-dial FILTER — selectProxies reads per-(target, node)
//      ShortSuccessRate from the already-existing AtomicStatsRecord
//      and demotes nodes whose recent track record on THIS target is
//      bad enough to outweigh their overall alive status. Zero new
//      probe cost; pure read-side change.
//
//   B. Active SNI PROBE — a periodic task picks the top-K most-
//      visited targets in this group and dials a 2s TCP+TLS
//      handshake to each (target-SNI, alive-node) pair via the node's
//      outbound. Handshake success → per-(target, node) probe history
//      records "ok"; handshake failure → "blocked". Filter A reads
//      this history alongside the stats record, so the first time a
//      node is found to SNI-block a hot target, it gets pulled from
//      that target's candidate list without the user ever seeing a
//      failed dial.

// ── A: pre-dial filter constants ─────────────────────────────────────────────

const (
	// Minimum (success + failure) sample count on a (target, node)
	// before ShortSuccessRate is trusted enough to gate selection.
	// Below this threshold we fall through to the generic alive/breaker
	// filters so fresh nodes aren't unfairly penalised by one bad
	// observation.
	targetLivenessMinSamples = 3

	// Short-window EWMA success rate below which we consider a
	// (target, node) suspicious. 0.40 is intentionally permissive:
	// nodes that dip to 50-60% stay in rotation (variance absorbs
	// normal flakiness), only clearly broken ones (<40% recent
	// success despite 3+ attempts) get demoted.
	targetLivenessSuspicionRate = 0.40
)

// ── B: SNI-probe history ─────────────────────────────────────────────────────

// sniProbeResult is one observation from an active TLS-handshake
// probe. Kept intentionally small — x *(targets * nodes) of these
// live in memory simultaneously.
type sniProbeResult struct {
	// tsNS is the unix-nano of the observation.
	tsNS int64
	// ok is true when the probe completed a TLS handshake to the
	// target within the probe budget.
	ok bool
	// rttMS is the observed handshake round-trip for successful
	// probes, 0 for failures.
	rttMS int32
}

// sniProbeTTL is how long a probe result remains authoritative.
// After expiry the filter ignores it and falls back to
// AtomicStatsRecord + alive/breaker chain. 15 min matches the order
// of targetDebargoTTL so a single session's routing decisions stay
// coherent against the same observation horizon.
const sniProbeTTL = 15 * time.Minute

// sniProbeBudget caps the TLS-handshake phase of each probe. Short
// enough that the periodic task doesn't pile up under bad network,
// long enough that a typical 200-600ms handshake finishes cleanly.
const sniProbeBudget = 2 * time.Second

// targetHitTracker counts recent dials per target within this group.
// The periodic probe task samples the top-K entries to decide which
// (target, SNI) pairs to actively verify.
//
// Why xsync.MapOf over a plain sync.Map: we do a lot of Compute-or-
// Inc on the hot DialContext path, and xsync's lock-free LoadOrStore
// wins by ~3x over sync.Map in benchmarks. The counter values are
// *atomic.Int64 so we can Inc() without Store().
type targetHitTracker struct {
	counts *xsync.MapOf[string, *atomic.Int64]
}

func newTargetHitTracker() *targetHitTracker {
	return &targetHitTracker{
		counts: xsync.NewMapOf[string, *atomic.Int64](),
	}
}

// recordHit bumps the counter for target. Runs on every DialContext
// so it must stay O(1) and allocation-free past first-use of a
// given target.
func (t *targetHitTracker) recordHit(target string) {
	if target == "" {
		return
	}
	c, _ := t.counts.LoadOrCompute(target, func() *atomic.Int64 {
		return new(atomic.Int64)
	})
	c.Add(1)
}

// topK returns the K most-visited targets, reading the counter map
// in a single pass. Callers use this to pick probe targets — the
// tail is discarded because probe cost scales linearly with target
// count and long-tail targets see so little traffic that per-SNI
// verification isn't worth the network cost.
func (t *targetHitTracker) topK(k int) []string {
	if t == nil || k <= 0 {
		return nil
	}
	type row struct {
		target string
		count  int64
	}
	var rows []row
	t.counts.Range(func(target string, c *atomic.Int64) bool {
		rows = append(rows, row{target, c.Load()})
		return true
	})
	if len(rows) == 0 {
		return nil
	}
	// Partial sort — full sort is O(n log n), we only need top-K so
	// selection sort on the small k is faster for typical n < 100.
	if k > len(rows) {
		k = len(rows)
	}
	for i := 0; i < k; i++ {
		maxIdx := i
		for j := i + 1; j < len(rows); j++ {
			if rows[j].count > rows[maxIdx].count {
				maxIdx = j
			}
		}
		if maxIdx != i {
			rows[i], rows[maxIdx] = rows[maxIdx], rows[i]
		}
	}
	result := make([]string, k)
	for i := 0; i < k; i++ {
		result[i] = rows[i].target
	}
	return result
}

// ── B: probe + filter hook API ──────────────────────────────────────────────

// targetLivenessState holds the per-group runtime data added for
// this feature. Embedded into *Smart so the zero value is valid.
type targetLivenessState struct {
	hits *targetHitTracker
	// probeHistory keys on "target|node" (same delimiter pattern as
	// targetDebargo). Value is sniProbeResult (pointer to heap-
	// allocated). nil until first use.
	probeHistory *xsync.MapOf[string, *sniProbeResult]
}

// initTargetLiveness lazily allocates the state. Called once during
// PostStart so subsequent use is contention-free.
func (s *Smart) initTargetLiveness() {
	s.targetLiveness.hits = newTargetHitTracker()
	s.targetLiveness.probeHistory = xsync.NewMapOf[string, *sniProbeResult]()
}

// recordTargetHit is the DialContext hook that the caller fires once
// per successful selection — cheap enough to call on every dial.
func (s *Smart) recordTargetHit(target string) {
	if s == nil || s.targetLiveness.hits == nil || target == "" {
		return
	}
	s.targetLiveness.hits.recordHit(target)
}

// ── A: candidate-list post-processor ────────────────────────────────────────

// deprioritiseSuspicious stable-partitions candidates so that
// is-TargetSuspicious(target, node) pairs drop to the tail while
// trusted nodes keep their existing head order. Differs from a hard
// filter: we never REMOVE a node — if every node is suspicious the
// dial loop still has the full list, it just tries the best-looking
// (by the existing ranking) bad node last. That way a temporary
// broad-network-issue doesn't strand the request.
//
// Called AFTER reorderForRequestScene so the scene-rerank's choice
// at position 0 only survives when it's not also suspicious; if it
// is, the next non-suspicious candidate surfaces ahead of it.
//
// Cost: O(n) to compute the per-tag suspicion flags (each is one
// sync-map lookup + one atomic read), O(n log n) for the stable
// sort. For the typical K=10 candidate list this is sub-microsecond.
func (s *Smart) deprioritiseSuspicious(candidates []adapter.Outbound, target string) []adapter.Outbound {
	if s == nil || len(candidates) <= 1 || target == "" {
		return candidates
	}
	marks := make([]bool, len(candidates))
	anySuspicious := false
	for i, ob := range candidates {
		if s.isTargetSuspicious(target, ob.Tag()) {
			marks[i] = true
			anySuspicious = true
		}
	}
	if !anySuspicious {
		return candidates
	}
	// Stable partition: build two slices in one pass to preserve
	// original order within each group. Cheaper than sort.SliceStable
	// here because we already have the marks precomputed.
	trusted := candidates[:0]
	var suspicious []adapter.Outbound
	for i, ob := range candidates {
		if marks[i] {
			suspicious = append(suspicious, ob)
		} else {
			trusted = append(trusted, ob)
		}
	}
	return append(trusted, suspicious...)
}

// ── A: the per-target suspicion filter ──────────────────────────────────────

// isTargetSuspicious reports whether the (target, proxyTag) pair
// has enough negative recent observations — via real traffic stats
// OR active SNI probe — that selectProxies should demote it from
// the current request's candidate list. Returns false when data is
// insufficient so fresh nodes don't get unfairly filtered.
//
// Order of evidence (most recent beats the rest):
//   1. Active SNI probe in the last sniProbeTTL: a RECENT probe
//      failure is the strongest signal — we literally just tried
//      and couldn't reach this SNI via this node.
//   2. AtomicStatsRecord ShortSuccessRate < suspicionRate with
//      samples >= minSamples: classical telemetry, catches "the
//      pipe technically works but keeps dropping connections".
//   3. Otherwise: false (let alive/breaker filters decide).
//
// Allocation-free on the hot path — one xsync map lookup plus one
// atomic read from the AtomicStatsRecord when it exists.
func (s *Smart) isTargetSuspicious(target, proxyTag string) bool {
	if target == "" || proxyTag == "" || s == nil {
		return false
	}

	// Evidence 1: recent SNI probe outcome.
	if s.targetLiveness.probeHistory != nil {
		key := target + "|" + proxyTag
		if v, ok := s.targetLiveness.probeHistory.Load(key); ok && v != nil {
			age := time.Since(time.Unix(0, v.tsNS))
			if age < sniProbeTTL && !v.ok {
				return true
			}
		}
	}

	// Evidence 2: short-window stats EWMA on this (target, node).
	if s.store == nil {
		return false
	}
	cacheKey := smart.FormatDBKey(smart.KeyTypeStats,
		smartConfigName, s.Tag(), target, proxyTag)
	rec := s.store.LookupAtomicRecord(cacheKey)
	if rec == nil {
		return false
	}
	samples := rec.GetInt64("success") + rec.GetInt64("failure")
	if samples < targetLivenessMinSamples {
		return false
	}
	return rec.ShortSuccessRate() < targetLivenessSuspicionRate
}

// ── B: the active SNI probe ─────────────────────────────────────────────────

// probeSNIOnce runs one TLS handshake to target via ob's outbound
// and returns the outcome. No HTTP traffic is sent — we only care
// whether the tunnel can reach the target SNI; once TLS is up the
// probe tears the connection down immediately.
//
// Why we don't reuse the existing URLTest probe here: URLTest hits
// a FIXED URL (generate_204 by default), which is exactly the
// "single point of doubt" we're trying to break free of. A per-
// target probe MUST connect to the target's own SNI to be
// meaningful.
func (s *Smart) probeSNIOnce(ctx context.Context, target string, ob adapter.Outbound) (rttMS int32, err error) {
	probeCtx, cancel := context.WithTimeout(ctx, sniProbeBudget)
	defer cancel()

	// Parse target into host:port. target is meta.smartTarget shape,
	// typically "host:port". Fall back to 443 when parsing leaves
	// port empty so a bare domain string still probes meaningfully.
	host, port, parseErr := net.SplitHostPort(target)
	if parseErr != nil {
		host = target
		port = "443"
	}
	dest := M.ParseSocksaddrHostPortStr(host, port)

	start := time.Now()
	conn, err := ob.DialContext(probeCtx, "tcp", dest)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// If the destination port is the default HTTPS port we attempt
	// a TLS handshake to the SNI — that's the phase GFW-style
	// SNI-based blockers inject RST on. For non-443 ports we accept
	// the bare TCP connect as "reachable" since the port might be
	// plaintext (QUIC uses UDP so won't reach here; TCP/443 is the
	// interesting case).
	if port == "443" {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: host,
			// We don't care about cert validity for reachability
			// — target might use self-signed / pinned TLS and
			// we're not the consuming client here.
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		})
		defer tlsConn.Close()
		if err := tlsConn.HandshakeContext(probeCtx); err != nil {
			return 0, err
		}
	}
	rtt := time.Since(start).Milliseconds()
	if rtt > 2147483000 {
		rtt = 2147483000 // clamp to int32 safety range
	}
	return int32(rtt), nil
}

// recordSNIProbe writes the probe result into the per-group probe
// history. One allocation per write (the sniProbeResult on heap).
// Called from the periodic probe task — not the dial hot path.
func (s *Smart) recordSNIProbe(target, proxyTag string, ok bool, rttMS int32) {
	if s == nil || s.targetLiveness.probeHistory == nil {
		return
	}
	key := target + "|" + proxyTag
	s.targetLiveness.probeHistory.Store(key, &sniProbeResult{
		tsNS:  time.Now().UnixNano(),
		ok:    ok,
		rttMS: rttMS,
	})
}

// ── B: driver — the periodic "run a probe batch" task ───────────────────────

const (
	// sniProbeTopK controls how many hot targets per round.
	// Balances signal coverage against probe traffic:
	//   k=10 + 20 nodes + 15 min interval = ~200 probes / 15 min
	//   = ~14 probes / min amortised across the process. Acceptable
	//   even on metered connections.
	sniProbeTopK = 10

	// sniProbeInterval is the wall-clock cadence of the probe task.
	// Trade-off: shorter → faster detection of new blockages;
	// longer → less probe traffic. 15 min aligns with sniProbeTTL
	// so every entry in the history gets re-verified at least once
	// per TTL, which keeps stale "blocked" entries from lingering
	// after the network condition clears.
	sniProbeInterval = 15 * time.Minute

	// sniProbeInitialDelay defers the first batch so process startup
	// and the initial runHealthCheck aren't competing for the shared
	// worker pool. Long enough that the warm-up path has filled
	// URLTestHistory once.
	sniProbeInitialDelay = 2 * time.Minute
)

// runTargetLivenessProbes is the body the timing-wheel fires. Picks
// top-K hot targets, picks a small number of alive nodes, and does
// a TLS handshake probe to each (target, node) pair. Records the
// results into probeHistory for the filter to read.
//
// Single pass, fully non-blocking from the wheel's viewpoint — the
// probes themselves dispatch through the shared ants pool. The
// function returns as soon as it has FIRED probes, not waited for
// them, so the wheel stays unblocked even when individual probes
// hit their 2s budget.
func (s *Smart) runTargetLivenessProbes() {
	if s == nil || !s.started.Load() || s.targetLiveness.hits == nil {
		return
	}
	// Skip entirely when the group is idle — probe traffic on a
	// sleeping phone is waste.
	if s.isGroupIdle() {
		return
	}
	// Also skip during a confirmed network storm: SNI handshakes will
	// all fail, recording "blocked" for every (target, node) pair
	// which over-demotes trusted nodes once the network recovers. The
	// next storm-clear tick gets us fresh data.
	if s.inNetworkStorm() {
		s.logger.Debug("smart[", s.Tag(),
			"] target-liveness probes skipped — network-storm gate active")
		return
	}
	targets := s.targetLiveness.hits.topK(sniProbeTopK)
	if len(targets) == 0 {
		return
	}
	snap := s.state.Load()
	if snap == nil || len(snap.outbounds) == 0 {
		return
	}

	// Build the alive node list once for the whole batch. One probe
	// per (target, first-3-alive-nodes) gives us coverage of the
	// nodes most likely to be selected without blowing up the fan-
	// out.
	var aliveNodes []adapter.Outbound
	for _, ob := range snap.outbounds {
		if smartSkipType(ob.Type()) {
			continue
		}
		if !s.isAlive(ob.Tag()) || s.isBreakerOpen(ob.Tag()) {
			continue
		}
		aliveNodes = append(aliveNodes, ob)
		if len(aliveNodes) >= 3 {
			break
		}
	}
	if len(aliveNodes) == 0 {
		return
	}

	worker := getSmartWorker()
	for _, target := range targets {
		for _, ob := range aliveNodes {
			target, ob := target, ob
			worker.submit(func() {
				if !s.started.Load() {
					return
				}
				rtt, err := s.probeSNIOnce(s.taskCtx, target, ob)
				s.recordSNIProbe(target, ob.Tag(), err == nil, rtt)
				if err != nil {
					s.logger.Debug("smart[", s.Tag(),
						"] SNI-probe miss [", ob.Tag(),
						"] target=[", target, "] err=", err)
				}
			})
		}
	}
}
