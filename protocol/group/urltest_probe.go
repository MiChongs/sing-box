package group

import (
	"context"
	"maps"
	"math"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// Health check scheduling for URLTestGroup.
//
// A round probes three kinds of members:
//   - the hot set (manual pin, current selection and the best ranked
//     members; the priority prefix in fallback mode) every round, since the
//     selection depends on them;
//   - members that were never measured, without limit, so startup and
//     provider updates find the best member in one pass;
//   - the remaining cold members, least recently probed first, at most
//     max(minColdBudget, N/coldSweepRounds) per round. A large group costs a
//     bounded slice of probes per interval and is still fully refreshed
//     every coldSweepRounds intervals; small groups are refreshed every round.
//
// Members whose probes keep failing back off exponentially instead of
// holding a probe slot for a full timeout every round. Rounds are
// single-flight: periodic ticks are dropped while one runs, and other
// requests are merged into one queued round.
const (
	probeConcurrency    = 8
	maxProbeConcurrency = 16
	hotCandidates       = 4
	minColdBudget       = 64
	coldSweepRounds     = 8
	// Retry delay of a failing member grows from one interval up to this
	// many intervals.
	maxFailureBackoff = 8
	// User-triggered tests skip members this group measured this recently,
	// so repeated clicks and overlapping dashboard requests stay cheap.
	fullTestFreshness = 15 * time.Second
	maxRoundTimeout   = 10 * time.Minute
	// Ranking leaders measured before the round started are re-probed in up
	// to this many passes before the selection may move to them.
	maxVerifyPasses = 2
)

type memberHealth struct {
	lastProbe time.Time
	failures  uint8 // consecutive failed probes
}

// retryAt is when a failing member is due as a cold target again: one
// interval after the first failure, doubling up to maxFailureBackoff.
func (h *memberHealth) retryAt(interval time.Duration) time.Time {
	backoff := interval
	for i := uint8(1); i < h.failures && backoff < maxFailureBackoff*interval; i++ {
		backoff *= 2
	}
	return h.lastProbe.Add(backoff)
}

type probePlan struct {
	forceHot bool                // re-probe the hot set even when fresh
	cold     bool                // probe unmeasured members and the cold budget
	all      bool                // probe every member not measured within fullTestFreshness
	focus    map[string]struct{} // members probed regardless of freshness and backoff
}

var (
	probeScheduled = probePlan{cold: true}
	probeFull      = probePlan{forceHot: true, all: true}
)

func (p *probePlan) merge(other probePlan) {
	p.forceHot = p.forceHot || other.forceHot
	p.cold = p.cold || other.cold
	p.all = p.all || other.all
	if len(other.focus) > 0 && p.focus == nil {
		p.focus = make(map[string]struct{}, len(other.focus))
	}
	maps.Copy(p.focus, other.focus)
}

type probeRound struct {
	plan    probePlan
	session *urlTestSession
	done    chan struct{}
	access  sync.Mutex
	result  map[string]uint16
}

func newProbeRound(plan probePlan, session *urlTestSession) *probeRound {
	plan.focus = maps.Clone(plan.focus)
	return &probeRound{
		plan:    plan,
		session: session,
		done:    make(chan struct{}),
		result:  make(map[string]uint16),
	}
}

type probeTarget struct {
	tag     string
	realTag string
	dialer  adapter.Outbound
}

func (g *URLTestGroup) lifetime() context.Context {
	if g.ctx == nil {
		return context.Background()
	}
	return g.ctx
}

// requestRound starts a round when none is running. Otherwise a request
// that may not queue is dropped (nil), a full request joins a running full
// round, and anything else is merged into the single queued round. The
// round shares the probe session carried by ctx, so sibling groups tested
// in one recursive pass measure a common leaf once.
func (g *URLTestGroup) requestRound(ctx context.Context, plan probePlan, queue bool) *probeRound {
	_, session := urlTestSessionFromContext(ctx)
	g.roundAccess.Lock()
	defer g.roundAccess.Unlock()
	if g.runningRound == nil {
		round := newProbeRound(plan, session)
		g.runningRound = round
		go g.runRounds(round)
		return round
	}
	if !queue {
		return nil
	}
	if plan.all && g.runningRound.plan.all {
		return g.runningRound
	}
	if g.queuedRound == nil {
		g.queuedRound = newProbeRound(plan, session)
	} else {
		g.queuedRound.plan.merge(plan)
	}
	return g.queuedRound
}

func (g *URLTestGroup) runRounds(round *probeRound) {
	for round != nil {
		g.executeRound(round)
		g.roundAccess.Lock()
		next := g.queuedRound
		g.queuedRound = nil
		g.runningRound = next
		g.roundAccess.Unlock()
		close(round.done)
		round = next
	}
}

func (g *URLTestGroup) executeRound(round *probeRound) {
	lifetime := g.lifetime()
	if lifetime.Err() != nil {
		return
	}
	st := g.state.Load()
	if st == nil {
		return
	}
	startedAt := time.Now()
	targets := g.planTargets(st, round.plan, startedAt)
	verifiedSince := startedAt.Add(-g.freshness(round.plan))
	ctx, cancel := context.WithTimeout(context.WithValue(lifetime, urlTestSessionContextKey{}, round.session), g.roundTimeout(len(targets)))
	defer cancel()
	probed := len(targets)
	g.probeTargets(ctx, round, targets)
	if !g.fallback.enabled {
		// A member can reach the top of the ranking on an old measurement;
		// confirm it before the selection may move there.
		for range maxVerifyPasses {
			if ctx.Err() != nil {
				break
			}
			g.rebuildRankedCandidates()
			leaders := g.unverifiedLeaders(round, verifiedSince)
			if len(leaders) == 0 {
				break
			}
			probed += len(leaders)
			g.probeTargets(ctx, round, leaders)
		}
	}
	if lifetime.Err() != nil {
		return
	}
	g.performUpdateCheck()
	if probed > 0 {
		round.access.Lock()
		available := len(round.result)
		round.access.Unlock()
		g.logger.Debug("health check completed: ", available, "/", probed, " probed outbounds available")
	}
}

// planTargets lists the members a round probes, hot set first so they are
// measured in the first wave with the least contention.
func (g *URLTestGroup) planTargets(st *groupState, plan probePlan, now time.Time) []probeTarget {
	type candidate struct {
		detour   adapter.Outbound
		realTag  string
		lastSeen time.Time
	}
	var (
		hot        = g.hotMembers(st)
		freshness  = g.freshness(plan)
		priority   []candidate
		unmeasured []candidate
		cold       []candidate
	)
	for _, detour := range st.outbounds {
		tag := detour.Tag()
		// RealTag may enter nested groups, so it runs without healthAccess.
		realTag := RealTag(detour, N.NetworkTCP)
		if realTag == "" {
			continue
		}
		var lastProbe, retryAt time.Time
		g.healthAccess.Lock()
		if health := g.health[tag]; health != nil {
			lastProbe = health.lastProbe
			if health.failures > 0 {
				retryAt = health.retryAt(g.interval)
			}
		}
		g.healthAccess.Unlock()
		// Measurements by other groups or the API count for periodic checks;
		// user tests only skip what this group itself just measured.
		lastSeen := lastProbe
		if history := g.history.LoadURLTestHistory(realTag); history != nil && history.Time.After(lastSeen) {
			lastSeen = history.Time
		}
		var fresh bool
		if plan.all {
			fresh = !lastProbe.IsZero() && now.Sub(lastProbe) < freshness
		} else {
			fresh = !lastSeen.IsZero() && now.Sub(lastSeen) < freshness
		}
		member := candidate{detour, realTag, lastSeen}
		_, focused := plan.focus[tag]
		_, isHot := hot[tag]
		switch {
		case focused, isHot && plan.forceHot:
			priority = append(priority, member)
		case isHot:
			if !fresh {
				priority = append(priority, member)
			}
		case plan.all:
			if !fresh {
				unmeasured = append(unmeasured, member)
			}
		case !plan.cold:
		case lastSeen.IsZero():
			unmeasured = append(unmeasured, member)
		case fresh, now.Before(retryAt):
		default:
			cold = append(cold, member)
		}
	}

	sort.SliceStable(cold, func(i, j int) bool {
		return cold[i].lastSeen.Before(cold[j].lastSeen)
	})
	budget := max(minColdBudget, (len(st.outbounds)+coldSweepRounds-1)/coldSweepRounds)
	cold = cold[:min(len(cold), budget)]

	targets := make([]probeTarget, 0, len(priority)+len(unmeasured)+len(cold))
	planned := make(map[string]bool, cap(targets))
	for _, members := range [][]candidate{priority, unmeasured, cold} {
		for _, member := range members {
			if planned[member.realTag] {
				continue
			}
			dialer, loaded := g.outbound.Outbound(member.realTag)
			if !loaded {
				continue
			}
			planned[member.realTag] = true
			targets = append(targets, probeTarget{tag: member.detour.Tag(), realTag: member.realTag, dialer: dialer})
		}
	}
	return targets
}

// freshness is how recent a measurement must be for plan to skip a member.
func (g *URLTestGroup) freshness(plan probePlan) time.Duration {
	if plan.all {
		return fullTestFreshness
	}
	return g.interval / 2
}

// hotMembers returns the tags probed every round.
func (g *URLTestGroup) hotMembers(st *groupState) map[string]struct{} {
	hot := make(map[string]struct{}, 2*hotCandidates+3)
	if pin := g.manualPin.Load(); pin != nil {
		hot[pin.tag] = struct{}{}
	}
	selectedTCP := g.selectedOutboundTCP.Load()
	for _, selected := range []adapter.Outbound{selectedTCP, g.selectedOutboundUDP.Load()} {
		if selected != nil {
			hot[selected.Tag()] = struct{}{}
		}
	}
	if g.fallback.enabled {
		// Members ahead of the selection decide when fallback switches back,
		// the next one takes over when the selection fails.
		limit := hotCandidates
		if selectedTCP != nil {
			limit = max(limit, slices.Index(st.tags, selectedTCP.Tag())+2)
		}
		for _, detour := range st.outbounds[:min(limit, 2*hotCandidates, len(st.outbounds))] {
			hot[detour.Tag()] = struct{}{}
		}
		return hot
	}
	for _, ranked := range [][]rankedOutbound{st.rankedTCP, st.rankedUDP} {
		for _, candidate := range ranked[:min(len(ranked), hotCandidates)] {
			hot[candidate.outbound.Tag()] = struct{}{}
		}
	}
	return hot
}

// unverifiedLeaders returns the ranking leaders not measured in round
// whose delay is older than since.
func (g *URLTestGroup) unverifiedLeaders(round *probeRound, since time.Time) []probeTarget {
	st := g.state.Load()
	if st == nil {
		return nil
	}
	var targets []probeTarget
	planned := make(map[string]bool)
	for _, ranked := range [][]rankedOutbound{st.rankedTCP, st.rankedUDP} {
		for _, candidate := range ranked[:min(len(ranked), hotCandidates)] {
			tag := candidate.outbound.Tag()
			round.access.Lock()
			_, measured := round.result[tag]
			round.access.Unlock()
			if measured {
				continue
			}
			realTag := RealTag(candidate.outbound, N.NetworkTCP)
			if realTag == "" || planned[realTag] {
				continue
			}
			if history := g.history.LoadURLTestHistory(realTag); history != nil && !history.Time.Before(since) {
				continue
			}
			dialer, loaded := g.outbound.Outbound(realTag)
			if !loaded {
				continue
			}
			planned[realTag] = true
			targets = append(targets, probeTarget{tag: tag, realTag: realTag, dialer: dialer})
		}
	}
	return targets
}

func probeWorkers(targets int) int {
	return min(max(targets/16, probeConcurrency), maxProbeConcurrency, targets)
}

// roundTimeout bounds a round to the waves its targets need at full
// timeout, but never below one interval.
func (g *URLTestGroup) roundTimeout(targets int) time.Duration {
	timeout := 2 * C.TCPTimeout
	if workers := probeWorkers(targets); workers > 0 {
		waves := (targets+workers-1)/workers + maxVerifyPasses
		timeout = max(timeout, time.Duration(waves)*C.TCPTimeout)
	}
	return min(max(timeout, g.interval), maxRoundTimeout)
}

// probeTargets measures targets on a fixed worker pool, so a round over a
// large group never holds more than maxProbeConcurrency goroutines.
func (g *URLTestGroup) probeTargets(ctx context.Context, round *probeRound, targets []probeTarget) {
	if len(targets) == 0 {
		return
	}
	var (
		next      atomic.Int32
		waitGroup sync.WaitGroup
	)
	for range probeWorkers(len(targets)) {
		waitGroup.Go(func() {
			for ctx.Err() == nil {
				index := int(next.Add(1)) - 1
				if index >= len(targets) {
					return
				}
				g.probe(ctx, round, targets[index])
			}
		})
	}
	waitGroup.Wait()
}

func (g *URLTestGroup) probe(ctx context.Context, round *probeRound, target probeTarget) {
	key := urlTestSessionKey{tag: target.realTag, link: g.link, matcher: g.expectedStatus}
	result := round.session.test(ctx, key, func() urlTestResult {
		probeCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
		defer cancel()
		delay, err := urlTestBounded(probeCtx, g.link, target.dialer, g.expectedStatus)
		return urlTestResult{delay, err}
	})
	if result.err != nil {
		if ctx.Err() != nil {
			// The round was cut short; that says nothing about the member.
			return
		}
		failures := g.recordProbe(target.tag, false)
		g.history.DeleteURLTestHistory(target.realTag)
		g.logger.Debug("outbound ", target.tag, " unavailable: ", result.err)
		if failures == selectionFailureGrace && g.isSelected(target.tag) {
			g.logger.Info("selected outbound ", target.tag, " failed ", failures, " health checks in a row")
		}
		return
	}
	g.recordProbe(target.tag, true)
	g.history.StoreURLTestHistory(target.realTag, &adapter.URLTestHistory{
		Time:  time.Now(),
		Delay: result.delay,
	})
	round.access.Lock()
	round.result[target.tag] = result.delay
	round.access.Unlock()
	g.logger.Debug("outbound ", target.tag, " available: ", result.delay, "ms")
}

func (g *URLTestGroup) isSelected(tag string) bool {
	for _, selected := range []adapter.Outbound{g.selectedOutboundTCP.Load(), g.selectedOutboundUDP.Load()} {
		if selected != nil && selected.Tag() == tag {
			return true
		}
	}
	return false
}

// recordProbe updates a member's health and returns its consecutive
// failures.
func (g *URLTestGroup) recordProbe(tag string, available bool) uint8 {
	g.healthAccess.Lock()
	defer g.healthAccess.Unlock()
	if g.health == nil {
		g.health = make(map[string]*memberHealth)
	}
	health := g.health[tag]
	if health == nil {
		health = new(memberHealth)
		g.health[tag] = health
	}
	health.lastProbe = time.Now()
	if available {
		health.failures = 0
	} else if health.failures < math.MaxUint8 {
		health.failures++
	}
	return health.failures
}

func (g *URLTestGroup) probeFailures(tag string) uint8 {
	g.healthAccess.Lock()
	defer g.healthAccess.Unlock()
	if health := g.health[tag]; health != nil {
		return health.failures
	}
	return 0
}

// networkChanged drops what the previous network taught: failing members
// may be reachable now, so their backoff is cleared, and the hot set is
// re-probed right away. The cold members refresh on the regular schedule.
func (g *URLTestGroup) networkChanged() {
	g.healthAccess.Lock()
	for _, health := range g.health {
		health.failures = 0
	}
	g.healthAccess.Unlock()
	g.dialFailureAccess.Lock()
	clear(g.dialFailureCount)
	g.dialFailureTracked.Store(0)
	g.dialFailureAccess.Unlock()
	if !g.loopRunning.Load() {
		// Idle: the loop runs a round as soon as traffic resumes.
		return
	}
	g.requestRound(g.lifetime(), probePlan{forceHot: true}, true)
}

// delaySnapshot reports the delays measured by round plus the last known
// delay of every other member, keyed by member tag.
func (g *URLTestGroup) delaySnapshot(round *probeRound) map[string]uint16 {
	result := make(map[string]uint16)
	if round != nil {
		round.access.Lock()
		maps.Copy(result, round.result)
		round.access.Unlock()
	}
	st := g.state.Load()
	if st == nil || g.history == nil {
		return result
	}
	for _, detour := range st.outbounds {
		if _, loaded := result[detour.Tag()]; loaded {
			continue
		}
		if history := g.history.LoadURLTestHistory(RealTag(detour, N.NetworkTCP)); history != nil {
			result[detour.Tag()] = history.Delay
		}
	}
	return result
}
