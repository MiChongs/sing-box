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
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// Health check scheduling for URLTestGroup.
//
// A member is probed once its last measurement, by this group or by anyone
// sharing the history, is older than its refresh period:
//   - hot members (manual pin, current selection and the best ranked
//     members; the priority prefix in fallback mode) every interval, since
//     the selection depends on them;
//   - other members every coldRefreshIntervals intervals;
//   - members whose probes keep failing after 1, 2, 4 up to
//     maxFailureBackoff intervals;
//   - members never measured right away.
//
// Every probe goes through the box-wide urltest.Prober, so a member shared
// by several groups costs one connection however many groups are due.
// Rounds are single-flight: periodic ticks are dropped while one runs, and
// other requests are merged into one queued round.
const (
	probeConcurrency     = 8
	hotCandidates        = 3
	coldRefreshIntervals = 4
	// Retry delay of a failing member grows from one interval up to this
	// many intervals.
	maxFailureBackoff = 8
	// User-triggered tests skip members measured this recently, so repeated
	// clicks and overlapping dashboard requests stay cheap.
	fullTestFreshness = 15 * time.Second
	maxRoundTimeout   = 10 * time.Minute
	// Ranking leaders measured before the round started are re-probed in up
	// to this many passes before the selection may move to them.
	maxVerifyPasses = 2
	// Network changes re-probe the hot set at most this often.
	networkRecheckCooldown = 30 * time.Second
)

type memberHealth struct {
	lastProbe time.Time
	failures  uint8 // consecutive failed probes
}

// backoff is how long a failing member waits for its next probe: one
// interval after the first failure, doubling up to maxFailureBackoff.
func (h memberHealth) backoff(interval time.Duration) time.Duration {
	backoff := interval
	for i := uint8(1); i < h.failures && backoff < maxFailureBackoff*interval; i++ {
		backoff *= 2
	}
	return backoff
}

type probePlan struct {
	scheduled bool                // members whose refresh period elapsed
	full      bool                // every member not measured within fullTestFreshness
	hotBefore time.Time           // hot members last measured before this time
	focus     map[string]struct{} // members probed regardless of freshness and backoff
}

var (
	probeScheduled = probePlan{scheduled: true}
	probeFull      = probePlan{full: true}
)

func (p *probePlan) merge(other probePlan) {
	p.scheduled = p.scheduled || other.scheduled
	p.full = p.full || other.full
	if other.hotBefore.After(p.hotBefore) {
		p.hotBefore = other.hotBefore
	}
	if len(other.focus) > 0 && p.focus == nil {
		p.focus = make(map[string]struct{}, len(other.focus))
	}
	maps.Copy(p.focus, other.focus)
}

type probeRound struct {
	plan probePlan
	// session is the start of the recursive test that requested the round,
	// whose results are shared with it; zero outside one.
	session time.Time
	done    chan struct{}
	access  sync.Mutex
	result  map[string]uint16
}

func newProbeRound(plan probePlan, session time.Time) *probeRound {
	plan.focus = maps.Clone(plan.focus)
	return &probeRound{
		plan:    plan,
		session: session,
		done:    make(chan struct{}),
		result:  make(map[string]uint16),
	}
}

func (r *probeRound) measured(tag string) bool {
	r.access.Lock()
	defer r.access.Unlock()
	_, loaded := r.result[tag]
	return loaded
}

type probeTarget struct {
	tag     string
	realTag string
	dialer  adapter.Outbound
	// since is the oldest shared result accepted for this target.
	since time.Time
}

func (g *URLTestGroup) lifetime() context.Context {
	if g.ctx == nil {
		return context.Background()
	}
	return g.ctx
}

// requestRound starts a round when none is running. Otherwise a request
// that may not queue is dropped (nil), a full request joins a running full
// round, and anything else is merged into the single queued round.
func (g *URLTestGroup) requestRound(ctx context.Context, plan probePlan, queue bool) *probeRound {
	session := urlTestSessionFromContext(ctx)
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
	if plan.full && g.runningRound.plan.full {
		return g.runningRound
	}
	if g.queuedRound == nil {
		g.queuedRound = newProbeRound(plan, session)
	} else {
		g.queuedRound.plan.merge(plan)
		if !session.IsZero() && (g.queuedRound.session.IsZero() || session.Before(g.queuedRound.session)) {
			g.queuedRound.session = session
		}
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
	ctx, cancel := context.WithTimeout(lifetime, g.roundTimeout(len(targets)))
	defer cancel()
	probed := len(targets)
	g.probeTargets(ctx, round, targets)
	if !g.fallback.enabled {
		// A member can reach the top of the ranking on an old measurement;
		// confirm it before the selection may move there.
		verifiedSince := startedAt.Add(-g.freshness(round.plan))
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

// planTargets lists the members a round probes, hot and focused members
// first so they are measured in the first wave.
func (g *URLTestGroup) planTargets(st *groupState, plan probePlan, now time.Time) []probeTarget {
	type candidate struct {
		detour   adapter.Outbound
		realTag  string
		lastSeen time.Time
		since    time.Time
	}
	var (
		hot        = g.hotMembers(st)
		dueSince   = now.Add(-g.interval / 2)
		priority   []candidate
		unmeasured []candidate
		due        []candidate
	)
	for _, detour := range st.outbounds {
		tag := detour.Tag()
		// RealTag may enter nested groups, so it runs without healthAccess.
		realTag := RealTag(detour, N.NetworkTCP)
		if realTag == "" {
			continue
		}
		g.healthAccess.Lock()
		var health memberHealth
		if current := g.health[tag]; current != nil {
			health = *current
		}
		g.healthAccess.Unlock()
		lastSeen := health.lastProbe
		if history := g.history.LoadURLTestHistory(realTag); history != nil && history.Time.After(lastSeen) {
			lastSeen = history.Time
		}
		member := candidate{detour: detour, realTag: realTag, lastSeen: lastSeen}
		_, focused := plan.focus[tag]
		_, isHot := hot[tag]
		switch {
		case focused:
			member.since = now
			priority = append(priority, member)
		case isHot && lastSeen.Before(plan.hotBefore):
			member.since = plan.hotBefore
			priority = append(priority, member)
		case plan.full && (lastSeen.IsZero() || now.Sub(lastSeen) >= fullTestFreshness):
			member.since = now.Add(-fullTestFreshness)
			if isHot {
				priority = append(priority, member)
			} else {
				unmeasured = append(unmeasured, member)
			}
		case !plan.scheduled:
		case lastSeen.IsZero():
			member.since = dueSince
			unmeasured = append(unmeasured, member)
		case g.isDue(health, isHot, lastSeen, now):
			member.since = dueSince
			if isHot {
				priority = append(priority, member)
			} else {
				due = append(due, member)
			}
		}
	}
	sort.SliceStable(due, func(i, j int) bool {
		return due[i].lastSeen.Before(due[j].lastSeen)
	})

	targets := make([]probeTarget, 0, len(priority)+len(unmeasured)+len(due))
	planned := make(map[string]bool, cap(targets))
	for _, members := range [][]candidate{priority, unmeasured, due} {
		for _, member := range members {
			if planned[member.realTag] {
				continue
			}
			dialer, loaded := g.outbound.Outbound(member.realTag)
			if !loaded {
				continue
			}
			planned[member.realTag] = true
			targets = append(targets, probeTarget{tag: member.detour.Tag(), realTag: member.realTag, dialer: dialer, since: member.since})
		}
	}
	return targets
}

// isDue reports whether a measured member's refresh period has elapsed.
func (g *URLTestGroup) isDue(health memberHealth, hot bool, lastSeen time.Time, now time.Time) bool {
	period := g.interval
	switch {
	case health.failures > 0:
		// A failing selection or pin keeps being probed every interval
		// until the selection moves on.
		if !hot {
			period = health.backoff(g.interval)
		}
	case !hot:
		period = coldRefreshIntervals * g.interval
	}
	// Ticks are one interval apart, while the last measurement finished
	// some time after its tick; half an interval of slack keeps members
	// from slipping to the following tick.
	return now.Sub(lastSeen) >= period-g.interval/2
}

// freshness is how recent a measurement must be for plan to skip a member.
func (g *URLTestGroup) freshness(plan probePlan) time.Duration {
	if plan.full {
		return fullTestFreshness
	}
	return g.interval / 2
}

// hotMembers returns the tags refreshed every interval.
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
		// the one after it takes over when the selection fails.
		limit := hotCandidates
		if selectedTCP != nil {
			if index := slices.Index(st.tags, selectedTCP.Tag()); index >= 0 {
				limit = max(limit, min(index, 2*hotCandidates))
				if index+1 < len(st.tags) {
					hot[st.tags[index+1]] = struct{}{}
				}
			}
		}
		for _, detour := range st.outbounds[:min(limit, len(st.outbounds))] {
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
			if round.measured(tag) {
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
			targets = append(targets, probeTarget{tag: tag, realTag: realTag, dialer: dialer, since: since})
		}
	}
	return targets
}

func probeWorkers(targets int) int {
	return min(probeConcurrency, targets)
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
// large group never holds more than probeConcurrency probes.
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
	since := target.since
	if !round.session.IsZero() && round.session.Before(since) {
		since = round.session
	}
	result := g.history.Prober().Probe(ctx, urltest.ProbeRequest{
		Tag:     target.realTag,
		Link:    g.link,
		Status:  g.expectedStatus,
		Dialer:  target.dialer,
		Timeout: C.TCPTimeout,
		Since:   since,
	})
	if result.Err != nil {
		if ctx.Err() != nil {
			// The round was cut short; that says nothing about the member.
			return
		}
		failures := g.recordProbe(target.tag, result.Time, false)
		deleteURLTestHistory(g.history, target.realTag, result.Time)
		g.logger.Debug("outbound ", target.tag, " unavailable: ", result.Err)
		if failures == selectionFailureGrace && g.isSelected(target.tag) {
			g.logger.Info("selected outbound ", target.tag, " failed ", failures, " health checks in a row")
		}
		return
	}
	g.recordProbe(target.tag, result.Time, true)
	storeURLTestHistory(g.history, target.realTag, result)
	round.access.Lock()
	round.result[target.tag] = result.Delay
	round.access.Unlock()
	g.logger.Debug("outbound ", target.tag, " available: ", result.Delay, "ms")
}

// storeURLTestHistory records a successful probe unless a newer
// measurement arrived meanwhile; shared results may be seconds old.
func storeURLTestHistory(history adapter.URLTestHistoryStorage, tag string, result urltest.ProbeResult) {
	if current := history.LoadURLTestHistory(tag); current != nil && current.Time.After(result.Time) {
		return
	}
	history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
		Time:  result.Time,
		Delay: result.Delay,
	})
}

// deleteURLTestHistory drops the delay of a member that failed at
// failedAt, keeping a measurement taken after the failure.
func deleteURLTestHistory(history adapter.URLTestHistoryStorage, tag string, failedAt time.Time) {
	current := history.LoadURLTestHistory(tag)
	if current == nil || current.Time.After(failedAt) {
		return
	}
	history.DeleteURLTestHistory(tag)
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
// failures. A successful probe also forgives its dial failures.
func (g *URLTestGroup) recordProbe(tag string, at time.Time, available bool) uint8 {
	if available {
		g.reportDialSuccess(tag)
	}
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
	if at.After(health.lastProbe) {
		health.lastProbe = at
	}
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
// are retried on the next tick instead of after their backoff, dial
// failures are forgotten, and the hot set is re-probed right away unless
// that happened within networkRecheckCooldown. Other members refresh on
// their regular schedule.
func (g *URLTestGroup) networkChanged() {
	g.healthAccess.Lock()
	for _, health := range g.health {
		health.failures = min(health.failures, 1)
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
	now := urlTestClock()
	last := g.networkRecheckAt.Load()
	if last != 0 && now-last < int64(networkRecheckCooldown) {
		return
	}
	if !g.networkRecheckAt.CompareAndSwap(last, now) {
		return
	}
	g.requestRound(g.lifetime(), probePlan{hotBefore: time.Now()}, true)
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
