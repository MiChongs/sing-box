package smart

import (
	"slices"
	"sort"
	"sync"
	"sync/atomic"
)

// Context is the selection context of one business attempt.
type Context struct {
	Network Network
	Family  Family
	// Target is the normalized destination ("host:port", lowercase, no
	// trailing dot), Site its eTLD+1 or "AS<n>" with prefer_asn. Either may
	// be empty.
	Target string
	Site   string

	targetHash uint64
	siteHash   uint64
	prepared   bool
}

func (c *Context) prepare() {
	if !c.prepared {
		c.targetHash = HashString(c.Target)
		c.siteHash = HashString(c.Site)
		c.prepared = true
	}
}

// Candidate is one dialable member offered to selection, in declaration
// order. Priority is the policy_priority factor (1 when unset).
type Candidate struct {
	Node     uint32
	Priority float64
}

// Reason is why a decision chose its primary member.
type Reason uint8

const (
	ReasonNone Reason = iota
	ReasonSingleton
	ReasonColdExplore
	ReasonPeriodicExplore
	ReasonRecoveryExplore
	ReasonIncumbentIneligible
	ReasonFreshFailureBypass
	ReasonInsufficientEvidenceHeld
	ReasonDirectionalTradeoffHeld
	ReasonIncumbentHeld
	ReasonReliabilityWinner
	ReasonPerformanceWinner
	reasonCount
)

var reasonNames = [reasonCount]string{
	"", "singleton", "coldExplore", "periodicExplore", "recoveryExplore",
	"incumbentIneligible", "freshFailureBypass", "insufficientEvidenceHeld",
	"directionalTradeoffHeld", "incumbentHeld", "reliabilityWinner", "performanceWinner",
}

func (r Reason) String() string { return reasonNames[r] }

// Decision is the dial plan for one business attempt.
type Decision struct {
	// Order lists candidate indexes in dial order; Order[0] is the primary.
	Order []int
	// PoolSize is how many leading entries of Order are serving pool
	// members; the rest are outside members in declaration order.
	PoolSize int
	Reason   Reason
	// Trial is set when the primary is a funded exploration attempt.
	Trial  TrialKind
	budget *Budget
}

type budgetKey struct {
	network Network
	family  Family
}

// Group is one Smart group's view onto the engine.
type Group struct {
	engine *Engine
	id     uint32
	tag    string

	pools [2]Pool

	budgetAccess sync.Mutex
	budgets      map[budgetKey]*Budget
	members      atomic.Int32

	reasons  [2][reasonCount]atomic.Uint64
	switches [2]atomic.Uint64
	flaps    [2]atomic.Uint64
	filtered atomic.Uint64
	backoff  atomic.Uint64
}

func newGroup(e *Engine, id uint32, tag string) *Group {
	return &Group{engine: e, id: id, tag: tag, budgets: make(map[budgetKey]*Budget)}
}

func (g *Group) Tag() string     { return g.tag }
func (g *Group) ID() uint32      { return g.id }
func (g *Group) Engine() *Engine { return g.engine }

func (g *Group) resetState() {
	for i := range g.pools {
		g.pools[i].Reset()
	}
	g.budgetAccess.Lock()
	clear(g.budgets)
	g.budgetAccess.Unlock()
}

// SetMembers publishes the current membership. Cells of removed members are
// dropped, the pools rebuild and the budgets keep their earned currency.
func (g *Group) SetMembers(nodes []uint32) {
	g.members.Store(int32(len(nodes)))
	keep := make(map[uint32]struct{}, len(nodes))
	for _, n := range nodes {
		keep[n] = struct{}{}
	}
	g.engine.ForgetNodes(g.id, func(node uint32) bool {
		_, ok := keep[node]
		return ok
	})
	for i := range g.pools {
		g.pools[i].Reset()
	}
	g.budgetAccess.Lock()
	for _, b := range g.budgets {
		b.Reload(len(nodes))
	}
	g.budgetAccess.Unlock()
}

func (g *Group) budget(network Network, family Family) *Budget {
	key := budgetKey{network, family}
	g.budgetAccess.Lock()
	defer g.budgetAccess.Unlock()
	b := g.budgets[key]
	if b == nil {
		b = NewBudget(int(g.members.Load()))
		g.budgets[key] = b
	}
	return b
}

func (g *Group) key(node uint32, network Network, family Family, layer Layer, scope uint64) Key {
	return Key{Group: g.id, Node: node, Network: network, Family: family, Layer: layer, Scope: scope}
}

// snapshot blends the evidence layers of one node for ctx. full adds the
// site and exact layers; without it the snapshot is the aggregate view used
// for pool ranking.
func (g *Group) snapshot(ctx *Context, node uint32, now Mono, full bool) Snapshot {
	e := g.engine
	var (
		s           Snapshot
		nodeInvalid Mono
	)
	e.aggregate.Peek(g.key(node, ctx.Network, FamilyNone, LayerGlobal, 0), now, func(c *Cell) {
		s = snapshotOf(c, now)
		if c != nil {
			s.Probe = c.Probe.ReadAge(now, max(c.ProbeMaxAge, performanceMaxAge))
			nodeInvalid = c.InvalidatedAt
		}
	})
	s.NodeFailStreak = s.FailStreak
	child := func(t *Table, k Key, targetLayer bool) {
		t.Peek(k, now, func(c *Cell) {
			if c == nil {
				return
			}
			s.merge(snapshotOf(c, now), nodeInvalid > c.InvalidatedAt, targetLayer)
		})
	}
	if ctx.Family != FamilyNone {
		child(e.aggregate, g.key(node, ctx.Network, ctx.Family, LayerFamily, 0), false)
	}
	if full && (ctx.siteHash != 0 || ctx.targetHash != 0) {
		s.Recovered = false
		if ctx.siteHash != 0 {
			child(e.site, g.key(node, ctx.Network, ctx.Family, LayerSite, ctx.siteHash), true)
		}
		if ctx.targetHash != 0 {
			child(e.exact, g.key(node, ctx.Network, ctx.Family, LayerExact, ctx.targetHash), true)
		}
	}
	s.finalize()
	return s
}

// scratch holds per-selection buffers, pooled to keep the dial path free of
// allocations proportional to the group size.
type scratch struct {
	nodes     []uint32
	mask      []bool
	snapshots []Snapshot
	members   []int
	order     []int
	utility   []float64
	eligible  []bool
}

var scratchPool = sync.Pool{New: func() any { return new(scratch) }}

func grow[T any](s []T, n int) []T {
	if cap(s) < n {
		return make([]T, n)
	}
	return s[:n]
}

// Select plans one business attempt. With apply set it is an authorized
// selection: it counts demand, may fund an exploration trial, commits the
// incumbent and records the reason. Without it, it is a neutral read.
func (g *Group) Select(ctx *Context, candidates []Candidate, apply bool, now Mono) Decision {
	ctx.prepare()
	n := len(candidates)
	switch n {
	case 0:
		return Decision{}
	case 1:
		return Decision{Order: []int{0}, Reason: ReasonSingleton}
	}
	sc := scratchPool.Get().(*scratch)
	defer scratchPool.Put(sc)

	pool := &g.pools[ctx.Network&1]
	sc.nodes = grow(sc.nodes, n)
	for i := range candidates {
		sc.nodes[i] = candidates[i].Node
	}
	if apply {
		pool.RecordDemand(now)
	}
	sc.snapshots = grow(sc.snapshots, n)
	computed := false
	aggregate := func(i int) *Snapshot {
		if !computed {
			aggCtx := Context{Network: ctx.Network, Family: ctx.Family, prepared: true}
			for j := range candidates {
				sc.snapshots[j] = g.snapshot(&aggCtx, candidates[j].Node, now, false)
				sc.snapshots[j].Priority = priorityOf(candidates[j])
			}
			computed = true
		}
		return &sc.snapshots[i]
	}
	failing := func(node uint32) bool {
		var streak uint32
		g.engine.aggregate.Peek(g.key(node, ctx.Network, FamilyNone, LayerGlobal, 0), now, func(c *Cell) {
			if c != nil {
				streak = c.FailStreak
			}
		})
		return streak >= failStreakExclude
	}
	sc.mask = pool.Derive(sc.nodes, aggregate, failing, apply, now, sc.mask)

	// Full snapshots for pool members only.
	sc.members = sc.members[:0]
	for i := range candidates {
		if sc.mask[i] {
			sc.snapshots[i] = g.snapshot(ctx, candidates[i].Node, now, true)
			sc.snapshots[i].Priority = priorityOf(candidates[i])
			sc.members = append(sc.members, i)
		}
	}
	baseline := NewBaseline(sc.snapshots, sc.mask)
	sc.utility = grow(sc.utility, n)
	sc.eligible = grow(sc.eligible, n)
	for _, i := range sc.members {
		sc.eligible[i] = Eligible(&sc.snapshots[i], baseline)
		sc.utility[i] = Utility(&sc.snapshots[i], baseline)
	}

	hkey := g.historyKey(ctx)
	incumbent := -1
	if node, ok := g.engine.history.incumbent(hkey, now); ok {
		for _, i := range sc.members {
			if candidates[i].Node == node {
				incumbent = i
				break
			}
		}
	}
	chosen, reason := g.ordinary(sc, incumbent)

	decision := Decision{Reason: reason}
	primary := chosen
	if apply {
		budget := g.budget(ctx.Network, ctx.Family)
		budget.Earn(pool.OfferedRate(now) >= busyRate, now)
		escaped := incumbent >= 0 && chosen != incumbent &&
			(reason == ReasonIncumbentIneligible || reason == ReasonFreshFailureBypass)
		if !escaped {
			if trial, kind := g.trial(sc, candidates, chosen, ctx.targetHash != 0, budget, now); trial >= 0 {
				primary = trial
				decision.Trial = kind
				decision.budget = budget
				switch kind {
				case TrialCold:
					decision.Reason = ReasonColdExplore
				case TrialPeriodic:
					decision.Reason = ReasonPeriodicExplore
				case TrialRecovery:
					decision.Reason = ReasonRecoveryExplore
				}
			}
		}
		if switched, flap := g.engine.history.commit(hkey, candidates[chosen].Node, now); switched {
			g.switches[ctx.Network&1].Add(1)
			if flap {
				g.flaps[ctx.Network&1].Add(1)
			}
		}
		pool.Anchor(candidates[chosen].Node, now)
		g.reasons[ctx.Network&1][decision.Reason].Add(1)
	}

	// Dial order: the primary, the rest of the pool by eligibility and
	// utility, then the members outside the pool in declaration order.
	order := make([]int, 0, n)
	order = append(order, primary)
	sc.order = append(sc.order[:0], sc.members...)
	sort.SliceStable(sc.order, func(a, b int) bool {
		l, r := sc.order[a], sc.order[b]
		if sc.eligible[l] != sc.eligible[r] {
			return sc.eligible[l]
		}
		return sc.utility[l] > sc.utility[r]
	})
	for _, i := range sc.order {
		if i != primary {
			order = append(order, i)
		}
	}
	for i := range candidates {
		if !sc.mask[i] && i != primary {
			order = append(order, i)
		}
	}
	decision.Order = order
	decision.PoolSize = len(sc.members)
	if !sc.mask[primary] {
		decision.PoolSize++
	}
	return decision
}

func priorityOf(c Candidate) float64 {
	if c.Priority > 0 {
		return c.Priority
	}
	return 1
}

// ordinary is the ordinary choice: the utility winner among eligible pool
// members, unless a trained, eligible incumbent holds against every
// challenger that cannot prove a gain beyond the switch margin.
func (g *Group) ordinary(sc *scratch, incumbent int) (int, Reason) {
	best, bestReason := g.best(sc)
	if incumbent < 0 {
		return best, bestReason
	}
	current := &sc.snapshots[incumbent]
	if !sc.eligible[incumbent] {
		return best, ReasonIncumbentIneligible
	}
	if current.UnresolvedFailure {
		return best, ReasonFreshFailureBypass
	}
	if current.Completed < minTrainedEvidence {
		return best, bestReason
	}
	margin := switchMargin(current.Completed)
	promoted, promotedGain := -1, 0.0
	bestComparable := false
	tradeoff := false
	for _, i := range sc.members {
		candidate := &sc.snapshots[i]
		if i == incumbent || !sc.eligible[i] || candidate.Completed < minTrainedEvidence {
			continue
		}
		result := promotion(pairOf(current, candidate), current.Qualified && candidate.Qualified, current.Observed, candidate.Observed)
		// The policy priority factor scales the payoff on both sides.
		gain := result.gain + (sc.utility[i]-sc.utility[incumbent])*boolFloat(candidate.Priority != current.Priority)
		tradeoff = tradeoff || result.tradeoff
		if i == best || best == incumbent {
			bestComparable = bestComparable || result.comparable
		}
		if gain >= margin && gain > 0 && (promoted < 0 || gain > promotedGain) {
			promoted, promotedGain = i, gain
		}
	}
	switch {
	case promoted >= 0:
		return promoted, ReasonPerformanceWinner
	case tradeoff:
		return incumbent, ReasonDirectionalTradeoffHeld
	case bestComparable:
		return incumbent, ReasonIncumbentHeld
	default:
		return incumbent, ReasonInsufficientEvidenceHeld
	}
}

func boolFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (g *Group) best(sc *scratch) (int, Reason) {
	best := -1
	eligibleCount := 0
	for _, i := range sc.members {
		if !sc.eligible[i] {
			continue
		}
		eligibleCount++
		if best < 0 || sc.utility[i] > sc.utility[best] {
			best = i
		}
	}
	if best < 0 {
		// Nobody is eligible: take the most reliable pool member.
		for _, i := range sc.members {
			if best < 0 || sc.snapshots[i].Reliability > sc.snapshots[best].Reliability {
				best = i
			}
		}
		return best, ReasonReliabilityWinner
	}
	if eligibleCount > 1 {
		return best, ReasonPerformanceWinner
	}
	return best, ReasonReliabilityWinner
}

type pairMetric struct {
	incumbent, candidate float64
	ok                   bool
}

type pairEvidence struct {
	response, upload, download pairMetric
}

// pairOf compares the incumbent and a challenger on the same cohort: mature
// target (site/exact) evidence on both sides, otherwise mature probes.
func pairOf(incumbent, candidate *Snapshot) pairEvidence {
	var p pairEvidence
	both := func(a, b MetricValue) pairMetric {
		if a.Mature() && b.Mature() {
			return pairMetric{a.Value, b.Value, true}
		}
		return pairMetric{}
	}
	p.response = both(incumbent.TargetPerformance.Response, candidate.TargetPerformance.Response)
	if !p.response.ok {
		p.response = both(incumbent.Probe, candidate.Probe)
	}
	p.upload = both(incumbent.TargetPerformance.Upload, candidate.TargetPerformance.Upload)
	p.download = both(incumbent.TargetPerformance.Download, candidate.TargetPerformance.Download)
	return p
}

type promotionResult struct {
	gain       float64
	comparable bool
	tradeoff   bool
}

func promotion(p pairEvidence, qualified bool, incumbentReliability, candidateReliability float64) promotionResult {
	var latencyGain float64
	if p.response.ok {
		best := max(min(p.response.incumbent, p.response.candidate), 1)
		latencyGain = min(best/max(p.response.candidate, 1), 1) - min(best/max(p.response.incumbent, 1), 1)
	}
	var improved, regressed bool
	directional := 0.0
	for _, m := range [2]pairMetric{p.upload, p.download} {
		if !m.ok {
			continue
		}
		improved = improved || m.candidate-m.incumbent >= m.incumbent*performanceSwitchMargin
		regressed = regressed || m.incumbent-m.candidate > m.incumbent*performanceSwitchMargin
		directional = max(directional, (m.candidate-m.incumbent)/max(m.candidate, m.incumbent, 1))
	}
	responseGuard := p.response.ok && p.response.candidate-p.response.incumbent <= p.response.incumbent*performanceSwitchMargin
	reliabilityGain := 0.0
	if qualified {
		reliabilityGain = candidateReliability - incumbentReliability
	}
	throughputGain := 0.0
	if improved && !regressed && responseGuard && qualified && candidateReliability >= incumbentReliability {
		throughputGain = directional
	}
	return promotionResult{
		gain:       reliabilityGain + utilityLatency*latencyGain + utilityGoodput*throughputGain,
		comparable: p.response.ok || p.upload.ok || p.download.ok,
		tradeoff:   improved && regressed,
	}
}

// trial walks the pool members with an open question in dispatch order and
// funds the first one the budget admits.
func (g *Group) trial(sc *scratch, candidates []Candidate, selection int, targeted bool, budget *Budget, now Mono) (int, TrialKind) {
	selected := &sc.snapshots[selection]
	usable := selected.Qualified && !selected.UnresolvedFailure
	type open struct {
		index    int
		recovery bool
	}
	var queue []open
	for _, i := range sc.members {
		if i == selection {
			continue
		}
		s := &sc.snapshots[i]
		switch {
		case s.FailStreak > 0:
			if s.ExploreBackedOff {
				g.backoff.Add(1)
				continue
			}
			queue = append(queue, open{i, true})
		case s.ExploreBackedOff:
			continue
		case !s.Qualified, targeted && sc.eligible[i] && !s.TargetPerformance.Response.Mature() && selected.TargetPerformance.Response.Mature():
			// First choice follows evidence: train a challenger only while it
			// has fewer completions than the selection.
			if s.UsefulCompleted >= selected.UsefulCompleted {
				continue
			}
			queue = append(queue, open{i, false})
		}
	}
	if len(queue) == 0 {
		return -1, TrialNone
	}
	slices.SortStableFunc(queue, func(a, b open) int {
		sa, sb := &sc.snapshots[a.index], &sc.snapshots[b.index]
		ua, ub := sa.UsefulCompleted < minTrainedEvidence, sb.UsefulCompleted < minTrainedEvidence
		if ua != ub {
			if ua {
				return -1
			}
			return 1
		}
		if sa.UsefulCompleted != sb.UsefulCompleted {
			if sa.UsefulCompleted > sb.UsefulCompleted {
				return -1
			}
			return 1
		}
		switch {
		case sa.SelectedAt < sb.SelectedAt:
			return -1
		case sa.SelectedAt > sb.SelectedAt:
			return 1
		}
		return 0
	})
	for _, q := range queue {
		kind, ok := budget.Reserve(candidates[q.index].Node, q.recovery, usable, now)
		if ok {
			return q.index, kind
		}
		if budget.Busy(candidates[q.index].Node, now) {
			continue
		}
		break
	}
	return -1, TrialNone
}

// Release refunds the trial of a decision that was never dialed.
func (g *Group) Release(d *Decision, node uint32) {
	if d.Trial != TrialNone && d.budget != nil {
		d.budget.Refund(node, d.Trial)
		d.Trial = TrialNone
	}
}

// CountFiltered counts candidates removed before selection (health, blocks).
func (g *Group) CountFiltered(n int) {
	if n > 0 {
		g.filtered.Add(uint64(n))
	}
}

// Adopt makes node the incumbent of ctx after it carried a connection the
// planned member failed (a failover winner).
func (g *Group) Adopt(ctx *Context, node uint32, now Mono) {
	ctx.prepare()
	g.engine.history.commit(g.historyKey(ctx), node, now)
	g.pools[ctx.Network&1].Anchor(node, now)
}

// ConnectAverage returns the node's connect time EMA in milliseconds.
func (g *Group) ConnectAverage(node uint32, network Network) float64 {
	var avg float64
	g.engine.aggregate.Peek(g.key(node, network, FamilyNone, LayerGlobal, 0), Now(), func(c *Cell) {
		if c != nil {
			avg = c.ConnectAvg
		}
	})
	return avg
}

// historyKey keys the incumbent by the service key when there is one, so
// every target of a service converges on one exit (mihomo pinning), else by
// the exact target.
func (g *Group) historyKey(ctx *Context) historyKey {
	scope := ctx.siteHash
	if scope == 0 {
		scope = ctx.targetHash
	}
	return historyKey{group: g.id, network: ctx.Network, family: ctx.Family, target: scope}
}

// CellHistory is the lifetime record of one node for one service: the
// inputs of the quality weight and LightGBM features.
type CellHistory struct {
	Success       int64
	Failure       int64
	ConnectAvg    float64
	LatencyAvg    float64
	UploadTotal   float64
	DownloadTotal float64
	MaxUpRate     float64
	MaxDownRate   float64
	DurationAvg   float64
	LastUsed      int64
	CumulSent     uint64
	CumulRetrans  uint64
	LossEMA       float64
}

func historyOf(c *Cell) CellHistory {
	return CellHistory{
		Success:       c.Success,
		Failure:       c.Failure,
		ConnectAvg:    c.ConnectAvg,
		LatencyAvg:    c.LatencyAvg,
		UploadTotal:   c.UploadTotal,
		DownloadTotal: c.DownloadTotal,
		MaxUpRate:     c.MaxUpRate,
		MaxDownRate:   c.MaxDownRate,
		DurationAvg:   c.DurationAvg,
		LastUsed:      c.LastUsed,
		CumulSent:     c.CumulSent,
		CumulRetrans:  c.CumulRetrans,
		LossEMA:       c.LossEMA,
	}
}

// History returns the node's record for the context's service (its site
// cell), else its group-wide record.
func (g *Group) History(ctx *Context, node uint32) CellHistory {
	ctx.prepare()
	now := Now()
	var (
		h     CellHistory
		found bool
	)
	if ctx.siteHash != 0 {
		g.engine.site.Peek(g.key(node, ctx.Network, ctx.Family, LayerSite, ctx.siteHash), now, func(c *Cell) {
			if c != nil {
				h, found = historyOf(c), true
			}
		})
	}
	if !found {
		g.engine.aggregate.Peek(g.key(node, ctx.Network, FamilyNone, LayerGlobal, 0), now, func(c *Cell) {
			if c != nil {
				h = historyOf(c)
			}
		})
	}
	return h
}

// ForgetKey drops the incumbents of a service key (a pin dropped after its
// node was blocked for the key).
func (g *Group) ForgetKey(key string) {
	hash := HashString(key)
	if hash == 0 {
		return
	}
	g.engine.history.deleteTarget(g.id, hash)
}
