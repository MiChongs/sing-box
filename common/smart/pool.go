package smart

import (
	"slices"
	"sort"
	"sync"
)

// Pool is the committed serving pool of one (group, network): ordinary
// choice, failure escape, promotion and trials all pick inside it, which
// bounds per-dial work and concentrates evidence on few enough members to
// compare them. Its capacity follows offered business: k = 1 + D/128 for
// projected demand D, between 3 and min(25, ceil(sqrt(n))+1). One slot of a
// view larger than k rotates through the rest every ten minutes.
type Pool struct {
	access sync.Mutex

	ranked      []uint32
	rotation    uint32
	hasRotation bool
	rotationAt  Mono
	refreshedAt Mono
	// substitutedAt rate-limits replacement attempts while a failing
	// member has no healthy outsider to replace it.
	substitutedAt Mono
	limit         int
	demand        float64
	demandAt      Mono
	version       uint64
}

// RecordDemand counts one original business start.
func (p *Pool) RecordDemand(now Mono) {
	p.access.Lock()
	p.demand = p.demandNowLocked(now) + 1
	p.demandAt = now
	p.access.Unlock()
}

func (p *Pool) demandNowLocked(now Mono) float64 {
	if p.demandAt == 0 {
		return 0
	}
	return p.demand * decay(now.Sub(p.demandAt), demandHalfLife)
}

// OfferedRate is the group's recent original business in flows per second.
func (p *Pool) OfferedRate(now Mono) float64 {
	p.access.Lock()
	defer p.access.Unlock()
	// A decayed count with half-life h approximates rate*h/ln2.
	return p.demandNowLocked(now) * 0.6931471805599453 / demandHalfLife.Seconds()
}

func (p *Pool) targetLimitLocked(now Mono, candidates int) int {
	sustained := p.demandNowLocked(now) * evidenceHalfLife.Seconds() / demandHalfLife.Seconds()
	challengers := qualificationShare * sustained / (validationSamples * explorationPeriod)
	capacity := max(min(max(explorationTarget(candidates), poolMinMembers), poolMaxMembers), p.limit)
	return min(max(1+int(challengers), poolMinMembers), capacity)
}

// Contains reports whether node is in the committed pool.
func (p *Pool) Contains(node uint32) bool {
	p.access.Lock()
	defer p.access.Unlock()
	return p.containsLocked(node)
}

func (p *Pool) containsLocked(node uint32) bool {
	return slices.Contains(p.ranked, node) || (p.hasRotation && p.rotation == node)
}

// Members returns the committed membership.
func (p *Pool) Members() []uint32 {
	p.access.Lock()
	defer p.access.Unlock()
	out := slices.Clone(p.ranked)
	if p.hasRotation {
		out = append(out, p.rotation)
	}
	return out
}

// Anchor promotes an ordinary winner that holds the rotation slot into the
// ranked set, giving the displaced member a fresh rotation interval.
func (p *Pool) Anchor(node uint32, now Mono) {
	p.access.Lock()
	defer p.access.Unlock()
	if !p.hasRotation || p.rotation != node {
		return
	}
	if n := len(p.ranked); n > 0 {
		p.ranked[n-1], p.rotation = p.rotation, p.ranked[n-1]
		p.rotationAt = now
	} else {
		p.ranked = append(p.ranked, node)
		p.hasRotation = false
	}
	p.version++
}

// Reset drops membership after a membership change, keeping the decayed
// demand which reflects offered business.
func (p *Pool) Reset() {
	p.access.Lock()
	p.ranked = nil
	p.hasRotation = false
	p.refreshedAt = 0
	p.limit = 0
	p.version++
	p.access.Unlock()
}

func (p *Pool) initialized() bool { return p.refreshedAt != 0 }

// Derive returns the pool membership mask aligned with nodes (declaration
// order). An authorized apply refreshes the committed pool when it is due
// (every five minutes), when a ranked member fails while a healthy outsider
// exists, or before its first use; a read uses the committed membership, or
// a temporary projection before initialization. aggregate returns the
// targetless snapshot of nodes[i] and is only called when ranking.
func (p *Pool) Derive(nodes []uint32, aggregate func(int) *Snapshot, failing func(uint32) bool, apply bool, now Mono, buf []bool) []bool {
	n := len(nodes)
	mask := grow(buf, n)
	if n <= poolMinMembers {
		// Small groups serve every available member.
		for i := range mask {
			mask[i] = true
		}
		return mask
	}
	p.access.Lock()
	defer p.access.Unlock()
	target := p
	if !apply {
		if p.initialized() {
			for i, node := range nodes {
				mask[i] = p.containsLocked(node)
			}
			if slices.Contains(mask, true) {
				return mask
			}
		}
		projection := &Pool{demand: p.demand, demandAt: p.demandAt}
		target = projection
	}
	target.deriveLocked(nodes, aggregate, failing, now)
	for i, node := range nodes {
		mask[i] = target.containsLocked(node)
	}
	return mask
}

func (p *Pool) deriveLocked(nodes []uint32, aggregate func(int) *Snapshot, failing func(uint32) bool, now Mono) {
	n := len(nodes)
	inView := func(node uint32) bool { return slices.Contains(nodes, node) }
	// A member absent from a filtered view is replaceable once it fails.
	substitute := n > len(p.ranked) && now.Sub(p.substitutedAt) >= poolSubstituteGap && slices.ContainsFunc(p.ranked, failing)
	if substitute {
		p.substitutedAt = now
	}
	due := !p.initialized() || now.Sub(p.refreshedAt) >= poolRefresh
	if due || substitute {
		target := p.targetLimitLocked(now, n)
		if p.limit == 0 || (due && (target > p.limit || target+2 <= p.limit)) {
			p.limit = target
		}
		snapshots := make([]*Snapshot, n)
		for i := range nodes {
			snapshots[i] = aggregate(i)
		}
		baseline := NewBaselineOf(snapshots)
		order := make([]int, n)
		utilities := make([]float64, n)
		eligible := make([]bool, n)
		for i := range nodes {
			order[i] = i
			eligible[i] = Eligible(snapshots[i], baseline)
			utilities[i] = Utility(snapshots[i], baseline)
		}
		probe := func(i int) float64 {
			if v := snapshots[i].Probe; v.Valid {
				return v.Value
			}
			return 1e18
		}
		// Untried members tie on utility; the configured probe then hints
		// the promising ones.
		sort.SliceStable(order, func(a, b int) bool {
			l, r := order[a], order[b]
			if eligible[l] != eligible[r] {
				return eligible[l]
			}
			if utilities[l] != utilities[r] {
				return utilities[l] > utilities[r]
			}
			return probe(l) < probe(r)
		})
		rankedLen := p.limit
		if n > p.limit {
			rankedLen = p.limit - 1
		}
		position := make(map[uint32]int, n)
		for pos, idx := range order {
			position[nodes[idx]] = pos
		}
		pos := func(node uint32) int {
			if v, ok := position[node]; ok {
				return v
			}
			return n
		}
		healthyNode := func(idx int) bool { return snapshots[idx].FailStreak < failStreakExclude }
		// Members keep their place until they fall rankHysteresis below the
		// cut; a member absent from this view keeps its place.
		p.ranked = slices.DeleteFunc(p.ranked, func(node uint32) bool {
			v, ok := position[node]
			return ok && v >= rankedLen+rankHysteresis
		})
		sort.SliceStable(p.ranked, func(a, b int) bool {
			fa, fb := failing(p.ranked[a]), failing(p.ranked[b])
			if fa != fb {
				return !fa
			}
			return pos(p.ranked[a]) < pos(p.ranked[b])
		})
		if len(p.ranked) > rankedLen {
			p.ranked = p.ranked[:rankedLen]
		}
		healthy := 0
		for healthy < len(p.ranked) && !failing(p.ranked[healthy]) {
			healthy++
		}
		for _, idx := range order {
			if healthy >= rankedLen {
				break
			}
			node := nodes[idx]
			if !healthyNode(idx) || slices.Contains(p.ranked, node) {
				continue
			}
			if len(p.ranked) == rankedLen {
				p.ranked = p.ranked[:len(p.ranked)-1]
			}
			p.ranked = slices.Insert(p.ranked, healthy, node)
			healthy++
		}
		// Without enough replacements, failing members keep access to
		// funded recovery.
		for _, idx := range order {
			if len(p.ranked) >= rankedLen {
				break
			}
			if node := nodes[idx]; !slices.Contains(p.ranked, node) {
				p.ranked = append(p.ranked, node)
			}
		}
		if due {
			p.refreshedAt = now
		}
		p.version++
	}
	if len(p.ranked) >= p.limit || n <= len(p.ranked) {
		p.hasRotation = false
		return
	}
	replaceRotation := p.hasRotation && failing(p.rotation)
	if p.hasRotation && !replaceRotation && !slices.Contains(p.ranked, p.rotation) && inView(p.rotation) && now.Sub(p.rotationAt) < poolRotationSlot {
		return
	}
	// Rotate through the outsiders in declaration order, continuing after
	// the previous rotation member and wrapping around.
	outsiders := make([]uint32, 0, n)
	start := 0
	for _, node := range nodes {
		if slices.Contains(p.ranked, node) || (replaceRotation && failing(node)) {
			continue
		}
		if p.hasRotation && node == p.rotation {
			start = len(outsiders) + 1
		}
		outsiders = append(outsiders, node)
	}
	p.hasRotation = len(outsiders) > 0
	if p.hasRotation {
		p.rotation = outsiders[start%len(outsiders)]
	}
	p.rotationAt = now
	p.version++
}
