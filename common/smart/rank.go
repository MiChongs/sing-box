package smart

import (
	"math"
	"sort"
)

// Node rank tiers (mihomo NodeRankItem.Rank).
const (
	RankMostUsed   = "MostUsed"
	RankOccasional = "OccasionalUsed"
	RankRarelyUsed = "RarelyUsed"
)

// rankSites is how many recently used services the ranking reads.
const rankSites = 64

// NodeRank is one member's place in the group ranking. Name, Rank and
// Weight (0-100) keep mihomo's keys so Clash dashboards read them; the rest
// expose the comprehensive score behind it.
type NodeRank struct {
	Name        string  `json:"Name"`
	Rank        string  `json:"Rank"`
	Weight      float64 `json:"Weight"`
	Alive       bool    `json:"Alive"`
	Pool        bool    `json:"Pool"`
	Utility     float64 `json:"Utility"`
	Reliability float64 `json:"Reliability"`
	Observed    float64 `json:"Observed"`
	Quality     float64 `json:"Quality"`
	Completed   float64 `json:"Completed"`
	Qualified   bool    `json:"Qualified"`
	FailStreak  uint32  `json:"FailStreak"`
	BackedOff   bool    `json:"BackedOff"`
	ProbeMS     float64 `json:"ProbeMs,omitempty"`
	ResponseMS  float64 `json:"ResponseMs,omitempty"`
	SetupMS     float64 `json:"SetupMs,omitempty"`
	UploadBps   float64 `json:"UploadBps,omitempty"`
	DownloadBps float64 `json:"DownloadBps,omitempty"`
	Loss        float64 `json:"Loss,omitempty"`
	Success     int64   `json:"Success"`
	Failure     int64   `json:"Failure"`
	Targets     int     `json:"Targets"`
}

// RankMember is one member offered to the ranking.
type RankMember struct {
	Name     string
	Node     uint32
	Priority float64
	Alive    bool
}

// Ranking ranks the members like mihomo's node ranking: each recently used
// service orders its members by learned connection quality and every
// member at least AllowedWeight scores 1/(position+1). Without learned
// services the comprehensive utility orders them.
func (g *Group) Ranking(members []RankMember, network Network) []NodeRank {
	now := Now()
	type siteEntry struct {
		node    uint32
		quality float64
	}
	type site struct {
		touched Mono
		entries []siteEntry
	}
	index := make(map[uint32]int, len(members))
	for i, m := range members {
		index[m.Node] = i
	}
	sites := make(map[uint64]*site)
	targets := make([]int, len(members))
	g.engine.site.Range(func(k Key, c *Cell) bool {
		if k.Group != g.id {
			return true
		}
		i, ok := index[k.Node]
		if !ok {
			return true
		}
		targets[i]++
		q := c.Quality.Read(now)
		if !q.Valid {
			return true
		}
		s := sites[k.Scope]
		if s == nil {
			s = &site{}
			sites[k.Scope] = s
		}
		s.touched = maxMono(s.touched, c.touched)
		s.entries = append(s.entries, siteEntry{k.Node, q.Value * members[i].Priority})
		return true
	})
	recent := make([]*site, 0, len(sites))
	for _, s := range sites {
		recent = append(recent, s)
	}
	sort.Slice(recent, func(a, b int) bool { return recent[a].touched > recent[b].touched })
	if len(recent) > rankSites {
		recent = recent[:rankSites]
	}
	scores := make([]float64, len(members))
	for _, s := range recent {
		sort.SliceStable(s.entries, func(a, b int) bool { return s.entries[a].quality > s.entries[b].quality })
		for position, e := range s.entries {
			if e.quality < AllowedWeight {
				break
			}
			scores[index[e.node]] += 1 / float64(position+1)
		}
	}
	ctx := Context{Network: network, prepared: true}
	snapshots := make([]Snapshot, len(members))
	for i, m := range members {
		snapshots[i] = g.snapshot(&ctx, m.Node, now, false)
		snapshots[i].Priority = max(m.Priority, 0)
		if snapshots[i].Priority == 0 {
			snapshots[i].Priority = 1
		}
	}
	baseline := NewBaseline(snapshots, nil)
	pool := g.pools[network&1].Members()
	inPool := make(map[uint32]bool, len(pool))
	for _, n := range pool {
		inPool[n] = true
	}
	utilities := make([]float64, len(members))
	learned := false
	for _, v := range scores {
		if v > 0 {
			learned = true
			break
		}
	}
	for i := range members {
		utilities[i] = Utility(&snapshots[i], baseline)
		if !learned && Eligible(&snapshots[i], baseline) && snapshots[i].Completed > 0 {
			scores[i] = utilities[i]
		}
	}
	best := 0.0
	for _, v := range scores {
		best = math.Max(best, v)
	}
	out := make([]NodeRank, len(members))
	for i, m := range members {
		s := &snapshots[i]
		r := NodeRank{
			Name:        m.Name,
			Alive:       m.Alive,
			Pool:        inPool[m.Node],
			Utility:     round(utilities[i], 4),
			Reliability: round(s.Reliability, 4),
			Observed:    round(s.Observed, 4),
			Completed:   round(s.Completed, 2),
			Qualified:   s.Qualified,
			FailStreak:  s.FailStreak,
			BackedOff:   s.ExploreBackedOff,
			Loss:        round(s.Loss, 4),
			Targets:     targets[i],
		}
		if s.Quality.Valid {
			r.Quality = round(s.Quality.Value, 4)
		}
		if s.Probe.Valid {
			r.ProbeMS = round(s.Probe.Value, 1)
		}
		if s.Performance.Response.Valid {
			r.ResponseMS = round(s.Performance.Response.Value, 1)
		}
		if s.Performance.Setup.Valid {
			r.SetupMS = round(s.Performance.Setup.Value, 1)
		}
		if s.Performance.Upload.Valid {
			r.UploadBps = math.Round(s.Performance.Upload.Value)
		}
		if s.Performance.Download.Valid {
			r.DownloadBps = math.Round(s.Performance.Download.Value)
		}
		g.engine.aggregate.Peek(g.key(m.Node, network, FamilyNone, LayerGlobal, 0), now, func(c *Cell) {
			if c != nil {
				r.Success, r.Failure = c.Success, c.Failure
			}
		})
		if best > 0 && scores[i] > 0 {
			r.Weight = round(scores[i]/best*100, 2)
		}
		out[i] = r
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Alive != out[b].Alive {
			return out[a].Alive
		}
		if out[a].Weight != out[b].Weight {
			return out[a].Weight > out[b].Weight
		}
		return out[a].Name < out[b].Name
	})
	alive, positive := 0, 0
	for _, r := range out {
		if r.Alive {
			alive++
			if r.Weight > 0 {
				positive++
			}
		}
	}
	most, occasional := 0, 0
	if alive > 0 && positive > 0 {
		most = max(1, int(float64(positive)*0.2))
		occasional = most + int(float64(positive)*0.5)
	}
	for i := range out {
		switch {
		case i < most:
			out[i].Rank = RankMostUsed
		case i < occasional:
			out[i].Rank = RankOccasional
		default:
			out[i].Rank = RankRarelyUsed
		}
	}
	return out
}

func round(v float64, digits int) float64 {
	p := math.Pow10(digits)
	return math.Round(v*p) / p
}

// GroupStats describes a group's selection behavior for the API.
type GroupStats struct {
	Network  string            `json:"network"`
	Reasons  map[string]uint64 `json:"reasons"`
	Switches uint64            `json:"ordinarySwitch"`
	Flaps    uint64            `json:"switchFlap"`
	Pool     []string          `json:"pool"`
	Budgets  []BudgetReport    `json:"budgets"`
}

// BudgetReport is one exploration budget scope.
type BudgetReport struct {
	Family string `json:"family"`
	BudgetState
}

// Stats returns the per-network selection statistics.
func (g *Group) Stats() []GroupStats {
	now := Now()
	busy := [2]bool{g.pools[0].OfferedRate(now) >= busyRate, g.pools[1].OfferedRate(now) >= busyRate}
	out := make([]GroupStats, 2)
	for n := range out {
		network := Network(n)
		s := GroupStats{Network: network.String(), Reasons: make(map[string]uint64)}
		for r := Reason(1); r < reasonCount; r++ {
			if v := g.reasons[n][r].Load(); v > 0 {
				s.Reasons[r.String()] = v
			}
		}
		s.Switches = g.switches[n].Load()
		s.Flaps = g.flaps[n].Load()
		for _, node := range g.pools[n].Members() {
			s.Pool = append(s.Pool, g.engine.NodeName(node))
		}
		g.budgetAccess.Lock()
		for key, b := range g.budgets {
			if key.network != network {
				continue
			}
			family := "none"
			switch key.family {
			case FamilyIPv4:
				family = "ipv4"
			case FamilyIPv6:
				family = "ipv6"
			}
			s.Budgets = append(s.Budgets, BudgetReport{Family: family, BudgetState: b.State(busy[n], now)})
		}
		g.budgetAccess.Unlock()
		out[n] = s
	}
	return out
}

// Filtered counts candidates removed before selection.
func (g *Group) Filtered() uint64 { return g.filtered.Load() }

// TargetQuality returns each node's learned connection quality for the
// context's service (site), else exact target, on the scale of
// CalculateWeight.
func (g *Group) TargetQuality(ctx *Context, nodes []uint32) map[uint32]float64 {
	ctx.prepare()
	now := Now()
	out := make(map[uint32]float64)
	for _, node := range nodes {
		read := func(t *Table, k Key) bool {
			found := false
			t.Peek(k, now, func(c *Cell) {
				if c == nil {
					return
				}
				if q := c.Quality.Read(now); q.Valid {
					out[node] = q.Value
					found = true
				}
			})
			return found
		}
		if ctx.siteHash != 0 && read(g.engine.site, g.key(node, ctx.Network, ctx.Family, LayerSite, ctx.siteHash)) {
			continue
		}
		if ctx.targetHash != 0 {
			read(g.engine.exact, g.key(node, ctx.Network, ctx.Family, LayerExact, ctx.targetHash))
		}
	}
	return out
}

// NodeFailing reports whether node is excluded by its group-wide failure
// streak on network.
func (g *Group) NodeFailing(node uint32, network Network) bool {
	failing := false
	now := Now()
	g.engine.aggregate.Peek(g.key(node, network, FamilyNone, LayerGlobal, 0), now, func(c *Cell) {
		failing = c != nil && c.FailStreak >= failStreakExclude && c.ExploreNotBefore > now
	})
	return failing
}

// KeyFailing reports whether node holds unresolved failures for a service
// key, in any address family.
func (g *Group) KeyFailing(key string, node uint32, network Network) bool {
	hash := HashString(key)
	if hash == 0 {
		return false
	}
	now := Now()
	failing := false
	for _, family := range [...]Family{FamilyNone, FamilyIPv4, FamilyIPv6} {
		g.engine.site.Peek(g.key(node, network, family, LayerSite, hash), now, func(c *Cell) {
			if c != nil && c.FailStreak > 0 && c.ExploreNotBefore > now {
				failing = true
			}
		})
		if failing {
			return true
		}
	}
	return false
}

// KeyDegraded reports whether node recently answered a service key much
// slower than its history.
func (g *Group) KeyDegraded(key string, node uint32, network Network) bool {
	hash := HashString(key)
	if hash == 0 {
		return false
	}
	now := Now()
	degraded := false
	for _, family := range [...]Family{FamilyNone, FamilyIPv4, FamilyIPv6} {
		g.engine.site.Peek(g.key(node, network, family, LayerSite, hash), now, func(c *Cell) {
			if c != nil && c.DegradedAt != 0 && now.Sub(c.DegradedAt) < performanceMaxAge {
				degraded = true
			}
		})
		if degraded {
			return true
		}
	}
	return false
}
