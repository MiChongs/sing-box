package smart

import (
	"sync"
	"time"
)

// Attempt reports the observations of one business attempt on one node into
// every evidence layer of its context. It is created when node-specific
// work begins (the dial) and settled exactly once.
type Attempt struct {
	group  *Group
	keys   [4]Key
	layers int
	node   uint32
	site   string
	trial  TrialKind
	budget *Budget
	start  Mono

	access   sync.Mutex
	credited [4]uint32
	lastRX   Mono
	pendRX   Mono
	settled  bool
}

// Begin starts an attempt on node. trial and the decision's budget come from
// the decision when node is its trial primary.
func (g *Group) Begin(ctx *Context, d *Decision, node uint32, now Mono) *Attempt {
	ctx.prepare()
	a := &Attempt{group: g, node: node, site: ctx.Site, start: now}
	a.keys[0] = g.key(node, ctx.Network, FamilyNone, LayerGlobal, 0)
	a.layers = 1
	if ctx.Family != FamilyNone {
		a.keys[a.layers] = g.key(node, ctx.Network, ctx.Family, LayerFamily, 0)
		a.layers++
	}
	if ctx.siteHash != 0 {
		a.keys[a.layers] = g.key(node, ctx.Network, ctx.Family, LayerSite, ctx.siteHash)
		a.layers++
	}
	if ctx.targetHash != 0 {
		a.keys[a.layers] = g.key(node, ctx.Network, ctx.Family, LayerExact, ctx.targetHash)
		a.layers++
	}
	if d != nil && d.Trial != TrialNone && len(d.Order) > 0 {
		a.trial, a.budget = d.Trial, d.budget
		d.Trial = TrialNone
	}
	// An admitted begin is a real opportunity: it advances the rotation
	// order of the dispatch queue.
	tick := g.engine.tick.Add(1)
	g.engine.aggregate.Update(a.keys[0], now, func(c *Cell) {
		c.SelectedAt = tick
	})
	if a.layers > 1 && a.keys[a.layers-1].Layer == LayerExact {
		g.engine.exact.Peek(a.keys[a.layers-1], now, func(c *Cell) {
			if c != nil {
				c.SelectedAt = tick
			}
		})
	}
	return a
}

// Node returns the attempted node.
func (a *Attempt) Node() uint32 { return a.node }

// Trial returns how the attempt was funded.
func (a *Attempt) Trial() TrialKind { return a.trial }

func (a *Attempt) each(now Mono, fn func(i int, c *Cell)) {
	e := a.group.engine
	for i := 0; i < a.layers; i++ {
		k := a.keys[i]
		e.table(k.Layer).Update(k, now, func(c *Cell) {
			if k.Layer == LayerSite && c.Name == "" {
				c.Name = a.site
			}
			fn(i, c)
		})
	}
}

// Setup records the setup latency of a successful dial.
func (a *Attempt) Setup(latency time.Duration) {
	now := Now()
	degraded := false
	a.each(now, func(i int, c *Cell) {
		c.observeLatency(&c.Setup, latency, now, a.keys[i].Layer == LayerExact)
		degraded = degraded || (a.keys[i].Layer == LayerExact && c.DegradedAt == now)
	})
	a.markSiteDegraded(degraded, now)
}

// Response records the first-response latency.
func (a *Attempt) Response(latency time.Duration) {
	now := Now()
	degraded := false
	a.each(now, func(i int, c *Cell) {
		c.observeLatency(&c.Response, latency, now, a.keys[i].Layer == LayerExact)
		degraded = degraded || (a.keys[i].Layer == LayerExact && c.DegradedAt == now)
	})
	a.markSiteDegraded(degraded, now)
}

// Transfer records one goodput window of tx/rx bytes over elapsed.
func (a *Attempt) Transfer(tx, rx int64, elapsed time.Duration) {
	if elapsed < minThroughputDuration || elapsed > maxThroughputDuration || (tx < minThroughputBytes && rx < minThroughputBytes) {
		return
	}
	now := Now()
	a.each(now, func(_ int, c *Cell) {
		c.observeTransfer(tx, rx, elapsed, now)
	})
}

// RX publishes business progress (a receive after setup and a send). The
// first is published immediately, later ones at most once per second.
func (a *Attempt) RX(at Mono) {
	a.access.Lock()
	if a.settled || (a.lastRX != 0 && at.Sub(a.lastRX) < time.Second) {
		if !a.settled {
			a.pendRX = maxMono(a.pendRX, at)
		}
		a.access.Unlock()
		return
	}
	a.lastRX = at
	a.pendRX = 0
	a.access.Unlock()
	a.publishRX(at)
}

func (a *Attempt) publishRX(at Mono) {
	now := Now()
	a.each(now, func(i int, c *Cell) {
		c.observeRX(at, now, &a.credited[i])
	})
}

// Probe records a configured health-probe latency on the node's global
// cell. interval is the probe cadence: probe evidence stays valid for
// max(performanceMaxAge, 2.5 intervals), so a slow cadence still keeps a
// baseline (honk's cadence-aware probe support).
func (g *Group) Probe(node uint32, network Network, latency time.Duration, ok bool, interval time.Duration) {
	now := Now()
	maxAge := max(performanceMaxAge, interval*5/2)
	g.engine.aggregate.Update(g.key(node, network, FamilyNone, LayerGlobal, 0), now, func(c *Cell) {
		c.ProbeMaxAge = maxAge
		if ok {
			c.Probe.RecordAge(float64(latency)/float64(time.Millisecond), now, maxAge)
		} else {
			c.Probe = Metric{}
		}
	})
}

// Finish settles the attempt. Node-scoped failures open hard failure state
// on every layer; target-scoped failures only on the site and exact layers,
// while the parent layers keep the numeric outcome.
func (a *Attempt) Finish(f *Finish) {
	a.access.Lock()
	if a.settled {
		a.access.Unlock()
		return
	}
	a.settled = true
	pending := a.pendRX
	a.access.Unlock()
	if pending != 0 && f.Outcome != OutcomeCancelled {
		a.publishRX(pending)
	}
	now := Now()
	if f.Outcome != OutcomeCancelled {
		a.each(now, func(i int, c *Cell) {
			layer := a.keys[i].Layer
			hard := f.Scope == ScopeNode || layer == LayerSite || layer == LayerExact
			c.finish(f, now, hard)
		})
	}
	if a.trial != TrialNone && a.budget != nil {
		a.budget.Settle(a.node, a.trial, f.Outcome, now)
	}
}

// RecordLoss feeds a carrier retransmission sample without settling an
// attempt (periodic sampling of long-lived connections).
func (a *Attempt) RecordLoss(sent, retrans uint64) {
	if sent == 0 {
		return
	}
	now := Now()
	rate := float64(retrans) / float64(sent)
	a.each(now, func(_ int, c *Cell) {
		if c.LossAt == 0 {
			c.LossEMA = rate
		} else {
			c.LossEMA += lossAlpha * (rate - c.LossEMA)
		}
		c.LossAt = now
	})
}

// markSiteDegraded carries an exact target's degradation to its service, so
// service-level readers (smart-loadbalance suspicion) see it.
func (a *Attempt) markSiteDegraded(degraded bool, now Mono) {
	if !degraded {
		return
	}
	for i := 0; i < a.layers; i++ {
		if k := a.keys[i]; k.Layer == LayerSite {
			a.group.engine.site.Peek(k, now, func(c *Cell) {
				if c != nil {
					c.DegradedAt = now
				}
			})
		}
	}
}
