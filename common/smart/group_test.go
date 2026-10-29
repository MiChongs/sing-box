package smart

import (
	"fmt"
	"testing"
	"time"
)

func newTestGroup(t testing.TB, n int) (*Group, []Candidate) {
	e := NewEngine()
	g := e.Group(t.Name())
	candidates := make([]Candidate, n)
	nodes := make([]uint32, n)
	for i := range candidates {
		nodes[i] = e.NodeID(fmt.Sprint("node", i))
		candidates[i] = Candidate{Node: nodes[i]}
	}
	g.SetMembers(nodes)
	return g, candidates
}

func settle(g *Group, ctx *Context, d *Decision, node uint32, ok bool, scope FailureScope, latency time.Duration) {
	now := Now()
	a := g.Begin(ctx, d, node, now)
	if ok {
		a.Setup(latency)
		a.Response(latency)
		a.RX(Now())
		a.Finish(&Finish{Outcome: OutcomeSuccess, SetupOK: true, TX: 100, RX: 100, RXAt: Now()})
	} else {
		a.Finish(&Finish{Outcome: OutcomeFailure, Scope: scope})
	}
}

func TestSelectPrefersReliableNode(t *testing.T) {
	g, cands := newTestGroup(t, 3)
	ctx := &Context{Network: NetworkTCP, Family: FamilyIPv4, Target: "example.com:443", Site: "example.com"}
	for range 10 {
		settle(g, ctx, nil, cands[0].Node, false, ScopeNode, 0)
		settle(g, ctx, nil, cands[1].Node, true, ScopeNode, 50*time.Millisecond)
		settle(g, ctx, nil, cands[2].Node, true, ScopeNode, 200*time.Millisecond)
	}
	d := g.Select(ctx, cands, false, Now())
	if d.Order[0] == 0 {
		t.Fatalf("failing node selected: %+v", d)
	}
	if d.Order[0] != 1 {
		t.Fatalf("expected faster node 1, got %d (%s)", d.Order[0], d.Reason)
	}
}

func TestIncumbentHeldWithoutComparableGain(t *testing.T) {
	g, cands := newTestGroup(t, 2)
	ctx := &Context{Network: NetworkTCP, Family: FamilyIPv4, Target: "a.test:443"}
	for range 10 {
		settle(g, ctx, nil, cands[0].Node, true, ScopeNode, 100*time.Millisecond)
	}
	d := g.Select(ctx, cands, true, Now())
	if d.Order[0] != 0 && d.Trial == TrialNone {
		t.Fatalf("expected node 0 as incumbent, got %+v", d)
	}
	// Node 1 gets a little evidence, slightly faster but not proven.
	settle(g, ctx, nil, cands[1].Node, true, ScopeNode, 90*time.Millisecond)
	d = g.Select(ctx, cands, false, Now())
	if d.Order[0] != 0 {
		t.Fatalf("incumbent not held: %+v", d)
	}
}

func TestFailureEscapes(t *testing.T) {
	g, cands := newTestGroup(t, 2)
	ctx := &Context{Network: NetworkTCP, Family: FamilyIPv4, Target: "b.test:443"}
	for range 6 {
		settle(g, ctx, nil, cands[0].Node, true, ScopeNode, 50*time.Millisecond)
		settle(g, ctx, nil, cands[1].Node, true, ScopeNode, 80*time.Millisecond)
	}
	d := g.Select(ctx, cands, true, Now())
	first := d.Order[0]
	settle(g, ctx, &d, cands[first].Node, false, ScopeNode, 0)
	d = g.Select(ctx, cands, true, Now())
	if d.Order[0] == first {
		t.Fatalf("did not escape failed incumbent: %+v", d)
	}
	if d.Reason != ReasonFreshFailureBypass && d.Reason != ReasonIncumbentIneligible {
		t.Fatalf("unexpected reason %s", d.Reason)
	}
}

func TestColdExplorationFunded(t *testing.T) {
	g, cands := newTestGroup(t, 4)
	ctx := &Context{Network: NetworkTCP, Family: FamilyIPv4, Target: "c.test:443"}
	trials := 0
	for range 40 {
		d := g.Select(ctx, cands, true, Now())
		if d.Trial != TrialNone {
			trials++
		}
		settle(g, ctx, &d, cands[d.Order[0]].Node, true, ScopeNode, 60*time.Millisecond)
	}
	if trials == 0 || trials > 8 {
		t.Fatalf("unexpected trial count %d", trials)
	}
}

func TestTargetFailureStaysScoped(t *testing.T) {
	g, cands := newTestGroup(t, 2)
	bad := &Context{Network: NetworkTCP, Family: FamilyIPv4, Target: "blocked.test:443", Site: "blocked.test"}
	good := &Context{Network: NetworkTCP, Family: FamilyIPv4, Target: "ok.test:443", Site: "ok.test"}
	for range 6 {
		settle(g, good, nil, cands[0].Node, true, ScopeNode, 40*time.Millisecond)
		settle(g, good, nil, cands[1].Node, true, ScopeNode, 60*time.Millisecond)
		settle(g, bad, nil, cands[0].Node, false, ScopeTarget, 0)
		settle(g, bad, nil, cands[1].Node, true, ScopeNode, 60*time.Millisecond)
	}
	if d := g.Select(bad, cands, false, Now()); d.Order[0] != 1 {
		t.Fatalf("blocked target should avoid node 0: %+v", d)
	}
	s := g.snapshot(&Context{Network: NetworkTCP, Family: FamilyIPv4, prepared: true}, cands[0].Node, Now(), false)
	if s.FailStreak != 0 {
		t.Fatalf("target failure leaked into node state: %+v", s)
	}
}

func BenchmarkSelect25(b *testing.B) {
	g, cands := newTestGroup(b, 100)
	ctx := &Context{Network: NetworkTCP, Family: FamilyIPv4, Target: "bench.test:443", Site: "bench.test"}
	for i := range cands {
		settle(g, ctx, nil, cands[i].Node, i%7 != 0, ScopeNode, time.Duration(20+i)*time.Millisecond)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c := *ctx
			d := g.Select(&c, cands, true, Now())
			g.Release(&d, cands[d.Order[0]].Node)
		}
	})
}
