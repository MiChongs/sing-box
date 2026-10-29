package group

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// smartStub is a member whose dials either fail or reach an echo server.
type smartStub struct {
	tag   string
	delay time.Duration
	fail  atomic.Bool
	dials atomic.Int32
}

func (s *smartStub) Tag() string            { return s.tag }
func (s *smartStub) Type() string           { return "stub" }
func (s *smartStub) Dependencies() []string { return nil }
func (s *smartStub) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }

func (s *smartStub) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	s.dials.Add(1)
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	if s.fail.Load() {
		return nil, errors.New("stub: connection refused")
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	return client, nil
}

func (s *smartStub) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	s.dials.Add(1)
	return nil, errors.New("stub: no UDP")
}

func newTestSmart(t *testing.T, stubs ...*smartStub) *Smart {
	t.Helper()
	logger := log.NewNOPFactory().NewLogger("smart")
	s, err := newSmart(context.Background(), nil, logger, t.Name(), C.TypeSmart, option.SmartOutboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s.engine = smart.NewEngine()
	s.group = s.engine.Group(t.Name())
	s.blocks = s.engine.Blocks()
	outbounds := make([]adapter.Outbound, len(stubs))
	for i, stub := range stubs {
		outbounds[i] = stub
	}
	s.setMembers(outbounds)
	return s
}

func dialEcho(t *testing.T, s *Smart, host string) (string, error) {
	t.Helper()
	// Not 443: short answers there trigger response probes, which the echo
	// stub cannot serve.
	metadata := &adapter.InboundContext{Destination: M.ParseSocksaddrHostPort(host, 8080)}
	trace := new(adapter.OutboundDialTrace)
	ctx := adapter.ContextWithOutboundDialTrace(adapter.WithContext(context.Background(), metadata), trace)
	conn, err := s.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	if err != nil {
		return "", err
	}
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if _, err = io.ReadFull(conn, buffer); err != nil {
		t.Fatal(err)
	}
	chain := trace.Resolve([]adapter.Outbound{s})
	_ = conn.Close()
	if len(chain) != 2 {
		t.Fatalf("dial trace %v", chain)
	}
	return chain[1].Tag(), nil
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSmartDialRecordsEvidence(t *testing.T) {
	a, b := &smartStub{tag: "A"}, &smartStub{tag: "B"}
	s := newTestSmart(t, a, b)
	tag, err := dialEcho(t, s, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if s.Now() != tag {
		t.Fatalf("Now %q after dialing %q", s.Now(), tag)
	}
	waitFor(t, func() bool {
		for _, r := range s.refreshRanking().ranking {
			if r.Name == tag && r.Success == 1 {
				return true
			}
		}
		return false
	})
}

func TestSmartFailoverBlocksNothingButLearns(t *testing.T) {
	a, b := &smartStub{tag: "A"}, &smartStub{tag: "B"}
	a.fail.Store(true)
	s := newTestSmart(t, a, b)
	for range 4 {
		tag, err := dialEcho(t, s, "www.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if tag != "B" {
			t.Fatalf("dialed %s", tag)
		}
	}
	// A failed node is excluded once it failed three times in a row, so the
	// later dials no longer try it first.
	before := a.dials.Load()
	for range 3 {
		if _, err := dialEcho(t, s, "www.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if a.dials.Load()-before > 1 {
		t.Fatalf("failing member still dialed first: %d dials", a.dials.Load()-before)
	}
}

// The first choice of an untrained group is the first member; funded
// exploration trains the other one, and once both have mature paired
// response evidence the clearly faster member is promoted.
func TestSmartPromotesFasterMember(t *testing.T) {
	slow, fast := &smartStub{tag: "slow", delay: 30 * time.Millisecond}, &smartStub{tag: "fast", delay: 2 * time.Millisecond}
	s := newTestSmart(t, slow, fast)
	var last []string
	for i := range 80 {
		tag, err := dialEcho(t, s, "www.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if i >= 70 {
			last = append(last, tag)
		}
		// Let the close-time judgement land before the next selection.
		time.Sleep(time.Millisecond)
	}
	fastCount := 0
	for _, tag := range last {
		if tag == "fast" {
			fastCount++
		}
	}
	stats := s.group.Stats()[0]
	if fastCount < 8 {
		t.Fatalf("faster member not promoted: last dials %v (stats %+v)", last, stats)
	}
	if stats.Reasons["performanceWinner"] == 0 || stats.Switches == 0 {
		t.Fatalf("promotion not recorded: %+v", stats)
	}
	t.Logf("reasons %v switches %d", stats.Reasons, stats.Switches)
}

func TestSmartAllMembersFail(t *testing.T) {
	a, b := &smartStub{tag: "A"}, &smartStub{tag: "B"}
	a.fail.Store(true)
	b.fail.Store(true)
	s := newTestSmart(t, a, b)
	if _, err := dialEcho(t, s, "www.example.com"); err == nil {
		t.Fatal("dial succeeded with every member failing")
	}
}

// UDP dials members one at a time and every planned member gets a try.
func TestSmartUDPTriesEveryMember(t *testing.T) {
	stubs := make([]*smartStub, 7)
	for i := range stubs {
		stubs[i] = &smartStub{tag: string(rune('A' + i))}
	}
	s := newTestSmart(t, stubs...)
	destination := M.ParseSocksaddrHostPort("8.8.8.8", 53)
	ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{Destination: destination})
	if _, err := s.ListenPacket(ctx, destination); err == nil {
		t.Fatal("UDP succeeded through failing members")
	}
	for _, stub := range stubs {
		if stub.dials.Load() != 1 {
			t.Fatalf("member %s dialed %d times", stub.tag, stub.dials.Load())
		}
	}
}

func TestSmartManualPin(t *testing.T) {
	a, b := &smartStub{tag: "A"}, &smartStub{tag: "B"}
	s := newTestSmart(t, a, b)
	if !s.SelectOutbound("B") || s.PinnedTag() != "B" || s.Now() != "B" {
		t.Fatalf("pin: %q now %q", s.PinnedTag(), s.Now())
	}
	for range 3 {
		if tag, err := dialEcho(t, s, "www.example.com"); err != nil || tag != "B" {
			t.Fatalf("pinned dial %q %v", tag, err)
		}
	}
	if s.SelectOutbound("missing") {
		t.Fatal("pinned a non-member")
	}
	result := s.ClearSelection()
	if result.PreviousPin != "B" || s.PinnedTag() != "" {
		t.Fatalf("clear selection %+v", result)
	}
}

func TestSmartVerdicts(t *testing.T) {
	s := newTestSmart(t, &smartStub{tag: "A"})
	meta := &smartDialMeta{destPort: 443, host: "example.com"}
	feedback := func(tx, rx int64, age time.Duration) *smartFeedback {
		f := &smartFeedback{s: s, meta: meta, start: time.Now().Add(-age)}
		f.tx.Store(tx)
		f.rx.Store(rx)
		return f
	}
	cases := []struct {
		name    string
		f       *smartFeedback
		outcome smart.Outcome
		stalled bool
	}{
		{"success", feedback(100, 100, time.Second), smart.OutcomeSuccess, false},
		{"idle", feedback(0, 0, time.Second), smart.OutcomeCancelled, false},
		{"client gave up", feedback(100, 0, time.Second), smart.OutcomeCancelled, false},
		{"stalled", feedback(100, 0, 5*time.Second), smart.OutcomeFailure, true},
	}
	for _, c := range cases {
		v := c.f.verdict(time.Since(c.f.start))
		if v.outcome != c.outcome || v.stalled != c.stalled {
			t.Errorf("%s: %+v", c.name, v)
		}
	}
	upstream := feedback(100, 100, time.Second)
	err := errors.New("reset")
	upstream.readErr.Store(&err)
	if v := upstream.verdict(time.Second); v.outcome != smart.OutcomeFailure || v.scope != smart.ScopeTarget {
		t.Fatalf("upstream error: %+v", v)
	}
	degraded := feedback(100, 100, time.Second)
	degraded.degraded.Store(true)
	if v := degraded.verdict(time.Second); v.outcome != smart.OutcomeCancelled {
		t.Fatalf("degraded close: %+v", v)
	}
}

func TestSmartDialBatches(t *testing.T) {
	type bounds struct{ begin, end int }
	var got []bounds
	for round := range smartMaxRetries {
		b, e := smartDialBatch(10, round, false)
		got = append(got, bounds{b, e})
	}
	want := []bounds{{0, 1}, {1, 2}, {2, 3}, {3, 8}, {8, 10}}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("round %d: %v, want %v", i, got[i], want[i])
		}
	}
	if b, e := smartDialBatch(2, 3, true); b != 0 || e != 0 {
		t.Fatal("pinned plan beyond its members")
	}
}

func TestSmartPersistence(t *testing.T) {
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, b := &smartStub{tag: "A"}, &smartStub{tag: "B"}
	s := newTestSmart(t, a, b)
	if s.store, err = smart.NewStore(db, s.engine); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err = dialEcho(t, s, "www.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool {
		total := int64(0)
		for _, r := range s.refreshRanking().ranking {
			total += r.Success
		}
		return total == 3
	})
	s.SelectOutbound("B")
	s.persist()

	restored := newTestSmart(t, &smartStub{tag: "A"}, &smartStub{tag: "B"})
	restored.store, _ = smart.NewStore(db, restored.engine)
	restored.restore()
	if restored.PinnedTag() != "B" {
		t.Fatalf("pin not restored: %q", restored.PinnedTag())
	}
	total := int64(0)
	for _, r := range restored.refreshRanking().ranking {
		total += r.Success
	}
	if total != 3 {
		t.Fatalf("restored %d successes", total)
	}
	if _, err = restored.FlushStore(); err != nil {
		t.Fatal(err)
	}
	if len(restored.store.Records(restored.Tag(), smartRecordPin)) != 0 {
		t.Fatal("flush kept the pin record")
	}
}

func TestSmartMADMetrics(t *testing.T) {
	steady := []uint16{100, 102, 98, 101, 99, 100}
	if anomaly, unstable, grade := madMetrics(steady); anomaly || unstable || grade != 1 {
		t.Fatalf("steady: %v %v %d", anomaly, unstable, grade)
	}
	spike := []uint16{100, 102, 98, 101, 900, 950}
	if anomaly, _, _ := madMetrics(spike); !anomaly {
		t.Fatal("two slow probes in a row not anomalous")
	}
	failing := []uint16{100, 101, smartProbeFailed, smartProbeFailed}
	if anomaly, unstable, _ := madMetrics(failing); !anomaly || !unstable {
		t.Fatal("failing probes not flagged")
	}
}

func TestSmartServiceKeys(t *testing.T) {
	s := newTestSmart(t, &smartStub{tag: "A"})
	meta := &smartDialMeta{host: "img.example.com", destPort: 443, ruleTarget: "RuleSet [geosite-netflix]"}
	s.completeMeta(meta)
	if meta.smartTarget != "RuleSet [geosite-netflix]" || meta.wildcard != "*.example.com" || meta.target != "img.example.com:443" {
		t.Fatalf("keys %+v", meta)
	}
	plain := &smartDialMeta{host: "a.b.example.co.uk", destPort: 443}
	s.completeMeta(plain)
	if plain.smartTarget != "*.b.example.co.uk" {
		t.Fatalf("wildcard %q", plain.smartTarget)
	}
}

func BenchmarkSmartPlan100(b *testing.B) {
	stubs := make([]*smartStub, 100)
	for i := range stubs {
		stubs[i] = &smartStub{tag: "node-" + string(rune('A'+i%26)) + string(rune('a'+i/26))}
	}
	t := &testing.T{}
	s := newTestSmart(t, stubs...)
	hosts := []string{"www.example.com", "api.github.com", "img.netflix.net", "cdn.jsdelivr.net"}
	metas := make([]*smartDialMeta, len(hosts))
	for i, host := range hosts {
		metas[i] = &smartDialMeta{host: host, destPort: 443}
		s.completeMeta(metas[i])
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			meta := metas[i%len(metas)]
			plan := s.plan(meta, N.NetworkTCP)
			s.group.Release(&plan.decision, plan.nodes[0])
			i++
		}
	})
}
