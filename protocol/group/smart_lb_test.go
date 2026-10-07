package group

import (
	"context"
	"math"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type lbStub struct {
	tag string
	udp bool
}

func (s *lbStub) Tag() string            { return s.tag }
func (s *lbStub) Type() string           { return "stub" }
func (s *lbStub) Dependencies() []string { return nil }
func (s *lbStub) Network() []string {
	if s.udp {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return []string{N.NetworkTCP}
}
func (s *lbStub) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	panic("lbStub dial unexpected")
}
func (s *lbStub) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("lbStub listen unexpected")
}

func newTestLoadBalance(t *testing.T, ctx context.Context, options option.SmartLoadBalanceOutboundOptions, tags ...string) *Smart {
	t.Helper()
	logger := log.NewNOPFactory().NewLogger("smart-loadbalance")
	s, err := newSmart(ctx, nil, logger, "LB", C.TypeSmartLoadBalance, options.SmartOutboundOptions)
	if err != nil {
		t.Fatal(err)
	}
	s.balance, err = newSmartBalance(s, options.Balance, options.Region)
	if err != nil {
		t.Fatal(err)
	}
	outbounds := make([]adapter.Outbound, len(tags))
	for i, tag := range tags {
		outbounds[i] = &lbStub{tag: tag, udp: true}
	}
	s.state.Store(&smartGroupState{outbounds: outbounds, tags: tags})
	s.balance.rebuild()
	return s
}

func setDelays(s *Smart, delays map[string]uint16) {
	history := urltest.NewHistoryStorage()
	for tag, delay := range delays {
		history.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now(), Delay: delay})
	}
	s.history = history
}

func regionOfFirst(t *testing.T, s *Smart, meta *smartDialMeta) (string, string) {
	t.Helper()
	candidates, source := s.balance.selectCandidates(meta, false, false)
	if len(candidates) == 0 {
		return "", source
	}
	return s.RegionOf(candidates[0].Tag()), source
}

func TestClassifyRegionByName(t *testing.T) {
	cases := map[string]string{
		"🇭🇰 香港 01":            "HK",
		"🇯🇵 日本 东京 IPLC":       "JP",
		"Japan Tokyo 02":      "JP",
		"HK01":                "HK",
		"hk-bgp-1":            "HK",
		"JP-NRT-3":            "JP",
		"沪日 IPLC 01":          "JP",
		"IEPL 深港 2":           "HK",
		"香港中转美国":              "US",
		"HK → JP":             "JP",
		"美国 洛杉矶 [HK中转]":       "US",
		"🇨🇳 台湾 01":            "TW",
		"印度尼西亚 01":            "ID",
		"🇺🇸 US LA 01":         "US",
		"CN2 GIA 洛杉矶":         "US",
		"美西 01":               "US",
		"Ｈｏｎｇ Ｋｏｎｇ":           "HK",
		"白俄罗斯":                "BY",
		"新西兰 奥克兰":             "NZ",
		"UK London":           "GB",
		"🇺🇲 美国":               "US",
		"上海-日本 IPLC":          "JP",
		"Singapore 1x":        "SG",
		"🇳🇴 Norway":           "NO",
		"剩余流量：100.5 GB":       "",
		"节点 NO.1":             "",
		"VIP 专线":              "",
		"套餐到期：2026-12-31":     "",
		"Plus Premium Node 3": "",
	}
	for name, want := range cases {
		if got := classifyRegionByName(name); got != want {
			t.Errorf("classifyRegionByName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestNormaliseRegionCode(t *testing.T) {
	cases := map[string]string{
		"hk": "HK", "香港": "HK", "Japan": "JP", "uk": "GB", "🇩🇪": "DE", "iplc": "IPLC", " sg ": "SG", "": "",
	}
	for in, want := range cases {
		if got := normaliseRegionCode(in); got != want {
			t.Errorf("normaliseRegionCode(%q) = %q, want %q", in, got, want)
		}
	}
	if regionFlag("JP") != "🇯🇵" || regionFlag("IPLC") != "" {
		t.Fatal("regionFlag")
	}
}

func TestParseExitResponse(t *testing.T) {
	trace := "fl=123\nh=www.cloudflare.com\nip=203.0.113.7\nts=1\nvisit_scheme=https\nloc=JP\ntls=TLSv1.3\n"
	if country, ip := parseExitResponse([]byte(trace)); country != "JP" || ip != "203.0.113.7" {
		t.Fatalf("trace: %q %q", country, ip)
	}
	if country, ip := parseExitResponse([]byte(`{"ip":"198.51.100.1","country":"SG"}`)); country != "SG" || ip != "198.51.100.1" {
		t.Fatalf("json: %q %q", country, ip)
	}
	if country, ip := parseExitResponse([]byte(`{"query":"198.51.100.2","countryCode":"de"}`)); country != "DE" || ip != "198.51.100.2" {
		t.Fatalf("ip-api: %q %q", country, ip)
	}
	if country, ip := parseExitResponse([]byte("192.0.2.9\n")); country != "" || ip != "192.0.2.9" {
		t.Fatalf("plain: %q %q", country, ip)
	}
	if country, _ := parseExitResponse([]byte("loc=XX\n")); country != "" {
		t.Fatalf("unknown loc must be ignored, got %q", country)
	}
}

func TestSmartBalanceOptionValidation(t *testing.T) {
	bad := []option.SmartLoadBalanceOutboundOptions{
		{Balance: option.SmartBalanceOptions{Strategy: "fastest"}},
		{Balance: option.SmartBalanceOptions{Affinity: "cookie"}},
		{Balance: option.SmartBalanceOptions{MinQuality: 1.5}},
		{Region: option.SmartRegionOptions{Mode: "nearest"}},
		{Region: option.SmartRegionOptions{Mode: "priority"}},
		{Region: option.SmartRegionOptions{Fallback: "random"}},
		{Region: option.SmartRegionOptions{Weights: map[string]float64{"HK": -1}}},
		{Region: option.SmartRegionOptions{Detect: option.SmartRegionDetectOptions{Exit: "sometimes"}}},
		{Region: option.SmartRegionOptions{Detect: option.SmartRegionDetectOptions{ExitURL: "ftp://x"}}},
		{Region: option.SmartRegionOptions{Outbounds: option.SmartRegionOutboundsOptions{Enabled: true, Tag: "static"}}},
		{Region: option.SmartRegionOptions{Rules: []option.SmartRegionRule{{Name: "no code"}}}},
	}
	for i, options := range bad {
		if _, err := newSmartBalance(&Smart{}, options.Balance, options.Region); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
	b, err := newSmartBalance(&Smart{}, option.SmartBalanceOptions{Strategy: "WRR", Affinity: "sticky-sessions"}, option.SmartRegionOptions{Mode: "geo", Fallback: "fail"})
	if err != nil {
		t.Fatal(err)
	}
	if b.currentStrategy() != balanceStrategyWeightedRoundRobin || b.currentAffinity() != balanceAffinitySourceSite ||
		b.currentMode() != regionModeDestination || b.fallback != regionFallbackNone {
		t.Fatalf("aliases not normalised: %s %s %s %s", b.currentStrategy(), b.currentAffinity(), b.currentMode(), b.fallback)
	}
}

func TestRegionSnapshotClassification(t *testing.T) {
	options := option.SmartLoadBalanceOutboundOptions{
		Region: option.SmartRegionOptions{
			Rules: []option.SmartRegionRule{
				{Region: "IPLC", Name: "专线", Match: (*badoption.Regexp)(regexp.MustCompile(`IPLC`))},
				{Region: "jp", Outbounds: []string{"mystery-7"}},
			},
		},
	}
	s := newTestLoadBalance(t, context.Background(), options,
		"🇭🇰 香港 01", "HK02", "沪日 IPLC 01", "mystery-7", "airport/🇸🇬 狮城", "plain node")
	s.providerTags = []string{"airport"}
	snap := s.balance.rebuild()
	want := map[string]string{
		"🇭🇰 香港 01":      "HK",
		"HK02":          "HK",
		"沪日 IPLC 01":    "IPLC",
		"mystery-7":     "JP",
		"airport/🇸🇬 狮城": "SG",
		"plain node":    regionUnknown,
	}
	for tag, code := range want {
		if got := snap.regionOf[tag]; got != code {
			t.Errorf("%s: region %q, want %q", tag, got, code)
		}
	}
	if snap.sourceOf["mystery-7"] != "rule" || snap.sourceOf["HK02"] != "name" || snap.sourceOf["plain node"] != "unknown" {
		t.Fatalf("sources: %v", snap.sourceOf)
	}
	if snap.codes[len(snap.codes)-1] != regionUnknown {
		t.Fatalf("OTHER must sort last: %v", snap.codes)
	}
	if name, _, _ := s.balance.regionName("IPLC"); name != "专线" {
		t.Fatalf("custom region name %q", name)
	}

	// An exit result places the unknown member (fallback mode) …
	s.balance.exitGeo.Store("plain node", exitGeoEntry{country: "US", at: time.Now().UnixNano()})
	if got := s.balance.rebuild().regionOf["plain node"]; got != "US" {
		t.Fatalf("exit fallback: %q", got)
	}
	// … and overrides the name in prefer mode.
	s.balance.exit.mode = exitDetectPrefer
	s.balance.exitGeo.Store("HK02", exitGeoEntry{country: "JP", at: time.Now().UnixNano()})
	if got := s.balance.rebuild().regionOf["HK02"]; got != "JP" {
		t.Fatalf("exit prefer: %q", got)
	}
	// Expired results are ignored.
	s.balance.exitGeo.Store("HK02", exitGeoEntry{country: "JP", at: time.Now().Add(-48 * time.Hour).UnixNano()})
	if got := s.balance.rebuild().regionOf["HK02"]; got != "HK" {
		t.Fatalf("expired exit result used: %q", got)
	}
}

func TestRegionUnknownHandling(t *testing.T) {
	exclude := option.SmartLoadBalanceOutboundOptions{Region: option.SmartRegionOptions{Unknown: "exclude"}}
	s := newTestLoadBalance(t, context.Background(), exclude, "HK01", "node-x")
	snap := s.balance.snapshot()
	if _, ok := snap.regionOf["node-x"]; ok || len(snap.excluded) != 1 {
		t.Fatalf("exclude: %v %v", snap.regionOf, snap.excluded)
	}
	assign := option.SmartLoadBalanceOutboundOptions{Region: option.SmartRegionOptions{Unknown: "香港"}}
	s = newTestLoadBalance(t, context.Background(), assign, "JP01", "node-x")
	if got := s.RegionOf("node-x"); got != "HK" {
		t.Fatalf("assign: %q", got)
	}
}

func TestRegionAutoPicksBestAndSticks(t *testing.T) {
	s := newTestLoadBalance(t, context.Background(), option.SmartLoadBalanceOutboundOptions{},
		"HK01", "HK02", "JP01", "JP02", "US01")
	setDelays(s, map[string]uint16{"HK01": 300, "HK02": 320, "JP01": 60, "JP02": 70, "US01": 200})
	meta := &smartDialMeta{smartTarget: "*.example.com", host: "www.example.com", destPort: 443}
	if region, source := regionOfFirst(t, s, meta); region != "JP" {
		t.Fatalf("auto picked %s (%s), want JP", region, source)
	}
	// HK becomes better, but not by the switch margin: the target keeps JP
	// even after the re-evaluation interval.
	setDelays(s, map[string]uint16{"HK01": 55, "HK02": 58, "JP01": 60, "JP02": 70, "US01": 200})
	memo, _ := s.balance.regionMemo.Load(meta.smartTarget)
	memo.checkedAt = 0
	s.balance.regionMemo.Store(meta.smartTarget, memo)
	if region, source := regionOfFirst(t, s, meta); region != "JP" {
		t.Fatalf("small improvement switched region to %s (%s)", region, source)
	}
	// JP goes down: the target moves.
	s.knownDead.Store("JP01", time.Now())
	s.knownDead.Store("JP02", time.Now())
	if region, _ := regionOfFirst(t, s, meta); region != "HK" {
		t.Fatalf("dead region kept: %s", region)
	}
	// A new target picks the best region directly.
	s.knownDead.Clear()
	if region, _ := regionOfFirst(t, s, &smartDialMeta{smartTarget: "*.other.org"}); region != "HK" {
		t.Fatalf("fresh target: %s", region)
	}
}

func TestRegionAutoSwitchesOnLargeImprovement(t *testing.T) {
	s := newTestLoadBalance(t, context.Background(), option.SmartLoadBalanceOutboundOptions{}, "HK01", "JP01")
	setDelays(s, map[string]uint16{"HK01": 900, "JP01": 600})
	meta := &smartDialMeta{smartTarget: "*.example.com"}
	if region, _ := regionOfFirst(t, s, meta); region != "JP" {
		t.Fatalf("initial %s", region)
	}
	s.publishRankingSnapshot([]smart.NodeRank{{Name: "HK01", Weight: 1.1}, {Name: "JP01", Weight: 0.5}})
	memo, _ := s.balance.regionMemo.Load(meta.smartTarget)
	memo.checkedAt = 0
	s.balance.regionMemo.Store(meta.smartTarget, memo)
	if region, source := regionOfFirst(t, s, meta); region != "HK" || source[:11] != "auto-switch" {
		t.Fatalf("expected auto-switch to HK, got %s (%s)", region, source)
	}
}

func TestRegionLockPriorityAndFallback(t *testing.T) {
	options := option.SmartLoadBalanceOutboundOptions{
		Region: option.SmartRegionOptions{Mode: "priority", Priority: []string{"SG", "日本"}},
	}
	s := newTestLoadBalance(t, context.Background(), options, "HK01", "JP01", "SG01", "US01")
	meta := &smartDialMeta{smartTarget: "*.example.com"}
	if region, _ := regionOfFirst(t, s, meta); region != "SG" {
		t.Fatalf("priority picked %s", region)
	}
	s.knownDead.Store("SG01", time.Now())
	s.balance.healthTCP.Store(nil)
	if region, _ := regionOfFirst(t, s, meta); region != "JP" {
		t.Fatalf("priority fallback picked %s", region)
	}
	if applied, err := s.SetRegionLock("🇺🇸"); err != nil || applied != "US" {
		t.Fatalf("lock: %q %v", applied, err)
	}
	if region, source := regionOfFirst(t, s, meta); region != "US" || source[:4] != "lock" {
		t.Fatalf("lock ignored: %s (%s)", region, source)
	}
	if _, err := s.SetRegionLock("KR"); err == nil {
		t.Fatal("locking a region without members must fail")
	}
	// A dead locked region falls back with fallback=auto …
	s.knownDead.Store("US01", time.Now())
	s.balance.healthTCP.Store(nil)
	if region, _ := regionOfFirst(t, s, meta); region == "US" || region == "" {
		t.Fatalf("dead lock not bypassed: %q", region)
	}
	// … and fails with fallback=none.
	s.balance.fallback = regionFallbackNone
	if candidates, _ := s.balance.selectCandidates(meta, false, false); len(candidates) != 0 {
		t.Fatalf("fallback none still served: %v", outboundNames(candidates))
	}
	s.balance.fallback = regionFallbackAuto
	s.knownDead.Clear()
	s.balance.healthTCP.Store(nil)
	if _, err := s.SetRegionLock(""); err != nil {
		t.Fatal(err)
	}
	if region, _ := regionOfFirst(t, s, meta); region != "SG" {
		t.Fatalf("unlock: %s", region)
	}
}

func TestRegionDestinationMode(t *testing.T) {
	options := option.SmartLoadBalanceOutboundOptions{
		Region: option.SmartRegionOptions{
			Mode: "destination",
			Destination: option.SmartRegionDestinationOptions{
				Map: map[string]badoption.Listable[string]{"KR": {"JP", "HK"}},
			},
		},
	}
	s := newTestLoadBalance(t, context.Background(), options, "HK01", "JP01", "US01", "DE01")
	setDelays(s, map[string]uint16{"HK01": 50, "JP01": 80, "US01": 150, "DE01": 250})
	cases := []struct {
		meta *smartDialMeta
		want string
	}{
		{&smartDialMeta{smartTarget: "*.example.de", host: "www.example.de"}, "DE"},
		{&smartDialMeta{smartTarget: "*.naver.kr", host: "naver.kr"}, "JP"},
		{&smartDialMeta{smartTarget: "1.2.3.4", destGeoIP: []string{"us"}}, "US"},
		{&smartDialMeta{smartTarget: "*.example.io", host: "app.example.io"}, "HK"}, // .io is generic → auto
		{&smartDialMeta{smartTarget: "*.example.fr", host: "example.fr"}, "HK"},     // no FR pool → auto
	}
	for _, c := range cases {
		if region, source := regionOfFirst(t, s, c.meta); region != c.want {
			t.Errorf("%s: %s (%s), want %s", c.meta.smartTarget, region, source, c.want)
		}
	}
	// A landing server given by name: the resolved country (cached) decides.
	s.balance.destCache.Store("landing.example.net", destinationCacheEntry{country: "US", expires: time.Now().Add(time.Minute).UnixNano()})
	landing := &smartDialMeta{smartTarget: "landing.example.net", host: "landing.example.net"}
	if region, source := regionOfFirst(t, s, landing); region != "US" {
		t.Fatalf("resolved landing server: %s (%s), want US", region, source)
	}
	s.balance.destResolve = false
	if region, _ := regionOfFirst(t, s, &smartDialMeta{smartTarget: "landing.example.net", host: "landing.example.net"}); region != "HK" {
		t.Fatalf("disable_resolve still resolved: %s", region)
	}
}

func TestRegionAllowDenyAndMinNodes(t *testing.T) {
	options := option.SmartLoadBalanceOutboundOptions{
		Region: option.SmartRegionOptions{Deny: []string{"HK"}, MinNodes: 2},
	}
	s := newTestLoadBalance(t, context.Background(), options, "HK01", "HK02", "JP01", "SG01", "SG02")
	setDelays(s, map[string]uint16{"HK01": 20, "HK02": 20, "JP01": 30, "SG01": 300, "SG02": 310})
	if region, _ := regionOfFirst(t, s, &smartDialMeta{smartTarget: "a"}); region != "SG" {
		t.Fatalf("deny / min_nodes not honoured: %s", region)
	}
}

func TestRegionModeOffUsesAllMembers(t *testing.T) {
	options := option.SmartLoadBalanceOutboundOptions{
		Region:  option.SmartRegionOptions{Mode: "off"},
		Balance: option.SmartBalanceOptions{Strategy: "round-robin"},
	}
	s := newTestLoadBalance(t, context.Background(), options, "HK01", "JP01", "US01")
	seen := make(map[string]bool)
	for range 6 {
		candidates, _ := s.balance.selectCandidates(&smartDialMeta{smartTarget: "x"}, false, false)
		seen[candidates[0].Tag()] = true
	}
	if len(seen) != 3 {
		t.Fatalf("global round-robin covered %v", seen)
	}
}

func TestRegionViewRequest(t *testing.T) {
	s := newTestLoadBalance(t, context.Background(), option.SmartLoadBalanceOutboundOptions{}, "HK01", "JP01", "JP02")
	setDelays(s, map[string]uint16{"HK01": 20, "JP01": 200, "JP02": 210})
	meta := &smartDialMeta{smartTarget: "x", balance: &balanceRequest{group: "LB", region: "JP"}}
	candidates, _ := s.balance.selectCandidates(meta, false, false)
	for _, ob := range candidates {
		if s.RegionOf(ob.Tag()) != "JP" {
			t.Fatalf("region view leaked %s", ob.Tag())
		}
	}
	meta.balance.pin = "JP02"
	if candidates, source := s.balance.selectCandidates(meta, false, false); len(candidates) != 1 || candidates[0].Tag() != "JP02" || source != "region-pin" {
		t.Fatalf("region pin: %v %s", outboundNames(candidates), source)
	}
	// Without fallback a dead region fails; with fallback it moves on.
	s.knownDead.Store("JP01", time.Now())
	s.knownDead.Store("JP02", time.Now())
	meta.balance.pin = ""
	if candidates, _ := s.balance.selectCandidates(meta, false, false); len(candidates) != 0 {
		t.Fatalf("dead region view served %v", outboundNames(candidates))
	}
	meta.balance.fallback = true
	if candidates, _ := s.balance.selectCandidates(meta, false, false); len(candidates) == 0 || candidates[0].Tag() != "HK01" {
		t.Fatalf("fallback view: %v", outboundNames(candidates))
	}
}

func TestBalanceSmartStrategySpreadsByQuality(t *testing.T) {
	options := option.SmartLoadBalanceOutboundOptions{Region: option.SmartRegionOptions{Mode: "off"}}
	s := newTestLoadBalance(t, context.Background(), options, "A", "B", "C")
	s.publishRankingSnapshot([]smart.NodeRank{{Name: "A", Weight: 1.0}, {Name: "B", Weight: 1.0}, {Name: "C", Weight: 0.5}})
	// Simulate long-lived connections: every pick stays open.
	counts := make(map[string]int)
	for range 400 {
		candidates, _ := s.balance.selectCandidates(&smartDialMeta{smartTarget: "t"}, false, false)
		tag := candidates[0].Tag()
		counts[tag]++
		s.nodeLoad.inc(tag)
	}
	// Equilibrium of (load+1)/q: A ≈ B ≈ 2 × C.
	if math.Abs(float64(counts["A"]-counts["B"])) > 20 || counts["C"] < 60 || counts["C"] > 100 {
		t.Fatalf("smart spread %v, want A≈B≈160, C≈80", counts)
	}
}

func TestBalanceMinQualityAndCaps(t *testing.T) {
	options := option.SmartLoadBalanceOutboundOptions{
		Region:  option.SmartRegionOptions{Mode: "off"},
		Balance: option.SmartBalanceOptions{MinQuality: 0.6, MaxNodes: 2, MaxConnectionsPerNode: 3},
	}
	s := newTestLoadBalance(t, context.Background(), options, "A", "B", "C", "D")
	s.publishRankingSnapshot([]smart.NodeRank{{Name: "A", Weight: 1.0}, {Name: "B", Weight: 0.9}, {Name: "C", Weight: 0.8}, {Name: "D", Weight: 0.3}})
	sc := s.balance.newScorer(&smartDialMeta{smartTarget: "t"}, false)
	pool := s.balance.buildPool("", s.balance.snapshot(), &smartDialMeta{smartTarget: "t"}, false, nil, sc)
	if len(pool) != 2 || pool[0].tag != "A" || pool[1].tag != "B" {
		t.Fatalf("pool %v", pool)
	}
	for range 3 {
		s.nodeLoad.inc("A")
	}
	pool = s.balance.buildPool("", s.balance.snapshot(), &smartDialMeta{smartTarget: "t"}, false, nil, sc)
	if len(pool) != 1 || pool[0].tag != "B" {
		t.Fatalf("connection cap not applied: %v", pool)
	}
}

func TestBalanceLeastConnectionsAndRoundRobin(t *testing.T) {
	pool := []poolEntry{{tag: "a", q: 1, load: 5}, {tag: "b", q: 0.5, load: 1}, {tag: "c", q: 1, load: 3}}
	if got := pickLeastConnections(pool); pool[got].tag != "b" {
		t.Fatalf("least-connections picked %s", pool[got].tag)
	}
	b, _ := newSmartBalance(&Smart{}, option.SmartBalanceOptions{}, option.SmartRegionOptions{})
	seen := make([]string, 0, 6)
	for range 6 {
		seen = append(seen, pool[b.pickRoundRobin(pool, "R")].tag)
	}
	if seen[0] != "a" || seen[1] != "b" || seen[2] != "c" || seen[3] != "a" {
		t.Fatalf("round-robin order %v", seen)
	}
	weighted := []poolEntry{{tag: "x", q: 3}, {tag: "y", q: 1}}
	counts := map[string]int{}
	for range 40 {
		counts[weighted[b.pickWeightedRoundRobin(weighted, "W")].tag]++
	}
	if counts["x"] != 30 || counts["y"] != 10 {
		t.Fatalf("weighted round-robin %v", counts)
	}
}

func TestBalanceRendezvousStability(t *testing.T) {
	pool := []poolEntry{{tag: "a", q: 1}, {tag: "b", q: 1}, {tag: "c", q: 1}, {tag: "d", q: 1}}
	assign := make(map[string]string)
	for i := range 400 {
		key := "site-" + string(rune('A'+i%26)) + string(rune('a'+i/26))
		assign[key] = pool[pickRendezvous(pool, key)].tag
	}
	shrunk := []poolEntry{pool[0], pool[1], pool[3]}
	moved := 0
	for key, tag := range assign {
		now := shrunk[pickRendezvous(shrunk, key)].tag
		if tag != "c" && now != tag {
			moved++
		}
	}
	if moved != 0 {
		t.Fatalf("%d keys not on the removed node moved", moved)
	}
}

func TestBalanceAffinity(t *testing.T) {
	options := option.SmartLoadBalanceOutboundOptions{
		Region:  option.SmartRegionOptions{Mode: "off"},
		Balance: option.SmartBalanceOptions{Affinity: "site"},
	}
	s := newTestLoadBalance(t, context.Background(), options, "A", "B", "C", "D")
	meta := &smartDialMeta{smartTarget: "*.example.com", host: "img.example.com"}
	candidates, _ := s.balance.selectCandidates(meta, false, false)
	first := candidates[0].Tag()
	s.balance.onDialSuccess(meta, first)
	for range 20 {
		s.nodeLoad.inc(first)
		other := &smartDialMeta{smartTarget: "*.example.com", host: "api.example.com"}
		candidates, source := s.balance.selectCandidates(other, false, false)
		if candidates[0].Tag() != first {
			t.Fatalf("site affinity broken: %s (%s), want %s", candidates[0].Tag(), source, first)
		}
	}
	if siteOf(&smartDialMeta{host: "a.b.example.co.uk"}) != "example.co.uk" {
		t.Fatal("siteOf")
	}
	if key := s.balance.affinityKey(&smartDialMeta{host: "x.com", source: netip.MustParseAddr("10.0.0.2")}, "HK"); key != "HK|x.com" {
		t.Fatalf("site key %q", key)
	}
	s.balance.setAffinity(balanceAffinitySourceSite)
	if key := s.balance.affinityKey(&smartDialMeta{host: "x.com", source: netip.MustParseAddr("10.0.0.2")}, "HK"); key != "HK|10.0.0.2|x.com" {
		t.Fatalf("source-site key %q", key)
	}
}

func TestBalanceCandidatesIncludeFallbackRegions(t *testing.T) {
	s := newTestLoadBalance(t, context.Background(), option.SmartLoadBalanceOutboundOptions{}, "HK01", "HK02", "JP01", "US01")
	setDelays(s, map[string]uint16{"HK01": 30, "HK02": 40, "JP01": 80, "US01": 200})
	candidates, _ := s.balance.selectCandidates(&smartDialMeta{smartTarget: "t"}, false, false)
	regions := make([]string, len(candidates))
	for i, ob := range candidates {
		regions[i] = s.RegionOf(ob.Tag())
	}
	if len(regions) != 4 || regions[0] != "HK" || regions[1] != "HK" || regions[2] != "JP" || regions[3] != "US" {
		t.Fatalf("candidate regions %v", regions)
	}
	s.balance.fallback = regionFallbackNone
	candidates, _ = s.balance.selectCandidates(&smartDialMeta{smartTarget: "t2"}, false, false)
	if len(candidates) != 2 {
		t.Fatalf("fallback none appended other regions: %v", outboundNames(candidates))
	}
}

// The candidate list must keep the fallback tail within what dialWithRetry
// dials before re-selecting (1 + 3 × 3 = 10), even with a large primary pool.
func TestBalanceCandidatesFallbackReachable(t *testing.T) {
	tags := []string{"JP01", "US01", "US02", "SG01"}
	for i := range 15 {
		tags = append(tags, "HK"+strconv.Itoa(10+i))
	}
	s := newTestLoadBalance(t, context.Background(), option.SmartLoadBalanceOutboundOptions{}, tags...)
	delays := map[string]uint16{"JP01": 120, "US01": 200, "US02": 210, "SG01": 300}
	for _, tag := range tags[4:] {
		delays[tag] = 40
	}
	setDelays(s, delays)
	candidates, _ := s.balance.selectCandidates(&smartDialMeta{smartTarget: "t"}, false, false)
	if len(candidates) != 1+(smartMaxRetries-1)*smartParallelDials {
		t.Fatalf("candidate list of %d does not match the dial reach", len(candidates))
	}
	var tail []string
	for _, ob := range candidates[7:] {
		tail = append(tail, s.RegionOf(ob.Tag()))
	}
	if len(tail) != 3 || tail[0] == "HK" || tail[1] == "HK" || tail[2] == "HK" {
		t.Fatalf("fallback tail %v", tail)
	}
}

func TestBalanceUDPHonoursSupport(t *testing.T) {
	s := newTestLoadBalance(t, context.Background(), option.SmartLoadBalanceOutboundOptions{}, "HK01", "HK02")
	s.state.Load().outbounds[0].(*lbStub).udp = false
	s.balance.healthUDP.Store(nil)
	for range 10 {
		candidates, _ := s.balance.selectCandidates(&smartDialMeta{smartTarget: "u", isUDP: true}, true, false)
		if len(candidates) != 1 || candidates[0].Tag() != "HK02" {
			t.Fatalf("UDP candidates %v", outboundNames(candidates))
		}
	}
}

func TestCountryFromTLD(t *testing.T) {
	cases := map[string]string{"www.yahoo.co.jp": "JP", "bbc.co.uk": "GB", "example.io": "", "example.com": "", "1.2.3.4": "", "naver.kr.": "KR"}
	for host, want := range cases {
		if got := countryFromTLD(host); got != want {
			t.Errorf("countryFromTLD(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestSubgroupsRegisterAndSelect(t *testing.T) {
	registry := outbound.NewRegistry()
	manager := outbound.NewManager(registry, nil, "")
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
	options := option.SmartLoadBalanceOutboundOptions{
		Region: option.SmartRegionOptions{
			Outbounds: option.SmartRegionOutboundsOptions{Enabled: true, Regions: []string{"hk", "日本"}, Tag: "{flag} {name}"},
		},
	}
	logger := log.NewNOPFactory().NewLogger("smart-loadbalance")
	s, err := newSmart(ctx, nil, logger, "LB", C.TypeSmartLoadBalance, options.SmartOutboundOptions)
	if err != nil {
		t.Fatal(err)
	}
	if s.balance, err = newSmartBalance(s, options.Balance, options.Region); err != nil {
		t.Fatal(err)
	}
	if err = s.balance.createDeclaredSubgroups(ctx, nil, logger); err != nil {
		t.Fatal(err)
	}
	hk, loaded := manager.Outbound("🇭🇰 香港")
	if !loaded {
		t.Fatal("HK region outbound not registered")
	}
	if manager.Default() != nil {
		t.Fatal("a generated region outbound became the default outbound")
	}
	if deps := hk.Dependencies(); len(deps) != 1 || deps[0] != "LB" {
		t.Fatalf("dependencies %v", deps)
	}
	outbounds := []adapter.Outbound{&lbStub{tag: "HK01"}, &lbStub{tag: "JP01"}, &lbStub{tag: "JP02"}}
	s.state.Store(&smartGroupState{outbounds: outbounds, tags: []string{"HK01", "JP01", "JP02"}})
	s.balance.rebuild()

	if all := s.All(); len(all) != 2 || all[0] != "🇯🇵 日本" || all[1] != "🇭🇰 香港" {
		t.Fatalf("All() = %v", all)
	}
	if members := hk.(*SmartRegion).All(); len(members) != 1 || members[0] != "HK01" {
		t.Fatalf("region members %v", members)
	}
	if !s.SelectOutbound("🇭🇰 香港") || s.RegionLock() != "HK" || s.Now() != "🇭🇰 香港" || s.FixedSelection() != "🇭🇰 香港" {
		t.Fatalf("selecting a region outbound: lock=%q now=%q fixed=%q", s.RegionLock(), s.Now(), s.FixedSelection())
	}
	if !s.SelectOutbound("JP01") || s.PinnedTag() != "JP01" || s.RegionLock() != "HK" {
		t.Fatalf("node pin: pin=%q lock=%q", s.PinnedTag(), s.RegionLock())
	}
	if !s.SelectOutbound("") || s.PinnedTag() != "" || s.RegionLock() != "" {
		t.Fatalf("clear: pin=%q lock=%q", s.PinnedTag(), s.RegionLock())
	}
	if !hk.(*SmartRegion).SelectOutbound("HK01") || hk.(*SmartRegion).SelectOutbound("JP01") {
		t.Fatal("region outbound pin must accept members only")
	}
	// Members listing switches back to nodes on request.
	s.balance.sub.members = subgroupMembersNodes
	if all := s.All(); len(all) != 3 {
		t.Fatalf("nodes listing %v", all)
	}
	// A duplicate tag is an error at construction time.
	if err = s.balance.createDeclaredSubgroups(ctx, nil, logger); err == nil {
		t.Fatal("duplicate region outbound tag accepted")
	}
}

func TestAttachRequestScopesToGroup(t *testing.T) {
	s := newTestLoadBalance(t, context.Background(), option.SmartLoadBalanceOutboundOptions{}, "HK01")
	meta := &smartDialMeta{smartTarget: "t"}
	ctx := contextWithBalanceRequest(context.Background(), &balanceRequest{group: "other", region: "JP"})
	if got := s.balance.attachRequest(ctx, meta); got.balance != nil {
		t.Fatal("request for another group attached")
	}
	ctx = contextWithBalanceRequest(context.Background(), &balanceRequest{group: "LB", region: "HK"})
	got := s.balance.attachRequest(ctx, meta)
	if got.balance == nil || got == meta || meta.balance != nil {
		t.Fatal("request must attach to a copy of meta")
	}
}

func TestDialIsChainedHop(t *testing.T) {
	website := &smartDialMeta{
		host:        "www.example.com",
		smartTarget: normaliseDialTarget("www.example.com", ""),
		resolvedIPs: []netip.Addr{netip.MustParseAddr("93.184.216.34")},
	}
	cases := []struct {
		destination M.Socksaddr
		hop         bool
	}{
		{M.ParseSocksaddrHostPort("www.example.com", 443), false},
		{M.ParseSocksaddrHostPort("cdn.example.com", 443), false},
		{M.ParseSocksaddrHostPort("93.184.216.34", 443), false},
		{M.ParseSocksaddrHostPort("::ffff:93.184.216.34", 443), false},
		{M.ParseSocksaddrHostPort("landing.example.net", 443), true},
		{M.ParseSocksaddrHostPort("203.0.113.9", 8443), true},
	}
	for _, c := range cases {
		if got := dialIsChainedHop(website, c.destination); got != c.hop {
			t.Errorf("%s: hop=%v, want %v", c.destination, got, c.hop)
		}
	}
	if dialIsChainedHop(&smartDialMeta{}, M.ParseSocksaddrHostPort("203.0.113.9", 443)) {
		t.Fatal("meta without a target is never a hop")
	}
}

func TestRegionStatePersistence(t *testing.T) {
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := smart.GetOrInitStore(db)
	s := newTestLoadBalance(t, context.Background(), option.SmartLoadBalanceOutboundOptions{}, "HK01", "JP01")
	s.store = store
	if _, err = s.SetRegionLock("JP"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.SetBalance("least-connections", "site"); err != nil {
		t.Fatal(err)
	}
	s.balance.persistExitGeo("JP01", "JP", "203.0.113.1", time.Now())
	if err = store.StoreFlushNow(); err != nil {
		t.Fatal(err)
	}

	restored := newTestLoadBalance(t, context.Background(), option.SmartLoadBalanceOutboundOptions{}, "HK01", "JP01")
	restored.store = store
	restored.balance.hydrate()
	if restored.RegionLock() != "JP" || restored.balance.currentStrategy() != balanceStrategyLeastConnections || restored.balance.currentAffinity() != balanceAffinitySite {
		t.Fatalf("restored lock=%q strategy=%q affinity=%q", restored.RegionLock(), restored.balance.currentStrategy(), restored.balance.currentAffinity())
	}
	if country, ok := restored.balance.freshExit("JP01"); !ok || country != "JP" {
		t.Fatalf("exit result not restored: %q %v", country, ok)
	}
	// Clearing every override deletes the record.
	if _, err = restored.SetRegionLock(""); err != nil {
		t.Fatal(err)
	}
	if _, _, err = restored.SetBalance("default", "default"); err != nil {
		t.Fatal(err)
	}
	if err = store.StoreFlushNow(); err != nil {
		t.Fatal(err)
	}
	rows, _ := store.GetSubBytesByPath(smart.FormatDBKey(smart.KeyTypeRegionState, smartConfigName, "LB"))
	if len(rows) != 0 {
		t.Fatalf("region state not deleted: %v", rows)
	}

	// A flush clears the stored and the in-memory state alike.
	if _, err = restored.SetRegionLock("HK"); err != nil {
		t.Fatal(err)
	}
	stats, err := restored.FlushStore()
	if err != nil {
		t.Fatal(err)
	}
	// The new lock may still sit in the write queue.
	if stats.ExitGeo != 1 || stats.RegionState+stats.Queue < 1 {
		t.Fatalf("flush stats %+v", stats)
	}
	if rows, _ := store.GetSubBytesByPath(smart.FormatDBKey(smart.KeyTypeRegionState, smartConfigName, "LB")); len(rows) != 0 {
		t.Fatalf("region state survived the flush: %v", rows)
	}
	if restored.RegionLock() != "" {
		t.Fatal("flush kept the region lock")
	}
	if _, ok := restored.balance.freshExit("JP01"); ok {
		t.Fatal("flush kept exit results")
	}
}
