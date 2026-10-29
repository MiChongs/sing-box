package smart

import (
	"math"
	"testing"
	"time"
)

func TestBetaBoundsAndMetric(t *testing.T) {
	lower, upper := betaBounds(0, 0)
	if math.Abs(lower+upper-1) > 1e-9 || lower >= 0.5 {
		t.Fatalf("prior bounds %v %v", lower, upper)
	}
	var m Metric
	now := Now()
	for _, v := range []float64{100, 100, 100, 100, 200} {
		m.Record(v, now)
	}
	v := m.Read(now)
	if !v.Mature() || math.Abs(v.Value-125) > 1e-9 {
		t.Fatalf("weighted mean %+v", v)
	}
	if v = m.Read(now.Add(performanceMaxAge)); v.Valid {
		t.Fatal("metric survived its max age")
	}
	if got := switchMargin(8); math.Abs(got-0.005) > 1e-12 {
		t.Fatalf("switch margin %v", got)
	}
	if exploreBackoff(1) != 5*time.Minute || exploreBackoff(20) != 6*time.Hour {
		t.Fatal("backoff ladder")
	}
}

func TestBudgetAccounting(t *testing.T) {
	if explorationTarget(45) != 8 || explorationTarget(3) != 3 {
		t.Fatal("cold allowance")
	}
	b := NewBudget(2)
	now := Now()
	if _, ok := b.Reserve(1, false, true, now); !ok {
		t.Fatal("cold trial refused")
	}
	if _, ok := b.Reserve(1, false, true, now); ok {
		t.Fatal("second unanswered trial on the same node")
	}
	if _, ok := b.Reserve(2, false, true, now); !ok {
		t.Fatal("second cold trial refused")
	}
	if _, ok := b.Reserve(3, false, true, now); ok {
		t.Fatal("trial beyond the allowance")
	}
	for range explorationPeriod {
		b.Earn(false, now)
	}
	if _, ok := b.Reserve(3, false, true, now); !ok {
		t.Fatal("earned trial refused")
	}
	for range 100 * explorationPeriod {
		b.Earn(false, now)
	}
	if b.State(false, now).Earned != earnedCap {
		t.Fatal("earned credit not capped")
	}
	if kind, ok := b.Reserve(9, true, true, now); !ok || kind != TrialRecovery {
		t.Fatal("recovery must stay budget neutral")
	}
}

func TestBlockLadders(t *testing.T) {
	b := NewBlocks()
	now := time.Now()
	update := func(code BlockCode, failure bool, at time.Time) bool {
		return b.Update(BlockUpdate{Group: 1, Key: "*.example.com", Node: 7, Failure: failure, Checked: true, Code: code, Host: "www.example.com", MaxFailedTimes: 3, HostLimit: 5}, at)
	}
	// Errors block after max_failed_times in the strike window.
	for i := range 2 {
		if update(BlockError, false, now.Add(time.Duration(i)*time.Second)) {
			t.Fatal("error blocked early")
		}
	}
	if !update(BlockError, false, now.Add(3*time.Second)) {
		t.Fatal("third error did not block")
	}
	codes, broken := b.Lookup(1, "*.example.com", false, 5, nil, now.Add(4*time.Second))
	if codes[7] != BlockError || broken {
		t.Fatalf("lookup %v %v", codes, broken)
	}
	// A reachable answer clears it.
	update(BlockNone, false, now.Add(5*time.Second))
	if codes, _ = b.Lookup(1, "*.example.com", false, 5, nil, now.Add(40*time.Second)); len(codes) != 0 {
		t.Fatalf("not cleared: %v", codes)
	}
	// Loss needs two strikes, then climbs its ladder.
	if update(BlockLoss, true, now.Add(time.Minute)) {
		t.Fatal("first loss strike blocked")
	}
	if !update(BlockLoss, true, now.Add(61*time.Second)) {
		t.Fatal("second loss strike did not block")
	}
	// A weaker code does not overwrite a stronger one.
	update(BlockManual, true, now.Add(2*time.Minute))
	update(BlockStalled, true, now.Add(3*time.Minute))
	if codes, _ = b.Lookup(1, "*.example.com", false, 5, nil, now.Add(4*time.Minute)); codes[7] != BlockManual {
		t.Fatalf("manual block overwritten: %v", codes)
	}
	// Extra keys merge the strongest code.
	b.Update(BlockUpdate{Group: 1, Key: "RuleSet [netflix]", Node: 8, Failure: true, Checked: true, Code: BlockLowWeight, HostLimit: 5}, now)
	codes, _ = b.Lookup(1, "*.example.com", false, 5, []string{"RuleSet [netflix]"}, now.Add(5*time.Minute))
	if codes[8] != BlockLowWeight || codes[7] != BlockManual {
		t.Fatalf("merged %v", codes)
	}
}

func TestBlockHostBroken(t *testing.T) {
	b := NewBlocks()
	now := time.Now()
	for node := range uint32(4) {
		b.Update(BlockUpdate{Group: 1, Key: "*.down.test", Node: node, Failure: true, Checked: true, Code: BlockLowWeight, HostLimit: 2}, now)
	}
	if _, broken := b.Lookup(1, "*.down.test", false, 2, nil, now); !broken {
		t.Fatal("host with every node blocked is not broken")
	}
}

func TestPolicyPriority(t *testing.T) {
	p, err := ParsePriority(`香港|HK:1.5; 日本:1.2 ;Premium\:Plus:2`)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]float64{"🇭🇰 HK 01": 1.5, "日本 东京": 1.2, "Premium:Plus 1": 2, "美国": 1}
	for name, want := range cases {
		if got := p.Factor(name); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	for _, bad := range []string{"HK", "HK:0", "HK:x"} {
		if _, err = ParsePriority(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTargetKeys(t *testing.T) {
	cases := map[string]string{
		"www.example.com":          "*.example.com",
		"a.b.example.com":          "*.b.example.com",
		"cdn-1.example.com":        "*.example.com",
		"example.com":              "*.example.com",
		"example.co.uk":            "*.example.co.uk",
		"a1b2c3d4e5f6.example.com": "*.example.com",
	}
	for host, want := range cases {
		if got := GetEffectiveTarget(host, ""); got != want {
			t.Errorf("%s: %q, want %q", host, got, want)
		}
	}
	if GetEffectiveTarget("", "1.2.3.4") != "1.2.3.4" {
		t.Fatal("IP target")
	}
	kinds := map[string]TargetKind{
		"RuleSet [geosite-netflix]":         TargetKindRuleName,
		"RuleSet [geosite-geolocation-!cn]": TargetKindBroad,
		"RuleSet [geoip-us]":                TargetKindBroad,
		"DomainSuffix [example.com]":        TargetKindService,
		"*.example.com":                     TargetKindNoRule,
		"RuleSet [category-ads-all]":        TargetKindBroad,
	}
	for target, want := range kinds {
		if got := ClassifyTargetName(target); got != want {
			t.Errorf("%s: %v, want %v", target, got, want)
		}
	}
	claims := ClaimedASNRules(map[string]map[string]int{
		"RuleSet [netflix]": {"2906": 5, "40027": 2},
		"RuleSet [disney]":  {"40027": 1, "11251": 3},
	})
	if claims["2906"] != "RuleSet [netflix]" || claims["40027"] != ASNClaimAmbiguous {
		t.Fatalf("claims %v", claims)
	}
}

func TestQualityWeightScenes(t *testing.T) {
	good := &ModelInput{Success: 10, Failure: 0, ConnectTime: 50, Latency: 80, DownloadTotal: 5, UploadTotal: 0.5, MaxdownloadRate: 3000, MaxuploadRate: 200, ConnectionDuration: 2}
	bad := &ModelInput{Success: 1, Failure: 9, ConnectTime: 1800, Latency: 1900, ConnectionFailed: true}
	g, _ := CalculateWeight(good, 1)
	b, _ := CalculateWeight(bad, 1)
	if g <= AllowedWeight || b >= AllowedWeight || g <= b {
		t.Fatalf("good %v bad %v", g, b)
	}
	if w, _ := CalculateWeight(&ModelInput{Success: 1}, 1); w != 0 {
		t.Fatal("weight below the minimum sample count")
	}
}

func TestStoreRoundTrip(t *testing.T) {
	// Exercised end to end by the group tests; here only the key escaping.
	if unescapeKey(escapeKey("RuleSet [a/b%c]")) != "RuleSet [a/b%c]" {
		t.Fatal("key escaping")
	}
}
