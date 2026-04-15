package group

import (
	"testing"

	"github.com/puzpuzpuz/xsync/v3"
)

// TestParsePriorityRule_PrefixGrammar covers every supported prefix
// combination — the explicit grammar replaces the previous "auto-detect
// regex" foot-gun, so this matrix freezes the canonical interpretation.
func TestParsePriorityRule_PrefixGrammar(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    bool
		wantPat string
		wantKnd priorityMatchKind
		wantNeg bool
		wantFac float64
	}{
		{"substring_default", "HK:1.5", true, "HK", priorityMatchSubstring, false, 1.5},
		{"exact_prefix", "=US-1:1.5", true, "US-1", priorityMatchExact, false, 1.5},
		{"regex_prefix", "~^HK\\d+$:2", true, "^HK\\d+$", priorityMatchRegex, false, 2},
		{"glob_star", "HK*:1.2", true, "HK*", priorityMatchGlob, false, 1.2},
		{"glob_question", "?P:0.5", true, "?P", priorityMatchGlob, false, 0.5},
		{"negate_substring", "!CN:0.5", true, "CN", priorityMatchSubstring, true, 0.5},
		{"negate_exact", "!=premium:0.8", true, "premium", priorityMatchExact, true, 0.8},
		{"negate_regex", "!~^test:0.5", true, "^test", priorityMatchRegex, true, 0.5},
		{"factor_one_dropped", "HK:1.0", false, "", 0, false, 0},
		{"factor_zero_invalid", "HK:0", false, "", 0, false, 0},
		{"factor_negative_invalid", "HK:-1", false, "", 0, false, 0},
		{"empty_pattern", ":1.5", false, "", 0, false, 0},
		{"missing_factor", "HK:", false, "", 0, false, 0},
		{"no_separator", "HK1.5", false, "", 0, false, 0},
		{"bad_regex", "~[unclosed:1.5", false, "", 0, false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parsePriorityRule(c.in)
			if ok != c.want {
				t.Fatalf("parse ok = %v, want %v (rule=%q)", ok, c.want, c.in)
			}
			if !ok {
				return
			}
			if got.pattern != c.wantPat {
				t.Errorf("pattern = %q, want %q", got.pattern, c.wantPat)
			}
			if got.kind != c.wantKnd {
				t.Errorf("kind = %d, want %d", got.kind, c.wantKnd)
			}
			if got.negate != c.wantNeg {
				t.Errorf("negate = %v, want %v", got.negate, c.wantNeg)
			}
			if got.factor != c.wantFac {
				t.Errorf("factor = %v, want %v", got.factor, c.wantFac)
			}
		})
	}
}

// TestPriorityRule_Matches walks each match kind through hit / miss /
// negated-hit / negated-miss to lock the boolean truth table.
func TestPriorityRule_Matches(t *testing.T) {
	mk := func(s string) priorityRule {
		r, ok := parsePriorityRule(s)
		if !ok {
			t.Fatalf("setup: parse failed for %q", s)
		}
		return r
	}
	cases := []struct {
		rule string
		tag  string
		want bool
	}{
		// substring
		{"HK:1.5", "HK-IPLC-1", true},
		{"HK:1.5", "JP-AWS-1", false},
		// exact
		{"=US-1:1.5", "US-1", true},
		{"=US-1:1.5", "US-12", false},
		// regex
		{"~^HK\\d+$:1.5", "HK1", true},
		{"~^HK\\d+$:1.5", "HKabc", false},
		// glob
		{"HK*:1.5", "HKjp", true},
		{"HK*:1.5", "JP-HK", false}, // anchored
		// negate (substring)
		{"!CN:0.5", "JP-1", true},
		{"!CN:0.5", "CN-1", false},
		// negate exact
		{"!=premium:0.5", "regular", true},
		{"!=premium:0.5", "premium", false},
	}
	for _, c := range cases {
		t.Run(c.rule+"_vs_"+c.tag, func(t *testing.T) {
			r := mk(c.rule)
			if got := r.matches(c.tag); got != c.want {
				t.Errorf("matches(%q) = %v, want %v", c.tag, got, c.want)
			}
		})
	}
}

// TestGetPriorityFactor_Multiplicative proves multiple matching rules
// compose by multiplication — the contract that lets users write
// orthogonal facets like "region:1.5;tier:1.2".
func TestGetPriorityFactor_Multiplicative(t *testing.T) {
	s := &Smart{}
	s.parsePolicyPriority("HK:1.5;VIP:1.2;CN:0.5")

	// HK + VIP both match → 1.5 × 1.2 = 1.8
	if got := s.getPriorityFactor("HK-VIP-01"); !floatEq(got, 1.8) {
		t.Errorf("HK-VIP-01 factor = %v, want 1.8", got)
	}
	// Only HK
	if got := s.getPriorityFactor("HK-IPLC"); !floatEq(got, 1.5) {
		t.Errorf("HK-IPLC factor = %v, want 1.5", got)
	}
	// No match → identity
	if got := s.getPriorityFactor("US-1"); !floatEq(got, 1.0) {
		t.Errorf("US-1 factor = %v, want 1.0", got)
	}
	// Negative-bias rule
	if got := s.getPriorityFactor("CN-1"); !floatEq(got, 0.5) {
		t.Errorf("CN-1 factor = %v, want 0.5", got)
	}
}

// TestGetPriorityFactor_Cache verifies the per-tag cache is wired and
// the returned value matches the freshly-computed one.
func TestGetPriorityFactor_Cache(t *testing.T) {
	s := &Smart{}
	s.parsePolicyPriority("HK:1.5;VIP:1.2")
	first := s.getPriorityFactor("HK-VIP")
	if s.priorityFactorCache == nil {
		t.Fatal("cache should be allocated when rules parse")
	}
	cached, ok := s.priorityFactorCache.Load("HK-VIP")
	if !ok {
		t.Fatal("cache miss after first lookup")
	}
	if cached != first {
		t.Fatalf("cache value %v != first lookup %v", cached, first)
	}
}

// TestReorderByPriority pushes two candidates with distinct priority
// factors through the all-tier reorder pass; the higher-priority
// candidate must surface to position 0 regardless of input order.
func TestReorderByPriority(t *testing.T) {
	s := &Smart{}
	s.parsePolicyPriority("HK:2.0;US:0.5")
	in := makeStubs("US-1", "HK-1", "JP-1", "HK-2")
	got := s.reorderByPriority(in, nil)
	if got[0].Tag() != "HK-1" && got[0].Tag() != "HK-2" {
		t.Fatalf("position 0 = %q, want HK-*", got[0].Tag())
	}
	// US (factor 0.5) must end up after JP (factor 1.0).
	var jpIdx, usIdx int
	for i, ob := range got {
		switch ob.Tag() {
		case "JP-1":
			jpIdx = i
		case "US-1":
			usIdx = i
		}
	}
	if usIdx <= jpIdx {
		t.Fatalf("US-1 (factor 0.5) at idx %d should come AFTER JP-1 (factor 1.0) at idx %d", usIdx, jpIdx)
	}
}

// TestReorderByPriority_AllIdentityNoOp confirms the fast path: when
// no candidate has a non-1.0 factor, the original ordering is
// returned as-is (no allocation, no sort).
func TestReorderByPriority_AllIdentityNoOp(t *testing.T) {
	s := &Smart{}
	s.parsePolicyPriority("HK:1.5") // applies to nobody in input
	in := makeStubs("a", "b", "c")
	got := s.reorderByPriority(in, nil)
	for i, want := range []string{"a", "b", "c"} {
		if got[i].Tag() != want {
			t.Fatalf("idx %d reordered: got %q, want %q", i, got[i].Tag(), want)
		}
	}
}

// TestPolicyPriorityRules_Snapshot confirms the JSON-friendly view
// reflects the parsed rules — the data piped to /smart/groups must
// stay accurate.
func TestPolicyPriorityRules_Snapshot(t *testing.T) {
	s := &Smart{}
	s.parsePolicyPriority("HK:1.5;!=premium:0.5;~^US\\d+$:0.8;HK*:1.1")
	rules := s.PolicyPriorityRules()
	if len(rules) != 4 {
		t.Fatalf("rule count = %d, want 4", len(rules))
	}
	if rules[0]["kind"] != "substring" || rules[0]["pattern"] != "HK" {
		t.Errorf("rule 0 unexpected: %+v", rules[0])
	}
	if rules[1]["kind"] != "exact" || rules[1]["negate"] != true {
		t.Errorf("rule 1 unexpected: %+v", rules[1])
	}
	if rules[2]["kind"] != "regex" {
		t.Errorf("rule 2 unexpected: %+v", rules[2])
	}
	if rules[3]["kind"] != "glob" {
		t.Errorf("rule 3 unexpected: %+v", rules[3])
	}
}

// TestParsePolicyPriority_DropsIdentityFactor: a rule with factor 1.0
// is identity and would only burn CPU per dial; parser MUST drop it
// so the rule slice stays minimal.
func TestParsePolicyPriority_DropsIdentityFactor(t *testing.T) {
	s := &Smart{}
	s.parsePolicyPriority("HK:1.0;US:0.5")
	if got := len(s.policyPriority); got != 1 {
		t.Fatalf("rule count = %d, want 1 (identity rule should be dropped)", got)
	}
	if s.policyPriority[0].pattern != "US" {
		t.Fatalf("kept rule pattern = %q, want US", s.policyPriority[0].pattern)
	}
}

// TestInvalidatePriorityCache: hot-reload of rules should invalidate
// cached factors so the next dial picks up the new semantics.
func TestInvalidatePriorityCache(t *testing.T) {
	s := &Smart{}
	s.parsePolicyPriority("HK:2.0")
	_ = s.getPriorityFactor("HK-1")
	if s.priorityFactorCache == nil {
		t.Fatal("cache should be alloc'd")
	}
	if s.priorityFactorCache.Size() == 0 {
		t.Fatal("cache should be populated")
	}
	s.invalidatePriorityCache()
	if s.priorityFactorCache.Size() != 0 {
		t.Fatalf("cache size after invalidate = %d, want 0", s.priorityFactorCache.Size())
	}
}

// floatEq is a tolerant float comparator — exact equality is fine
// here because all our test inputs are simple decimals representable
// without rounding error.
func floatEq(a, b float64) bool {
	if a == b {
		return true
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}

// Suppress xsync import warning when the file is reduced in a future
// refactor — keeping the reference here so reviewers see why the test
// can introspect priorityFactorCache.Size().
var _ = xsync.NewMapOf[string, float64]
