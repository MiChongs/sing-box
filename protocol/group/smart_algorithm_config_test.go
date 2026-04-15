package group

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// TestSmartAlgorithmConfig_Normalize: "fastest-recent" and every
// documented synonym must normalize to the canonical value. This is
// the core of the "my config says X but the API shows strict-best"
// complaint — if something in the chain is breaking the canonical
// mapping, the failure surfaces here first.
func TestSmartAlgorithmConfig_Normalize(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"fastest-recent", smartAlgoFastestRecent},
		{"FASTEST-RECENT", smartAlgoFastestRecent},
		{"fastest_recent", smartAlgoFastestRecent},
		{"fastest", smartAlgoFastestRecent},
		{"recent", smartAlgoFastestRecent},
		{" fastest-recent ", smartAlgoFastestRecent},

		{"strict-best", smartAlgoStrictBest},
		{"", smartAlgoStrictBest},
		{"auto", smartAlgoStrictBest},

		{"p2c", smartAlgoP2C},
		{"power-of-two", smartAlgoP2C},
		{"two-choices", smartAlgoP2C},

		{"sticky-session", smartAlgoStickySession},
		{"sticky", smartAlgoStickySession},

		{"round-robin", smartAlgoRoundRobin},
		{"rr", smartAlgoRoundRobin},

		{"weighted-rr", smartAlgoWeightedRR},
		{"wrr", smartAlgoWeightedRR},

		{"latency-banded", smartAlgoLatencyBanded},
		{"banded", smartAlgoLatencyBanded},

		// Typos that should NOT match — normalizer falls back to
		// strict-best and SetAlgorithm will warn the user.
		{"fastestrecent", smartAlgoStrictBest},
		{"p-2-c", smartAlgoStrictBest},
		{"garbage", smartAlgoStrictBest},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := normalizeAlgorithm(c.in); got != c.want {
				t.Errorf("normalizeAlgorithm(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestSmartOutboundOptions_JSONDecode confirms the `algorithm` key
// flows through sing-box's outbound options machinery into the
// SmartOutboundOptions struct with the expected raw value. If a
// future refactor renames the JSON tag or adds a custom
// UnmarshalJSON that drops unknown fields, this test catches it.
func TestSmartOutboundOptions_JSONDecode(t *testing.T) {
	src := []byte(`{
		"outbounds": ["a", "b"],
		"url": "https://www.gstatic.com/generate_204",
		"interval": "3m",
		"algorithm": "fastest-recent",
		"hysteresis": "3s",
		"policy_priority": "HK:1.5",
		"use_asn": true
	}`)
	var opts option.SmartOutboundOptions
	if err := json.Unmarshal(src, &opts); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if opts.Algorithm != "fastest-recent" {
		t.Errorf("Algorithm = %q, want %q (JSON tag is `algorithm`)",
			opts.Algorithm, "fastest-recent")
	}
	if got := normalizeAlgorithm(opts.Algorithm); got != smartAlgoFastestRecent {
		t.Errorf("post-normalize = %q, want %q", got, smartAlgoFastestRecent)
	}
}

// TestSetAlgorithm_ConfiguredValueTakesEffect: plumb a real
// config-style string into SetAlgorithm against a Smart instance
// and verify CurrentAlgorithm reports it back. Catches regressions
// where the atomic Store / Load pair somehow decouples from the
// config intake path (e.g. someone re-introduces a separate
// non-atomic `algorithm string` field that shadows the pointer).
func TestSetAlgorithm_ConfiguredValueTakesEffect(t *testing.T) {
	s := &Smart{}
	got := s.SetAlgorithm("fastest-recent")
	if got != smartAlgoFastestRecent {
		t.Fatalf("SetAlgorithm returned %q, want %q", got, smartAlgoFastestRecent)
	}
	if cur := s.CurrentAlgorithm(); cur != smartAlgoFastestRecent {
		t.Fatalf("CurrentAlgorithm = %q, want %q (atomic Store/Load disconnect?)",
			cur, smartAlgoFastestRecent)
	}
	// Run the whole cycle end-to-end for every documented name.
	for _, name := range []string{
		smartAlgoStrictBest, smartAlgoWeightedRandom, smartAlgoLeastLoaded,
		smartAlgoFastestRecent, smartAlgoStickySession, smartAlgoRoundRobin,
		smartAlgoWeightedRR, smartAlgoP2C, smartAlgoLatencyBanded,
	} {
		_ = s.SetAlgorithm(name)
		if cur := s.CurrentAlgorithm(); cur != name {
			t.Errorf("%q round-trip: CurrentAlgorithm = %q", name, cur)
		}
	}
}
