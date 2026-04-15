package smart

import (
	"math"
	"testing"
)

// TestGetTimeDecay_Exponential verifies the post-refactor exponential
// curve at key reference points. Half-life default is 168 h (7 d), so
// decay(168 h) must be exactly 0.5 modulo float rounding.
func TestGetTimeDecay_Exponential(t *testing.T) {
	// Force-default the half-life in case a previous test mutated env.
	t.Setenv("SMART_LEGACY", "")
	t.Setenv("SMART_DECAY_HALF_LIFE_HOURS", "")
	RefreshFlags()

	const minDecay = 0.05
	now := int64(7 * 24 * 3600) // 7 d since epoch

	cases := []struct {
		name     string
		agedAgo  int64
		want     float64
		tolerate float64
	}{
		{"fresh", 0, 1.0, 1e-9},
		{"1d", 24 * 3600, math.Exp2(-24.0 / 168.0), 1e-9},
		{"7d", 7 * 24 * 3600, 0.5, 1e-9},
		{"14d", 14 * 24 * 3600, 0.25, 1e-9},
		{"floor", 365 * 24 * 3600, minDecay, 1e-9},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GetTimeDecay(now-c.agedAgo, now, minDecay)
			if math.Abs(got-c.want) > c.tolerate {
				t.Errorf("decay(%ds ago) = %.6f, want %.6f±%g", c.agedAgo, got, c.want, c.tolerate)
			}
		})
	}
}

// TestGetTimeDecay_LegacyFallback flips SMART_LEGACY and confirms the
// piecewise curve is exercised — the 50 %-at-7 d midpoint is a cheap
// cross-check that both branches agree at the calibration point.
func TestGetTimeDecay_LegacyFallback(t *testing.T) {
	t.Setenv("SMART_LEGACY", "1")
	RefreshFlags()
	t.Cleanup(func() {
		t.Setenv("SMART_LEGACY", "")
		RefreshFlags()
	})

	now := int64(30 * 24 * 3600)
	// hours=168 (7d). Legacy curve: 0.5 - (168-168)/552*0.2 = 0.5.
	got := GetTimeDecay(now-7*24*3600, now, 0.05)
	if math.Abs(got-0.5) > 1e-9 {
		t.Fatalf("legacy decay at 7d = %.6f, want 0.5", got)
	}
	// Well past 30 d: legacy clamps to 0.1 (above the 0.05 floor).
	got = GetTimeDecay(now-60*24*3600, now, 0.05)
	if math.Abs(got-0.1) > 1e-9 {
		t.Fatalf("legacy decay at 60d = %.6f, want 0.1", got)
	}
}

// TestGetTimeDecay_HalfLifeOverride validates the env-var override and
// its range guards — out-of-range values must fall back silently.
func TestGetTimeDecay_HalfLifeOverride(t *testing.T) {
	t.Setenv("SMART_LEGACY", "")
	t.Setenv("SMART_DECAY_HALF_LIFE_HOURS", "24")
	RefreshFlags()
	t.Cleanup(func() {
		t.Setenv("SMART_DECAY_HALF_LIFE_HOURS", "")
		RefreshFlags()
	})

	now := int64(48 * 3600)
	got := GetTimeDecay(now-24*3600, now, 0.0)
	if math.Abs(got-0.5) > 1e-9 {
		t.Fatalf("custom halfLife=24h, decay at 24h = %.6f, want 0.5", got)
	}

	// Out-of-range override must silently revert to default 168.
	t.Setenv("SMART_DECAY_HALF_LIFE_HOURS", "-5")
	RefreshFlags()
	got = GetTimeDecay(now-168*3600, now, 0.0)
	if math.Abs(got-0.5) > 1e-9 {
		t.Fatalf("invalid halfLife env should fall back to 168h; decay(168h)=%.6f", got)
	}
}
