package smart

import (
	"math"
	"testing"
	"time"
)

// TestShortRTTAndSuccessRate_Basic wires UpdateLatencySample + AddInt64
// and verifies the EWMA signals converge toward the feed distribution.
// Exact equality isn't meaningful for EWMA (it's a moving target), so
// we assert tolerance bands.
func TestShortRTTAndSuccessRate_Basic(t *testing.T) {
	r := NewAtomicStatsRecord()

	// Feed 200 samples around 100 ms. EWMA(age=30) should land within
	// ~10 ms of 100 after that many samples.
	for i := 0; i < 200; i++ {
		r.UpdateLatencySample(100)
	}
	rtt := r.ShortRTT()
	if math.Abs(rtt-100.0) > 10 {
		t.Fatalf("shortRTT = %.2f, want ~100 ±10", rtt)
	}

	// Alternate success/failure 1:1; rate should converge near 0.5.
	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			r.AddInt64("success", 1)
		} else {
			r.AddInt64("failure", 1)
		}
	}
	rate := r.ShortSuccessRate()
	if math.Abs(rate-0.5) > 0.1 {
		t.Fatalf("shortSuccessRate = %.3f, want ~0.5 ±0.1", rate)
	}
}

// TestShortSuccessRate_RecentDeterioration ensures a node that succeeds
// 95 times then fails 20 times is flagged by ShortSuccessRate while its
// lifetime counter still looks mostly-healthy.
func TestShortSuccessRate_RecentDeterioration(t *testing.T) {
	r := NewAtomicStatsRecord()
	for i := 0; i < 95; i++ {
		r.AddInt64("success", 1)
	}
	for i := 0; i < 20; i++ {
		r.AddInt64("failure", 1)
	}
	// Lifetime success rate: 95/115 ≈ 0.83.
	// Short rate with age=20 should be well below that after 20 failures.
	short := r.ShortSuccessRate()
	if short > 0.40 {
		t.Fatalf("shortSuccessRate after 20 failures = %.3f, want ≤ 0.40", short)
	}
}

// TestAdaptiveHalfLife_Scale_Bounds checks the clamp boundaries and the
// calibration point (n == adaptiveDecayReferenceN → scale == 1.0).
func TestAdaptiveHalfLife_Scale_Bounds(t *testing.T) {
	if s := adaptiveHalfLifeScale(0); s != adaptiveScaleMax {
		t.Fatalf("scale(0) = %.2f, want max=%.2f", s, adaptiveScaleMax)
	}
	if s := adaptiveHalfLifeScale(adaptiveDecayReferenceN); math.Abs(s-1.0) > 1e-9 {
		t.Fatalf("scale(refN) = %.4f, want 1.0", s)
	}
	if s := adaptiveHalfLifeScale(1 << 20); s != adaptiveScaleMin {
		t.Fatalf("scale(huge) = %.2f, want min=%.2f", s, adaptiveScaleMin)
	}
}

// TestAdaptiveHalfLife_SparseMemoryLongerThanDense confirms that a
// sparse record (fewer samples) retains more signal at a given elapsed
// time than a dense record, for the same lastUsed timestamp.
func TestAdaptiveHalfLife_SparseMemoryLongerThanDense(t *testing.T) {
	t.Setenv("SMART_LEGACY", "")
	t.Setenv("SMART_DECAY_HALF_LIFE_HOURS", "")
	RefreshFlags()

	now := int64(30 * 24 * 3600)
	lastUsed := now - 48*3600 // 2 days ago
	minDecay := 0.0

	sparse := GetTimeDecayAdaptive(lastUsed, now, minDecay, 2)
	dense := GetTimeDecayAdaptive(lastUsed, now, minDecay, 1000)
	if sparse <= dense {
		t.Fatalf("sparse should retain more signal (sparse=%.4f ≤ dense=%.4f)", sparse, dense)
	}
}

// TestFailureSticky_Biases verifies GetTimeDecayForFailure returns a
// larger (less decayed) value than GetTimeDecayAdaptive for the same
// inputs — the whole point is that failures outlast successes.
func TestFailureSticky_Biases(t *testing.T) {
	t.Setenv("SMART_LEGACY", "")
	t.Setenv("SMART_DECAY_HALF_LIFE_HOURS", "")
	t.Setenv("SMART_FAILURE_STICKY", "")
	RefreshFlags()

	now := int64(30 * 24 * 3600)
	lastUsed := now - 168*3600 // 7 days ago (= one halfLife at n=refN)

	s := GetTimeDecayAdaptive(lastUsed, now, 0.0, adaptiveDecayReferenceN)
	f := GetTimeDecayForFailure(lastUsed, now, 0.0, adaptiveDecayReferenceN)
	if f <= s {
		t.Fatalf("failure decay should be stickier (s=%.4f f=%.4f)", s, f)
	}
	// Default stickyFactor=2 so f ≈ 2^(-1/2) ≈ 0.707 while s ≈ 0.5.
	if math.Abs(f-math.Sqrt2/2) > 0.05 {
		t.Fatalf("failure decay at halfLife×2 = %.4f, expected ≈ %.4f", f, math.Sqrt2/2)
	}
}

// TestRecentPenalty_RTTBad applies the weight formula to two inputs
// identical EXCEPT one has a recent RTT spike; the spiked input must
// score strictly less. We use large Latency/Success so the rest of the
// formula is stable and only the recent penalty can move the result.
func TestRecentPenalty_RTTBad(t *testing.T) {
	common := ModelInput{
		Success: 100, Failure: 1,
		ConnectTime: 50, Latency: 60,
		UploadTotal: 5, DownloadTotal: 25,
		MaxuploadRate: 500, MaxdownloadRate: 4000,
		ConnectionDuration: 3.0,
		LastUsed:           time.Now().Unix(),
		IsTCP:              true, DestPort: 443,
		ShortSuccessRate: 0.99,
	}
	healthy := common
	healthy.ShortRTT = 60 // matches long-term
	degraded := common
	degraded.ShortRTT = 240 // 4× — strong RTT drift

	wHealthy, _ := CalculateWeight(&healthy, 1.0)
	wDegraded, _ := CalculateWeight(&degraded, 1.0)
	if wDegraded >= wHealthy {
		t.Fatalf("degraded should score lower (healthy=%.4f degraded=%.4f)", wHealthy, wDegraded)
	}
}

// BenchmarkGetTimeDecay_Variants compares the three code paths so we
// can verify math.Exp2 isn't a regression vs the legacy piecewise.
func BenchmarkGetTimeDecay_Variants(b *testing.B) {
	b.Setenv("SMART_LEGACY", "")
	b.Setenv("SMART_DECAY_HALF_LIFE_HOURS", "")
	RefreshFlags()

	now := int64(30 * 24 * 3600)
	lastUsed := now - 48*3600

	b.Run("exp_nonadaptive", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = GetTimeDecay(lastUsed, now, 0.05)
		}
	})
	b.Run("exp_adaptive", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = GetTimeDecayAdaptive(lastUsed, now, 0.05, 50)
		}
	})
	b.Run("failure_sticky", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = GetTimeDecayForFailure(lastUsed, now, 0.05, 50)
		}
	})
	b.Run("legacy_piecewise", func(b *testing.B) {
		b.Setenv("SMART_LEGACY", "1")
		RefreshFlags()
		b.Cleanup(func() { b.Setenv("SMART_LEGACY", ""); RefreshFlags() })
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = GetTimeDecay(lastUsed, now, 0.05)
		}
	})
}

// BenchmarkShortEWMA_Add measures the VividCortex/ewma Add hot path,
// covering the two signals we feed on every dial close.
func BenchmarkShortEWMA_Add(b *testing.B) {
	r := NewAtomicStatsRecord()
	b.Run("rtt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			r.UpdateLatencySample(100)
		}
	})
	b.Run("success_failure_mixed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if i&1 == 0 {
				r.AddInt64("success", 1)
			} else {
				r.AddInt64("failure", 1)
			}
		}
	})
}
