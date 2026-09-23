package smart

import (
	"math"
	"testing"
)

// TestTDigest_SampleBelowWarmup confirms QuantileRTT returns ok=false
// below the warm-up threshold so callers fall back to mean+stddev.
func TestTDigest_SampleBelowWarmup(t *testing.T) {
	r := NewAtomicStatsRecord()
	for i := 0; i < tdigestWarmupSamples-1; i++ {
		r.UpdateLatencySample(int64(100 + i))
	}
	if _, ok := r.QuantileRTT(0.95); ok {
		t.Fatalf("quantile should be unavailable below %d samples", tdigestWarmupSamples)
	}
	if b := r.rttDigestBytes(); b != nil {
		t.Fatalf("serialisation should be skipped below warmup; got %d bytes", len(b))
	}
}

// TestTDigest_QuantileAccuracy feeds a known distribution and checks the
// estimated p50 and p95 are within a few ms of the analytical values.
// At compression=100 the t-digest paper claims < 1 % error on the
// extremes; 5 ms slack is comfortable for the 0–200 ms range used here.
func TestTDigest_QuantileAccuracy(t *testing.T) {
	r := NewAtomicStatsRecord()
	// Samples: 0, 1, 2, ... 199. P50 = 99, P95 = 189.
	for i := 0; i < 200; i++ {
		r.UpdateLatencySample(int64(i))
	}
	p50, ok := r.QuantileRTT(0.5)
	if !ok {
		t.Fatalf("p50 unavailable after 200 samples")
	}
	if math.Abs(p50-99.0) > 5 {
		t.Fatalf("p50 = %.2f, want ~99 ±5", p50)
	}
	p95, ok := r.QuantileRTT(0.95)
	if !ok {
		t.Fatalf("p95 unavailable after 200 samples")
	}
	if math.Abs(p95-189.0) > 5 {
		t.Fatalf("p95 = %.2f, want ~189 ±5", p95)
	}
}

// TestTDigest_Roundtrip validates that the digest survives serialisation
// through CreateStatsSnapshot → MarshalStatsRecord → UnmarshalStatsRecord
// → loadRTTDigestBytes, and that the restored quantile is within
// tolerance of the pre-serialisation value.
func TestTDigest_Roundtrip(t *testing.T) {
	r := NewAtomicStatsRecord()
	for i := 0; i < 200; i++ {
		r.UpdateLatencySample(int64(10 + i))
	}

	snap := r.CreateStatsSnapshot()
	defer ReleaseStatsRecord(snap)
	if len(snap.RTTDigest) == 0 {
		t.Fatal("snapshot RTTDigest should be non-empty after warmup")
	}

	blob, err := MarshalStatsRecord(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded StatsRecord
	if err := UnmarshalStatsRecord(blob, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded.RTTDigest) == 0 {
		t.Fatal("round-tripped RTTDigest should be non-empty")
	}

	restored := NewAtomicStatsRecord()
	restored.loadRTTDigestBytes(decoded.RTTDigest)
	p95Before, _ := r.QuantileRTT(0.95)
	p95After, ok := restored.QuantileRTT(0.95)
	if !ok {
		t.Fatal("restored digest must report warm")
	}
	if math.Abs(p95Before-p95After) > 2 {
		t.Fatalf("p95 drift across roundtrip: before=%.2f after=%.2f", p95Before, p95After)
	}
}
