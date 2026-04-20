package smart

import (
	"testing"
	"time"
)

// TestBandwidthBonus_StreamingHighBpsOutranksLowBps validates the
// intended behaviour: in a streaming scene, a node with identical
// success/latency stats but a higher peak throughput should outrank
// the slower node thanks to the new bandwidthBonus factor.
//
// Setup: both nodes identical on every dimension EXCEPT maxDownloadRate.
// The high-bps node is ~40 MB/s peak, the low-bps node is 500 KB/s peak.
// With total traffic > 10 MB (full confidence) both trigger the bonus,
// but the high-bps one takes ~20% more composite — enough to outrank
// despite identical base signal.
func TestBandwidthBonus_StreamingHighBpsOutranksLowBps(t *testing.T) {
	now := time.Now().Unix()
	base := ModelInput{
		Success: 50, Failure: 2,
		ConnectTime: 60, Latency: 45,
		UploadTotal: 2, DownloadTotal: 100, // 102 MB total, clearly streaming
		ConnectionDuration: 10.0, // 10 min → ~10 MB/min avg, triggers streaming
		LastUsed:           now,
		IsTCP:              true, DestPort: 443,
	}

	highBps := base
	highBps.MaxuploadRate = 200
	highBps.MaxdownloadRate = 40000 // 40 MB/s peak

	lowBps := base
	lowBps.MaxuploadRate = 200
	lowBps.MaxdownloadRate = 500 // 500 KB/s peak

	hw, _ := CalculateWeight(&highBps, 1.0)
	lw, _ := CalculateWeight(&lowBps, 1.0)

	if hw <= lw {
		t.Fatalf("high-bps should outrank low-bps in streaming: hw=%.3f lw=%.3f", hw, lw)
	}
	// Bonus max is +20%; with log-scaled confidence & bpsScale both near 1,
	// delta should be at least +8% (empirical floor).
	ratio := hw / lw
	if ratio < 1.08 {
		t.Fatalf("bandwidthBonus too weak: hw/lw=%.3f, want ≥ 1.08", ratio)
	}
}

// TestBandwidthBonus_SmallRequestNoBoost guards against the main
// failure mode: a tiny request (< 1 MB total) must NOT trigger the
// bonus, even if the single-request peak bps happened to be high
// (eg a fast TCP window snapshot on a 200KB image).
//
// If the bonus fires here, a lucky single-burst measurement would
// spuriously elevate a node that has no sustained bandwidth record.
func TestBandwidthBonus_SmallRequestNoBoost(t *testing.T) {
	now := time.Now().Unix()
	// Tiny total traffic — well under the 1 MB confidence floor. Note:
	// these inputs don't match "streaming" scene rules anyway (needs
	// downloadMB > 15 MB); this test specifically validates that even
	// if we artificially coerced into streaming via scene, confidence
	// gate still bounds the bonus. Since identifyConnectionScene would
	// map this to "web" the bonus is never applied — which IS the
	// correct behaviour we want to guard.
	input := &ModelInput{
		Success: 50, Failure: 0,
		ConnectTime: 40, Latency: 30,
		UploadTotal: 0.05, DownloadTotal: 0.2, // 250 KB total
		MaxuploadRate:      50,
		MaxdownloadRate:    20000, // 20 MB/s "burst" — looks fat but unproven
		ConnectionDuration: 0.1,
		LastUsed:           now,
		IsTCP:              true, DestPort: 443,
	}
	w, _ := CalculateWeight(input, 1.0)

	// Equivalent input but with realistic bps (500 KB/s). Weights should
	// be ESSENTIALLY IDENTICAL because web scene doesn't run the bonus,
	// and the log-space trafficFactor rate bonuses barely differ at this
	// total-bytes level.
	input2 := *input
	input2.MaxdownloadRate = 500
	w2, _ := CalculateWeight(&input2, 1.0)

	ratio := w / w2
	if ratio > 1.10 {
		t.Fatalf("small-request must NOT get a strong bandwidth boost: w=%.3f w2=%.3f ratio=%.3f",
			w, w2, ratio)
	}
}

// TestBandwidthBonus_WebSceneNotAmplified ensures that in the default
// "web" scene (the common latency-sensitive case), even a beefy-looking
// bps number doesn't artificially boost the node over a same-stats
// low-bps peer. Web users should see latency/success dominate selection.
func TestBandwidthBonus_WebSceneNotAmplified(t *testing.T) {
	now := time.Now().Unix()
	// Construct a "web" scene: moderate total, short-ish duration, mixed
	// upload/download — no streaming signature.
	base := ModelInput{
		Success: 100, Failure: 2,
		ConnectTime: 40, Latency: 30,
		UploadTotal: 1.5, DownloadTotal: 2.0,
		ConnectionDuration: 0.5, // 30s — web
		LastUsed:           now,
		IsTCP:              true, DestPort: 443,
	}

	high := base
	high.MaxuploadRate, high.MaxdownloadRate = 2000, 30000

	low := base
	low.MaxuploadRate, low.MaxdownloadRate = 300, 800

	hw, _ := CalculateWeight(&high, 1.0)
	lw, _ := CalculateWeight(&low, 1.0)

	// In web scene, the high-bps peer may still win via the existing
	// trafficFactor rateBonus, but the spread should be SMALL (≤ ~8%)
	// — not the +15-20% we'd see if bandwidthBonus incorrectly fired.
	ratio := hw / lw
	if ratio > 1.12 {
		t.Fatalf("web scene should not heavily amplify bandwidth: hw=%.3f lw=%.3f ratio=%.3f",
			hw, lw, ratio)
	}
}

// TestBandwidthBonus_TransferScene verifies the bonus also fires in
// bulk-transfer scenes (big uploads like backups or Docker pulls),
// not just streaming.
func TestBandwidthBonus_TransferScene(t *testing.T) {
	now := time.Now().Unix()
	base := ModelInput{
		Success: 30, Failure: 1,
		ConnectTime: 80, Latency: 60,
		UploadTotal: 400, DownloadTotal: 5, // big upload → transfer
		ConnectionDuration: 10.0,
		LastUsed:           now,
		IsTCP:              true, DestPort: 443,
	}

	high := base
	high.MaxuploadRate, high.MaxdownloadRate = 20000, 500

	low := base
	low.MaxuploadRate, low.MaxdownloadRate = 400, 500

	hw, _ := CalculateWeight(&high, 1.0)
	lw, _ := CalculateWeight(&low, 1.0)

	if hw <= lw {
		t.Fatalf("transfer scene: high-upload-bps should outrank low: hw=%.3f lw=%.3f", hw, lw)
	}
}
