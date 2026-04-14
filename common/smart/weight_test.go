package smart

import (
	"testing"
	"time"
)

// TestCalculateWeight_BasicOrdering asserts that a fast, reliable node
// outranks a slow, flaky one across every scene. This is the single most
// important invariant — if the algorithm can't get this right, nothing
// downstream (prefetch, ranking, selection) will behave.
func TestCalculateWeight_BasicOrdering(t *testing.T) {
	now := time.Now().Unix()
	good := &ModelInput{
		Success: 50, Failure: 1,
		ConnectTime: 50, Latency: 40,
		UploadTotal: 5, DownloadTotal: 25,
		MaxuploadRate: 500, MaxdownloadRate: 4000,
		ConnectionDuration: 3.0,
		LastUsed:           now,
		IsTCP:              true, DestPort: 443,
	}
	bad := &ModelInput{
		Success: 30, Failure: 20,
		ConnectTime: 1500, Latency: 800,
		UploadTotal: 0.5, DownloadTotal: 1.0,
		MaxuploadRate: 50, MaxdownloadRate: 100,
		ConnectionDuration: 3.0,
		LastUsed:           now,
		IsTCP:              true, DestPort: 443,
	}
	gw, _ := CalculateWeight(good, 1.0)
	bw, _ := CalculateWeight(bad, 1.0)
	if gw <= bw {
		t.Fatalf("good=%.3f should outrank bad=%.3f", gw, bw)
	}
}

// TestCalculateWeight_ColdStart verifies that inputs below MinSampleCount
// return 0 — the caller (prefetch) relies on this to skip unproven nodes.
func TestCalculateWeight_ColdStart(t *testing.T) {
	w, _ := CalculateWeight(&ModelInput{Success: 1, Failure: 0}, 1.0)
	if w != 0 {
		t.Fatalf("cold-start should return 0, got %.3f", w)
	}
}

// TestCalculateWeight_RealtimeHardFloor verifies that a "realtime"-scene
// match with latency above the floor is forced below AllowedWeight. This
// is the critical guarantee that a gaming session can never pick a node
// that's too slow to play games against.
func TestCalculateWeight_RealtimeHardFloor(t *testing.T) {
	input := &ModelInput{
		Success: 100, Failure: 1,
		ConnectTime: 50, Latency: 500, // way above realtime 150ms floor
		UploadTotal: 1, DownloadTotal: 1, // symmetric small bytes = realtime signature
		MaxuploadRate: 100, MaxdownloadRate: 100,
		ConnectionDuration: 5.0,
		LastUsed:           time.Now().Unix(),
		IsUDP:              true, DestPort: 3478, // WebRTC STUN port — triggers realtime
	}
	w, _ := CalculateWeight(input, 1.0)
	if w >= AllowedWeight {
		t.Fatalf("realtime with 500ms latency must score below AllowedWeight (%.2f), got %.3f", AllowedWeight, w)
	}
}

// TestCalculateWeight_BayesianSmoothing: 1/1 should NOT read as 100% — the
// prior ensures a new node isn't immediately over-trusted. Compared against
// a node with 20/1 (far more evidence), the smoothing makes the difference
// visible in the output.
func TestCalculateWeight_BayesianSmoothing(t *testing.T) {
	now := time.Now().Unix()
	base := ModelInput{
		ConnectTime: 100, Latency: 80,
		UploadTotal: 2, DownloadTotal: 5,
		MaxuploadRate: 500, MaxdownloadRate: 1000,
		ConnectionDuration: 2.0, LastUsed: now,
		IsTCP: true, DestPort: 443,
	}
	thin := base
	thin.Success, thin.Failure = 1, 1
	thick := base
	thick.Success, thick.Failure = 20, 1

	wThin, _ := CalculateWeight(&thin, 1.0)
	wThick, _ := CalculateWeight(&thick, 1.0)
	if wThick <= wThin {
		t.Fatalf("thicker evidence (20/1) should outrank thin (1/1): thick=%.3f thin=%.3f", wThick, wThin)
	}
}

// TestIdentifyScene_Realtime: gaming signature classification.
func TestIdentifyScene_Realtime(t *testing.T) {
	scene := identifyConnectionScene(
		true, 40,  // UDP, 40ms latency
		0.5, 0.6, // small symmetric bytes
		200, 200, // small rates
		1.0,   // 1 min duration
		27015, // steam game port
	)
	if scene != "realtime" {
		t.Fatalf("expected realtime, got %q", scene)
	}
}

// TestIdentifyScene_Streaming: video download signature.
func TestIdentifyScene_Streaming(t *testing.T) {
	scene := identifyConnectionScene(
		false, 80,
		2, 200, // heavy download
		500, 10000,
		5.0,
		443,
	)
	if scene != "streaming" {
		t.Fatalf("expected streaming, got %q", scene)
	}
}

// TestWilsonLowerBound_ConvergesToMean: Wilson should approach the naive
// rate as n grows; for small n it should be meaningfully below naive.
func TestWilsonLowerBound_ConvergesToMean(t *testing.T) {
	// 3/3 — naive says 100%, Wilson@90 should be WELL below.
	w3 := wilsonLowerBound(3, 3)
	if w3 >= 0.7 {
		t.Fatalf("3/3 wilson should be <0.7, got %.3f", w3)
	}
	// 50/50 — naive says 100%, Wilson should be high but not 1.
	w50 := wilsonLowerBound(50, 50)
	if w50 < 0.85 || w50 >= 1 {
		t.Fatalf("50/50 wilson should be in [0.85, 1), got %.3f", w50)
	}
	// 500/500 — should be very close to 1.
	w500 := wilsonLowerBound(500, 500)
	if w500 < 0.98 {
		t.Fatalf("500/500 wilson should be >0.98, got %.3f", w500)
	}
	// 5/10 — naive 50%, Wilson below.
	w5of10 := wilsonLowerBound(5, 10)
	if w5of10 >= 0.5 {
		t.Fatalf("5/10 wilson should be <0.5, got %.3f", w5of10)
	}
}

// TestSampleConfidence: monotone, in (0,1), saturates near 1.
func TestSampleConfidence(t *testing.T) {
	c2 := sampleConfidence(2)
	c10 := sampleConfidence(10)
	c200 := sampleConfidence(200)
	if !(c2 < c10 && c10 < c200) {
		t.Fatalf("confidence must be monotone increasing: c2=%.3f c10=%.3f c200=%.3f", c2, c10, c200)
	}
	if c200 <= 0.9 {
		t.Fatalf("c200 should be >0.9, got %.3f", c200)
	}
}

// TestJitterCost: monotone increasing, saturates.
func TestJitterCost(t *testing.T) {
	if jitterCost(0.05) != 0 {
		t.Fatalf("cv<0.1 should return 0, got %.3f", jitterCost(0.05))
	}
	j03 := jitterCost(0.3)
	j1 := jitterCost(1.0)
	j5 := jitterCost(5.0)
	if !(j03 < j1 && j1 < j5 && j5 < 1.01) {
		t.Fatalf("jitter cost ordering broken: j03=%.3f j1=%.3f j5=%.3f", j03, j1, j5)
	}
}

// TestCalculateWeight_JitterPenalty: two nodes with same mean latency but
// very different jitter — the low-jitter one must score higher.
func TestCalculateWeight_JitterPenalty(t *testing.T) {
	now := time.Now().Unix()
	common := ModelInput{
		Success: 100, Failure: 2,
		ConnectTime: 80, Latency: 100,
		UploadTotal: 2, DownloadTotal: 5,
		MaxuploadRate: 500, MaxdownloadRate: 2000,
		ConnectionDuration: 3.0,
		LastUsed:           now,
		IsTCP:              true, DestPort: 443,
	}
	stable := common
	stable.LatencyStdDev = 8 // low jitter
	stable.ConnectTimeStdDev = 5
	jittery := common
	jittery.LatencyStdDev = 120 // CV > 1
	jittery.ConnectTimeStdDev = 90

	ws, _ := CalculateWeight(&stable, 1.0)
	wj, _ := CalculateWeight(&jittery, 1.0)
	if ws <= wj {
		t.Fatalf("stable (σ=8) should outrank jittery (σ=120): stable=%.3f jittery=%.3f", ws, wj)
	}
}

// TestCalculateWeight_ConfidenceDampening: a 3/3 node should NOT outrank
// a battle-tested 200/5 node with comparable mean metrics. Previously
// lucky-small-sample nodes could top the list; confidence factor fixes it.
func TestCalculateWeight_ConfidenceDampening(t *testing.T) {
	now := time.Now().Unix()
	base := ModelInput{
		ConnectTime: 100, Latency: 80,
		UploadTotal: 1, DownloadTotal: 3,
		MaxuploadRate: 300, MaxdownloadRate: 1000,
		ConnectionDuration: 2.0, LastUsed: now,
		IsTCP: true, DestPort: 443,
	}
	fresh := base
	fresh.Success, fresh.Failure = 3, 0
	seasoned := base
	seasoned.Success, seasoned.Failure = 200, 5

	wf, _ := CalculateWeight(&fresh, 1.0)
	ws, _ := CalculateWeight(&seasoned, 1.0)
	if ws <= wf {
		t.Fatalf("seasoned (200/5) should outrank fresh (3/0): seasoned=%.3f fresh=%.3f", ws, wf)
	}
}

// BenchmarkCalculateWeight — hot path. Should be well under 1 µs on modern
// hardware so per-dial weight computation doesn't show up in profiles.
func BenchmarkCalculateWeight(b *testing.B) {
	input := &ModelInput{
		Success: 100, Failure: 3,
		ConnectTime:       50,
		Latency:           80,
		ConnectTimeStdDev: 10,
		LatencyStdDev:     15,
		UploadTotal:       2, DownloadTotal: 10,
		MaxuploadRate: 500, MaxdownloadRate: 3000,
		ConnectionDuration: 2.5,
		LastUsed:           time.Now().Unix(),
		IsTCP:              true, DestPort: 443,
		DestIPASN: "13335",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CalculateWeight(input, 1.0)
	}
}
