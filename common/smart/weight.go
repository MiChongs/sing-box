package smart

import (
	"math"
	"time"
)

// sceneParams is the weighted-sum parameter bundle per scene. Kept as a
// tagged struct instead of [7]float64 so the scene tuning stays readable
// when future scenes are added.
type sceneParams struct {
	successRateWeight float64
	connectTimeWeight float64
	latencyWeight     float64
	trafficWeight     float64
	durationWeight    float64
	qualityWeight     float64
	minDecayFactor    float64
	// Hard floors. When the relevant metric crosses the floor, the returned
	// weight is forced below AllowedWeight so the node is dropped from the
	// candidate list. Value 0 = "no floor for this scene".
	maxLatencyMS     int64
	maxConnectTimeMS int64
	minSuccessRate   float64
	// Jitter penalty amplifier — realtime/voip scenes care about timing
	// stability far more than bulk-transfer scenes. Default 1.0 = apply
	// base jitter penalty; >1 amplifies; <1 softens.
	jitterAmp float64
}

// Scene presets. Tuned to mihomo-parity plus the three new scenes we
// introduced (realtime / voip / api). See CalculateWeight for how each
// field is consumed.
var presetSceneParams = map[string]sceneParams{
	"interactive": {0.55, 0.10, 0.30, 1.20, 1.00, 1.30, 0.30, 300, 500, 0.70, 1.2},
	"streaming":   {0.50, 0.15, 0.30, 1.50, 0.80, 1.20, 0.20, 600, 800, 0.75, 0.6},
	"transfer":    {0.50, 0.15, 0.25, 1.80, 0.70, 0.90, 0.10, 0, 0, 0.70, 0.4},
	"web":         {0.50, 0.15, 0.35, 0.80, 0.60, 1.00, 0.20, 800, 1000, 0.60, 0.8},
	"realtime":    {0.55, 0.20, 0.35, 0.30, 0.30, 0.80, 0.35, 150, 300, 0.80, 2.5},
	"voip":        {0.55, 0.15, 0.40, 0.40, 0.40, 0.80, 0.25, 200, 400, 0.75, 2.0},
	"api":         {0.55, 0.25, 0.25, 0.60, 0.40, 1.00, 0.20, 600, 600, 0.70, 1.1},
}

// Precomputed constants for hot path — one allocation saved per dial.
const (
	connectExpDivisor = 1500.0 // exp(-ms/1500) for connect/latency scoring
	latencyExpDivisor = 1500.0
	// Wilson score z = 1.96 (95% confidence) is the usual default; we use
	// z = 1.645 (90%) as a less aggressive pessimism — a node should be
	// trusted after ~5 successful dials, not ~15. The squared form
	// (wilsonZSq = z*z) is the only form we actually use.
	wilsonZSq = 1.645 * 1.645
	// Confidence-factor ceiling: low-sample nodes drag toward the group
	// mean by at most this fraction. 0.30 = new nodes score at most 30%
	// of their own weight until enough evidence accumulates.
	maxConfidenceDampening = 0.30
)

// CalculateWeight computes a node's weight for a specific (target, ASN, UDP)
// combination. Second return is false — this is the traditional algorithm
// (LightGBM path flips it to true in predict.go).
//
// Design goals (what makes this accurate + fast):
//
//  1. WILSON LOWER BOUND on success rate — statistically sound pessimism
//     that converges to true rate as samples grow. Replaces the prior
//     Laplace prior which gave 50% for 0/0 (reasonable) but also gave
//     ~67% for 1/0 (not reasonable — one success is weak evidence).
//     Wilson at 90% gives 1/0 ≈ 0.28, 5/0 ≈ 0.57, 50/0 ≈ 0.93 — exactly
//     the sample-size-aware trust curve we want.
//
//  2. JITTER-AWARE BASE. Standard deviation of connect/latency times now
//     directly subtracts from the respective score component. A node
//     with mean=100ms σ=200ms scores WORSE than mean=150ms σ=10ms for
//     realtime, matching human intuition. Scene-specific jitterAmp lets
//     realtime/voip weigh jitter 2.5x more than bulk transfer.
//
//  3. GEOMETRIC-MEAN BASE. Multiplies the three core factors with
//     scene-weighted exponents. One terrible factor (e.g. 50% success
//     rate) drags the composite down instead of being averaged away.
//
//  4. CONFIDENCE FACTOR. Low-sample nodes get damped toward 0 so a lucky
//     3/3 doesn't outrank a battle-tested 500/10. Converges to 1.0 as
//     sample count grows.
//
//  5. SCENE HARD FLOORS. Latency / connect / success floors force weight
//     below AllowedWeight when crossed — a gaming-classified session
//     with 500ms latency CANNOT get a high weight.
//
//  6. RATE EFFICIENCY FACTOR. actualRate/maxRate ratio rewards nodes
//     that sustain throughput; punishes bursty nodes that peak then stall.
//
//  7. ASN TRUST BONUS for stable repeat-ASN success. Caps at +8% so a
//     fresh-but-good node isn't blocked out.
//
//  8. ZERO-PAYLOAD 443 PENALTY. Repeated TCP-443 closures with no bytes
//     = TLS handshake succeed + immediate reset pattern = upstream bad.
//
// All bonuses / penalties are gated by priority_factor at the end.
func CalculateWeight(input *ModelInput, priorityFactor float64) (float64, bool) {
	total := input.Success + input.Failure
	if total < DefaultMinSampleCount {
		return 0, false
	}

	scene := identifyConnectionScene(
		input.IsUDP, input.Latency,
		input.UploadTotal, input.DownloadTotal,
		input.MaxuploadRate, input.MaxdownloadRate,
		input.ConnectionDuration, input.DestPort,
	)
	params, ok := presetSceneParams[scene]
	if !ok {
		params = presetSceneParams["web"]
	}

	// ─── time decay ──────────────────────────────────────────────────────
	// Positive observations (connect/latency/success) and negative
	// observations (failure) decay on separate curves so a once-burned
	// node stays pessimistic even after its good samples have faded.
	// adaptiveHalfLifeScale also stretches halfLife for records with
	// few samples, preserving their signal until more arrive.
	timeFactor := 1.0           // applied to success/connect/latency
	timeFactorFailure := 1.0    // applied to failure (≥ timeFactor)
	n := input.Success + input.Failure
	if input.LastUsed > 0 {
		now := time.Now().Unix()
		timeFactor = GetTimeDecayAdaptive(input.LastUsed, now, params.minDecayFactor, n)
		timeFactorFailure = GetTimeDecayForFailure(input.LastUsed, now, params.minDecayFactor, n)
	}

	// ─── WILSON LOWER BOUND success rate ─────────────────────────────────
	// Pessimistic success rate that converges to the true rate as n grows:
	//   p_hat = success / n
	//   lower = (p_hat + z²/2n - z·√((p_hat·(1-p_hat) + z²/4n)/n)) / (1 + z²/n)
	// Apply time decay to n so ancient samples aren't fully weighted.
	decayedSuccess := math.Max(0, float64(input.Success)*timeFactor)
	decayedFailure := math.Max(0, float64(input.Failure)*timeFactorFailure)
	decayedN := decayedSuccess + decayedFailure
	// Minimum effective n of 1 — keeps Wilson numerator/denominator stable
	// for nodes that had only failures recently.
	if decayedN < 1 {
		decayedN = 1
	}
	successRate := wilsonLowerBound(decayedSuccess, decayedN)

	// ─── connect / latency scores (exp-decay, clamped) ───────────────────
	connectTime := input.ConnectTime
	if connectTime <= 0 {
		connectTime = 2000
	}
	latency := input.Latency
	if latency <= 0 {
		latency = 2000
	}
	connectScore := math.Exp(-float64(connectTime)/connectExpDivisor) * timeFactor
	latencyScore := math.Exp(-float64(latency)/latencyExpDivisor) * timeFactor

	// ─── jitter penalty ──────────────────────────────────────────────────
	// Coefficient of variation (σ/μ) captures relative timing instability.
	// We scale jitterPenalty non-linearly so small jitter (<20% of mean)
	// barely registers, but large jitter (>100% of mean) bites hard.
	jitterPenalty := 0.0
	if input.ConnectTimeStdDev > 0 && float64(connectTime) > 0 {
		cv := input.ConnectTimeStdDev / float64(connectTime)
		jitterPenalty += jitterCost(cv) * 0.4
	}
	if input.LatencyStdDev > 0 && float64(latency) > 0 {
		cv := input.LatencyStdDev / float64(latency)
		jitterPenalty += jitterCost(cv) * 0.6 // latency jitter weighs more
	}
	jitterPenalty *= params.jitterAmp
	jitterPenalty = clamp(jitterPenalty, 0, 0.40)
	// Apply jitter penalty directly to the sub-scores before clamping.
	connectScore *= 1.0 - jitterPenalty*0.5
	latencyScore *= 1.0 - jitterPenalty

	connectScore = clamp(connectScore, 0.10, 0.95)
	latencyScore = clamp(latencyScore, 0.10, 0.95)

	// UDP emphasises latency more aggressively (gaming/voip dominate UDP).
	if input.IsUDP {
		params.latencyWeight = math.Min(0.55, params.latencyWeight*1.25)
		params.successRateWeight = math.Min(0.60, params.successRateWeight*1.10)
		params.connectTimeWeight = math.Max(0.05, 1.0-params.successRateWeight-params.latencyWeight)
	}

	// ─── GEOMETRIC-MEAN BASE ─────────────────────────────────────────────
	base := math.Pow(successRate, params.successRateWeight) *
		math.Pow(connectScore, params.connectTimeWeight) *
		math.Pow(latencyScore, params.latencyWeight)
	baseWeight := base * 1.6

	// ─── traffic factor ──────────────────────────────────────────────────
	durationMinutes := input.ConnectionDuration
	isShortConn := durationMinutes > 0 && durationMinutes <= 1
	isLongConn := durationMinutes > 10

	var trafficFactor float64
	if input.UploadTotal > 0 || input.DownloadTotal > 0 {
		uploadFactor := calculateTrafficFactor(input.UploadTotal, input.MaxuploadRate, durationMinutes, isShortConn)
		downloadFactor := calculateTrafficFactor(input.DownloadTotal, input.MaxdownloadRate, durationMinutes, isShortConn)

		var uploadWeight, downloadWeight float64
		switch {
		case scene == "streaming":
			uploadWeight, downloadWeight = 0.2, 0.8
		case scene == "transfer" && input.UploadTotal > input.DownloadTotal*2:
			uploadWeight, downloadWeight = 0.7, 0.3
		case scene == "voip", scene == "realtime":
			uploadWeight, downloadWeight = 0.5, 0.5
		default:
			uploadWeight, downloadWeight = 0.4, 0.6
		}
		trafficFactor = (uploadFactor * uploadWeight) + (downloadFactor * downloadWeight)
	}

	// ─── rate efficiency ─────────────────────────────────────────────────
	efficiencyFactor := 1.0
	if durationMinutes > 0 {
		avgDownRateKB := input.DownloadTotal * 1024.0 / (durationMinutes * 60.0)
		avgUpRateKB := input.UploadTotal * 1024.0 / (durationMinutes * 60.0)
		if input.MaxdownloadRate > 0 && avgDownRateKB > 0 {
			r := clamp(avgDownRateKB/input.MaxdownloadRate, 0.05, 1.0)
			efficiencyFactor *= 0.85 + 0.30*r
		}
		if input.MaxuploadRate > 0 && avgUpRateKB > 0 {
			r := clamp(avgUpRateKB/input.MaxuploadRate, 0.05, 1.0)
			efficiencyFactor *= 0.95 + 0.10*r
		}
	}
	efficiencyFactor = clamp(efficiencyFactor, 0.75, 1.25)

	// ─── duration factor ─────────────────────────────────────────────────
	durationFactor := 0.1
	if durationMinutes > 0 {
		switch {
		case isShortConn:
			durationFactor = math.Min(0.3, 0.1+math.Log1p(durationMinutes)*0.08)
		case isLongConn:
			durationFactor = math.Min(0.5, 0.2+math.Log1p(durationMinutes)*0.10)
		default:
			durationFactor = math.Min(0.4, 0.15+math.Log1p(durationMinutes)*0.09)
		}
	}

	// ─── quality bonus / penalty ─────────────────────────────────────────
	var quality float64
	if latency > 0 && latency < 100 {
		quality += 0.10
	}
	if connectTime > 0 && connectTime < 50 {
		quality += 0.10
	}
	if successRate > 0.95 {
		quality += 0.10
	}
	if (scene == "streaming" || scene == "transfer") && input.DownloadTotal > 20 {
		quality += 0.10
	}
	if scene == "interactive" && latency > 0 && latency < 100 && successRate > 0.9 {
		quality += 0.10
	}
	if scene == "realtime" && latency < 80 && successRate > 0.95 {
		quality += 0.15
	}
	// Low-jitter bonus: when CV(latency) < 0.15, reward stability explicitly.
	if input.LatencyStdDev > 0 && float64(latency) > 0 {
		cv := input.LatencyStdDev / float64(latency)
		if cv < 0.15 && input.Success >= 5 {
			quality += 0.08
		}
	}
	// Penalty: repeated zero-payload 443/TCP closures smell like TLS reset.
	if !input.IsUDP && input.DestPort == 443 && input.UploadTotal+input.DownloadTotal < 0.01 && input.Success > 3 {
		quality -= 0.15
	}
	quality = clamp(quality, -0.20, 0.30)

	// ─── ASN trust bonus ─────────────────────────────────────────────────
	var asnBonus float64
	if input.DestIPASN != "" && !CdnASNs[input.DestIPASN] &&
		input.Success >= 10 && successRate > 0.90 {
		asnBonus = math.Min(0.08, 0.02*math.Log10(float64(input.Success)))
	}

	// ─── composite weight ────────────────────────────────────────────────
	composite := baseWeight * (1 +
		trafficFactor*params.trafficWeight +
		durationFactor*params.durationWeight +
		quality*params.qualityWeight +
		asnBonus) * efficiencyFactor * priorityFactor

	// ─── RECENT-WINDOW PENALTY (VividCortex/ewma signals) ────────────────
	// Short-horizon moving averages maintained by AtomicStatsRecord catch
	// "just got worse" before the lifetime Welford mean has enough weight
	// to swing. We translate them to a multiplicative penalty in
	// [recentMinMul, 1.0] so a node that looks fine on paper but is
	// currently flapping drops out of the top ranks within a dozen dials.
	//
	// Multiplicative instead of additive because the composite has already
	// been through trafficFactor + quality + asnBonus adjustments; a
	// straight addition would stack explosively on already-high scores.
	//
	// Both signals are skipped when they haven't warmed up (value == 0)
	// or when lifetime counters are too sparse to give them context.
	composite *= recentPenaltyMultiplier(input, latency)

	// ─── CONFIDENCE FACTOR ───────────────────────────────────────────────
	// Low-sample nodes are untrustworthy regardless of their raw score.
	// sampleConfidence(n) = 1 - 1/√(n+1), so n=2 → 0.42, n=10 → 0.70,
	// n=50 → 0.86, n=200 → 0.93, n=1000 → 0.97. Multiplied in to drag
	// fresh-but-lucky nodes toward zero until enough evidence accumulates.
	//
	// The drag is bounded below by (1 - maxConfidenceDampening) = 0.70
	// so even a single-sample node still gets 70% of its raw score —
	// otherwise cold-start nodes would be stuck at the bottom forever.
	confidence := sampleConfidence(total)
	composite *= math.Max(1.0-maxConfidenceDampening, confidence)

	// ─── scene hard floors ───────────────────────────────────────────────
	if params.maxLatencyMS > 0 && latency > params.maxLatencyMS {
		composite = math.Min(composite, AllowedWeight*0.95)
	}
	if params.maxConnectTimeMS > 0 && connectTime > params.maxConnectTimeMS {
		composite = math.Min(composite, AllowedWeight*0.95)
	}
	if params.minSuccessRate > 0 && successRate < params.minSuccessRate {
		deficit := params.minSuccessRate - successRate
		composite *= math.Max(0.3, 1.0-deficit*2.0)
	}

	if composite < 0 {
		return 0, false
	}
	return composite, false
}

// wilsonLowerBound computes the lower bound of the Wilson score interval
// at z = 1.645 (90% confidence). For low n with high success ratio this
// returns much lower than the naive success/n — which is exactly the
// pessimism we want to avoid over-trusting small samples.
//
// Formula:
//   p̂ = s / n
//   numerator = p̂ + z²/(2n) - z·√((p̂(1-p̂) + z²/(4n))/n)
//   denominator = 1 + z²/n
//   lower = numerator / denominator
func wilsonLowerBound(success, n float64) float64 {
	if n <= 0 {
		return 0
	}
	phat := success / n
	z2 := wilsonZSq
	inner := (phat*(1-phat) + z2/(4*n)) / n
	if inner < 0 {
		inner = 0
	}
	num := phat + z2/(2*n) - math.Sqrt(z2)*math.Sqrt(inner)
	den := 1 + z2/n
	lower := num / den
	return clamp(lower, 0, 1)
}

// sampleConfidence maps sample count to a [0, 1] trust score. Converges
// to 1 as n grows. Formula: 1 - 1/√(n+1).
func sampleConfidence(n int64) float64 {
	if n <= 0 {
		return 0
	}
	return 1.0 - 1.0/math.Sqrt(float64(n)+1)
}

// recentPenaltyMultiplier turns the two short-window EWMA signals into
// a single multiplier in [recentMinMul, 1.0] for the composite weight.
//
// Two triggers, each contributing at most half of the total drag:
//
//  1. Recent RTT much worse than long-term latency: if ShortRTT is
//     ≥ recentRTTBadRatio × long-term latency AND the ShortRTT is above
//     a meaningful absolute floor (to avoid over-reacting when both are
//     tiny), scale down by up to recentPenaltyMax × 0.5.
//
//  2. Recent success rate dropped well below 1.0: applied only after
//     the lifetime counters have enough samples to compare against
//     (shortEnoughSamples). Drag proportional to (1 - shortSuccessRate)
//     up to recentPenaltyMax × 0.5.
//
// Both signals are gated on Value() > 0 because VividCortex/ewma treats
// zero as "uninitialized" — we don't want the first few dials of a
// freshly-constructed record to look artificially awful.
func recentPenaltyMultiplier(input *ModelInput, latencyMS int64) float64 {
	const (
		recentPenaltyMax     = 0.30 // max total drag = 30 %
		recentRTTBadRatio    = 1.50 // shortRTT / longTerm >= 1.5 triggers
		recentRTTAbsFloorMS  = 80.0 // don't react when both are tiny
		recentSuccessFloor   = 0.95 // below 0.95 starts penalising
		shortEnoughSamples   = 10   // need ≥10 lifetime samples to judge
	)
	recentMinMul := 1.0 - recentPenaltyMax

	drag := 0.0
	if input.ShortRTT > recentRTTAbsFloorMS && float64(latencyMS) > 0 {
		if ratio := input.ShortRTT / float64(latencyMS); ratio >= recentRTTBadRatio {
			// Saturate via tanh so a 10× ratio doesn't pin drag at max.
			drag += (recentPenaltyMax * 0.5) * math.Tanh(ratio-recentRTTBadRatio)
		}
	}
	if input.ShortSuccessRate > 0 && input.Success+input.Failure >= shortEnoughSamples &&
		input.ShortSuccessRate < recentSuccessFloor {
		deficit := recentSuccessFloor - input.ShortSuccessRate
		drag += (recentPenaltyMax * 0.5) * clamp(deficit/recentSuccessFloor, 0, 1)
	}
	mul := 1.0 - drag
	if mul < recentMinMul {
		return recentMinMul
	}
	return mul
}

// jitterCost maps coefficient-of-variation (σ/μ) to a penalty in [0, 1].
// cv<0.1 → ~0 (no penalty), cv=0.3 → 0.18, cv=1.0 → 0.50, cv=2.0 → 0.67.
// Saturates via tanh so extreme CVs don't produce unbounded penalties.
func jitterCost(cv float64) float64 {
	if cv <= 0.10 {
		return 0
	}
	// tanh(cv-0.1) — smooth saturation around cv=1-2.
	return math.Tanh(cv - 0.10)
}

// identifyConnectionScene is the expanded scene classifier. Seven scenes:
// realtime / voip / interactive / streaming / transfer / api / web.
//
// Decision order matters — the first matching rule wins. Critical: latency
// is NOT used as a classification gate (that would cause circular reasoning
// where a gaming-with-high-latency session falls to "web" and escapes the
// realtime latency floor). Scenes are classified by traffic SHAPE (what
// the connection IS, by byte patterns + port hints). The returned scene's
// maxLatencyMS / maxConnectTimeMS floors do the "too slow" enforcement.
func identifyConnectionScene(
	isUDP bool,
	latency int64,
	uploadMB, downloadMB, maxUploadRateKB, maxDownloadRateKB, durationMinutes float64,
	destPort uint16,
) string {
	total := uploadMB + downloadMB
	realtimePort := isRealtimePort(destPort)
	voipPort := isVoipPort(destPort)

	// ── Realtime: games. UDP + small bytes/min + persistent + symmetric.
	if isUDP && durationMinutes > 0.3 &&
		total > 0.01 && total < 50 &&
		maxUploadRateKB < 3000 && maxDownloadRateKB < 3000 {
		if realtimePort {
			return "realtime"
		}
		ratio := 0.0
		if downloadMB > 0 {
			ratio = uploadMB / downloadMB
		}
		if ratio > 0.3 && ratio < 3.0 {
			return "realtime"
		}
	}

	// ── Voip: UDP + very low bytes.
	if isUDP && durationMinutes > 0.3 &&
		total < 20 && total > 0.005 &&
		maxUploadRateKB < 800 && maxDownloadRateKB < 800 {
		if voipPort {
			return "voip"
		}
		if latency > 0 && latency < 250 {
			return "voip"
		}
	}

	// ── Interactive: SSH/remote-desktop — TCP, low latency, small bytes, long duration.
	if (isUDP && latency < 150 && durationMinutes > 3 &&
		uploadMB > 0.2 && downloadMB > 0.2 &&
		maxUploadRateKB > 200 && maxDownloadRateKB > 200 &&
		total/durationMinutes > 0.1 && total/durationMinutes < 10) ||
		(!isUDP && latency < 250 && durationMinutes > 3 &&
			uploadMB > 0.1 && downloadMB > 0.1 &&
			uploadMB < 150 && downloadMB < 150 &&
			ratioInRange(uploadMB, downloadMB, 0.2, 5.0) &&
			maxUploadRateKB > 150 && maxDownloadRateKB > 150 &&
			total/durationMinutes > 0.05 && total/durationMinutes < 15) {
		return "interactive"
	}

	// ── Streaming: download-heavy with strong asymmetry. Tested BEFORE
	//    transfer so Netflix-like sustained watching doesn't get misread.
	if durationMinutes > 1 {
		downThroughput := downloadMB / durationMinutes
		upMB := math.Max(0.001, uploadMB)
		if (downloadMB > 60 && downloadMB/upMB > 3 && maxDownloadRateKB > 2000 && maxDownloadRateKB/math.Max(1, maxUploadRateKB) > 4 && downThroughput > 5) ||
			(downloadMB > 15 && downloadMB/upMB > 3 && maxDownloadRateKB > 1000 && maxDownloadRateKB/math.Max(1, maxUploadRateKB) > 3 && downThroughput > 2) {
			return "streaming"
		}
	}

	// ── Transfer: bulk uploads / downloads.
	if (uploadMB > 100 || downloadMB > 100 || maxUploadRateKB > 5000) && durationMinutes > 0.5 {
		throughput := total / durationMinutes
		if throughput > 5 {
			return "transfer"
		}
	}

	// ── Api: short TCP request-response.
	if !isUDP && durationMinutes < 1 && total < 1 && destPort != 443 && destPort != 80 {
		if destPort == 8080 || destPort == 8443 || destPort == 3000 || destPort == 5000 ||
			(destPort >= 10000 && destPort < 60000) {
			return "api"
		}
	}

	return "web"
}

// ratioInRange returns true when a/b lies in [low, high], safe against b=0.
func ratioInRange(a, b, low, high float64) bool {
	if b <= 0 {
		return false
	}
	r := a / b
	return r >= low && r <= high
}

// clamp caps x into [lo, hi].
func clamp(x, lo, hi float64) float64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

// isRealtimePort reports whether port is a well-known game/realtime UDP
// endpoint. Covers Steam, Battle.net, Riot, Epic, Minecraft + WebRTC STUN.
func isRealtimePort(p uint16) bool {
	switch p {
	case 3478, 3479, // STUN / TURN (WebRTC)
		5349,                                // STUNS
		27015, 27016, 27017, 27018, 27019,   // Steam
		3074,                                // Xbox Live / Warzone
		6112, 6113, 6114,                    // Battle.net legacy
		5060, 5061,                          // SIP (sometimes realtime)
		25565,                               // Minecraft
		7777, 7778, 7779,                    // UT / ARK / KF
		19132, 19133,                        // Minecraft Bedrock
		8767, 8768,                          // TeamSpeak voice
		9987:                                // TeamSpeak 3 voice
		return true
	}
	// Riot games: 5000-5500 range for League / Valorant.
	if p >= 5000 && p <= 5500 {
		return true
	}
	return false
}

// isVoipPort reports whether port is a common VoIP/calling endpoint.
func isVoipPort(p uint16) bool {
	switch p {
	case 5060, 5061, // SIP
		3478, 5349,                   // STUN (WebRTC)
		10000, 10001, 10002, 10003,   // Zoom / generic media
		3480, 3481:                   // misc voip
		return true
	}
	return false
}

func calculateTrafficFactor(trafficMB, maxRateKB, durationMinutes float64, isShort bool) float64 {
	if trafficMB <= 0 || durationMinutes <= 0 {
		return 0.0
	}

	var baseFactor float64
	switch {
	case trafficMB < 0.005:
		baseFactor = 0.10 + 0.05*math.Log10(trafficMB/0.001)
	case trafficMB < 0.01:
		baseFactor = 0.18 + 0.08*math.Log10(trafficMB/0.005)
	case trafficMB < 0.05:
		baseFactor = 0.35 + 0.10*math.Log10(trafficMB/0.01)
	case trafficMB < 0.1:
		baseFactor = 0.53 + 0.15*math.Log10(trafficMB/0.05)
	case trafficMB < 0.5:
		baseFactor = 0.72 + 0.18*math.Log10(trafficMB/0.1)
	case trafficMB < 1:
		baseFactor = 0.98 + 0.15*math.Log10(trafficMB/0.5)
	case trafficMB < 5:
		baseFactor = 1.18 + 0.10*math.Log10(trafficMB/1)
	case trafficMB < 20:
		baseFactor = 1.32 + 0.08*math.Log10(trafficMB/5)
	case trafficMB < 100:
		baseFactor = 1.45 + 0.06*math.Log10(trafficMB/20)
	case trafficMB < 500:
		baseFactor = 1.56 + 0.05*math.Log10(trafficMB/100)
	case trafficMB < 3000:
		baseFactor = 1.66 + 0.04*math.Log10(trafficMB/500)
	default:
		baseFactor = 1.74 + 0.02*math.Log10(trafficMB/3000)
	}

	var rateBonus float64
	switch {
	case maxRateKB < 20:
		rateBonus = 1.0 + 0.05*(maxRateKB/20.0)
	case maxRateKB < 100:
		rateBonus = 1.05 + 0.05*((maxRateKB-20)/80.0)
	case maxRateKB < 500:
		rateBonus = 1.10 + 0.05*((maxRateKB-100)/400.0)
	case maxRateKB < 2000:
		rateBonus = 1.15 + 0.05*((maxRateKB-500)/1500.0)
	case maxRateKB < 5000:
		rateBonus = 1.20 + 0.04*((maxRateKB-2000)/3000.0)
	case maxRateKB < 20000:
		rateBonus = 1.24 + 0.04*((maxRateKB-5000)/15000.0)
	case maxRateKB < 100000:
		rateBonus = math.Min(1.32, 1.28+0.03*math.Log10(maxRateKB/20000.0))
	default:
		rateBonus = math.Min(1.36, 1.32+0.02*math.Log10(maxRateKB/100000.0))
	}
	baseFactor *= rateBonus

	connectionFactor := 1.0
	throughput := trafficMB / math.Max(1.0, durationMinutes)
	if isShort {
		connectionFactor = 0.85 + 0.15*math.Min(1, throughput/25.0)
	} else if throughput > 5 {
		baseFactor *= 1.0 + 0.15*math.Min(1, (throughput-5)/80.0)
	}

	return math.Min(1.25, baseFactor*connectionFactor)
}

// GetTimeDecay computes a 0..1 weight multiplier for historical stats
// based on how long ago the sample was last refreshed.
//
// Default (post-refactor): smooth exponential decay with a half-life
// of 168 h (7 days). decay = 2^(-elapsedHours / halfLife), floored at
// minDecay. The 168 h half-life is chosen so the new curve crosses the
// old piecewise curve near its midpoint (old: decay=0.5 at 7 d; new:
// decay=0.5 at 7 d) — keeps selection-volume distribution close to
// legacy builds while eliminating the hard plateau transitions that
// caused measurable reselection jitter on records that straddled a
// boundary (e.g. exactly 72 h).
//
// Legacy (SMART_LEGACY=1): piecewise linear plateaus (24 h full → 72 h
// 80 % → 7 d 50 % → 30 d 10 %), bit-identical to prior builds. Used as
// the regression baseline during rollout; will be removed once the
// exponential path is validated.
//
// Why not pull in an EWMA library: EWMA (VividCortex/ewma and peers)
// averages a stream of SAMPLES, not a weight-from-elapsed-time; it has
// no natural fit for "how stale is this single stored datapoint".
// Evaluating an exp decay is one math.Exp2 — no state, no library.
//
// Override: SMART_DECAY_HALF_LIFE_HOURS env var adjusts half-life for
// ops who want shorter/longer memory (range 1..8760 h = 1y).
func GetTimeDecay(lastUsedTime, now int64, minDecay float64) float64 {
	// Fuzzy-round to the hour boundary so two dials within the same
	// minute yield identical decay (reduces ordering noise in ranking).
	fuzzy := (lastUsedTime / 3600) * 3600
	hours := float64(now-fuzzy) / 3600.0
	if hours < 0 {
		hours = 0
	}

	if LegacyMode() {
		return legacyTimeDecay(hours, minDecay)
	}

	halfLife := timeDecayHalfLifeHours()
	decay := math.Exp2(-hours / halfLife)
	return math.Max(minDecay, decay)
}

// GetTimeDecayAdaptive is the sample-count-aware variant of
// GetTimeDecay. The base halfLife is multiplied by
// adaptiveHalfLifeScale(n) so records with few samples decay slowly
// (retain their sparse signal) and records with many samples decay
// faster (adapt quickly to recent behaviour).
//
// n is typically Success + Failure. Pass 0 to keep the non-adaptive
// behaviour — adaptiveHalfLifeScale returns adaptiveScaleMax in that
// case, which collapses back to GetTimeDecay when combined with a
// base halfLife.
//
// Legacy mode (SMART_LEGACY=1) ignores n entirely and returns the
// piecewise curve for A/B parity.
func GetTimeDecayAdaptive(lastUsedTime, now int64, minDecay float64, n int64) float64 {
	fuzzy := (lastUsedTime / 3600) * 3600
	hours := float64(now-fuzzy) / 3600.0
	if hours < 0 {
		hours = 0
	}
	if LegacyMode() {
		return legacyTimeDecay(hours, minDecay)
	}
	halfLife := timeDecayHalfLifeHours() * adaptiveHalfLifeScale(n)
	decay := math.Exp2(-hours / halfLife)
	return math.Max(minDecay, decay)
}

// GetTimeDecayForFailure computes the decay factor for the failure
// half of a record's observations. The halfLife is scaled by both
// adaptiveHalfLifeScale(n) AND failureStickyFactor (default 2.0), so
// negative samples outlast positive ones and a node that just burned
// us stays pessimistically weighted longer than it stays optimistic.
//
// Call site pattern in CalculateWeight:
//
//	decayedSuccess := Success * GetTimeDecayAdaptive(...)
//	decayedFailure := Failure * GetTimeDecayForFailure(...)
//	wilson(decayedSuccess, decayedN)  // biased toward pessimism
//
// Legacy mode falls back to the piecewise curve (no stickiness).
func GetTimeDecayForFailure(lastUsedTime, now int64, minDecay float64, n int64) float64 {
	fuzzy := (lastUsedTime / 3600) * 3600
	hours := float64(now-fuzzy) / 3600.0
	if hours < 0 {
		hours = 0
	}
	if LegacyMode() {
		return legacyTimeDecay(hours, minDecay)
	}
	halfLife := timeDecayHalfLifeHours() * adaptiveHalfLifeScale(n) * failureStickyFactor()
	decay := math.Exp2(-hours / halfLife)
	return math.Max(minDecay, decay)
}

// legacyTimeDecay implements the pre-refactor piecewise-linear curve.
// Preserved verbatim so SMART_LEGACY=1 is bit-for-bit equivalent to
// previous builds — used as the regression baseline during rollout.
func legacyTimeDecay(hours, minDecay float64) float64 {
	var decay float64
	switch {
	case hours <= 24:
		decay = 1.0
	case hours <= 72:
		decay = 1.0 - (hours-24.0)/48.0*0.2
	case hours <= 168:
		decay = 0.8 - (hours-72.0)/96.0*0.3
	case hours <= 720:
		decay = 0.5 - (hours-168.0)/552.0*0.2
	default:
		decay = 0.1
	}
	return math.Max(minDecay, decay)
}
