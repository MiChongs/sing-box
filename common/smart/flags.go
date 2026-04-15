package smart

import (
	"math"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

// Runtime flags for the Smart strategy group.
//
// These are all read from environment variables at process start and
// cached in atomics so the hot path (weight calculation, cache sizing,
// etc.) can query them without re-parsing env every call. Reloading is
// exposed via RefreshFlags for tests that want to flip a flag mid-run.
//
// Env vars handled here:
//
//   - SMART_LEGACY=1           keep the pre-refactor selection/decay math
//   - SMART_CACHE_BUDGET_MB=N  override total cache budget across the
//                              five in-process LRU/ristretto caches
//                              (read directly in store.go resolveCacheBudget)
//
// Keep the set small. Each flag is an explicit opt-out for a behavior
// change, not a feature gate — the "right" path is always the default.

var (
	smartLegacy       atomic.Bool
	timeDecayHalfLife atomic.Uint64 // math.Float64bits for lock-free float read
)

// defaultTimeDecayHalfLifeHours is the exponential-decay half-life used
// by GetTimeDecay when SMART_DECAY_HALF_LIFE_HOURS is unset. 168 h = 7 d,
// chosen to match the midpoint of the pre-refactor piecewise curve.
const defaultTimeDecayHalfLifeHours = 168.0

// Adaptive-halfLife tuning constants.
//
// adaptiveDecayReferenceN: sample count at which the adaptive scale is
// exactly 1.0 (i.e. we use the unmodified base halfLife). Picked to be
// slightly above DefaultMinSampleCount (2) so statistically meaningful
// records treat halfLife at its nominal value.
//
// adaptiveScaleMin/Max: clamp range. Without clamping, a record with
// thousands of dials would compress halfLife toward zero (decay too
// aggressive) and a record with zero dials would stretch it to
// infinity (never decays). The bounds pick a sane trade-off that
// keeps the selection behaviour stable on both extremes.
const (
	adaptiveDecayReferenceN = 20
	adaptiveScaleMin        = 0.5
	adaptiveScaleMax        = 3.0

	// failureStickyFactor multiplies the (already adaptive) halfLife
	// when computing the failure-side decay. Rationale: positive and
	// negative observations don't have symmetric utility — once a
	// node has burned you, the pessimism SHOULD outlast the optimism.
	// 2.0 is a conservative starting point matched to operator
	// intuition; tune via SMART_FAILURE_STICKY env var.
	defaultFailureStickyFactor = 2.0
)

// adaptiveHalfLifeScale returns a multiplier in
// [adaptiveScaleMin, adaptiveScaleMax] to apply to the base halfLife
// based on sample count n.
//
//	n == 0            → max  (no data; long memory so we don't flush it)
//	n == referenceN   → 1.0  (nominal halfLife)
//	n >> referenceN   → min  (short memory; adapt fast)
//
// Function: scale = clamp(1 + log2(referenceN / max(1, n))).
func adaptiveHalfLifeScale(n int64) float64 {
	if n < 1 {
		return adaptiveScaleMax
	}
	ratio := float64(adaptiveDecayReferenceN) / float64(n)
	scale := 1.0 + math.Log2(ratio)
	if scale < adaptiveScaleMin {
		return adaptiveScaleMin
	}
	if scale > adaptiveScaleMax {
		return adaptiveScaleMax
	}
	return scale
}

// failureStickyFactor returns the multiplier applied on top of the
// adaptive halfLife when computing the failure-side decay. Controlled
// by SMART_FAILURE_STICKY env var (floats in [1.0, 8.0]; out-of-range
// values silently fall back to the default). 1.0 disables the extra
// stickiness; in that case success and failure decay identically.
var failureStickyScale atomic.Uint64 // math.Float64bits

func failureStickyFactor() float64 {
	return math.Float64frombits(failureStickyScale.Load())
}

func parseFailureStickyEnv() float64 {
	raw := strings.TrimSpace(os.Getenv("SMART_FAILURE_STICKY"))
	if raw == "" {
		return defaultFailureStickyFactor
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v < 1.0 || v > 8.0 {
		return defaultFailureStickyFactor
	}
	return v
}

func init() {
	RefreshFlags()
}

// RefreshFlags re-reads the environment and updates cached flag state.
// Idempotent; safe to call concurrently with readers.
func RefreshFlags() {
	smartLegacy.Store(parseBoolEnv("SMART_LEGACY"))
	timeDecayHalfLife.Store(math.Float64bits(parseHalfLifeHoursEnv()))
	failureStickyScale.Store(math.Float64bits(parseFailureStickyEnv()))
}

// LegacyMode reports whether the user opted back into pre-refactor
// behaviour. Hot-path friendly: a single atomic.Bool load.
func LegacyMode() bool { return smartLegacy.Load() }

// timeDecayHalfLifeHours returns the currently-configured decay
// half-life in hours (default 168 h, override via env).
func timeDecayHalfLifeHours() float64 {
	return math.Float64frombits(timeDecayHalfLife.Load())
}

// parseHalfLifeHoursEnv reads SMART_DECAY_HALF_LIFE_HOURS and returns
// a validated positive value, falling back to the default on parse
// errors or out-of-range inputs. Range check guards against absurd
// configs (0 h would divide-by-zero, 9000 h is effectively no decay).
func parseHalfLifeHoursEnv() float64 {
	raw := strings.TrimSpace(os.Getenv("SMART_DECAY_HALF_LIFE_HOURS"))
	if raw == "" {
		return defaultTimeDecayHalfLifeHours
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v < 1 || v > 8760 {
		return defaultTimeDecayHalfLifeHours
	}
	return v
}

func parseBoolEnv(name string) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return false
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
