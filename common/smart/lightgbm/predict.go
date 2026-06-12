package lightgbm

import (
	"fmt"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dmitryikh/leaves"
	"github.com/sagernet/sing-box/common/smart"
)

// WeightModel wraps a loaded LightGBM ensemble with its feature transforms.
// Mu-protected to allow atomic hot-reload under concurrent PredictWeight calls.
type WeightModel struct {
	path       string
	model      *leaves.Ensemble
	transforms *FeatureTransforms
	lastUpdate time.Time
	mu         sync.RWMutex

	// reloadInFlight guards against concurrent reload requests.
	reloadInFlight atomic.Bool

	// predCache memoises recent inference results keyed by a caller-
	// supplied (node|target) string. On a busy group the SAME (node,
	// target) pair closes many connections per second, and its feature
	// vector barely moves between them — recomputing the full tree walk
	// each time was a top CPU consumer at high QPS. Entries carry a
	// timestamp; PredictWeightCached treats them as valid for a short
	// TTL chosen by the caller. sync.Map keeps reads lock-free; values
	// are small predCacheEntry structs stored by value.
	predCache sync.Map // map[string]predCacheEntry
}

// predCacheEntry is one memoised inference: the priority-INDEPENDENT base
// prediction plus its confidence and capture time. priorityFactor is
// applied by the caller after the cache lookup so per-dial priority/pin
// boosts still compose correctly on top of a cached base.
type predCacheEntry struct {
	base       float64
	confidence float64
	atNS       int64
}

// NewWeightModel creates an empty WeightModel bound to a model file path.
// Call Load() to actually read the .bin from disk.
func NewWeightModel(path string) *WeightModel {
	return &WeightModel{path: path}
}

// Path returns the on-disk path for the model file.
func (m *WeightModel) Path() string { return m.path }

// LastUpdate returns the last time the model was successfully (re)loaded.
func (m *WeightModel) LastUpdate() time.Time {
	if m == nil {
		return time.Time{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastUpdate
}

// IsLoaded reports whether a model is currently loaded in memory.
func (m *WeightModel) IsLoaded() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.model != nil
}

// Load reads the .bin file from m.path, parses transforms, and atomically
// swaps in the new model+transforms under the write lock.
func (m *WeightModel) Load() error {
	if m == nil {
		return fmt.Errorf("nil WeightModel")
	}
	if _, err := os.Stat(m.path); err != nil {
		return fmt.Errorf("model file unavailable: %v", err)
	}

	model, err := leaves.LGEnsembleFromFile(m.path, false)
	if err != nil {
		return fmt.Errorf("load binary model: %v", err)
	}

	transforms, err := LoadTransformsFromModel(m.path)
	if err != nil {
		// non-fatal: fall back to disabled transforms
		transforms = &FeatureTransforms{
			TransformsEnabled: false,
			FeatureOrder:      getDefaultFeatureOrder(),
			Transforms:        []TransformParams{},
		}
	} else if transforms.TransformsEnabled {
		if err := transforms.ValidateTransforms(MaxFeatureSize); err != nil {
			transforms.TransformsEnabled = false
		}
	}

	m.mu.Lock()
	m.model = model
	m.transforms = transforms
	m.lastUpdate = time.Now()
	m.mu.Unlock()
	return nil
}

// Reload re-reads the model file from disk. Safe to call concurrently;
// redundant callers return immediately while one reload is in flight.
func (m *WeightModel) Reload() error {
	if m == nil {
		return fmt.Errorf("nil WeightModel")
	}
	if !m.reloadInFlight.CompareAndSwap(false, true) {
		return nil // another reload in progress
	}
	defer m.reloadInFlight.Store(false)
	return m.Load()
}

// PredictWeight runs inference: ModelInput → features → transforms → model.
// Returns:
//
//	weight     — final weight (= prediction * priorityFactor), or the
//	             non-ML fallback weight when prediction is unavailable.
//	predicted  — true ⇔ the value came from the LightGBM model;
//	             false ⇔ it came from smart.CalculateWeight fallback.
//	confidence — inter-iteration agreement of the ensemble for this input,
//	             in the range [0, 1]. Computed as 1/(1+|predFull−predHalf|),
//	             where predHalf uses only the first n/2 trees and predFull
//	             uses all trees. High confidence ⇒ the back half of the
//	             ensemble barely shifted the prediction (input lies in a
//	             region the early trees already classified well). Low
//	             confidence ⇒ the late trees made large corrections, hinting
//	             the input is in a noisy / under-trained region; callers
//	             may down-weight the prediction or fall back to delay-based
//	             ranking. Returns 0 when no prediction was made.
func (m *WeightModel) PredictWeight(input *smart.ModelInput, priorityFactor float64) (weight float64, predicted bool, confidence float64) {
	base, predicted, confidence := m.predictBase(input, priorityFactor)
	if !predicted {
		return base, predicted, confidence
	}
	return base * priorityFactor, true, confidence
}

// PredictWeightCached is PredictWeight with a short-TTL memo keyed by
// `key` (caller composes it from node+target so distinct destinations
// don't collide). On a hit within ttl it skips the tree walk entirely and
// just re-applies priorityFactor to the cached base prediction. ttl<=0 or
// an empty key disables caching and falls through to PredictWeight.
//
// Correctness note: the cached base is priority-independent, so per-dial
// pin/priority boosts still apply on top. The only staleness is in the
// feature-derived base, which moves negligibly over a few-second TTL given
// the EWMA smoothing the caller already applies downstream.
func (m *WeightModel) PredictWeightCached(input *smart.ModelInput, priorityFactor float64, key string, ttl time.Duration) (weight float64, predicted bool, confidence float64) {
	if m == nil || key == "" || ttl <= 0 {
		return m.PredictWeight(input, priorityFactor)
	}
	nowNS := time.Now().UnixNano()
	if v, ok := m.predCache.Load(key); ok {
		e := v.(predCacheEntry)
		if nowNS-e.atNS < int64(ttl) {
			return e.base * priorityFactor, true, e.confidence
		}
	}
	base, ok, conf := m.predictBase(input, priorityFactor)
	if !ok {
		// Don't cache fallbacks/gated results — they must re-evaluate
		// as soon as the node accrues enough samples.
		return base, ok, conf
	}
	m.predCache.Store(key, predCacheEntry{base: base, confidence: conf, atNS: nowNS})
	return base * priorityFactor, true, conf
}

// PrunePredCache drops memoised inference entries older than maxAge so the
// cache can't retain tags for nodes/targets that have gone quiet. Cheap
// O(entries) sweep; intended to be called from an existing janitor tick.
func (m *WeightModel) PrunePredCache(maxAge time.Duration) {
	if m == nil || maxAge <= 0 {
		return
	}
	cutoff := time.Now().UnixNano() - int64(maxAge)
	m.predCache.Range(func(k, v any) bool {
		if v.(predCacheEntry).atNS < cutoff {
			m.predCache.Delete(k)
		}
		return true
	})
}

// predictBase runs the model and returns the priority-INDEPENDENT base
// prediction (predFull, before any priorityFactor multiply), along with
// whether the model produced it and the confidence. The non-ML fallback
// path returns the already-priority-applied CalculateWeight value with
// predicted=false — callers must NOT multiply by priorityFactor again in
// that case (PredictWeight / PredictWeightCached both guard on the flag).
func (m *WeightModel) predictBase(input *smart.ModelInput, priorityFactor float64) (base float64, predicted bool, confidence float64) {
	if m == nil {
		w, p := smart.CalculateWeight(input, priorityFactor)
		return w, p, 0
	}

	// Minimum sample gate: mihomo parity
	total := input.Success + input.Failure
	if total < smart.DefaultMinSampleCount {
		return 0, false, 0
	}

	m.mu.RLock()
	model := m.model
	transforms := m.transforms
	m.mu.RUnlock()

	if model == nil {
		w, p := smart.CalculateWeight(input, priorityFactor)
		return w, p, 0
	}

	features := PrepareFeatures(input)
	if len(features) == 0 {
		w, p := smart.CalculateWeight(input, priorityFactor)
		return w, p, 0
	}

	// Backward compat: if model was trained with fewer features (e.g. 27-dim
	// legacy), truncate to what the model expects. New 35-dim models use the
	// full vector.
	if numFeat := model.NFeatures(); numFeat > 0 && numFeat < len(features) {
		features = features[:numFeat]
	}

	if transforms != nil && transforms.TransformsEnabled {
		features = transforms.ApplyTransforms(features)
	}

	var (
		predFull, predHalf float64
		panicked           bool
	)

	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		predFull = model.PredictSingle(features, 0)
		// Half-ensemble probe — guarded against degenerate models with
		// fewer than 2 trees (computing |full−half| over the same tree
		// set would always yield 0 confidence which is misleading).
		if nTrees := model.NEstimators(); nTrees >= 2 {
			predHalf = model.PredictSingle(features, nTrees/2)
		} else {
			predHalf = predFull
		}
	}()

	if panicked || math.IsNaN(predFull) || predFull <= 0 {
		w, p := smart.CalculateWeight(input, priorityFactor)
		return w, p, 0
	}

	// Confidence collapses to 1.0 when the back half of the ensemble does
	// not move the prediction at all, and approaches 0 as the correction
	// magnitude grows. Bounded in (0, 1]; never NaN.
	confidence = 1.0 / (1.0 + math.Abs(predFull-predHalf))
	// Return the priority-INDEPENDENT base; callers apply priorityFactor.
	return predFull, true, confidence
}
