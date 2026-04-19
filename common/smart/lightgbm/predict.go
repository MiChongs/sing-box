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
	return predFull * priorityFactor, true, confidence
}
