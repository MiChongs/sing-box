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
// Returns (weight, true) on successful ML prediction; on any failure (nil
// model, NaN, panic, insufficient samples), falls back to
// smart.CalculateWeight(input, priorityFactor) and returns its (weight, false).
func (m *WeightModel) PredictWeight(input *smart.ModelInput, priorityFactor float64) (float64, bool) {
	if m == nil {
		return smart.CalculateWeight(input, priorityFactor)
	}

	// Minimum sample gate: mihomo parity
	total := input.Success + input.Failure
	if total < smart.DefaultMinSampleCount {
		return 0, false
	}

	m.mu.RLock()
	model := m.model
	transforms := m.transforms
	m.mu.RUnlock()

	if model == nil {
		return smart.CalculateWeight(input, priorityFactor)
	}

	features := PrepareFeatures(input)
	if len(features) == 0 {
		return smart.CalculateWeight(input, priorityFactor)
	}

	if transforms != nil && transforms.TransformsEnabled {
		features = transforms.ApplyTransforms(features)
	}

	var prediction float64
	var panicked bool

	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		prediction = model.PredictSingle(features, 0)
	}()

	if panicked || math.IsNaN(prediction) || prediction <= 0 {
		return smart.CalculateWeight(input, priorityFactor)
	}

	return prediction * priorityFactor, true
}
