package lightgbm

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/common/smart"
)

// Catalog slots past the MaxFeatureSize layout of PrepareFeatures. Models
// reach them only by naming them in feature_names.
const (
	// slotHistoryDuration is history_duration_minutes: log1p of the
	// record's smoothed connection duration.
	slotHistoryDuration = MaxFeatureSize + iota
	// slotLossRate is loss_rate: the recorded connection's TCP
	// retransmission rate.
	slotLossRate
	// slotCumulLossRate is cumul_loss_rate: the record's retransmission
	// rate across all its connections.
	slotCumulLossRate
	// slotLastDuration is duration_minutes as layouts that also name
	// history_duration_minutes define it: log1p of the recorded
	// connection's own duration.
	slotLastDuration
	catalogSize
)

// featureSlots maps every feature name a model may use to the catalog slot
// computing it.
var featureSlots = func() map[string]int {
	slots := make(map[string]int, catalogSize)
	for i, name := range getDefaultFeatureOrder() {
		slots[name] = i
	}
	slots["history_duration_minutes"] = slotHistoryDuration
	slots["loss_rate"] = slotLossRate
	slots["cumul_loss_rate"] = slotCumulLossRate
	return slots
}()

// unnamedFeature matches the names LightGBM assigns when a model is trained
// without feature names.
var unnamedFeature = regexp.MustCompile(`^Column_\d+$`)

// resolveLayout returns, for each of a model's nFeatures inputs, the catalog
// slot that computes it, matching names from the model's feature_names.
// Models without real names are read positionally against the
// PrepareFeatures layout.
func resolveLayout(names []string, nFeatures int) ([]int, error) {
	if len(names) != 0 && len(names) != nFeatures {
		return nil, fmt.Errorf("feature_names lists %d features, model uses %d", len(names), nFeatures)
	}
	layout := make([]int, nFeatures)
	if !hasFeatureNames(names) {
		if nFeatures > MaxFeatureSize {
			return nil, fmt.Errorf("model has %d unnamed features, at most %d are known", nFeatures, MaxFeatureSize)
		}
		for i := range layout {
			layout[i] = i
		}
		return layout, nil
	}
	// Layouts carrying history_duration_minutes (vernesong/mihomo models
	// from 2026 on) define duration_minutes as the recorded connection's
	// own duration; older layouts as the smoothed average.
	splitDuration := slices.Contains(names, "history_duration_minutes")
	var unknown []string
	for i, name := range names {
		slot, ok := featureSlots[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		if splitDuration && name == "duration_minutes" {
			slot = slotLastDuration
		}
		layout[i] = slot
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("model uses features this build cannot compute: %s", strings.Join(unknown, ", "))
	}
	return layout, nil
}

// layoutFeatures returns the model input vector for input: the catalog
// value of each slot in layout.
func layoutFeatures(input *smart.ModelInput, layout []int) []float64 {
	var catalog [catalogSize]float64
	all := fillCatalog(input, catalog[:0])
	features := make([]float64, len(layout))
	for i, slot := range layout {
		features[i] = all[slot]
	}
	return features
}

func hasFeatureNames(names []string) bool {
	for _, name := range names {
		if !unnamedFeature.MatchString(name) {
			return true
		}
	}
	return false
}

// readFeatureNames returns the feature_names of a LightGBM text model, read
// from the header before the first tree; nil when the header has none.
func readFeatureNames(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if value, found := strings.CutPrefix(line, "feature_names="); found {
			return strings.Fields(value), nil
		}
		if strings.HasPrefix(line, "Tree=") || err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
	}
}
