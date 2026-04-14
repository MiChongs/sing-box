package lightgbm

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// MaxFeatureSize is the fixed 27-dim feature vector size (mihomo parity).
const MaxFeatureSize = 27

// parseTransformsContent parses the [transforms] section from the model file.
// Format documented in mihomo's transform.go — preserved byte-identical for model compatibility.

type TransformType string

const (
	StandardScalerTransform TransformType = "StandardScaler"
	RobustScalerTransform   TransformType = "RobustScaler"
)

type TransformParams struct {
	Type           TransformType        `json:"type"`
	FeatureIndices []int                `json:"feature_indices"`
	Parameters     map[string][]float64 `json:"parameters"`
}

type FeatureTransforms struct {
	TransformsEnabled     bool              `json:"transforms_enabled"`
	FeatureOrder          map[int]string    `json:"order"`
	Transforms            []TransformParams `json:"transforms"`
	UntransformedFeatures []string          `json:"untransformed_features"`
}

var transformPool = sync.Pool{
	New: func() interface{} {
		return make([]float64, MaxFeatureSize)
	},
}

// LoadTransformsFromModel reads the last 16KB of the model file and extracts
// the [transforms] block.
func LoadTransformsFromModel(modelPath string) (*FeatureTransforms, error) {
	file, err := os.Open(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open model file: %v", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %v", err)
	}

	readSize := int64(16384)
	if stat.Size() < readSize {
		readSize = stat.Size()
	}

	if _, err = file.Seek(-readSize, 2); err != nil {
		return nil, fmt.Errorf("failed to seek file position: %v", err)
	}

	buffer := make([]byte, readSize)
	if _, err = file.Read(buffer); err != nil {
		return nil, fmt.Errorf("failed to read file content: %v", err)
	}

	content := string(buffer)
	startMarker := "[transforms]"
	endMarker := "[/transforms]"

	startIdx := strings.Index(content, startMarker)
	if startIdx == -1 {
		return &FeatureTransforms{
			TransformsEnabled: false,
			FeatureOrder:      getDefaultFeatureOrder(),
			Transforms:        []TransformParams{},
		}, nil
	}

	endIdx := strings.Index(content, endMarker)
	if endIdx == -1 {
		return nil, fmt.Errorf("found transforms start marker but no end marker")
	}

	return parseTransformsContent(content[startIdx+len(startMarker) : endIdx])
}

func parseTransformsContent(content string) (*FeatureTransforms, error) {
	ft := &FeatureTransforms{
		FeatureOrder: make(map[int]string),
		Transforms:   []TransformParams{},
	}

	lines := strings.Split(content, "\n")
	currentSection := ""
	transformDefs := make(map[string]map[string]string)

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.Trim(line, "[]")
			if strings.HasPrefix(section, "/") {
				currentSection = ""
			} else {
				currentSection = section
			}
			continue
		}
		if !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch currentSection {
		case "order":
			idx, err := strconv.Atoi(key)
			if err != nil || idx < 0 || idx >= MaxFeatureSize {
				continue
			}
			ft.FeatureOrder[idx] = value
		case "definitions":
			if strings.Contains(key, "_") {
				kp := strings.SplitN(key, "_", 2)
				if len(kp) == 2 {
					transformID, paramName := kp[0], kp[1]
					if transformDefs[transformID] == nil {
						transformDefs[transformID] = make(map[string]string)
					}
					transformDefs[transformID][paramName] = value
				}
			}
		default:
			switch key {
			case "transform":
				ft.TransformsEnabled = value == "true"
			case "untransformed_features":
				ft.UntransformedFeatures = parseStringArray(value)
			}
		}
	}

	for _, params := range transformDefs {
		transform, err := buildTransformParams(params)
		if err != nil || len(transform.FeatureIndices) == 0 {
			continue
		}
		valid := true
		for _, idx := range transform.FeatureIndices {
			if idx < 0 || idx >= MaxFeatureSize {
				valid = false
				break
			}
		}
		if valid {
			ft.Transforms = append(ft.Transforms, *transform)
		}
	}

	if len(ft.FeatureOrder) == 0 {
		ft.FeatureOrder = getDefaultFeatureOrder()
	} else {
		defaultOrder := getDefaultFeatureOrder()
		for idx, name := range defaultOrder {
			if _, ok := ft.FeatureOrder[idx]; !ok {
				ft.FeatureOrder[idx] = name
			}
		}
	}

	return ft, nil
}

func buildTransformParams(params map[string]string) (*TransformParams, error) {
	transform := &TransformParams{
		Parameters: make(map[string][]float64),
	}
	typeStr, ok := params["type"]
	if !ok {
		return nil, fmt.Errorf("missing transform type")
	}
	transform.Type = TransformType(typeStr)

	featuresStr, ok := params["features"]
	if !ok {
		return nil, fmt.Errorf("missing feature indices")
	}
	indices, err := parseIntArray(featuresStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse feature indices: %v", err)
	}
	transform.FeatureIndices = indices

	for paramName, paramValue := range params {
		if paramName == "type" || paramName == "features" {
			continue
		}
		values, err := parseFloatArray(paramValue)
		if err != nil {
			return nil, fmt.Errorf("failed to parse parameter %s: %v", paramName, err)
		}
		transform.Parameters[paramName] = values
	}
	return transform, nil
}

func parseFloatArray(value string) ([]float64, error) {
	if value == "" {
		return []float64{}, nil
	}
	parts := strings.Split(value, ",")
	result := make([]float64, len(parts))
	for i, part := range parts {
		v, err := strconv.ParseFloat(strings.TrimSpace(part), 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse float '%s': %v", part, err)
		}
		result[i] = v
	}
	return result, nil
}

func parseIntArray(value string) ([]int, error) {
	if value == "" {
		return []int{}, nil
	}
	parts := strings.Split(value, ",")
	result := make([]int, len(parts))
	for i, part := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("failed to parse integer '%s': %v", part, err)
		}
		result[i] = v
	}
	return result, nil
}

func parseStringArray(value string) []string {
	if value == "" {
		return []string{}
	}
	parts := strings.Split(value, ",")
	result := make([]string, len(parts))
	for i, part := range parts {
		result[i] = strings.TrimSpace(part)
	}
	return result
}

func getDefaultFeatureOrder() map[int]string {
	return map[int]string{
		0:  "success",
		1:  "failure",
		2:  "connect_time",
		3:  "latency",
		4:  "upload_mb",
		5:  "history_upload_mb",
		6:  "maxuploadrate_kb",
		7:  "history_maxuploadrate_kb",
		8:  "download_mb",
		9:  "history_download_mb",
		10: "maxdownloadrate_kb",
		11: "history_maxdownloadrate_kb",
		12: "duration_minutes",
		13: "last_used_seconds",
		14: "is_udp",
		15: "is_tcp",
		16: "asn_feature",
		17: "country_feature",
		18: "address_feature",
		19: "port_feature",
		20: "traffic_ratio",
		21: "traffic_density",
		22: "connection_type_feature",
		23: "asn_hash",
		24: "host_hash",
		25: "ip_hash",
		26: "geoip_hash",
	}
}

// ApplyTransforms applies enabled scalers to the feature vector.
func (ft *FeatureTransforms) ApplyTransforms(features []float64) []float64 {
	if ft == nil || !ft.TransformsEnabled || len(ft.Transforms) == 0 {
		return features
	}

	var result []float64
	poolObj := transformPool.Get()
	if arr, ok := poolObj.([]float64); ok && len(arr) >= len(features) {
		result = arr[:len(features)]
	} else {
		result = make([]float64, len(features))
	}
	copy(result, features)

	for _, transform := range ft.Transforms {
		valid := true
		for _, idx := range transform.FeatureIndices {
			if idx < 0 || idx >= len(result) {
				valid = false
				break
			}
		}
		if valid {
			ft.applyTransformInPlace(result, transform)
		}
	}

	out := make([]float64, len(result))
	copy(out, result)
	transformPool.Put(result)
	return out
}

func (ft *FeatureTransforms) applyTransformInPlace(features []float64, transform TransformParams) {
	switch transform.Type {
	case StandardScalerTransform:
		ft.applyStandardScaler(features, transform)
	case RobustScalerTransform:
		ft.applyRobustScaler(features, transform)
	}
}

func (ft *FeatureTransforms) applyStandardScaler(features []float64, transform TransformParams) {
	mean := transform.Parameters["mean"]
	scale := transform.Parameters["scale"]
	if len(mean) == 0 || len(scale) == 0 {
		return
	}
	expected := len(transform.FeatureIndices)
	if len(mean) != expected || len(scale) != expected {
		return
	}
	for i, featureIdx := range transform.FeatureIndices {
		if featureIdx < len(features) && i < len(mean) && i < len(scale) && scale[i] != 0 {
			features[featureIdx] = (features[featureIdx] - mean[i]) / scale[i]
		}
	}
}

func (ft *FeatureTransforms) applyRobustScaler(features []float64, transform TransformParams) {
	center := transform.Parameters["center"]
	scale := transform.Parameters["scale"]
	if len(center) == 0 || len(scale) == 0 {
		return
	}
	for i, featureIdx := range transform.FeatureIndices {
		if featureIdx < len(features) && i < len(center) && i < len(scale) && scale[i] != 0 {
			features[featureIdx] = (features[featureIdx] - center[i]) / scale[i]
		}
	}
}

// ValidateTransforms checks that all transforms reference valid feature indices
// and have matching parameter arrays.
func (ft *FeatureTransforms) ValidateTransforms(expectedCount int) error {
	if ft == nil {
		return fmt.Errorf("FeatureTransforms is nil")
	}
	if !ft.TransformsEnabled {
		return nil
	}
	if len(ft.FeatureOrder) == 0 {
		return fmt.Errorf("feature order mapping is empty")
	}
	for i := 0; i < expectedCount; i++ {
		if _, ok := ft.FeatureOrder[i]; !ok {
			return fmt.Errorf("feature index %d missing in feature order mapping", i)
		}
	}
	for i, transform := range ft.Transforms {
		switch transform.Type {
		case StandardScalerTransform, RobustScalerTransform:
		default:
			return fmt.Errorf("transform %d: unsupported type %s", i, transform.Type)
		}
		if len(transform.FeatureIndices) == 0 {
			return fmt.Errorf("transform %d: feature indices list is empty", i)
		}
		for _, idx := range transform.FeatureIndices {
			if idx < 0 || idx >= expectedCount {
				return fmt.Errorf("transform %d: feature index %d out of range", i, idx)
			}
		}
		if err := ft.validateTransformParams(transform); err != nil {
			return fmt.Errorf("transform %d parameter validation failed: %v", i, err)
		}
	}
	return nil
}

func (ft *FeatureTransforms) validateTransformParams(transform TransformParams) error {
	expected := len(transform.FeatureIndices)
	switch transform.Type {
	case StandardScalerTransform:
		mean := transform.Parameters["mean"]
		scale := transform.Parameters["scale"]
		if len(mean) != expected {
			return fmt.Errorf("StandardScaler mean parameter count mismatch")
		}
		if len(scale) != expected {
			return fmt.Errorf("StandardScaler scale parameter count mismatch")
		}
		for i, s := range scale {
			if s == 0 {
				return fmt.Errorf("StandardScaler scale[%d] is zero", i)
			}
		}
	case RobustScalerTransform:
		center := transform.Parameters["center"]
		scale := transform.Parameters["scale"]
		if len(center) != expected {
			return fmt.Errorf("RobustScaler center parameter count mismatch")
		}
		if len(scale) != expected {
			return fmt.Errorf("RobustScaler scale parameter count mismatch")
		}
		for i, s := range scale {
			if s == 0 {
				return fmt.Errorf("RobustScaler scale[%d] is zero", i)
			}
		}
	}
	return nil
}
