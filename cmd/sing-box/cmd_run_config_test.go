package main

import (
	"testing"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func decodeConfigMap(t *testing.T, content []byte) map[string]any {
	t.Helper()
	var root map[string]any
	require.NoError(t, json.Unmarshal(content, &root))
	return root
}

func TestNormalizeConfigContentJSONCKeepsComments(t *testing.T) {
	content := []byte(`{
  // comment
  "log": {"level": "info"} /* block */
}`)
	normalized, err := normalizeConfigContent("config.json", content)
	require.NoError(t, err)
	require.Equal(t, content, normalized)
}

func TestNormalizeConfigContentYAML(t *testing.T) {
	content := []byte(`
x-common: &common
  level: debug
_hidden: 1
log: *common
inbounds:
  - type: mixed
    listen_port: 2080
`)
	normalized, err := normalizeConfigContent("config.yaml", content)
	require.NoError(t, err)
	root := decodeConfigMap(t, normalized)
	require.NotContains(t, root, "x-common")
	require.NotContains(t, root, "_hidden")
	require.Equal(t, map[string]any{"level": "debug"}, root["log"])
	require.Len(t, root["inbounds"], 1)
}

func TestNormalizeConfigContentYAMLWithoutExtension(t *testing.T) {
	normalized, err := normalizeConfigContent("stdin", []byte("log:\n  level: warn\n"))
	require.NoError(t, err)
	require.Equal(t, map[string]any{"level": "warn"}, decodeConfigMap(t, normalized)["log"])
}

func TestNormalizeConfigContentReportsJSONError(t *testing.T) {
	_, err := normalizeConfigContent("config.json", []byte("{\n  \"log\": {\"level\": \"info\n}"))
	require.ErrorContains(t, err, "config syntax check")
}

func TestApplyConfigFilterWithoutFilterKeys(t *testing.T) {
	content := []byte(`{"inbounds": [{"type": "mixed"}]} // trailing`)
	filtered, err := applyConfigFilter(content)
	require.NoError(t, err)
	require.Equal(t, content, filtered)
}

func TestApplyConfigFilterMarks(t *testing.T) {
	content := []byte(`{
  // enable ebpf and tproxy only
  "filter_regex": "ebpf|tproxy",
  "inbounds": [
    {"type": "mixed", "tag": "mixed-in"},
    {"type": "ebpf", "tag": "ebpf-in", "filter_mark": "ebpf"},
    {"type": "tproxy", "tag": "tproxy-in", "filter_mark": ["tproxy"]},
    {"type": "tun", "tag": "tun-in", "filter_mark": "tun"},
    {"type": "redirect", "tag": "both", "filter_mark": ["ebpf", "tun"]}
  ]
}`)
	filtered, err := applyConfigFilter(content)
	require.NoError(t, err)
	root := decodeConfigMap(t, filtered)
	require.NotContains(t, root, "filter_regex")
	var tags []string
	for _, inbound := range root["inbounds"].([]any) {
		inboundMap := inbound.(map[string]any)
		require.NotContains(t, inboundMap, "filter_mark")
		tags = append(tags, inboundMap["tag"].(string))
	}
	require.Equal(t, []string{"mixed-in", "ebpf-in", "tproxy-in"}, tags)
}

func TestApplyConfigFilterReverse(t *testing.T) {
	filtered, err := applyConfigFilter([]byte(`{
  "filter_regex": "tun",
  "filter_reverse": true,
  "inbounds": [
    {"tag": "a", "filter_mark": "tun"},
    {"tag": "b", "filter_mark": "mixed"}
  ]
}`))
	require.NoError(t, err)
	inbounds := decodeConfigMap(t, filtered)["inbounds"].([]any)
	require.Len(t, inbounds, 1)
	require.Equal(t, "b", inbounds[0].(map[string]any)["tag"])
}

func TestApplyConfigFilterOption(t *testing.T) {
	filtered, err := applyConfigFilter([]byte(`{
  "filter_regex": "router",
  "route": {
    "auto_detect_interface": true,
    "default_mark": 1,
    "filter_option": {
      "router": {"auto_detect_interface": null, "default_interface": "eth0"},
      "desktop": {"default_mark": 2}
    }
  }
}`))
	require.NoError(t, err)
	route := decodeConfigMap(t, filtered)["route"].(map[string]any)
	require.NotContains(t, route, "filter_option")
	require.NotContains(t, route, "auto_detect_interface")
	require.Equal(t, "eth0", route["default_interface"])
	require.EqualValues(t, 1, route["default_mark"])
}

func TestApplyConfigFilterKeepsEmptyArray(t *testing.T) {
	filtered, err := applyConfigFilter([]byte(`{"filter_regex": "x", "inbounds": [{"filter_mark": "y"}]}`))
	require.NoError(t, err)
	require.Equal(t, []any{}, decodeConfigMap(t, filtered)["inbounds"])
}

func TestApplyConfigFilterInvalidRegex(t *testing.T) {
	_, err := applyConfigFilter([]byte(`{"filter_regex": "("}`))
	require.ErrorContains(t, err, "invalid filter_regex")
}

func TestNormalizeConfigContentLeadingComment(t *testing.T) {
	content := []byte("// header\n/* note */\n{\"log\": {}}")
	normalized, err := normalizeConfigContent("stdin", content)
	require.NoError(t, err)
	require.Equal(t, content, normalized)
}
