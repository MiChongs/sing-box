package parser

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A subscription may put any YAML shape where a scalar is expected; rendering
// it must never panic.
func TestClashValueString(t *testing.T) {
	t.Parallel()
	require.Equal(t, "text", clashValueString("text"))
	require.Equal(t, "true", clashValueString(true))
	require.Equal(t, "443", clashValueString(443))
	require.Equal(t, "1.5", clashValueString(1.5))
	require.Equal(t, "[a 1]", clashValueString([]any{"a", 1}))
	require.Equal(t, "map[k:v]", clashValueString(map[string]any{"k": "v"}))
	require.Equal(t, "{}", clashValueString(struct{}{}))

	require.Equal(t, "[a b]", clashStringOption(map[string]any{"host": []any{"a", "b"}}, "host"))
	require.Equal(t, []string{"a", "map[k:v]", "2"}, clashStringListOption(map[string]any{
		"alpn": []any{"a", map[string]any{"k": "v"}, 2},
	}, "alpn"))
	require.Equal(t, "mode=[x y]", shadowsocksPluginOptionsBuilder{"mode": []any{"x", "y"}, "skip": nil}.Build())
}
