// Package vectors resolves and loads Nowhere harness JSON conformance vectors.
package vectors

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Dir resolves the vectors directory. Prefer GO_NOWHERE_VECTORS, then
// testdata/vectors relative to the module root (walk up from cwd), then the
// monorepo harness/vectors path when developing inside mihomo-nowhere.
func Dir() (string, error) {
	if env := strings.TrimSpace(os.Getenv("GO_NOWHERE_VECTORS")); env != "" {
		if st, err := os.Stat(env); err == nil && st.IsDir() {
			return env, nil
		}
		return "", fmt.Errorf("GO_NOWHERE_VECTORS=%q is not a directory", env)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		candidate := filepath.Join(dir, "testdata", "vectors")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate, nil
		}
		// Monorepo layout: <root>/nowhere-go + <root>/harness/vectors
		harness := filepath.Join(dir, "harness", "vectors")
		if st, err := os.Stat(harness); err == nil && st.IsDir() {
			return harness, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("vector directory not found (set GO_NOWHERE_VECTORS or run from module root)")
}

// DecodeHex decodes a corpus hex string, ignoring whitespace.
func DecodeHex(s string) ([]byte, error) {
	clean := make([]byte, 0, len(s))
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			clean = append(clean, byte(r))
		}
	}
	return hex.DecodeString(string(clean))
}
