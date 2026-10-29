package veccheck

import (
	"path/filepath"
	"runtime"
	"testing"
)

func vectorsRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "testdata", "vectors"))
}

// TestNW3Corpus validates the exported nw3 conformance corpus against the nw3
// wire codecs. This keeps the corpus honest in CI, independent of nowhere-check.
func TestNW3Corpus(t *testing.T) {
	n, err := CheckNW3Dir(filepath.Join(vectorsRoot(t), "nw3"))
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no nw3 cases checked")
	}
	t.Logf("checked %d nw3 cases", n)
}

// TestNW2Corpus validates the legacy nw2 corpus still resolves.
func TestNW2Corpus(t *testing.T) {
	n, err := CheckDir(vectorsRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no nw2 cases checked")
	}
	t.Logf("checked %d nw2 cases", n)
}
