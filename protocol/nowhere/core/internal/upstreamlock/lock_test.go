package upstreamlock

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestCanonicalLockMatchesGeneratedConstantsAndVectors(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	lock, err := Read(filepath.Join(root, "UPSTREAM.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if !lock.MatchesGenerated() {
		t.Fatal("UPSTREAM.lock differs from generated constants")
	}
	got, err := TreeHash(filepath.Join(root, "testdata", "vectors"))
	if err != nil {
		t.Fatal(err)
	}
	if got != lock.VectorTreeSHA256 {
		t.Fatalf("vector tree hash = %s, want %s", got, lock.VectorTreeSHA256)
	}
}
