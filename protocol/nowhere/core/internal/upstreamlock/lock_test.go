package upstreamlock

import (
	"path/filepath"
	"runtime"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}

func TestCanonicalLockMatchesGeneratedConstantsAndVectors(t *testing.T) {
	root := repoRoot(t)
	lock, err := Read(filepath.Join(root, "UPSTREAM-nw2.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if !lock.MatchesGenerated() {
		t.Fatal("UPSTREAM-nw2.lock differs from generated constants")
	}
	// The nw2 corpus directory also holds the nw3 corpus under nw3/; the nw2
	// tree hash covers only the nw2 files.
	got, err := TreeHash(filepath.Join(root, "testdata", "vectors"), "nw3")
	if err != nil {
		t.Fatal(err)
	}
	if got != lock.VectorTreeSHA256 {
		t.Fatalf("nw2 vector tree hash = %s, want %s", got, lock.VectorTreeSHA256)
	}
}

func TestDefaultLockIsNowhere3(t *testing.T) {
	root := repoRoot(t)
	lock, err := Read(filepath.Join(root, "UPSTREAM.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if lock.Version != "3.2.0" || lock.Commit != "00000e23a0a131dd04fd7aec340b8d523a13ae51" {
		t.Fatalf("UPSTREAM.lock = %s %s", lock.Version, lock.Commit)
	}
	// Both locks define vector_tree_sha256 the same way: sha256-tree-v1 over
	// the files of their own corpus directory.
	got, err := TreeHash(filepath.Join(root, "testdata", "vectors", "nw3"))
	if err != nil {
		t.Fatal(err)
	}
	if got != lock.VectorTreeSHA256 {
		t.Fatalf("nw3 vector tree hash = %s, want %s", got, lock.VectorTreeSHA256)
	}
}

// TestLockHashesAreDistinct guards against a copy-paste that silently points
// both locks at the same corpus.
func TestLockHashesAreDistinct(t *testing.T) {
	root := repoRoot(t)
	nw2, err := Read(filepath.Join(root, "UPSTREAM-nw2.lock"))
	if err != nil {
		t.Fatal(err)
	}
	nw3, err := Read(filepath.Join(root, "UPSTREAM.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if nw2.VectorTreeSHA256 == nw3.VectorTreeSHA256 {
		t.Fatal("nw2 and nw3 locks pin the same vector tree")
	}
	if nw2.ProtocolSHA256 == nw3.ProtocolSHA256 {
		t.Fatal("nw2 and nw3 locks pin the same protocol hash")
	}
}
