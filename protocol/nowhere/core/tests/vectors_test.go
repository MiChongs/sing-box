package tests_test

import (
	"testing"

	"github.com/sagernet/sing-box/protocol/nowhere/core/internal/veccheck"
	"github.com/sagernet/sing-box/protocol/nowhere/core/internal/vectors"
)

func TestHarnessVectors(t *testing.T) {
	dir, err := vectors.Dir()
	if err != nil {
		t.Fatalf("vectors unavailable: %v", err)
	}
	n, err := veccheck.CheckDir(dir)
	if err != nil {
		t.Fatalf("CheckDir(%s): %v", dir, err)
	}
	if n == 0 {
		t.Fatal("no vector cases checked")
	}
	t.Logf("checked %d vector cases from %s", n, dir)
}
