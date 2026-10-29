package bundle

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSessionSourceHasNoGlobalPacketAllocator(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(current), "session.go"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for _, stale := range [][]byte{[]byte("func allocPacketID()"), []byte("var nextPacketID")} {
		if bytes.Contains(raw, stale) {
			t.Fatalf("session.go still contains stale global allocator %q", stale)
		}
	}
}
