package upstreamlock

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile creates a file under root, making parent directories as needed.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestProtocolHashIsOrderIndependent pins that protocol_sha256 is a function of
// the file set and contents only. WalkDir yields filesystem order (where
// src/transport/morph/tcp.rs can precede src/transport/morph.rs), which is not
// stable across machines; an unsorted hash made the lock value
// machine-dependent. The same fixture written with different creation orders
// must hash identically.
func TestProtocolHashIsOrderIndependent(t *testing.T) {
	files := map[string]string{
		"src/protocol/mod.rs":        "mod",
		"src/protocol/flow.rs":       "flow",
		"src/mux/wire.rs":            "mux",
		"src/transport/morph.rs":     "morph",
		"src/transport/morph/tcp.rs": "tcp",
		"src/transport/morph/udp.rs": "udp",
		"src/telemetry/ipc.rs":       "not in the coverage set",
	}

	orderA := []string{
		"src/transport/morph/tcp.rs", "src/transport/morph/udp.rs",
		"src/transport/morph.rs", "src/protocol/flow.rs", "src/protocol/mod.rs",
		"src/mux/wire.rs", "src/telemetry/ipc.rs",
	}
	orderB := []string{
		"src/mux/wire.rs", "src/protocol/mod.rs", "src/protocol/flow.rs",
		"src/transport/morph.rs", "src/transport/morph/tcp.rs",
		"src/transport/morph/udp.rs", "src/telemetry/ipc.rs",
	}

	dirA := t.TempDir()
	dirB := t.TempDir()
	for _, rel := range orderA {
		writeFile(t, dirA, rel, files[rel])
	}
	for _, rel := range orderB {
		writeFile(t, dirB, rel, files[rel])
	}

	hashA, err := ProtocolHash(dirA)
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := ProtocolHash(dirB)
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashB {
		t.Fatalf("protocol hash depends on filesystem order:\n A %s\n B %s", hashA, hashB)
	}

	// nw2 covers src/mux/wire.rs; nw3 does not, so the two must differ.
	nw3, err := ProtocolHashNW3(dirA)
	if err != nil {
		t.Fatal(err)
	}
	if nw3 == hashA {
		t.Fatal("nw2 and nw3 protocol hashes coincide despite the nw2-only mux/wire.rs")
	}
}
