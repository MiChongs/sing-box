package upstreamlock

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// protocolFiles lists, relative to a Nowhere checkout root, the wire-defining
// Rust sources pinned by the lock's protocol_sha256. It documents the coverage
// set of the value; see scripts/generate-upstream-lock.sh for the regeneration
// entry point.
//
// Coverage rationale: the nw2 wire contract is fixed since Nowhere 2.0. The
// files below define every byte on the wire (frame and header layout, auth,
// morph transform) and nothing else, so the hash changes exactly when the wire
// contract does. nw3 has no Mux, so its coverage set is the same minus
// src/mux/wire.rs. Nowhere 3.1 and later also pin the authenticated-prelude
// admission sources src/portal/replay.rs and src/portal/prehello.rs; the prelude codec
// itself is already covered under src/transport/morph/. See ProtocolHashNW3.
func protocolFiles(upstream string, nw3 bool) ([]string, error) {
	var names []string
	err := filepath.WalkDir(filepath.Join(upstream, "src"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rs") {
			return nil
		}
		rel, err := filepath.Rel(upstream, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case strings.HasPrefix(rel, "src/protocol/"):
		case !nw3 && rel == "src/mux/wire.rs":
		case rel == "src/transport/morph.rs" || strings.HasPrefix(rel, "src/transport/morph/"):
		case nw3 && (rel == "src/portal/replay.rs" || rel == "src/portal/prehello.rs"):
		default:
			return nil
		}
		names = append(names, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("nowhere: no protocol sources under %s", upstream)
	}
	// FilesTreeHash requires a sorted name list (sha256-tree-v1); WalkDir
	// yields filesystem order, which is not stable across machines.
	sort.Strings(names)
	return names, nil
}

// ProtocolHash computes protocol_sha256 over the documented wire-defining
// sources of a Nowhere checkout (see protocolFiles for the coverage set).
func ProtocolHash(upstream string) (string, error) {
	names, err := protocolFiles(upstream, false)
	if err != nil {
		return "", err
	}
	return FilesTreeHash(func(name string) ([]byte, error) {
		return os.ReadFile(filepath.Join(upstream, filepath.FromSlash(name)))
	}, names...)
}

// ProtocolHashNW3 computes protocol_sha256 for the nw3 wire contract: the same
// wire-defining sources minus src/mux/wire.rs, plus the authenticated TCP prelude
// admission sources src/portal/replay.rs and src/portal/prehello.rs.
func ProtocolHashNW3(upstream string) (string, error) {
	names, err := protocolFiles(upstream, true)
	if err != nil {
		return "", err
	}
	return FilesTreeHash(func(name string) ([]byte, error) {
		return os.ReadFile(filepath.Join(upstream, filepath.FromSlash(name)))
	}, names...)
}
