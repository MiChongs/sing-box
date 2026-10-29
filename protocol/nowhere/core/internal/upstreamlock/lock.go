// Package upstreamlock exposes generated upstream identity and hash helpers.
package upstreamlock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Lock is the JSON representation shared by UPSTREAM.lock (nw3) and UPSTREAM-nw2.lock.
type Lock struct {
	Schema                  int    `json:"schema"`
	Repository              string `json:"repository"`
	Version                 string `json:"version"`
	Commit                  string `json:"commit"`
	ProtocolSHA256          string `json:"protocol_sha256"`
	VectorTreeHashAlgorithm string `json:"vector_tree_hash_algorithm"`
	VectorTreeSHA256        string `json:"vector_tree_sha256"`
}

func Read(path string) (Lock, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Lock{}, err
	}
	var lock Lock
	if err := json.Unmarshal(raw, &lock); err != nil {
		return Lock{}, err
	}
	if err := lock.Validate(); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

func (l Lock) Validate() error {
	if l.Schema != Schema {
		return fmt.Errorf("nowhere: upstream lock schema %d, want %d", l.Schema, Schema)
	}
	if l.Repository == "" || l.Version == "" {
		return errors.New("nowhere: incomplete upstream lock identity")
	}
	if len(l.Commit) != 40 || !isLowerHex(l.Commit) {
		return errors.New("nowhere: invalid upstream commit")
	}
	if !validSHA256(l.ProtocolSHA256) || !validSHA256(l.VectorTreeSHA256) {
		return errors.New("nowhere: invalid upstream SHA-256")
	}
	if l.VectorTreeHashAlgorithm != VectorTreeHashAlgorithm {
		return fmt.Errorf("nowhere: vector tree algorithm %q, want %q", l.VectorTreeHashAlgorithm, VectorTreeHashAlgorithm)
	}
	return nil
}

// MatchesGenerated reports whether a parsed lock produced this build's
// generated constants.
func (l Lock) MatchesGenerated() bool {
	return l.Schema == Schema &&
		l.Repository == Repository &&
		l.Version == Version &&
		l.Commit == Commit &&
		l.ProtocolSHA256 == ProtocolSHA256 &&
		l.VectorTreeHashAlgorithm == VectorTreeHashAlgorithm &&
		l.VectorTreeSHA256 == VectorTreeSHA256
}

// TreeHash implements sha256-tree-v1: sorted relative filename + NUL +
// lowercase SHA-256(content) + LF, hashed again with SHA-256.
//
// skip names top-level subdirectories to exclude, so the nw2 corpus directory
// (which also holds the nw3 corpus under nw3/) hashes only its own files. Both
// locks then share one semantics: sha256-tree-v1 over the files of their own
// corpus.
func TreeHash(dir string, skip ...string) (string, error) {
	var names []string
	skipSet := make(map[string]bool, len(skip))
	for _, s := range skip {
		skipSet[s] = true
	}
	if err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(relative)
		if entry.IsDir() {
			if skipSet[rel] {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("nowhere: vector tree contains non-regular file %s", path)
		}
		names = append(names, rel)
		return nil
	}); err != nil {
		return "", err
	}
	sort.Strings(names)
	return FilesTreeHash(func(name string) ([]byte, error) {
		return os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
	}, names...)
}

// FilesTreeHash implements sha256-tree-v1 over an explicit sorted name list,
// reading each file through content. It backs both TreeHash and the upstream
// protocol hash (see scripts/generate-upstream-lock.sh).
func FilesTreeHash(content func(name string) ([]byte, error), names ...string) (string, error) {
	tree := sha256.New()
	for _, name := range names {
		raw, err := content(name)
		if err != nil {
			return "", err
		}
		contentHash := sha256.Sum256(raw)
		_, _ = tree.Write([]byte(name))
		_, _ = tree.Write([]byte{0})
		_, _ = tree.Write([]byte(hex.EncodeToString(contentHash[:])))
		_, _ = tree.Write([]byte{'\n'})
	}
	return hex.EncodeToString(tree.Sum(nil)), nil
}

func validSHA256(value string) bool {
	return len(value) == sha256.Size*2 && isLowerHex(value)
}

func isLowerHex(value string) bool {
	if strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
