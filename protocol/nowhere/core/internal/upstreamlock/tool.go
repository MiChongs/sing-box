//go:build ignore

// Command upstream-lock regenerates one upstream lock from a local Nowhere
// checkout. -lock UPSTREAM-nw2.lock also rewrites internal/upstreamlock/generated.go.
// -lock UPSTREAM.lock rewrites only the Nowhere 3 pin. It is not part of the
// module build; scripts/generate-upstream-lock.sh regenerates both locks.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/protocol/nowhere/core/internal/upstreamlock"
)

func main() {
	var (
		upstream = flag.String("upstream", "", "path to a local Nowhere checkout (any ref)")
		lockPath = flag.String("lock", "UPSTREAM-nw2.lock", "path to the lock file to regenerate")
		vectors  = flag.String("vectors", "testdata/vectors", "path to the local vector corpus")
		write    = flag.Bool("write", false, "rewrite the lock file and generated.go instead of printing")
	)
	flag.Parse()

	if *upstream == "" {
		fatal("usage: upstream-lock -upstream /path/to/Nowhere [-lock UPSTREAM.lock] [-write]")
	}
	if err := os.Chdir(mustRepoRoot()); err != nil {
		fatal(err.Error())
	}
	// UPSTREAM.lock is the Nowhere 3 pin and hashes its own corpus directory
	// (testdata/vectors/nw3). UPSTREAM-nw2.lock hashes testdata/vectors minus
	// that subdirectory and is the one mirrored into generated.go.
	nw3 := filepath.Base(*lockPath) == "UPSTREAM.lock"
	var skips []string
	if nw3 {
		*vectors = filepath.Join(*vectors, "nw3")
	} else {
		skips = append(skips, "nw3")
	}

	lock, err := upstreamlock.Read(*lockPath)
	if err != nil {
		fatal(err.Error())
	}

	commit, err := upstreamCommit(*upstream)
	if err != nil {
		fatal(err.Error())
	}
	version, err := cargoVersion(*upstream)
	if err != nil {
		fatal(err.Error())
	}
	protocol, err := upstreamlock.ProtocolHash(*upstream)
	if nw3 {
		protocol, err = upstreamlock.ProtocolHashNW3(*upstream)
	}
	if err != nil {
		fatal(err.Error())
	}
	tree, err := upstreamlock.TreeHash(*vectors, skips...)
	if err != nil {
		fatal(err.Error())
	}

	lock.Commit = commit
	lock.Version = version
	lock.ProtocolSHA256 = protocol
	lock.VectorTreeSHA256 = tree
	if !*write {
		fmt.Printf("version=%s\ncommit=%s\nprotocol_sha256=%s\nvector_tree_sha256=%s\n",
			lock.Version, lock.Commit, lock.ProtocolSHA256, lock.VectorTreeSHA256)
		return
	}
	if err := writeLock(*lockPath, lock); err != nil {
		fatal(err.Error())
	}
	if nw3 {
		fmt.Printf("rewrote %s for Nowhere %s @ %s\n", *lockPath, lock.Version, lock.Commit)
		return
	}
	if err := writeGenerated(lock); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("rewrote %s and internal/upstreamlock/generated.go for Nowhere %s @ %s\n",
		*lockPath, lock.Version, lock.Commit)
}

func mustRepoRoot() string {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		fatal("go env GOMOD: " + err.Error())
	}
	root := filepath.Dir(strings.TrimSpace(string(out)))
	if root == "" {
		fatal("cannot locate the nowhere-go module root")
	}
	return root
}

func upstreamCommit(dir string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("nowhere: %s is not a git checkout: %w", dir, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func cargoVersion(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "Cargo.toml"))
	if err != nil {
		return "", fmt.Errorf("nowhere: cannot read %s/Cargo.toml: %w", dir, err)
	}
	inPackage := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inPackage = trimmed == "[package]"
			continue
		}
		if inPackage && strings.HasPrefix(trimmed, "version") {
			_, value, found := strings.Cut(trimmed, "=")
			if !found {
				continue
			}
			value = strings.Trim(strings.TrimSpace(value), `"'`)
			if value != "" {
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("nowhere: no [package] version in %s/Cargo.toml", dir)
}

func writeLock(path string, lock upstreamlock.Lock) error {
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func writeGenerated(lock upstreamlock.Lock) error {
	body := fmt.Sprintf(`// Code generated from UPSTREAM-nw2.lock by generate-upstream-lock-go.sh; DO NOT EDIT.

package upstreamlock

const (
	Schema                  = %d
	Repository              = %q
	Version                 = %q
	Commit                  = %q
	ProtocolSHA256          = %q
	VectorTreeHashAlgorithm = %q
	VectorTreeSHA256        = %q
)
`, lock.Schema, lock.Repository, lock.Version, lock.Commit, lock.ProtocolSHA256, lock.VectorTreeHashAlgorithm, lock.VectorTreeSHA256)
	return os.WriteFile(filepath.Join("internal", "upstreamlock", "generated.go"), []byte(body), 0o644)
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
