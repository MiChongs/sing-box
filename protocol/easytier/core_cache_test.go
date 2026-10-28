package easytier

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"

	corehost "github.com/easytier/easytier/easytier-go"
	"github.com/metacubex/wazero"
	"github.com/stretchr/testify/require"
)

func TestCoreCompileContextCachesCompiledCore(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles the embedded core")
	}
	directory := t.TempDir()
	t.Chdir(directory)
	ctx := context.Background()
	endpoint := &Endpoint{ctx: ctx, logger: log.NewNOPFactory().NewLogger("easytier")}
	stale := filepath.Join(directory, coreCacheDirectory, "stale-core")
	require.NoError(t, os.MkdirAll(stale, 0o700))

	createHost := func() time.Duration {
		compileCtx, closeCache := endpoint.coreCompileContext(ctx)
		defer closeCache()
		start := time.Now()
		host, err := corehost.New(compileCtx, corehost.Options{})
		require.NoError(t, err)
		elapsed := time.Since(start)
		require.NoError(t, host.Close(ctx))
		return elapsed
	}
	cold := createHost()
	require.NoDirExists(t, stale, "caches of other core builds are pruned")
	entries, err := os.ReadDir(filepath.Join(directory, coreCacheDirectory))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	cached, err := os.ReadDir(filepath.Join(directory, coreCacheDirectory, entries[0].Name()))
	require.NoError(t, err)
	require.NotEmpty(t, cached)
	warm := createHost()
	t.Logf("cold %v, warm %v", cold, warm)
	require.Less(t, warm, cold/4)
}

func TestCoreCompileContextWithoutWritableDirectory(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	// A file where the cache directory belongs makes MkdirAll fail.
	require.NoError(t, os.WriteFile(coreCacheDirectory, nil, 0o600))
	endpoint := &Endpoint{ctx: context.Background(), logger: log.NewNOPFactory().NewLogger("easytier")}
	compileCtx, closeCache := endpoint.coreCompileContext(context.Background())
	defer closeCache()
	// The context still creates a working runtime, without a cache.
	runtime := wazero.NewRuntime(compileCtx)
	require.NoError(t, runtime.Close(context.Background()))
}
