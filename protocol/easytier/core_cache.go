package easytier

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sagernet/sing/service/filemanager"

	corehost "github.com/easytier/easytier/easytier-go"
	"github.com/metacubex/wazero"
	"github.com/metacubex/wazero/experimental"
)

const (
	coreCacheDirectory = "easytier-core-cache"
	// coreCompilationWorkers bounds the parallel compilation of the core on a
	// cache miss: each worker adds about 30MB to the compilation peak, and
	// two halve the time of a single one.
	coreCompilationWorkers = 2
	// coreCacheGeneration changes whenever the core is compiled differently
	// for the same embedded core, such as when the host started enforcing
	// guest termination, so that stale machine code is pruned with its
	// directory instead of lingering beside the new entry.
	coreCacheGeneration = "t1"
)

// coreCompileContext returns ctx carrying an on-disk cache of the compiled
// core and the compilation worker count, both read by the wazero runtime that
// the EasyTier host creates from ctx. Compiling the 7MB core takes seconds
// and allocates about 290MB, so it is done once per core build: a cache hit
// maps the stored machine code in about 75ms. The returned function releases
// the cache and must run after the host is closed.
func (e *Endpoint) coreCompileContext(ctx context.Context) (context.Context, func()) {
	ctx = experimental.WithCompilationWorkers(ctx, min(coreCompilationWorkers, runtime.NumCPU()))
	baseDirectory := filemanager.BasePath(e.ctx, coreCacheDirectory)
	// One directory per embedded core: the wazero version and CPU features
	// are part of each cached entry, but a replaced core would otherwise
	// leave its predecessor's machine code on disk.
	cacheName := runtime.GOARCH + "-" + coreCacheKey(corehost.CoreInfo().SHA256) + "-" + coreCacheGeneration
	cacheDirectory := filepath.Join(baseDirectory, cacheName)
	err := filemanager.MkdirAll(e.ctx, cacheDirectory, 0o700)
	if err != nil {
		e.logger.Debug("EasyTier core cache disabled: ", err)
		return ctx, func() {}
	}
	pruneCoreCaches(baseDirectory, cacheName)
	cache, err := wazero.NewCompilationCacheWithDir(cacheDirectory)
	if err != nil {
		e.logger.Debug("EasyTier core cache disabled: ", err)
		return ctx, func() {}
	}
	return wazero.WithCompilationCache(ctx, cache), func() {
		_ = cache.Close(context.Background())
	}
}

func coreCacheKey(sha256 string) string {
	if len(sha256) > 16 {
		sha256 = sha256[:16]
	}
	if sha256 == "" {
		return "unknown"
	}
	return strings.ToLower(sha256)
}

// pruneCoreCaches removes the caches of other core builds.
func pruneCoreCaches(baseDirectory string, current string) {
	entries, err := os.ReadDir(baseDirectory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.Name() != current {
			_ = os.RemoveAll(filepath.Join(baseDirectory, entry.Name()))
		}
	}
}
