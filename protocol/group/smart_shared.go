package group

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants/v2"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"golang.org/x/sync/singleflight"
)

// smartSharedWorker deduplicates cross-group work that targets the SAME
// physical outbound node, and bounds process-wide concurrency so N Smart
// groups don't stampede the CPU / network when all their health checks
// fire at once.
//
// Scenario that drove this: user has 15 Smart groups of 20-30 nodes each
// plus a 600-node global group. Many nodes overlap across groups. Per-group
// runHealthCheck previously probed the SAME node once per group it belonged
// to — a node shared by 16 groups got 16 concurrent probes every interval,
// 16× the real work.
//
// This worker fixes it at the process level:
//
//  1. singleflight.Group collapses in-flight probes of the same tag into
//     one HTTP request — all callers wait for the same result.
//
//  2. ants.Pool caps concurrent probe / prefetch / ranking goroutines so
//     the spike of "all 16 groups' health-check ticker fires simultaneously"
//     is flattened into a steady stream of work through a bounded worker set.
//
//  3. freshnessCache remembers very-recent probe results keyed by tag so
//     back-to-back calls from different groups (within a 1s burst window)
//     skip the URLTest entirely — singleflight only dedupes CONCURRENT
//     flight, not sequential.
type smartSharedWorker struct {
	// probeGroup dedupes concurrent URLTest probes by node tag.
	probeGroup singleflight.Group
	// pool is the bounded goroutine pool; nil = unlimited (fallback when
	// ants failed to initialize, which shouldn't happen).
	pool *ants.Pool
	// freshnessCache short-TTL result cache to absorb probe bursts.
	//   key = node tag; value = probeResult captured at that moment.
	freshnessCache *xsync.MapOf[string, probeResult]
	// freshWindow is how long a cached probeResult stays valid.
	freshWindow time.Duration
}

type probeResult struct {
	at    time.Time
	delay uint16
	err   error
}

var (
	smartWorker     *smartSharedWorker
	smartWorkerOnce sync.Once

	// smartGroupCounter hands out an ordinal to each Smart group so we
	// can stagger initial task firings — 16 groups all kicking their
	// first health-check at exactly +10s would create a thundering herd.
	// Instead each group gets a deterministic offset in [0, staggerRange).
	//
	// atomic.Int64 instead of xsync.Counter: the zero value of xsync.Counter
	// panics on access (requires NewCounter()), and Inc/Value are two
	// separate calls so concurrent groups could read the same value. A
	// plain atomic.Add is simpler, safer, and has identical performance
	// for this non-hot-path use (called once per Smart group at startup).
	smartGroupCounter atomic.Int64
)

// nextGroupOrdinal returns a unique monotonically-increasing ordinal for
// a new Smart group, used by staggeredInitialDelay to spread task firings.
func nextGroupOrdinal() int64 {
	return smartGroupCounter.Add(1)
}

// staggeredInitialDelay spreads the N-th group's initial delay across a
// 3-second window. Combined with singleflight de-duplication, this
// smooths the "all groups fire their health check at startup" spike
// into a steady stream of probe work.
func staggeredInitialDelay(base time.Duration, ordinal int64) time.Duration {
	const staggerRange = 3 * time.Second
	offset := time.Duration((ordinal % 30)) * (staggerRange / 30)
	return base + offset
}

// getSmartWorker lazily initialises the process-wide smartSharedWorker.
// Safe to call from any Smart group; all groups share a single instance.
func getSmartWorker() *smartSharedWorker {
	smartWorkerOnce.Do(func() {
		// Pool size: capped at 64 workers. With 16 groups running bursty
		// probe + prefetch work, 64 workers process the burst in parallel
		// without letting the goroutine count explode. Unused workers
		// expire after the idle timeout so idle resources are reclaimed.
		pool, err := ants.NewPool(64,
			ants.WithExpiryDuration(30*time.Second),
			ants.WithNonblocking(false),
			ants.WithPreAlloc(false),
		)
		if err != nil {
			// Extremely unlikely — ants.NewPool only fails on invalid
			// config. Fall back to unbounded (go func{}) via pool==nil.
			smartWorker = &smartSharedWorker{
				freshnessCache: xsync.NewMapOf[string, probeResult](),
				freshWindow:    1 * time.Second,
			}
			return
		}
		smartWorker = &smartSharedWorker{
			pool:           pool,
			freshnessCache: xsync.NewMapOf[string, probeResult](),
			freshWindow:    1 * time.Second,
		}
	})
	return smartWorker
}

// submit schedules fn to run on the shared worker pool. Blocks briefly if
// the pool is saturated (which is the intended back-pressure — we don't
// want unbounded goroutine creation on a busy config).
func (w *smartSharedWorker) submit(fn func()) {
	if w.pool != nil {
		_ = w.pool.Submit(fn)
		return
	}
	go fn()
}

// probeOnce runs a URLTest probe for ob, deduplicating concurrent calls
// with the same tag via singleflight + short-TTL cache. Returns the delay
// in ms and an error (same contract as urltest.URLTest).
//
// Three-stage resolution:
//  1. freshnessCache hit within freshWindow → return cached result instantly.
//  2. singleflight collapse → one in-flight probe serves all callers.
//  3. actual URLTest → cache result + resolve singleflight waiters.
func (w *smartSharedWorker) probeOnce(
	ctx context.Context,
	testURL string,
	ob adapter.Outbound,
) (uint16, error) {
	tag := ob.Tag()
	if hit, ok := w.freshnessCache.Load(tag); ok {
		if time.Since(hit.at) < w.freshWindow {
			return hit.delay, hit.err
		}
	}
	// Key includes testURL so different groups probing different URLs
	// don't collapse onto each other's result.
	key := testURL + "\x00" + tag
	v, err, _ := w.probeGroup.Do(key, func() (interface{}, error) {
		d, perr := urltest.URLTest(ctx, testURL, ob)
		w.freshnessCache.Store(tag, probeResult{
			at:    time.Now(),
			delay: d,
			err:   perr,
		})
		return d, perr
	})
	if v == nil {
		return 0, err
	}
	return v.(uint16), err
}
