package group

import (
	"sync"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
)

// Process-global task consolidation.
//
// Several Smart background tasks are IDEMPOTENT at the process level —
// running them once-per-group is pure waste. Specifically:
//
//   flush-queue           : writes the shared global write-queue to bbolt.
//                           First group's call drains everything; rest
//                           return immediately but still burn scheduler
//                           time.
//
//   cache-adjust          : calls runtime.ReadMemStats (STW!) to decide
//                           LRU sizing. Running this 16 times per 5-min
//                           interval = 16 stop-the-world pauses. On
//                           Android this is a concrete battery/UX cost.
//
//   cleanup-orphan        : iterates recordCache removing entries for
//                           dead groups. Process-global (cache is shared).
//
//   cleanup-orphan-groups : iterates bbolt finding groups not in the
//                           current config. Process-global.
//
// The per-group versions are NOT removed — they still register on the
// timing wheel, but the global scheduler runs a gate so only the first
// caller in a given interval actually does the work. Subsequent callers
// return immediately.
//
// Why gate instead of "only register once"?
//   - Smart groups come and go via config reload. If we skipped
//     registration, a process that starts with 1 group (and registers
//     globals from that group) then scales to 15 groups would keep the
//     globals tied to the first group's lifecycle.
//   - Gating by timestamp is lock-free with xsync and survives group
//     churn naturally.

var (
	// globalTaskLastRun records the last time each global task ran.
	// Keyed by task name. Readers check (now - lastRun) < interval to
	// skip; only the first caller past the interval boundary proceeds.
	globalTaskLastRun = xsync.NewMapOf[string, time.Time]()
	globalTaskMu      sync.Mutex
)

// claimGlobalTask atomically reserves the right to run the named task.
// Returns true if the caller should execute; false if another caller
// already ran it within the last `interval`. Serialises via a brief
// global mutex so two groups claiming simultaneously only grant one.
//
// The xsync.MapOf read outside the mutex avoids lock contention in the
// steady-state (cached-recent) case — only when the cache miss forces
// re-evaluation do we acquire the mutex.
func claimGlobalTask(name string, interval time.Duration) bool {
	if last, ok := globalTaskLastRun.Load(name); ok {
		if time.Since(last) < interval {
			return false
		}
	}
	globalTaskMu.Lock()
	defer globalTaskMu.Unlock()
	// Re-check under lock.
	if last, ok := globalTaskLastRun.Load(name); ok {
		if time.Since(last) < interval {
			return false
		}
	}
	globalTaskLastRun.Store(name, time.Now())
	return true
}

// globalFlushQueueInterval is the lower bound on how often the process
// will actually run flush-queue across all Smart groups. Matches the
// per-group initial period (5s) so behaviour is preserved.
const globalFlushQueueInterval = 5 * time.Second

// globalCacheAdjustInterval is the lower bound for cache-adjust. 5 min
// matches the per-group period.
const globalCacheAdjustInterval = 5 * time.Minute

// globalCleanupOrphanInterval is the lower bound for cleanup-orphan.
const globalCleanupOrphanInterval = 10 * time.Minute

// globalCleanupOrphanGroupsInterval is the lower bound for
// cleanup-orphan-groups. Matches the per-group period (120 min).
const globalCleanupOrphanGroupsInterval = 2 * time.Hour

// globalCleanupOldInterval for the bbolt-scan cleanup-old task.
const globalCleanupOldInterval = 2 * time.Hour

// globalFreshnessPruneInterval caps how often the process-wide freshness
// cache gets pruned. The cache is shared across Smart groups, so prune
// work must also be process-global — a single 5-min janitor call
// removes entries older than freshnessPruneTTL (=10 min) so a
// long-running daemon doesn't accumulate probeResult entries for tags
// from reconfigured / removed outbounds.
const globalFreshnessPruneInterval = 5 * time.Minute
