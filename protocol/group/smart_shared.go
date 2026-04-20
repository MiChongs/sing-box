package group

import (
	"context"
	"math/bits"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RussellLuo/timingwheel"
	"github.com/cespare/xxhash/v2"
	"github.com/josharian/intern"
	"github.com/panjf2000/ants/v2"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"golang.org/x/sync/singleflight"
)

// probeSem caps the number of concurrently in-flight URLTest
// probes process-wide. Sized at NumCPU*2 with a conservative
// [8, 32] clamp so low-end Android handsets (2-4 cores) stay around
// 8, while a 16-core desktop lets 32 probes race.
//
// Why we need this on TOP of ants.Pool(64) + singleflight:
//
//   ants.Pool limits total goroutines but doesn't know a probe
//   does a TLS handshake under the hood. A network-switch event
//   where 15 Smart groups each fire runHealthCheck + preWarm at
//   once used to spawn HUNDREDS of TLS handshakes in a few hundred
//   ms, which on Android cellular hand-off would peg CPU at 100%
//   and grow heap by tens of MBs before the dust settled.
//
//   singleflight collapses by TAG, not by concurrency count —
//   different tags still fan out unrestricted. The semaphore
//   gates the actual handshake regardless of tag identity.
//
// Initialised lazily so test builds that don't touch Smart never
// pay the channel alloc cost.
var (
	probeSem     chan struct{}
	probeSemOnce sync.Once
)

// ensureProbeSem lazy-initialises the global probe semaphore.
// Cheap to call on every probe (one atomic load via sync.Once).
func ensureProbeSem() {
	probeSemOnce.Do(func() {
		n := runtime.NumCPU() * 2
		if n < 8 {
			n = 8
		}
		if n > 32 {
			n = 32
		}
		probeSem = make(chan struct{}, n)
	})
}

// internTag dedupes a node-tag string against a process-wide pool so
// N Smart groups referencing the same outbound hold pointers to ONE
// backing byte slice instead of N independently-allocated copies.
//
// With 15 groups × 30 overlapping nodes × ~30 byte tag strings, the
// pre-interning footprint is ~13 KB of duplicated string data; after
// interning every group shares the same ~900 bytes of backing memory.
// Plus map keys hash identically which reduces cache misses.
//
// intern.String is safe for arbitrary strings — it maintains a weak
// map so unreferenced entries get garbage-collected naturally.
func internTag(s string) string {
	if s == "" {
		return s
	}
	return intern.String(s)
}

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

	// wheel is the process-wide timer wheel that drives every Smart group's
	// background tasks. Collapsing 16 groups × 9 tasks = 144 parked
	// ticker goroutines (each costing 2-8 KB stack and a runtime.timer
	// slot) into a single bucket-processor goroutine saves ~500 KB - 2 MB
	// of RSS on a 15-group config. Task fn()s are still dispatched through
	// the ants pool so concurrent execution remains bounded.
	wheel     *timingwheel.TimingWheel
	wheelOnce sync.Once
}

type probeResult struct {
	at     time.Time
	delay  uint16
	err    error
	detail urltest.URLTestDetail // phase timings; zero when the probe errored out early
}

// LastProbeDetail returns the most recent URLTest phase-timing detail for
// the given node tag, or a zero-value detail + ok=false when no cached probe
// exists. Used by recordStats to enrich ModelInput with TLSHandshakeTime /
// TLSSessionResumed / DNSResolveTime dimensions without paying an extra
// probe — the singleflight cache already amortised the measurement across
// all interested Smart groups.
func (w *smartSharedWorker) LastProbeDetail(tag string) (urltest.URLTestDetail, bool) {
	if w == nil || w.freshnessCache == nil {
		return urltest.URLTestDetail{}, false
	}
	v, ok := w.freshnessCache.Load(tag)
	if !ok {
		return urltest.URLTestDetail{}, false
	}
	return v.detail, true
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

// getWheel lazily starts the shared timing wheel on first use. 100ms tick
// with 200 buckets = 20s span; tasks fire at sub-tick precision via
// per-task scheduler NEXT times.
func (w *smartSharedWorker) getWheel() *timingwheel.TimingWheel {
	w.wheelOnce.Do(func() {
		w.wheel = timingwheel.NewTimingWheel(100*time.Millisecond, 200)
		w.wheel.Start()
	})
	return w.wheel
}

// periodSched implements timingwheel.Scheduler for "fire every period".
// Returning zero time ends the schedule (used when the owning Smart group
// has been closed and we want the wheel to drop this entry).
type periodSched struct {
	period   time.Duration
	firstAt  time.Time
	firedOnce atomic.Bool
	stopped  atomic.Bool
}

// Next is called by timingwheel to decide when the task should next fire.
// Returning zero Time tells the wheel to stop firing.
func (p *periodSched) Next(prev time.Time) time.Time {
	if p.stopped.Load() {
		return time.Time{}
	}
	if !p.firedOnce.Load() {
		p.firedOnce.Store(true)
		if !p.firstAt.IsZero() {
			return p.firstAt
		}
	}
	return prev.Add(p.period)
}

// stop signals the scheduler to end — the next Next() call returns zero.
func (p *periodSched) stop() { p.stopped.Store(true) }

// scheduleTask registers fn to fire once at `initial` (from now) and then
// every `period`. Actual execution happens on the ants pool so task work
// doesn't block the wheel's internal processor goroutine. Returns a handle
// the caller stores so Close() can cancel pending firings.
func (w *smartSharedWorker) scheduleTask(initial, period time.Duration, fn func(), once bool, taskCtx context.Context) *scheduledTask {
	wh := w.getWheel()
	sched := &periodSched{
		period:  period,
		firstAt: time.Now().Add(initial),
	}
	task := &scheduledTask{sched: sched, once: once}

	task.timer = wh.ScheduleFunc(sched, func() {
		// Respect the owning group's context so a stopped group doesn't
		// keep firing even before the wheel drops the entry.
		if taskCtx != nil {
			select {
			case <-taskCtx.Done():
				task.sched.stop()
				return
			default:
			}
		}
		// Dispatch the actual work to the shared pool.
		w.submit(fn)
		if once {
			task.sched.stop()
		}
	})
	return task
}

// scheduledTask bundles a timing-wheel timer with its scheduler so callers
// can stop both at once when the owning Smart group is closed.
type scheduledTask struct {
	timer *timingwheel.Timer
	sched *periodSched
	once  bool
}

// stop cancels the timer AND tells the scheduler to return zero on the
// next Next() call — ensures no stragglers fire after Close().
func (t *scheduledTask) stop() {
	if t == nil {
		return
	}
	t.sched.stop()
	if t.timer != nil {
		t.timer.Stop()
	}
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
	matcher *urltest.StatusMatcher,
) (uint16, error) {
	tag := ob.Tag()
	if hit, ok := w.freshnessCache.Load(tag); ok {
		if time.Since(hit.at) < w.freshWindow {
			return hit.delay, hit.err
		}
	}
	// Key 里除了 (testURL, tag) 还要混入 matcher.String() —— 不同 Smart 组
	// 可能对同一节点、同一 URL 用不同 expected-status。若 key 里不区分，
	// singleflight 会把探测结果互相覆盖，一个组的 200-299 结果被另一个
	// 组的 204-only 结果污染。matcher.String() 是规范化后的字符串（见
	// expected_status.go），MatchAny 的 matcher 输出 "*"，相同配置
	// 的组共享一个 key 保持性能优势。
	matcherKey := ""
	if matcher != nil {
		matcherKey = matcher.String()
	}
	key := strconv.FormatUint(
		xxhash.Sum64String(testURL)^
			bits.RotateLeft64(xxhash.Sum64String(tag), 31)^
			bits.RotateLeft64(xxhash.Sum64String(matcherKey), 17),
		36,
	)
	v, err, _ := w.probeGroup.Do(key, func() (interface{}, error) {
		// Gate the actual handshake on the global probe semaphore.
		// Only the singleflight LEADER reaches this — followers
		// for the same tag wait at w.probeGroup.Do and share the
		// result, so the sem cap counts distinct in-flight probes
		// regardless of how many Smart groups asked for them.
		ensureProbeSem()
		select {
		case probeSem <- struct{}{}:
			defer func() { <-probeSem }()
		case <-ctx.Done():
			return uint16(0), ctx.Err()
		}
		var detail urltest.URLTestDetail
		d, perr := urltest.URLTestWithDetailAndStatus(ctx, testURL, ob, &detail, matcher)
		w.freshnessCache.Store(tag, probeResult{
			at:     time.Now(),
			delay:  d,
			err:    perr,
			detail: detail,
		})
		return d, perr
	})
	if v == nil {
		return 0, err
	}
	return v.(uint16), err
}
