package group

import (
	"context"
	"errors"
	"math"
	"math/bits"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RussellLuo/timingwheel"
	"github.com/cespare/xxhash/v2"
	"github.com/josharian/intern"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
)

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

// smartSharedWorker owns the process-wide execution resources every Smart
// group shares, so N groups referencing the same nodes neither duplicate
// work nor stampede the CPU / network when their timers fire together:
//
//  1. Network probes (URL tests, SNI handshakes) run on a fixed set of
//     probe workers. A request for a probe that is already queued or in
//     flight joins it instead of probing again, and a probe's timeout
//     only starts when a worker picks it up — time spent queued is never
//     mistaken for a slow or dead node.
//
//  2. Connection bookkeeping (stats on close, failed-dial records) runs on
//     a few bookkeeping workers behind a bounded queue. Enqueueing never
//     blocks the IO path; a full queue drops the sample.
//
//  3. freshnessCache remembers very recent probe results by tag so
//     back-to-back requests from different groups (within freshWindow)
//     skip the probe entirely.
//
// Periodic tasks run on the shared timing wheel, see scheduleTask.
type smartSharedWorker struct {
	probes      probeQueue
	bookkeeping chan func()

	// freshnessCache short-TTL result cache to absorb probe bursts.
	//   key = node tag; value = probeResult captured at that moment.
	freshnessCache *xsync.MapOf[string, probeResult]
	// freshWindow is how long a cached probeResult stays valid.
	freshWindow time.Duration

	// wheel is the process-wide timer wheel that drives every Smart group's
	// background tasks. Collapsing 16 groups × 9 tasks = 144 parked
	// ticker goroutines (each costing 2-8 KB stack and a runtime.timer
	// slot) into a single bucket-processor goroutine saves ~500 KB - 2 MB
	// of RSS on a 15-group config.
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

// staggeredInitialDelay offsets the N-th group's first firing of a task
// so groups run it at different points of its period rather than in
// lockstep every cycle. Offsets follow the golden-ratio sequence, which
// keeps any number of groups evenly spread, within min(period/4, 30s) so
// a long period never delays the first run by much.
func staggeredInitialDelay(base, period time.Duration, ordinal int64) time.Duration {
	spread := min(period/4, 30*time.Second)
	if spread <= 0 {
		return base
	}
	const goldenRatioConjugate = 0.6180339887498949
	_, phase := math.Modf(float64(ordinal) * goldenRatioConjugate)
	return base + time.Duration(phase*float64(spread))
}

const (
	// probeQueueCapacity bounds probes waiting for a worker; requests
	// beyond it are skipped (no verdict) instead of piling up.
	probeQueueCapacity = 1024
	// bookkeepingQueueCapacity bounds connection bookkeeping waiting for
	// a worker. Absorbs the close burst of a network handoff.
	bookkeepingQueueCapacity = 2048
	// bookkeepingWorkers drain the bookkeeping queue. recordStats may
	// wait up to 200 ms on a DNS lookup, so a single worker would fall
	// behind under load.
	bookkeepingWorkers = 4
)

// smartProbeWorkers is the number of probe workers: NumCPU*2 clamped to
// [8, 32], so low-end handsets stay around 8 concurrent TLS handshakes
// while a desktop lets 32 race.
func smartProbeWorkers() int {
	return min(max(runtime.NumCPU()*2, 8), 32)
}

// getSmartWorker lazily initialises the process-wide smartSharedWorker.
// Safe to call from any Smart group; all groups share a single instance.
func getSmartWorker() *smartSharedWorker {
	smartWorkerOnce.Do(func() {
		w := &smartSharedWorker{
			probes: probeQueue{
				jobs:  make(map[string]*probeJob),
				queue: make(chan *probeJob, probeQueueCapacity),
			},
			bookkeeping:    make(chan func(), bookkeepingQueueCapacity),
			freshnessCache: xsync.NewMapOf[string, probeResult](),
			freshWindow:    1 * time.Second,
		}
		for range smartProbeWorkers() {
			go w.probes.work()
		}
		for range bookkeepingWorkers {
			go func() {
				for fn := range w.bookkeeping {
					runRecovered(fn)
				}
			}()
		}
		smartWorker = w
	})
	return smartWorker
}

// bookkeep queues fn for the bookkeeping workers. It never blocks: when
// the backlog is full fn is dropped and false is returned, which only
// loses one observation.
func (w *smartSharedWorker) bookkeep(fn func()) bool {
	select {
	case w.bookkeeping <- fn:
		return true
	default:
		return false
	}
}

// runRecovered runs a background task, logging instead of crashing the
// process when it panics.
func runRecovered(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("smart: background task panic: ", r)
		}
	}()
	fn()
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
	period    time.Duration
	firstAt   time.Time
	firedOnce atomic.Bool
	stopped   atomic.Bool
}

// Next is called by timingwheel to decide when the task should next fire.
// Returning zero Time tells the wheel to stop firing.
//
// The wheel calls Next before running the task, and re-adds the timer
// whenever the result is non-zero: a one-shot (period <= 0) must return
// zero after its first firing, or the wheel runs it again immediately.
func (p *periodSched) Next(prev time.Time) time.Time {
	if p.stopped.Load() {
		return time.Time{}
	}
	if p.firedOnce.CompareAndSwap(false, true) && !p.firstAt.IsZero() {
		return p.firstAt
	}
	if p.period <= 0 {
		return time.Time{}
	}
	next := prev.Add(p.period)
	// After a device suspend or a wall-clock step, prev lags far behind
	// and the wheel would replay every missed period back to back.
	// Resume the cadence from now instead.
	if now := time.Now(); next.Before(now) {
		next = now.Add(p.period)
	}
	return next
}

// stop signals the scheduler to end — the next Next() call returns zero.
func (p *periodSched) stop() { p.stopped.Store(true) }

// scheduleTask registers fn to fire once at `initial` (from now) and then
// every `period`. The wheel already runs each firing on its own goroutine,
// so fn runs there directly. A firing that finds the previous run of the
// same task still going is skipped, so a slow task never stacks copies of
// itself. Returns a handle the caller stores so Close() can cancel pending
// firings.
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
		if taskCtx != nil && taskCtx.Err() != nil {
			task.sched.stop()
			return
		}
		if once {
			task.sched.stop()
		}
		if !task.running.CompareAndSwap(false, true) {
			return
		}
		defer task.running.Store(false)
		runRecovered(fn)
	})
	return task
}

// scheduledTask bundles a timing-wheel timer with its scheduler so callers
// can stop both at once when the owning Smart group is closed.
type scheduledTask struct {
	timer   *timingwheel.Timer
	sched   *periodSched
	once    bool
	running atomic.Bool
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

// errProbeSkipped is reported to a probe's callbacks when it could not
// start before its deadline or the probe queue was full. It carries no
// verdict about the node: callers must not count it as a failure.
var errProbeSkipped = errors.New("smart: probe skipped before it started")

type probeJob struct {
	key     string
	run     func(ctx context.Context) (uint16, error)
	timeout time.Duration
	// startBy is the unix-nano deadline for a worker to pick the job up;
	// later requests joining the job may extend it.
	startBy int64
	waiters []func(delay uint16, err error)
}

type probeQueue struct {
	access sync.Mutex
	jobs   map[string]*probeJob // queued or running, by key
	queue  chan *probeJob
}

// enqueueProbe schedules run under key, or joins the queued / running job
// with the same key. done is called exactly once, from a probe worker, with
// the result or errProbeSkipped. A zero startBy never expires.
func (w *smartSharedWorker) enqueueProbe(key string, timeout time.Duration, startBy time.Time, run func(ctx context.Context) (uint16, error), done func(delay uint16, err error)) {
	startByNS := int64(math.MaxInt64)
	if !startBy.IsZero() {
		startByNS = startBy.UnixNano()
	}
	q := &w.probes
	q.access.Lock()
	if job, loaded := q.jobs[key]; loaded {
		job.waiters = append(job.waiters, done)
		job.startBy = max(job.startBy, startByNS)
		q.access.Unlock()
		return
	}
	job := &probeJob{
		key:     key,
		run:     run,
		timeout: timeout,
		startBy: startByNS,
		waiters: []func(uint16, error){done},
	}
	select {
	case q.queue <- job:
		q.jobs[key] = job
		q.access.Unlock()
	default:
		q.access.Unlock()
		done(0, errProbeSkipped)
	}
}

func (q *probeQueue) work() {
	for job := range q.queue {
		q.access.Lock()
		startBy := job.startBy
		q.access.Unlock()
		var (
			delay uint16
			err   error
		)
		if time.Now().UnixNano() > startBy {
			err = errProbeSkipped
		} else {
			runRecovered(func() {
				ctx, cancel := context.WithTimeout(context.Background(), job.timeout)
				defer cancel()
				delay, err = job.run(ctx)
			})
		}
		q.access.Lock()
		delete(q.jobs, job.key)
		waiters := job.waiters
		q.access.Unlock()
		for _, done := range waiters {
			runRecovered(func() { done(delay, err) })
		}
	}
}

// probeURL queues a URL test of ob through the probe workers, deduplicated
// across groups by (testURL, tag, matcher). done receives the delay, the
// probe error, or errProbeSkipped when the probe did not start by startBy.
func (w *smartSharedWorker) probeURL(testURL string, ob adapter.Outbound, matcher *urltest.StatusMatcher, timeout time.Duration, startBy time.Time, done func(delay uint16, err error)) {
	tag := ob.Tag()
	if hit, ok := w.freshnessCache.Load(tag); ok && time.Since(hit.at) < w.freshWindow {
		done(hit.delay, hit.err)
		return
	}
	// Key 里除了 (testURL, tag) 还要混入 matcher.String() —— 不同 Smart 组
	// 可能对同一节点、同一 URL 用不同 expected-status。若 key 里不区分，
	// 探测结果会互相覆盖，一个组的 200-299 结果被另一个组的 204-only
	// 结果污染。matcher.String() 是规范化后的字符串（见
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
	w.enqueueProbe(key, timeout, startBy, func(ctx context.Context) (uint16, error) {
		result := probeBounded(ctx, func() probeResult {
			var detail urltest.URLTestDetail
			delay, err := urltest.URLTestWithDetailAndStatus(ctx, testURL, ob, &detail, matcher)
			return probeResult{delay: delay, err: err, detail: detail}
		})
		result.at = time.Now()
		w.freshnessCache.Store(tag, result)
		return result.delay, result.err
	}, done)
}

// probeBounded returns once ctx is done even if the outbound ignores
// cancellation, so a stuck probe never holds a probe worker past its
// timeout.
func probeBounded(ctx context.Context, probe func() probeResult) probeResult {
	resultChan := make(chan probeResult, 1)
	go func() {
		resultChan <- probe()
	}()
	select {
	case result := <-resultChan:
		return result
	case <-ctx.Done():
		return probeResult{err: ctx.Err()}
	}
}

// freshnessPruneTTL is how long a probeResult lingers after its last
// refresh before pruneFreshnessCache drops it. Probes keyed by tag
// accumulate across the process lifetime — a Smart group that cycled
// through 500 historical node tags and then got reconfigured leaves
// 500 stale entries that never get overwritten again. Each entry holds
// a URLTestDetail struct (~200 bytes) plus map overhead, so without
// pruning the cache can climb into MB territory on long-running daemons
// even though the freshness window itself is just 1 second.
//
// 10 minutes is well past any live probe's usefulness (freshWindow is
// 1 s) and also past the maximum runHealthCheck freshWindow (5 min),
// so no probe that's still authoritative gets pruned.
const freshnessPruneTTL = 10 * time.Minute

// pruneFreshnessCache drops entries older than freshnessPruneTTL. Called
// periodically from the process-wide janitor task registered by the
// first Smart group that starts. Cheap O(N) scan of the xsync.MapOf;
// entries deleted inline while Range'ing is safe for xsync.
func (w *smartSharedWorker) pruneFreshnessCache() {
	if w == nil || w.freshnessCache == nil {
		return
	}
	cutoff := time.Now().Add(-freshnessPruneTTL)
	var dropped int
	w.freshnessCache.Range(func(tag string, v probeResult) bool {
		if v.at.Before(cutoff) {
			w.freshnessCache.Delete(tag)
			dropped++
		}
		return true
	})
	_ = dropped // observable via future instrumentation; no log spam on empty sweeps
}
