package smart

import (
	"hash/fnv"
	"math"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/VividCortex/ewma"
	"github.com/caio/go-tdigest/v4"
)

// shortRTTEwmaAge and shortSuccessEwmaAge are the "average metric age"
// tuning knobs for the two rolling-mean signals below.
//
// With VividCortex/ewma, a MovingAverage with age=N gives samples at
// the most recent ~N additions a cumulative weight of ~63 % (one 1/e
// time constant). We chose:
//
//   - RTT age = 30: latency can fluctuate with transient congestion,
//     so a ~30-sample horizon catches "something just got worse"
//     without overreacting to a single outlier.
//   - Success age = 20: success/failure is a coarser signal (one bit
//     per dial), so we can move faster. 20 samples still needs 3-4
//     consecutive failures to swing materially, but we won't wait
//     minutes to spot a node that just died.
const (
	shortRTTEwmaAge     = 30.0
	shortSuccessEwmaAge = 20.0
)

const (
	OpSaveNodeState = iota
	OpSaveStats
	OpSavePrefetch
	OpSaveRanking
	OpSaveHostFailures
	// Runtime-state persistence ops — extend the queue / bbolt pipeline to
	// cover in-memory Smart state that was previously lost on restart.
	// Paired Save/Delete variants share the same FormatOperationKey so the
	// queue's dedup slot naturally collapses a save-then-delete into a
	// single tombstone.
	OpSaveManualPin
	OpSaveKnownDead
	OpSaveBreaker
	OpDeleteManualPin // tombstone — bucket.Delete at flush time
	OpDeleteKnownDead
	OpDeleteBreaker
	// Pin-endorsement ledger: per-node, per-group record of how often
	// the user pinned this node, how recently, with what success rate,
	// and which targets it served. Drives time-decayed confidence
	// boosts at selection / weight-write time so user preferences
	// persist beyond the active pin.
	OpSavePinEndorsement
	OpDeletePinEndorsement
)

// isDeleteOp reports whether an op type is a tombstone. Used by BatchSave
// and GetSubBytesByPath to switch between Put and Delete semantics.
func isDeleteOp(t int) bool {
	switch t {
	case OpDeleteManualPin, OpDeleteKnownDead, OpDeleteBreaker, OpDeletePinEndorsement:
		return true
	}
	return false
}

const (
	KeyTypePrefetch     = "prefetch"
	KeyTypeNode         = "node"
	KeyTypeStats        = "stats"
	KeyTypeRanking      = "ranking"
	KeyTypeHostFailures = "failures"
	KeyTypeManualPin      = "manual"   // smart/manual/<cfg>/<grp>
	KeyTypeKnownDead      = "dead"     // smart/dead/<cfg>/<grp>/<node>
	KeyTypeBreaker        = "breaker"  // smart/breaker/<cfg>/<grp>/<node>
	KeyTypePinEndorsement = "pinendor" // smart/pinendor/<cfg>/<grp>/<node>

	WeightTypeTCP    = "tcp"
	WeightTypeUDP    = "udp"
	WeightTypeTCPASN = "tcp_asn"
	WeightTypeUDPASN = "udp_asn"
)

const (
	DefaultMinSampleCount = 2

	MaxTargetsLimit      = 5000
	MinTargetsLimit      = 500
	MaxBatchThreshLimit  = 300
	MinBatchThreshLimit  = 50

	AllowedWeight = 0.4

	RankMostUsed   = "MostUsed"
	RankOccasional = "OccasionalUsed"
	RankRarelyUsed = "RarelyUsed"
)

var CdnASNs = map[string]bool{
	"13335":  true, // Cloudflare
	"12222":  true, // Akamai
	"16625":  true, // Akamai
	"20940":  true, // Akamai
	"31110":  true, // Akamai
	"35994":  true, // Akamai
	"54113":  true, // Fastly
	"22822":  true, // Limelight Networks
	"15133":  true, // EdgeCast (Verizon)
	"19551":  true, // Incapsula (Imperva)
	"20446":  true, // StackPath / Bunny
	"60068":  true, // CDN77
	"16509":  true, // Amazon CloudFront
	"36408":  true, // CDNetworks
	"4809":   true, // ChinaCache
	"199524": true, // Gcore
	"212238": true, // BelugaCDN
	"55933":  true, // QUANTIL
	"43260":  true, // Medianova
	"43317":  true, // CDNvideo
	"43996":  true, // CDNsun
	"52320":  true, // GlobeNet
	"396982": true, // Leaseweb CDN
	"16276":  true, // OVH CDN
	"30081":  true, // CacheFly
	"12389":  true, // Zenlayer
	"37888":  true, // Alibaba CDN
	"45090":  true, // Tencent CDN
	"174":    true, // Cogent Communications
	"3356":   true, // Level 3 Communications
	"3209":   true, // Vodafone
	"14061":  true, // DigitalOcean
	"8452":   true, // Infospace
}

type StoreOperation struct {
	Type   int
	Group  string
	Config string
	Target string
	Node   string
	Data   []byte
}

type StatsRecord struct {
	Success            int64              `json:"success"`
	Failure            int64              `json:"failure"`
	ConnectTime        int64              `json:"connect_time"`
	Latency            int64              `json:"latency"`
	LastUsed           int64              `json:"last_used"`
	Weights            map[string]float64 `json:"weights"`
	UploadTotal        float64            `json:"upload_total"`
	DownloadTotal      float64            `json:"download_total"`
	MaxUploadRate      float64            `json:"max_upload_rate"`
	MaxDownloadRate    float64            `json:"max_download_rate"`
	ConnectionDuration float64            `json:"connection_duration"`

	// RTTDigest is an optional caio/go-tdigest/v4 serialisation of the
	// latency (first-byte) samples collected since the digest was reset.
	// Empty or nil when SampleCount < tdigestWarmupSamples — the per-
	// record overhead (~1 KiB at compression=100) isn't justified until
	// enough data exists for quantile estimates to be meaningful.
	//
	// Currently consumed only by diagnostics (QuantileRTT); the weight
	// function still uses mean+stddev. A future P2 switch can migrate
	// the weight formula to P95 once production data confirms the
	// distributions are skewed enough to benefit.
	//
	// Forward compatibility: both encoding/json and vmihailenco/msgpack
	// treat an unknown optional field as zero on decode, so older builds
	// reading records written by newer builds will silently ignore this
	// field. omitempty keeps the wire size unchanged for records that
	// haven't accumulated enough samples yet.
	RTTDigest []byte `json:"rtt_digest,omitempty"`
}

// modelInputPool recycles ModelInput structs. recordStats allocates one
// per closed connection; in a 16-Smart-group config under heavy traffic
// that's ~1000 × 512-byte allocs/sec (~500 KB/sec GC pressure). Pooling
// eliminates the alloc for the sync path; the async dataCollector path
// takes a stack-local copy so the pooled struct is always safe to reuse.
var modelInputPool = sync.Pool{
	New: func() any { return new(ModelInput) },
}

// AcquireModelInput returns a zero-valued ModelInput from the pool.
// Caller MUST overwrite every field they read — pooled structs carry
// stale data from the previous user otherwise.
func AcquireModelInput() *ModelInput {
	return modelInputPool.Get().(*ModelInput)
}

// ReleaseModelInput zeroes the struct and returns it to the pool.
// Nil-safe. After this call the argument must not be used.
func ReleaseModelInput(m *ModelInput) {
	if m == nil {
		return
	}
	*m = ModelInput{}
	modelInputPool.Put(m)
}

// statsRecordPool recycles StatsRecord snapshots produced on every
// recordStats call. Same rationale as modelInputPool — the snapshot is
// synchronously consumed by the JSON marshaller so pool reuse is safe
// as long as we release after marshal.
var statsRecordPool = sync.Pool{
	New: func() any { return new(StatsRecord) },
}

// AcquireStatsRecord pulls a zeroed StatsRecord off the pool.
func AcquireStatsRecord() *StatsRecord {
	return statsRecordPool.Get().(*StatsRecord)
}

// ReleaseStatsRecord zeroes the struct, releases its Weights map (if
// any), and returns it to the pool. Weights maps aren't reused — their
// size is variable and holding reference would leak ASN entries from a
// previous record.
func ReleaseStatsRecord(r *StatsRecord) {
	if r == nil {
		return
	}
	// Weights and RTTDigest both hold variable-size allocations (map
	// entries and the serialised t-digest buffer respectively). Nil
	// them before the struct-zero so the pooled instance doesn't carry
	// a previous record's memory into the next user.
	r.Weights = nil
	r.RTTDigest = nil
	*r = StatsRecord{}
	statsRecordPool.Put(r)
}

type ModelInput struct {
	Success     int64
	Failure     int64
	ConnectTime int64 // TCP / transport handshake (ms)
	Latency     int64 // first-byte latency from post-connect write (ms)

	// Jitter signals. Standard deviation (not variance) so the magnitude is
	// comparable to ConnectTime / Latency. Populated from AtomicStatsRecord's
	// Welford-online accumulators on snapshot; 0 when samples < 2.
	ConnectTimeStdDev float64
	LatencyStdDev     float64

	// FirstByteLatency is the delay from dial-success to first upstream byte.
	// Separate from Latency (= first-byte from write) so callers can tell
	// TCP-handshake time from TLS + upstream RTT. 0 when not measured.
	FirstByteLatency int64

	// ShortRTT is the VividCortex/ewma rolling mean of recent first-byte
	// latency (ms). 0 means "not enough samples yet" — CalculateWeight
	// treats 0 as absent and falls back to ConnectTime/Latency alone.
	// Purpose: catch nodes that just got worse before their lifetime
	// averages have moved enough to flip the weight ordering.
	ShortRTT float64

	// ShortSuccessRate is the ewma rolling probability of dial success
	// over the most recent ~20 outcomes (see shortSuccessEwmaAge).
	// 0 means "no samples yet"; callers must check >0 before using it.
	// Purpose: detect "node just started failing" within a handful of
	// dials instead of waiting for the lifetime counters to move.
	ShortSuccessRate float64

	UploadTotal            float64
	HistoryUploadTotal     float64
	MaxuploadRate          float64
	HistoryMaxUploadRate   float64
	DownloadTotal          float64
	HistoryDownloadTotal   float64
	MaxdownloadRate        float64
	HistoryMaxDownloadRate float64
	ConnectionDuration     float64
	LastUsed               int64

	IsUDP bool
	IsTCP bool

	DestIPASN string
	Host      string
	DestIP    string
	DestPort  uint16
	DestGeoIP []string

	GroupName string
	NodeName  string
}

type NodeState struct {
	Name           string  `json:"name"`
	FailureCount   int     `json:"failure_count"`
	LastFailure    int64   `json:"last_failure"`
	BlockedUntil   int64   `json:"blocked_until"`
	Degraded       bool    `json:"degraded"`
	DegradedFactor float64 `json:"degraded_factor"`
}

// ManualPinRecord persists a user-initiated "fix this node" choice made
// via ClashAPI PUT /proxies/{tag}. Without persistence the pin evaporates
// on every process restart. Tag=="" is the explicit-unpin sentinel (paired
// with OpDeleteManualPin tombstone).
type ManualPinRecord struct {
	Tag       string `json:"tag"`
	UpdatedAt int64  `json:"updated_at"` // unix seconds
}

// KnownDeadRecord persists "this node failed its last probe at DeadAt".
// Used by isAlive() to keep failed nodes excluded from selection for
// knownDeadTTL beyond the probe cycle. Wall-clock unix seconds so TTL
// arithmetic survives restart.
type KnownDeadRecord struct {
	DeadAt int64 `json:"dead_at"`
}

// BreakerRecord persists circuitBreakerState so a just-tripped breaker
// doesn't silently reset on restart. Timestamps are wall-clock unix-ns
// (matches the in-memory atomic.Int64 field format). OpenUntil==0 means
// the breaker is armed (failure streak active) but not yet tripped.
//
// TripCount was added in the PR3 circuit-breaker enhancement and drives
// exponential backoff across half-open trial failures within a single
// "open-period chain" (i.e. cycles of Open → half-open → fail → Open
// keep escalating the cooldown instead of resetting each time). Older
// builds that didn't write this field decode as zero, which naturally
// equals "first trip, use the base openDuration" — fully backwards
// compatible.
type BreakerRecord struct {
	ConsecFails int32 `json:"consec_fails"`
	FirstFailAt int64 `json:"first_fail_at_ns"`
	OpenUntil   int64 `json:"open_until_ns"`
	TripCount   int32 `json:"trip_count,omitempty"`
}

// PinEndorsementRecord captures the learning signal derived from every
// successful dial made while a node was manually pinned. Stored
// per-(group, node) so decayed boosts survive restart.
//
// Why these fields specifically:
//
//   - Count separates total exposure from the success / failure split —
//     the boost formula wants both (frequency alone is overfit-prone;
//     success rate alone ignores how MUCH the user relied on the node).
//
//   - FirstPinnedAt lets the formula distinguish a brand-new heavy pin
//     (count=100 in one day → possibly temporary "let me watch this one
//     show" preference) from a long-lived lighter pin (count=100 over
//     two months → a steadily-preferred baseline).
//
//   - TopTargets is the contextual signal — a pin used mostly for
//     youtube.com tells us the user likes this node FOR video, not
//     for everything. When recordStats later fires for a non-pinned
//     dial whose target matches a top-target, the endorsement boost
//     still applies (narrower). Capped at 16 entries to bound growth;
//     least-frequent entry evicted when the cap is reached.
//
// Durations / formulas that consume this record live in
// protocol/group/smart_pin_learning.go so the persistence layer has no
// opinion on what "recent" or "enough samples" mean.
type PinEndorsementRecord struct {
	Count         int64            `json:"count"`
	SuccessCount  int64            `json:"success_count"`
	FailureCount  int64            `json:"failure_count"`
	FirstPinnedAt int64            `json:"first_pinned_at"` // unix seconds
	LastPinnedAt  int64            `json:"last_pinned_at"`  // unix seconds
	TopTargets    map[string]int64 `json:"top_targets,omitempty"`
	TopASNs       map[string]int64 `json:"top_asns,omitempty"`
	PinnedHours   map[int]int64    `json:"pinned_hours,omitempty"`
	BaseRTT       float64          `json:"base_rtt,omitempty"`
}

type NodesWithWeights struct {
	Nodes   []string  `json:"nodes"`
	Weights []float64 `json:"weights"`
}

type NodeWithWeight struct {
	Node   string
	Weight float64
}

type PrefetchMap struct {
	TCP         NodesWithWeights `json:"tcp,omitempty"`
	UDP         NodesWithWeights `json:"udp,omitempty"`
	RefTCP      string           `json:"ref_tcp,omitempty"`
	RefUDP      string           `json:"ref_udp,omitempty"`
	UpdatedTime int64            `json:"updated_time,omitempty"`
}

type UnwrapMap struct {
	TCP    []string `json:"tcp,omitempty"`
	UDP    []string `json:"udp,omitempty"`
	RefTCP string   `json:"ref_tcp,omitempty"`
	RefUDP string   `json:"ref_udp,omitempty"`
}

// NodeRank is the API-surface representation of a node's weight standing.
//
// The distinction between Weight and Score is load-bearing — they encode
// two different truths and UIs need both:
//
//   - Weight = raw average weight across targets, SAME scale as the
//              internal CalculateWeight output used at dial selection.
//              Typically ~0.3 (bad) to ~3 (excellent). This is what
//              operators paste into logs to correlate API vs. debug.
//
//   - Score  = 0-100 percentage for progress-bar UIs. Normalised against
//              the group's current max so bar fills always look meaningful
//              even when absolute weights bunch up.
//
// Previous versions only exposed Score as "Weight", which confused users
// comparing ClashAPI output against the debug logs — debug prints raw
// CalculateWeight values, API printed a 0-100 bar, and they never agreed.
type NodeRank struct {
	Name string `json:"name"`
	Rank string `json:"rank"`
	// Weight is the raw average weight across this node's active targets.
	// Matches the scale of the internal weight store — comparable to the
	// values printed by `[Smart] weight=...` debug logs.
	Weight float64 `json:"weight"`
	// Score is a 0-100 normalised percentage derived from Weight / maxWeight
	// within the same ranking batch. Use this for UI bars; use Weight for
	// any comparison against the internal selection pipeline.
	Score float64 `json:"score"`
	// TargetCount is the number of distinct targets contributing to Weight.
	// A node averaged over 1 target is far less confident than one averaged
	// over 50 — exposing this lets UIs dim low-coverage rows. Cold-start
	// (delay-based fallback) reports 1 — the URLTest probe itself counts as
	// a single data point. 0 means truly unknown / no signal at all.
	TargetCount int `json:"targetCount"`
	// SampleCount is the SUM of (success + failure) dial samples across all
	// targets that contributed to Weight. Complements TargetCount: 50
	// targets each with 2 samples (TargetCount=50, SampleCount=100) is far
	// less confident than 1 target with 100 samples (TargetCount=1,
	// SampleCount=100). UIs can show "based on N dials across M targets"
	// for an honest confidence indicator. 0 in cold-start (no real dial
	// data yet) — only delay-probe history exists.
	//
	// Always-output: dropped the `omitempty` so the field is present
	// (even as 0) and dashboards never have to handle "field missing
	// vs field zero". TargetCount uses the same contract.
	SampleCount int   `json:"sampleCount"`
	LastUpdated int64 `json:"lastUpdated"`
}

type HostStatus struct {
	FailureCount int   `json:"failure_count"`
	LastFailure  int64 `json:"last_failure"`
	LastUsed     int64 `json:"last_used"`
}

type ActiveTarget struct {
	Target   string
	ASN      string
	IsUDP    bool
	LastUsed int64
}

// AtomicStatsRecord uses native sync/atomic types (Go 1.19+).
//
// Connect-time and latency each carry Welford-online accumulators
// (mean + M2 + n) so we can surface standard deviation without
// round-tripping every sample to stable storage. The accumulators are
// mutex-protected because Welford is three coupled reads + writes —
// CAS looping would burn more CPU than just taking the lock.
type AtomicStatsRecord struct {
	success     atomic.Int64
	failure     atomic.Int64
	connectTime atomic.Int64
	latency     atomic.Int64
	lastUsed    atomic.Int64

	uploadTotal     atomic.Uint64 // bits of float64
	downloadTotal   atomic.Uint64
	duration        atomic.Uint64
	maxUploadRate   atomic.Uint64
	maxDownloadRate atomic.Uint64

	// Welford online variance for connectTime and latency.
	// Protected together by varianceMu because each Update needs all three
	// fields consistent.
	varianceMu     sync.Mutex
	ctMean         float64 // running mean of connect time (ms)
	ctM2           float64 // sum of squared deviations
	ctN            int64
	latMean        float64
	latM2          float64
	latN           int64

	weightsMu sync.Mutex
	weights   map[string]float64

	// rttDigest accumulates first-byte latency samples into a t-digest
	// (caio/go-tdigest/v4) so we can surface p50/p95/p99 without storing
	// raw samples. Mutex-protected because TDigest.Add mutates internal
	// centroid state. Lazily allocated on first Add so idle records (no
	// dials yet) don't pay the ~2 KiB in-memory digest cost.
	rttDigestMu sync.Mutex
	rttDigest   *tdigest.TDigest

	// ewmaMu guards both shortRTT and shortSuccess — ewma.MovingAverage
	// is NOT safe for concurrent Add so we serialise access. Reads
	// (.Value()) could race-read without corruption but would return
	// a partially-updated double; taking the lock on reads too keeps
	// the numbers self-consistent.
	ewmaMu sync.Mutex

	// shortRTT tracks the recent-window moving average of first-byte
	// latency (ms). Complements the full-history Welford mean + t-digest
	// quantiles by giving the weight function a short-horizon signal:
	// a node whose shortRTT is much higher than its ctMean gets flagged
	// as "currently slow" even if its long-term stats still look fine.
	//
	// Not persisted — resets on process restart. Starts influencing
	// weights after shortRTTEwmaAge samples accumulate.
	shortRTT ewma.MovingAverage

	// shortSuccess tracks the recent success rate (0..1). Updated on
	// every AddInt64("success"/"failure"): 1.0 for success, 0.0 for
	// failure. A node that just dropped from >95 % to 70 % in the last
	// 20 dials shows up here long before the lifetime Success/Failure
	// counters move the needle, so the weight function can act fast.
	shortSuccess ewma.MovingAverage
}

// tdigestCompression controls the centroid budget for each record's
// RTT digest. 100 is a good middle — ≤ 1 % quantile error across the
// CDF, ~1 KiB serialised size.
const tdigestCompression = 100

// tdigestWarmupSamples is the sample-count threshold below which we do
// NOT serialise the digest into the bbolt record. With fewer than this
// many samples the quantile estimates are too noisy to be useful, and
// the extra bytes per row add up fast across 16 Smart groups × many
// proxies × many targets.
const tdigestWarmupSamples = 20

func NewAtomicStatsRecord() *AtomicStatsRecord {
	return &AtomicStatsRecord{
		weights:      make(map[string]float64),
		shortRTT:     ewma.NewMovingAverage(shortRTTEwmaAge),
		shortSuccess: ewma.NewMovingAverage(shortSuccessEwmaAge),
	}
}

func (r *AtomicStatsRecord) loadFloat(a *atomic.Uint64) float64 {
	return math.Float64frombits(a.Load())
}

func (r *AtomicStatsRecord) storeFloat(a *atomic.Uint64, v float64) {
	a.Store(math.Float64bits(v))
}

func (r *AtomicStatsRecord) addFloat(a *atomic.Uint64, delta float64) {
	for {
		old := a.Load()
		oldF := math.Float64frombits(old)
		newF := oldF + delta
		if a.CompareAndSwap(old, math.Float64bits(newF)) {
			return
		}
	}
}

func (r *AtomicStatsRecord) GetInt64(field string) int64 {
	switch field {
	case "success":
		return r.success.Load()
	case "failure":
		return r.failure.Load()
	case "connectTime":
		return r.connectTime.Load()
	case "latency":
		return r.latency.Load()
	case "lastUsed":
		return r.lastUsed.Load()
	}
	return 0
}

func (r *AtomicStatsRecord) GetFloat64(field string) float64 {
	switch field {
	case "uploadTotal":
		return r.loadFloat(&r.uploadTotal)
	case "downloadTotal":
		return r.loadFloat(&r.downloadTotal)
	case "maxUploadRate":
		return r.loadFloat(&r.maxUploadRate)
	case "maxDownloadRate":
		return r.loadFloat(&r.maxDownloadRate)
	case "duration":
		return r.loadFloat(&r.duration)
	}
	return 0
}

func (r *AtomicStatsRecord) SetInt64(field string, v int64) {
	switch field {
	case "success":
		r.success.Store(v)
	case "failure":
		r.failure.Store(v)
	case "connectTime":
		r.connectTime.Store(v)
	case "latency":
		r.latency.Store(v)
	case "lastUsed":
		r.lastUsed.Store(v)
	}
}

func (r *AtomicStatsRecord) SetFloat64(field string, v float64) {
	switch field {
	case "uploadTotal":
		r.storeFloat(&r.uploadTotal, v)
	case "downloadTotal":
		r.storeFloat(&r.downloadTotal, v)
	case "maxUploadRate":
		r.storeFloat(&r.maxUploadRate, v)
	case "maxDownloadRate":
		r.storeFloat(&r.maxDownloadRate, v)
	case "duration":
		r.storeFloat(&r.duration, v)
	}
}

func (r *AtomicStatsRecord) AddInt64(field string, delta int64) {
	const maxInt = math.MaxInt64 / 2
	switch field {
	case "success":
		if cur := r.success.Load(); delta > 0 && cur > maxInt-delta {
			r.success.Store(maxInt / 2)
		} else {
			r.success.Add(delta)
		}
		r.recordSuccessOutcome(delta, 1.0)
	case "failure":
		if cur := r.failure.Load(); delta > 0 && cur > maxInt-delta {
			r.failure.Store(maxInt / 2)
		} else {
			r.failure.Add(delta)
		}
		r.recordSuccessOutcome(delta, 0.0)
	}
}

func (r *AtomicStatsRecord) AddUpload(delta float64) {
	const maxBytes = 1125899906842624.0 // 1PB
	for {
		old := r.uploadTotal.Load()
		oldF := math.Float64frombits(old)
		newF := oldF + delta
		if newF > maxBytes {
			newF = maxBytes / 2
		}
		if r.uploadTotal.CompareAndSwap(old, math.Float64bits(newF)) {
			return
		}
	}
}

func (r *AtomicStatsRecord) AddDownload(delta float64) {
	const maxBytes = 1125899906842624.0
	for {
		old := r.downloadTotal.Load()
		oldF := math.Float64frombits(old)
		newF := oldF + delta
		if newF > maxBytes {
			newF = maxBytes / 2
		}
		if r.downloadTotal.CompareAndSwap(old, math.Float64bits(newF)) {
			return
		}
	}
}

// UpdateConnectTimeSample feeds a new connect-time measurement into the
// Welford online variance algorithm. Call once per successful dial.
// Thread-safe. Bounded samples (n capped at 2^31) so the accumulator
// never overflows; the cap is far beyond any realistic conn count and
// the update remains numerically stable long before it's reached.
func (r *AtomicStatsRecord) UpdateConnectTimeSample(sampleMS int64) {
	if sampleMS <= 0 {
		return
	}
	x := float64(sampleMS)
	r.varianceMu.Lock()
	r.ctN++
	if r.ctN > 1<<31 {
		// Reset with the current mean as a fresh seed — keeps the stat
		// responsive to recent behaviour once ancient history dominates.
		r.ctN = 1
		r.ctM2 = 0
	}
	delta := x - r.ctMean
	r.ctMean += delta / float64(r.ctN)
	delta2 := x - r.ctMean
	r.ctM2 += delta * delta2
	r.varianceMu.Unlock()
}

// UpdateLatencySample mirrors UpdateConnectTimeSample for first-byte latency.
// Additionally it feeds the sample into the per-record t-digest so p50/p95/p99
// estimates become available via (*AtomicStatsRecord).QuantileRTT once enough
// samples have accumulated.
func (r *AtomicStatsRecord) UpdateLatencySample(sampleMS int64) {
	if sampleMS <= 0 {
		return
	}
	x := float64(sampleMS)
	r.varianceMu.Lock()
	r.latN++
	if r.latN > 1<<31 {
		r.latN = 1
		r.latM2 = 0
	}
	delta := x - r.latMean
	r.latMean += delta / float64(r.latN)
	delta2 := x - r.latMean
	r.latM2 += delta * delta2
	r.varianceMu.Unlock()

	r.rttDigestMu.Lock()
	if r.rttDigest == nil {
		td, err := tdigest.New(tdigest.Compression(tdigestCompression))
		if err == nil {
			r.rttDigest = td
		}
	}
	if r.rttDigest != nil {
		// Add error is only returned on NaN/negative — we already guarded
		// with sampleMS > 0 above, so the ignore is safe.
		_ = r.rttDigest.Add(x)
	}
	r.rttDigestMu.Unlock()

	// Feed the recent-window EWMA too. Separated from the Welford path
	// because shortRTT has its own mutex and we want to keep the
	// variance-lock's critical section short.
	r.ewmaMu.Lock()
	if r.shortRTT != nil {
		r.shortRTT.Add(x)
	}
	r.ewmaMu.Unlock()
}

// recordSuccessOutcome feeds the shortSuccess EWMA with one sample per
// outcome event. `delta` is the amount by which the caller incremented
// the success/failure counter; each unit is a separate observation so
// we feed `delta` samples of value `outcomeVal` (1.0 success / 0.0
// failure). In practice delta is almost always 1.
func (r *AtomicStatsRecord) recordSuccessOutcome(delta int64, outcomeVal float64) {
	if delta <= 0 || r.shortSuccess == nil {
		return
	}
	r.ewmaMu.Lock()
	for i := int64(0); i < delta; i++ {
		r.shortSuccess.Add(outcomeVal)
	}
	r.ewmaMu.Unlock()
}

// ShortRTT returns the recent-window EWMA of first-byte latency (ms).
// Returns 0 before the first sample — callers should fall back to the
// long-term mean in that case.
func (r *AtomicStatsRecord) ShortRTT() float64 {
	if r == nil || r.shortRTT == nil {
		return 0
	}
	r.ewmaMu.Lock()
	defer r.ewmaMu.Unlock()
	return r.shortRTT.Value()
}

// ShortSuccessRate returns the recent-window success probability in
// [0, 1]. Returns 0 when no samples yet — callers should sanity-check
// against the lifetime counters to distinguish "truly zero" from
// "nothing observed yet".
func (r *AtomicStatsRecord) ShortSuccessRate() float64 {
	if r == nil || r.shortSuccess == nil {
		return 0
	}
	r.ewmaMu.Lock()
	defer r.ewmaMu.Unlock()
	return r.shortSuccess.Value()
}

// QuantileRTT returns the estimated first-byte latency in milliseconds
// at quantile q (0..1) together with ok=true when the digest has enough
// samples for a meaningful answer (>= tdigestWarmupSamples). Below that
// threshold it returns 0, false so callers can fall back to mean+stddev.
func (r *AtomicStatsRecord) QuantileRTT(q float64) (float64, bool) {
	if r == nil {
		return 0, false
	}
	r.rttDigestMu.Lock()
	defer r.rttDigestMu.Unlock()
	if r.rttDigest == nil || r.rttDigest.Count() < tdigestWarmupSamples {
		return 0, false
	}
	return r.rttDigest.Quantile(q), true
}

// loadRTTDigestBytes deserialises a payload previously produced by the
// snapshot path into the record's digest. Called from the bbolt
// hydration path so a restart retains observed quantile history.
// Silently ignores decode errors — a corrupted digest shouldn't brick
// the record; it just means we start the digest from empty.
func (r *AtomicStatsRecord) loadRTTDigestBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	td, err := tdigest.New(tdigest.Compression(tdigestCompression))
	if err != nil {
		return
	}
	if err := td.FromBytes(b); err != nil {
		return
	}
	r.rttDigestMu.Lock()
	r.rttDigest = td
	r.rttDigestMu.Unlock()
}

// rttDigestBytes returns the serialised digest, or nil when the digest
// has < tdigestWarmupSamples samples. Used on the snapshot-to-record
// path in CreateStatsSnapshot.
func (r *AtomicStatsRecord) rttDigestBytes() []byte {
	if r == nil {
		return nil
	}
	r.rttDigestMu.Lock()
	defer r.rttDigestMu.Unlock()
	if r.rttDigest == nil || r.rttDigest.Count() < tdigestWarmupSamples {
		return nil
	}
	b, err := r.rttDigest.AsBytes()
	if err != nil {
		return nil
	}
	return b
}

// ConnectTimeStdDev returns the sample standard deviation (√(M2/(n-1)))
// in milliseconds. Returns 0 when n < 2 — with a single sample variance
// is undefined and downstream code treats 0 as "unknown jitter".
func (r *AtomicStatsRecord) ConnectTimeStdDev() float64 {
	r.varianceMu.Lock()
	defer r.varianceMu.Unlock()
	if r.ctN < 2 {
		return 0
	}
	variance := r.ctM2 / float64(r.ctN-1)
	if variance <= 0 {
		return 0
	}
	return math.Sqrt(variance)
}

// LatencyStdDev returns the sample standard deviation for first-byte
// latency in milliseconds.
func (r *AtomicStatsRecord) LatencyStdDev() float64 {
	r.varianceMu.Lock()
	defer r.varianceMu.Unlock()
	if r.latN < 2 {
		return 0
	}
	variance := r.latM2 / float64(r.latN-1)
	if variance <= 0 {
		return 0
	}
	return math.Sqrt(variance)
}

func (r *AtomicStatsRecord) GetWeight(weightType string) float64 {
	r.weightsMu.Lock()
	v := r.weights[weightType]
	r.weightsMu.Unlock()
	return v
}

func (r *AtomicStatsRecord) SetWeight(weightType string, value float64, isUDP bool) {
	r.weightsMu.Lock()
	defer r.weightsMu.Unlock()
	r.weights[weightType] = value
	// When writing an ASN-scoped weight (tcp_asn:<n> / udp_asn:<n>), also
	// keep the generic tcp/udp weight in sync — set it to the minimum of
	// all ASN-scoped entries so a target query without ASN context still
	// sees a conservative view of node quality.
	if weightType != WeightTypeTCP && weightType != WeightTypeUDP {
		if isUDP {
			if minUDP := r.minASNWeightLocked(WeightTypeUDP); minUDP > 0 {
				r.weights[WeightTypeUDP] = minUDP
			}
		} else {
			if minTCP := r.minASNWeightLocked(WeightTypeTCP); minTCP > 0 {
				r.weights[WeightTypeTCP] = minTCP
			}
		}
	}
}

func (r *AtomicStatsRecord) minASNWeightLocked(prefix string) float64 {
	min := 0.0
	for k, v := range r.weights {
		if k == prefix || !strings.HasPrefix(k, prefix) {
			continue
		}
		if min == 0.0 || v < min {
			min = v
		}
	}
	return min
}

func (r *AtomicStatsRecord) GetAllWeights() map[string]float64 {
	r.weightsMu.Lock()
	defer r.weightsMu.Unlock()
	result := make(map[string]float64, len(r.weights))
	for k, v := range r.weights {
		result[k] = v
	}
	return result
}

// CreateStatsSnapshot fills a pool-acquired StatsRecord and returns it.
// Caller is expected to pair with ReleaseStatsRecord once the bytes are
// serialised. This sidesteps the prior per-call 200-byte allocation
// that dominated the recordStats write path.
func (r *AtomicStatsRecord) CreateStatsSnapshot() *StatsRecord {
	out := AcquireStatsRecord()
	if r == nil {
		return out
	}
	out.Success = r.success.Load()
	out.Failure = r.failure.Load()
	out.ConnectTime = r.connectTime.Load()
	out.Latency = r.latency.Load()
	out.LastUsed = r.lastUsed.Load()
	out.UploadTotal = r.loadFloat(&r.uploadTotal)
	out.DownloadTotal = r.loadFloat(&r.downloadTotal)
	out.MaxUploadRate = r.loadFloat(&r.maxUploadRate)
	out.MaxDownloadRate = r.loadFloat(&r.maxDownloadRate)
	out.ConnectionDuration = r.loadFloat(&r.duration)
	out.Weights = r.GetAllWeights()
	out.RTTDigest = r.rttDigestBytes()
	return out
}

// Sharded locks: 1024 shards, FNV-hashed
var (
	shardedLocks     [1024]*sync.RWMutex
	shardedLocksOnce sync.Once
)

func initShardedLocks() {
	shardedLocksOnce.Do(func() {
		for i := range shardedLocks {
			shardedLocks[i] = &sync.RWMutex{}
		}
	})
}

func GetTargetNodeLock(target, group, proxy string) *sync.RWMutex {
	initShardedLocks()
	h := fnv.New32a()
	h.Write([]byte(target))
	h.Write([]byte(group))
	h.Write([]byte(proxy))
	return shardedLocks[h.Sum32()&1023]
}

// UpdateAverageInt smoothes integer metrics with a 2:4 weighted average.
func UpdateAverageInt(old, new int64) int64 {
	if old > 0 {
		return (old*2 + new*4) / 6
	}
	return new
}

// UpdateAverageFloat smoothes float metrics. force=true replaces immediately.
func UpdateAverageFloat(old, new float64, force bool) float64 {
	if old > 0 {
		if force {
			return math.Max(new, 0.1)
		}
		return math.Max((old*4+new*2)/6, 0.1)
	}
	return math.Max(new, 0.1)
}

// FormatDBKey builds a bbolt key: "smart/<parts joined by />".
// FormatDBKey builds a hierarchical bbolt key by joining "smart" with
// the supplied parts using `/` as the separator. Each part is
// percent-escaped so any `/` characters appearing inside an outbound
// tag, target hostname, etc. don't accidentally introduce extra path
// segments — that would break every strings.Split-based parser
// downstream and silently drop stats / breakers / unwrap-cache
// entries for affected nodes (e.g. subscription-named nodes like
// "ENET/🇳🇿 Base 新西兰" where the `/` is part of the tag).
//
// Escape rules: `%` → `%25` (escape the escape char first), then
// `/` → `%2F`. Empty parts are skipped to preserve the previous
// behaviour where callers passed "" for "no this segment".
func FormatDBKey(parts ...string) string {
	sb := strings.Builder{}
	sb.WriteString("smart")
	for _, p := range parts {
		if p != "" {
			sb.WriteByte('/')
			sb.WriteString(escapeKeyPart(p))
		}
	}
	return sb.String()
}

// escapeKeyPart percent-escapes the two characters that would
// otherwise corrupt path-based parsing. Lightweight (no full URL
// encoder) because every other byte stays literal — including UTF-8
// emoji bytes which bbolt handles fine as raw byte sequences.
// escapeKeyPart percent-escapes the bytes that would otherwise
// corrupt path-based parsing OR make the key visually ambiguous in
// debug output. Three classes get encoded:
//
//   - `%` itself (must escape first — it's the escape sentinel).
//   - `/` (the path separator; raw `/` inside a part fragments the
//     downstream Split-based parser into more segments than expected).
//   - ASCII control bytes (0x00–0x1F and 0x7F): NUL would silently
//     truncate any C-string consumer; \r/\n/\t make log lines unsafe;
//     DEL is a backspace surprise. Encoding all of them is cheap and
//     makes the key safe to print, paste into shells, etc.
//
// Multi-byte UTF-8 sequences (Chinese / emoji / RTL marks / CJK
// punctuation / mathematical symbols) are LEFT RAW because bbolt
// stores arbitrary bytes and keeping them literal preserves the
// human readability that's critical for `bbolt cli` debugging — an
// outbound tagged "🇭🇰 香港 01" stays recognisable instead of
// becoming "%F0%9F%87%AD%F0%9F%87%B0…". The path parser only cares
// about literal `/`, which is already escaped above.
//
// Result: byte-safe for any input, including Windows-style backslashes,
// raw quotes, currency symbols, full-width punctuation, etc.
func escapeKeyPart(s string) string {
	if !needsEscape(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%':
			b.WriteString("%25")
		case c == '/':
			b.WriteString("%2F")
		case c < 0x20 || c == 0x7F:
			b.WriteString(percentEncodeByte(c))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// needsEscape is the cheap fast-path: most keys (`HK-1`, `*.example.com`,
// `🇭🇰 香港 01`) contain only safe bytes and short-circuit the
// StringBuilder allocation entirely.
func needsEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' || c == '/' || c < 0x20 || c == 0x7F {
			return true
		}
	}
	return false
}

// percentEncodeByte produces "%HH" for a single byte. Manual
// hex emit beats fmt.Sprintf by avoiding reflect/format overhead;
// only called on the rare control-byte path so simplicity wins.
func percentEncodeByte(b byte) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{'%', hex[b>>4], hex[b&0x0F]})
}

// UnescapeKeyPart inverts escapeKeyPart for ANY `%HH` sequence so
// every byte the encoder might have produced round-trips intact —
// control chars, `/`, `%`, and the printable subset are all
// reversible.
//
// Tolerant: malformed escapes ("%2X" / stray "%") are passed through
// unchanged rather than erroring, which means historical bbolt rows
// that pre-date the escape rules still decode back to their
// original raw form. Any byte that wasn't actually `%`-encoded by
// us appears literally in the output.
func UnescapeKeyPart(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := unhexNibble(s[i+1])
			lo, ok2 := unhexNibble(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// unhexNibble parses a single hex digit (case-insensitive) into 0–15.
// Inlinable; on the decode path it shaves a chunk off compared to
// strconv.ParseUint.
func unhexNibble(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10), true
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10), true
	}
	return 0, false
}

// SplitDBKey splits a key produced by FormatDBKey back into its
// original parts, reversing the percent-escape so callers see the
// real segment values (e.g. an outbound tag with `/` returns intact).
// The leading "smart" sentinel is dropped — first returned element
// is keyType.
func SplitDBKey(k string) []string {
	raw := strings.Split(k, "/")
	if len(raw) > 0 && raw[0] == "smart" {
		raw = raw[1:]
	}
	out := make([]string, len(raw))
	for i, p := range raw {
		out[i] = UnescapeKeyPart(p)
	}
	return out
}

func FormatOperationKey(op *StoreOperation) string {
	switch op.Type {
	case OpSaveNodeState:
		return FormatDBKey(KeyTypeNode, op.Config, op.Group, op.Node)
	case OpSaveStats:
		return FormatDBKey(KeyTypeStats, op.Config, op.Group, op.Target, op.Node)
	case OpSavePrefetch:
		return FormatDBKey(KeyTypePrefetch, op.Config, op.Group, op.Target)
	case OpSaveRanking:
		return FormatDBKey(KeyTypeRanking, op.Config, op.Group)
	case OpSaveHostFailures:
		return FormatDBKey(KeyTypeHostFailures, op.Config, op.Group, op.Target)
	// Save / Delete pairs return the SAME key so queue dedup collapses
	// "write then delete" into a single tombstone slot.
	case OpSaveManualPin, OpDeleteManualPin:
		return FormatDBKey(KeyTypeManualPin, op.Config, op.Group)
	case OpSaveKnownDead, OpDeleteKnownDead:
		return FormatDBKey(KeyTypeKnownDead, op.Config, op.Group, op.Node)
	case OpSaveBreaker, OpDeleteBreaker:
		return FormatDBKey(KeyTypeBreaker, op.Config, op.Group, op.Node)
	case OpSavePinEndorsement, OpDeletePinEndorsement:
		return FormatDBKey(KeyTypePinEndorsement, op.Config, op.Group, op.Node)
	}
	return ""
}
