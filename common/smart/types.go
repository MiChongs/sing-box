package smart

import (
	"hash/fnv"
	"math"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	OpSaveNodeState     = iota
	OpSaveStats
	OpSavePrefetch
	OpSaveRanking
	OpSaveHostFailures
)

const (
	KeyTypePrefetch     = "prefetch"
	KeyTypeNode         = "node"
	KeyTypeStats        = "stats"
	KeyTypeRanking      = "ranking"
	KeyTypeHostFailures = "failures"

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
}

type ModelInput struct {
	Success     int64
	Failure     int64
	ConnectTime int64
	Latency     int64

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

type NodeRank struct {
	Name        string
	Rank        string
	Weight      float64
	LastUpdated int64
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

// AtomicStatsRecord uses native sync/atomic types (Go 1.19+)
type AtomicStatsRecord struct {
	success         atomic.Int64
	failure         atomic.Int64
	connectTime     atomic.Int64
	latency         atomic.Int64
	lastUsed        atomic.Int64

	uploadTotal     atomic.Uint64 // bits of float64
	downloadTotal   atomic.Uint64
	duration        atomic.Uint64
	maxUploadRate   atomic.Uint64
	maxDownloadRate atomic.Uint64

	weightsMu sync.Mutex
	weights   map[string]float64
}

func NewAtomicStatsRecord() *AtomicStatsRecord {
	return &AtomicStatsRecord{
		weights: make(map[string]float64),
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
	case "failure":
		if cur := r.failure.Load(); delta > 0 && cur > maxInt-delta {
			r.failure.Store(maxInt / 2)
		} else {
			r.failure.Add(delta)
		}
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
	if weightType != WeightTypeTCP && weightType != WeightTypeUDP {
		minW := r.minASNWeightLocked(WeightTypeUDP)
		if isUDP {
			if minW > 0 {
				r.weights[WeightTypeUDP] = minW
			}
		} else {
			minW = r.minASNWeightLocked(WeightTypeTCP)
			if minW > 0 {
				r.weights[WeightTypeTCP] = minW
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

func (r *AtomicStatsRecord) CreateStatsSnapshot() *StatsRecord {
	if r == nil {
		return &StatsRecord{}
	}
	return &StatsRecord{
		Success:            r.success.Load(),
		Failure:            r.failure.Load(),
		ConnectTime:        r.connectTime.Load(),
		Latency:            r.latency.Load(),
		LastUsed:           r.lastUsed.Load(),
		UploadTotal:        r.loadFloat(&r.uploadTotal),
		DownloadTotal:      r.loadFloat(&r.downloadTotal),
		MaxUploadRate:      r.loadFloat(&r.maxUploadRate),
		MaxDownloadRate:    r.loadFloat(&r.maxDownloadRate),
		ConnectionDuration: r.loadFloat(&r.duration),
		Weights:            r.GetAllWeights(),
	}
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
func FormatDBKey(parts ...string) string {
	sb := strings.Builder{}
	sb.WriteString("smart")
	for _, p := range parts {
		if p != "" {
			sb.WriteByte('/')
			sb.WriteString(p)
		}
	}
	return sb.String()
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
	}
	return ""
}
