package smart

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/bbolt"
)

// BucketName is the cache file bucket holding Smart evidence.
const BucketName = "smart_score"

// SmartDBProvider is implemented by the cache file service.
type SmartDBProvider interface {
	SmartDB() *bbolt.DB
}

// Store persists the durable part of a group's evidence: global, family and
// site cells (their decayed outcomes, failure state, quality and totals),
// host block records, group-wide blocks and group records such as the
// manual pin. Exact-target cells and fresh performance stay in memory.
type Store struct {
	db     *bbolt.DB
	engine *Engine
}

func NewStore(db *bbolt.DB, engine *Engine) (*Store, error) {
	if db == nil {
		return nil, nil
	}
	err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(BucketName))
		return err
	})
	if err != nil {
		return nil, err
	}
	return &Store{db: db, engine: engine}, nil
}

const (
	prefixCell   = "cell/"
	prefixHost   = "host/"
	prefixBlock  = "gblock/"
	prefixRecord = "rec/"
)

func groupPrefix(kind, group string) []byte {
	return []byte(kind + escapeKey(group) + "/")
}

func escapeKey(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "%", "%25"), "/", "%2F")
}

func unescapeKey(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "%2F", "/"), "%25", "%")
}

// persistedCell is the on-disk form of a cell; times are unix milliseconds.
type persistedCell struct {
	Updated       int64   `json:"u"`
	SetupSuccess  float64 `json:"ss,omitempty"`
	SetupFailure  float64 `json:"sf,omitempty"`
	UsefulSuccess float64 `json:"us,omitempty"`
	UsefulFailure float64 `json:"uf,omitempty"`
	QualitySum    float64 `json:"qs,omitempty"`
	QualityWeight float64 `json:"qw,omitempty"`
	QualityAt     int64   `json:"qa,omitempty"`
	LossEMA       float64 `json:"le,omitempty"`
	LossAt        int64   `json:"la,omitempty"`
	FailStreak    uint32  `json:"fs,omitempty"`
	ExploreAfter  int64   `json:"ea,omitempty"`
	FailedAt      int64   `json:"fa,omitempty"`
	Success       int64   `json:"s,omitempty"`
	Failure       int64   `json:"f,omitempty"`
	UploadTotal   float64 `json:"ut,omitempty"`
	DownloadTotal float64 `json:"dt,omitempty"`
	MaxUpRate     float64 `json:"mu,omitempty"`
	MaxDownRate   float64 `json:"md,omitempty"`
	DurationAvg   float64 `json:"da,omitempty"`
	ConnectAvg    float64 `json:"ca,omitempty"`
	LatencyAvg    float64 `json:"lt,omitempty"`
	CumulSent     uint64  `json:"cs,omitempty"`
	CumulRetrans  uint64  `json:"cr,omitempty"`
	LastUsed      int64   `json:"lu,omitempty"`
}

func wallMillis(m Mono) int64 {
	if m == 0 {
		return 0
	}
	return m.Wall().UnixMilli()
}

func monoMillis(ms int64) Mono {
	if ms == 0 {
		return 0
	}
	return MonoAt(time.UnixMilli(ms))
}

func encodeCell(c *Cell) persistedCell {
	return persistedCell{
		Updated:       wallMillis(c.UpdatedAt),
		SetupSuccess:  c.SetupSuccess,
		SetupFailure:  c.SetupFailure,
		UsefulSuccess: c.UsefulSuccess,
		UsefulFailure: c.UsefulFailure,
		QualitySum:    c.Quality.Sum,
		QualityWeight: c.Quality.Weight,
		QualityAt:     wallMillis(c.Quality.At),
		LossEMA:       c.LossEMA,
		LossAt:        wallMillis(c.LossAt),
		FailStreak:    c.FailStreak,
		ExploreAfter:  wallMillis(c.ExploreNotBefore),
		FailedAt:      wallMillis(c.FailedAt),
		Success:       c.Success,
		Failure:       c.Failure,
		UploadTotal:   c.UploadTotal,
		DownloadTotal: c.DownloadTotal,
		MaxUpRate:     c.MaxUpRate,
		MaxDownRate:   c.MaxDownRate,
		DurationAvg:   c.DurationAvg,
		ConnectAvg:    c.ConnectAvg,
		LatencyAvg:    c.LatencyAvg,
		CumulSent:     c.CumulSent,
		CumulRetrans:  c.CumulRetrans,
		LastUsed:      c.LastUsed,
	}
}

func (p *persistedCell) restore(c *Cell) {
	c.UpdatedAt = monoMillis(p.Updated)
	c.SetupSuccess = p.SetupSuccess
	c.SetupFailure = p.SetupFailure
	c.UsefulSuccess = p.UsefulSuccess
	c.UsefulFailure = p.UsefulFailure
	c.Quality = SlowMetric{Sum: p.QualitySum, Weight: p.QualityWeight, At: monoMillis(p.QualityAt)}
	c.LossEMA = p.LossEMA
	c.LossAt = monoMillis(p.LossAt)
	c.FailStreak = p.FailStreak
	c.ExploreNotBefore = monoMillis(p.ExploreAfter)
	c.FailedAt = monoMillis(p.FailedAt)
	c.Success = p.Success
	c.Failure = p.Failure
	c.UploadTotal = p.UploadTotal
	c.DownloadTotal = p.DownloadTotal
	c.MaxUpRate = p.MaxUpRate
	c.MaxDownRate = p.MaxDownRate
	c.DurationAvg = p.DurationAvg
	c.ConnectAvg = p.ConnectAvg
	c.LatencyAvg = p.LatencyAvg
	c.CumulSent = p.CumulSent
	c.CumulRetrans = p.CumulRetrans
	c.LastUsed = p.LastUsed
}

// cellKey: cell/<group>/<layer>/<network>/<family>/<node>[/<site>]
func cellKey(group string, layer Layer, network Network, family Family, node, site string) []byte {
	var b strings.Builder
	b.WriteString(prefixCell)
	b.WriteString(escapeKey(group))
	b.WriteByte('/')
	b.WriteString(strconv.Itoa(int(layer)))
	b.WriteByte('/')
	b.WriteString(strconv.Itoa(int(network)))
	b.WriteByte('/')
	b.WriteString(strconv.Itoa(int(family)))
	b.WriteByte('/')
	b.WriteString(escapeKey(node))
	if layer == LayerSite {
		b.WriteByte('/')
		b.WriteString(escapeKey(site))
	}
	return []byte(b.String())
}

type persistedHost struct {
	LastFailure int64                     `json:"lf,omitempty"`
	Nodes       map[string]persistedBlock `json:"n"`
}

type persistedBlock struct {
	Code          BlockCode `json:"c"`
	Until         int64     `json:"t"`
	FailCount     int       `json:"f,omitempty"`
	Confirmations int       `json:"k,omitempty"`
	Host          string    `json:"h,omitempty"`
}

// SaveGroup replaces the persisted evidence of a group with its current
// durable cells and block records.
func (s *Store) SaveGroup(g *Group) error {
	if s == nil {
		return nil
	}
	e := s.engine
	type entry struct {
		key   []byte
		value []byte
	}
	var entries []entry
	collect := func(t *Table) {
		t.Range(func(k Key, c *Cell) bool {
			if k.Group != g.id || c.UpdatedAt == 0 {
				return true
			}
			if k.Layer == LayerSite && c.Name == "" {
				return true
			}
			value, err := json.Marshal(encodeCell(c))
			if err == nil {
				entries = append(entries, entry{cellKey(g.tag, k.Layer, k.Network, k.Family, e.NodeName(k.Node), c.Name), value})
			}
			return true
		})
	}
	collect(e.aggregate)
	collect(e.site)
	now := time.Now()
	for _, host := range e.blocks.Hosts(g.id, 1<<30, now) {
		record := persistedHost{LastFailure: host.LastFailure, Nodes: make(map[string]persistedBlock, len(host.Nodes))}
		for node, b := range host.Nodes {
			record.Nodes[e.NodeName(node)] = persistedBlock{b.Code, b.Until, b.FailCount, b.Confirmations, b.Host}
		}
		value, err := json.Marshal(record)
		if err != nil {
			continue
		}
		network := "tcp"
		if host.UDP {
			network = "udp"
		}
		entries = append(entries, entry{[]byte(prefixHost + escapeKey(g.tag) + "/" + network + "/" + escapeKey(host.Key)), value})
	}
	for node, block := range e.blocks.GroupBlocks(g.id, now) {
		value, err := json.Marshal(block)
		if err == nil {
			entries = append(entries, entry{[]byte(prefixBlock + escapeKey(g.tag) + "/" + escapeKey(e.NodeName(node))), value})
		}
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(BucketName))
		if bucket == nil {
			return nil
		}
		for _, kind := range []string{prefixCell, prefixHost, prefixBlock} {
			if err := deletePrefix(bucket, groupPrefix(kind, g.tag)); err != nil {
				return err
			}
		}
		for _, item := range entries {
			if err := bucket.Put(item.key, item.value); err != nil {
				return err
			}
		}
		return nil
	})
}

func deletePrefix(bucket *bbolt.Bucket, prefix []byte) error {
	cursor := bucket.Cursor()
	for k, _ := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = cursor.Seek(prefix) {
		if err := bucket.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// LoadGroup restores a group's persisted evidence for the given members;
// records of other nodes are skipped.
func (s *Store) LoadGroup(g *Group, member func(tag string) bool) (int, error) {
	if s == nil {
		return 0, nil
	}
	e := s.engine
	loaded := 0
	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(BucketName))
		if bucket == nil {
			return nil
		}
		prefix := groupPrefix(prefixCell, g.tag)
		cursor := bucket.Cursor()
		for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
			parts := strings.SplitN(string(k[len(prefix):]), "/", 5)
			if len(parts) < 4 {
				continue
			}
			layer, err1 := strconv.Atoi(parts[0])
			network, err2 := strconv.Atoi(parts[1])
			family, err3 := strconv.Atoi(parts[2])
			if err1 != nil || err2 != nil || err3 != nil || layer > int(LayerSite) {
				continue
			}
			nodeTag := unescapeKey(parts[3])
			if !member(nodeTag) {
				continue
			}
			var site string
			if Layer(layer) == LayerSite {
				if len(parts) < 5 {
					continue
				}
				site = unescapeKey(parts[4])
			}
			var record persistedCell
			if json.Unmarshal(v, &record) != nil {
				continue
			}
			key := Key{Group: g.id, Node: e.NodeID(nodeTag), Network: Network(network), Family: Family(family), Layer: Layer(layer)}
			if key.Layer == LayerSite {
				key.Scope = HashString(site)
			}
			e.table(key.Layer).Update(key, Now(), func(c *Cell) {
				record.restore(c)
				c.Name = site
			})
			loaded++
		}
		hostPrefix := groupPrefix(prefixHost, g.tag)
		cursor = bucket.Cursor()
		for k, v := cursor.Seek(hostPrefix); k != nil && bytes.HasPrefix(k, hostPrefix); k, v = cursor.Next() {
			network, key, ok := strings.Cut(string(k[len(hostPrefix):]), "/")
			if !ok {
				continue
			}
			var record persistedHost
			if json.Unmarshal(v, &record) != nil {
				continue
			}
			entry := HostEntry{Key: unescapeKey(key), UDP: network == "udp", LastFailure: record.LastFailure, Nodes: make(map[uint32]NodeBlock)}
			for tag, b := range record.Nodes {
				if member(tag) {
					entry.Nodes[e.NodeID(tag)] = NodeBlock{b.Code, b.Until, b.FailCount, b.Confirmations, b.Host}
				}
			}
			if len(entry.Nodes) > 0 {
				e.blocks.Restore(g.id, entry)
			}
		}
		blockPrefix := groupPrefix(prefixBlock, g.tag)
		cursor = bucket.Cursor()
		for k, v := cursor.Seek(blockPrefix); k != nil && bytes.HasPrefix(k, blockPrefix); k, v = cursor.Next() {
			tag := unescapeKey(string(k[len(blockPrefix):]))
			var block GroupBlock
			if !member(tag) || json.Unmarshal(v, &block) != nil {
				continue
			}
			if until := time.Unix(block.Until, 0); until.After(time.Now()) {
				e.blocks.BlockGroupNode(g.id, e.NodeID(tag), until, block.Reason)
			}
		}
		return nil
	})
	return loaded, err
}

// FlushGroup deletes every persisted entry of a group, records included.
func (s *Store) FlushGroup(group string) error {
	if s == nil {
		return nil
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(BucketName))
		if bucket == nil {
			return nil
		}
		for _, kind := range []string{prefixCell, prefixHost, prefixBlock, prefixRecord} {
			if err := deletePrefix(bucket, groupPrefix(kind, group)); err != nil {
				return err
			}
		}
		return nil
	})
}

// PruneGroups deletes the persisted entries of groups not in keep.
func (s *Store) PruneGroups(keep map[string]bool) error {
	if s == nil {
		return nil
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(BucketName))
		if bucket == nil {
			return nil
		}
		var stale [][]byte
		err := bucket.ForEach(func(k, _ []byte) error {
			kind, rest, ok := strings.Cut(string(k), "/")
			if !ok {
				return nil
			}
			group, _, _ := strings.Cut(rest, "/")
			if kind+"/" != prefixCell && kind+"/" != prefixHost && kind+"/" != prefixBlock && kind+"/" != prefixRecord {
				return nil
			}
			if !keep[unescapeKey(group)] {
				stale = append(stale, bytes.Clone(k))
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range stale {
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

func recordKey(group, kind, key string) []byte {
	return []byte(prefixRecord + escapeKey(group) + "/" + escapeKey(kind) + "/" + escapeKey(key))
}

// PutRecord stores one group record (manual pin, region state, exit
// information).
func (s *Store) PutRecord(group, kind, key string, value []byte) error {
	if s == nil {
		return nil
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(BucketName))
		if bucket == nil {
			return nil
		}
		return bucket.Put(recordKey(group, kind, key), value)
	})
}

// DeleteRecord deletes one group record.
func (s *Store) DeleteRecord(group, kind, key string) error {
	if s == nil {
		return nil
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(BucketName))
		if bucket == nil {
			return nil
		}
		return bucket.Delete(recordKey(group, kind, key))
	})
}

// Records returns every record of one kind of a group, keyed by record key.
func (s *Store) Records(group, kind string) map[string][]byte {
	if s == nil {
		return nil
	}
	out := make(map[string][]byte)
	prefix := []byte(prefixRecord + escapeKey(group) + "/" + escapeKey(kind) + "/")
	_ = s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(BucketName))
		if bucket == nil {
			return nil
		}
		cursor := bucket.Cursor()
		for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
			out[unescapeKey(string(k[len(prefix):]))] = bytes.Clone(v)
		}
		return nil
	})
	return out
}

// DeleteRecords deletes every record of one kind of a group.
func (s *Store) DeleteRecords(group, kind string) error {
	if s == nil {
		return nil
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(BucketName))
		if bucket == nil {
			return nil
		}
		return deletePrefix(bucket, []byte(prefixRecord+escapeKey(group)+"/"+escapeKey(kind)+"/"))
	})
}
