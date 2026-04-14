package lightgbm

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/smart"
)

// DefaultCollectorSizeMB is the default training-data file cap (100 MB).
const DefaultCollectorSizeMB = 100

// CollectorMeta carries per-connection metadata needed by AddSample
// (sing-box has no global statistic manager, so callers pass it in).
type CollectorMeta struct {
	DestASN   string
	Host      string
	DestIP    string
	DestPort  uint16
	DestGeoIP []string
}

// DataCollector appends training samples to a CSV file for offline training.
type DataCollector struct {
	mu          sync.Mutex
	dataPath    string
	file        *os.File
	writer      *csv.Writer
	configured  bool
	sampleCount int
	sizeLimit   int64 // bytes
}

// NewDataCollector opens / creates the CSV at csvPath. sizeLimitMB ≤ 0 uses
// DefaultCollectorSizeMB. Returns a ready collector; actual file init is lazy
// (happens on first AddSample).
func NewDataCollector(csvPath string, sizeLimitMB int64) (*DataCollector, error) {
	if csvPath == "" {
		return nil, fmt.Errorf("csvPath is required")
	}
	if sizeLimitMB <= 0 {
		sizeLimitMB = DefaultCollectorSizeMB
	}
	return &DataCollector{
		dataPath:  csvPath,
		sizeLimit: sizeLimitMB * 1024 * 1024,
	}, nil
}

// AddSample writes a training sample to the CSV. Silently becomes a no-op
// on size-limit or IO errors (collector is best-effort).
func (c *DataCollector) AddSample(input *smart.ModelInput, meta *CollectorMeta, actualWeight float64, weightSource string) {
	if c == nil || input == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Detect external deletion of file
	if c.configured {
		if _, err := os.Stat(c.dataPath); os.IsNotExist(err) {
			c.resetFileLocked()
		}
	}

	if c.file != nil {
		if stat, err := c.file.Stat(); err == nil && stat.Size() > c.sizeLimit {
			// Reached cap; silently stop writing
			return
		}
	}

	if !c.configured {
		if err := c.initWriterLocked(); err != nil {
			return
		}
	}

	features := PrepareFeatures(input)
	if len(features) == 0 {
		return
	}

	if meta == nil {
		meta = &CollectorMeta{}
	}

	featureStrs := make([]string, len(features))
	for i, f := range features {
		featureStrs[i] = fmt.Sprintf("%.6f", f)
	}

	geoIPStr := "unknown"
	if len(meta.DestGeoIP) > 0 {
		geoIPStr = strings.Join(meta.DestGeoIP, ",")
	}
	dstASN := "unknown"
	if meta.DestASN != "" {
		dstASN = meta.DestASN
	}
	dstIP := "unknown"
	if meta.DestIP != "" {
		dstIP = meta.DestIP
	}
	host := "unknown"
	if meta.Host != "" {
		host = meta.Host
	}
	source := weightSource
	if source == "" {
		source = "unknown"
	}

	sample := append(featureStrs,
		input.GroupName,
		input.NodeName,
		dstASN,
		host,
		dstIP,
		fmt.Sprintf("%d", meta.DestPort),
		geoIPStr,
		fmt.Sprintf("%.6f", actualWeight),
		source,
		time.Now().Format(time.RFC3339),
	)

	expectedColumns := MaxFeatureSize + 10
	if len(sample) != expectedColumns {
		return
	}

	if err := c.writer.Write(sample); err != nil {
		c.resetFileLocked()
		return
	}
	c.sampleCount++

	if c.sampleCount%100 == 0 {
		c.writer.Flush()
	}
}

func (c *DataCollector) initWriterLocked() error {
	fileExists := false
	if _, err := os.Stat(c.dataPath); err == nil {
		fileExists = true
	}

	needUpgrade := false
	if fileExists {
		if f, err := os.Open(c.dataPath); err == nil {
			reader := csv.NewReader(f)
			headers, err := reader.Read()
			_ = f.Close()
			if err == nil {
				hasMax := false
				for _, h := range headers {
					if h == "history_upload_mb" {
						hasMax = true
						break
					}
				}
				if !hasMax {
					needUpgrade = true
				}
			}
		}
	}

	if needUpgrade {
		backupPath := c.dataPath + ".bak." + time.Now().Format("20060102150405")
		_ = os.Rename(c.dataPath, backupPath)
		fileExists = false
	}

	file, err := os.OpenFile(c.dataPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	c.file = file
	c.writer = csv.NewWriter(file)

	if !fileExists {
		headers := []string{
			"success", "failure", "connect_time", "latency",
			"upload_mb", "history_upload_mb", "maxuploadrate_kb", "history_maxuploadrate_kb",
			"download_mb", "history_download_mb", "maxdownloadrate_kb", "history_maxdownloadrate_kb",
			"duration_minutes", "last_used_seconds", "is_udp", "is_tcp",
			"asn_feature", "country_feature", "address_feature", "port_feature",
			"traffic_ratio", "traffic_density", "connection_type_feature",
			"asn_hash", "host_hash", "ip_hash", "geoip_hash",
			"group_name", "node_name",
			"asn_raw", "host_raw", "ip_raw", "port_raw", "geoip_raw",
			"weight", "weight_source", "timestamp",
		}
		if err := c.writer.Write(headers); err != nil {
			_ = c.file.Close()
			c.file = nil
			c.writer = nil
			return err
		}
		c.writer.Flush()
	}

	c.configured = true
	return nil
}

func (c *DataCollector) resetFileLocked() {
	c.configured = false
	if c.file != nil {
		_ = c.file.Close()
		c.file = nil
	}
	c.writer = nil
}

// Flush writes buffered rows to disk.
func (c *DataCollector) Flush() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writer != nil {
		c.writer.Flush()
	}
}

// Close flushes and closes the underlying file.
func (c *DataCollector) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writer != nil {
		c.writer.Flush()
	}
	if c.file != nil {
		err := c.file.Close()
		c.file = nil
		c.writer = nil
		c.configured = false
		return err
	}
	return nil
}
