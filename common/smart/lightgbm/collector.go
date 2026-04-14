package lightgbm

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing/common/logger"
)

// DefaultCollectorSizeMB is the default training-data file cap (100 MB).
const DefaultCollectorSizeMB = 100

// flushInterval caps how long buffered rows may sit in memory without being
// written to disk. Prevents data loss if the process is killed right after
// starting — the previous "flush every 100 rows" rule could keep ~100 samples
// buffered for many minutes on low-traffic devices.
const flushInterval = 30 * time.Second

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
// All IO errors are surfaced to the configured logger (no silent drops).
type DataCollector struct {
	mu          sync.Mutex
	logger      logger.Logger
	dataPath    string
	file        *os.File
	writer      *csv.Writer
	configured  bool
	sampleCount int
	writtenRows atomic.Int64 // total rows successfully written since process start
	droppedRows atomic.Int64 // samples silently dropped (size limit / init error)
	sizeLimit   int64        // bytes

	stopCh   chan struct{}
	stopped  atomic.Bool
	closedCh chan struct{}
}

// NewDataCollector creates the collector and starts a background flusher goroutine.
// sizeLimitMB ≤ 0 uses DefaultCollectorSizeMB. logger may be nil (falls back to a
// no-op logger — but errors then become undetectable from outside).
func NewDataCollector(csvPath string, sizeLimitMB int64, log logger.Logger) (*DataCollector, error) {
	if csvPath == "" {
		return nil, fmt.Errorf("csvPath is required")
	}
	if sizeLimitMB <= 0 {
		sizeLimitMB = DefaultCollectorSizeMB
	}
	if log == nil {
		log = nopLogger{}
	}

	c := &DataCollector{
		logger:    log,
		dataPath:  csvPath,
		sizeLimit: sizeLimitMB * 1024 * 1024,
		stopCh:    make(chan struct{}),
		closedCh:  make(chan struct{}),
	}

	// Pre-flight: ensure the parent directory exists and we can write there.
	// Previously this happened lazily in initWriterLocked() with a silent
	// failure path; now we surface the error up front so misconfigurations
	// fail loudly at service start instead of dropping samples forever.
	if err := os.MkdirAll(filepath.Dir(csvPath), 0o755); err != nil {
		return nil, fmt.Errorf("create collector directory: %v", err)
	}
	log.Info("smart collector: CSV at ", csvPath, " (cap ", sizeLimitMB, " MB)")

	go c.flushLoop()
	return c, nil
}

// Path returns the absolute CSV path.
func (c *DataCollector) Path() string {
	if c == nil {
		return ""
	}
	return c.dataPath
}

// WrittenRows returns the count of successfully written rows.
func (c *DataCollector) WrittenRows() int64 {
	if c == nil {
		return 0
	}
	return c.writtenRows.Load()
}

// DroppedRows returns the count of dropped samples (size limit or init errors).
func (c *DataCollector) DroppedRows() int64 {
	if c == nil {
		return 0
	}
	return c.droppedRows.Load()
}

func (c *DataCollector) flushLoop() {
	defer close(c.closedCh)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.Flush()
		}
	}
}

// AddSample writes a training sample to the CSV. Errors are logged (not
// silently dropped) and dropped rows are counted.
func (c *DataCollector) AddSample(input *smart.ModelInput, meta *CollectorMeta, actualWeight float64, weightSource string) {
	if c == nil || input == nil {
		return
	}
	if c.stopped.Load() {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Detect external deletion of file between writes (e.g. user rm'd it)
	if c.configured {
		if _, err := os.Stat(c.dataPath); os.IsNotExist(err) {
			c.logger.Info("smart collector: data file was deleted externally, reinitializing")
			c.resetFileLocked()
		}
	}

	// Enforce size cap
	if c.file != nil {
		if stat, err := c.file.Stat(); err == nil && stat.Size() > c.sizeLimit {
			if c.droppedRows.Add(1) == 1 {
				c.logger.Warn("smart collector: reached size limit ", c.sizeLimit>>20, " MB; dropping further samples (delete or increase size_limit_mb to resume)")
			}
			return
		}
	}

	if !c.configured {
		if err := c.initWriterLocked(); err != nil {
			c.droppedRows.Add(1)
			c.logger.Warn("smart collector: init writer failed: ", err, " (dropping sample)")
			return
		}
	}

	features := PrepareFeatures(input)
	if len(features) == 0 {
		c.droppedRows.Add(1)
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
		c.droppedRows.Add(1)
		c.logger.Warn("smart collector: column count mismatch (got ", len(sample), ", expected ", expectedColumns, ")")
		return
	}

	if err := c.writer.Write(sample); err != nil {
		c.droppedRows.Add(1)
		c.logger.Warn("smart collector: write failed: ", err, " — will reinit on next sample")
		c.resetFileLocked()
		return
	}
	c.sampleCount++
	c.writtenRows.Add(1)

	// Per-100 flush keeps buffers tight on high-traffic devices;
	// flushLoop() covers the low-traffic case.
	if c.sampleCount%100 == 0 {
		c.writer.Flush()
		if err := c.writer.Error(); err != nil {
			c.logger.Warn("smart collector: flush error: ", err)
		}
	}
}

func (c *DataCollector) initWriterLocked() error {
	// Double-check parent dir (may have been deleted at runtime).
	if err := os.MkdirAll(filepath.Dir(c.dataPath), 0o755); err != nil {
		return fmt.Errorf("mkdir parent: %v", err)
	}

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
		if err := os.Rename(c.dataPath, backupPath); err == nil {
			c.logger.Info("smart collector: schema upgrade — old file backed up to ", backupPath)
			fileExists = false
		}
	}

	file, err := os.OpenFile(c.dataPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open csv: %v", err)
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
			return fmt.Errorf("write headers: %v", err)
		}
		c.writer.Flush()
		if err := c.writer.Error(); err != nil {
			_ = c.file.Close()
			c.file = nil
			c.writer = nil
			return fmt.Errorf("flush headers: %v", err)
		}
		c.logger.Info("smart collector: created new CSV with headers at ", c.dataPath)
	} else {
		c.logger.Info("smart collector: appending to existing CSV at ", c.dataPath)
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
		if err := c.writer.Error(); err != nil {
			c.logger.Warn("smart collector: periodic flush error: ", err)
		}
	}
}

// Close flushes and closes the underlying file, and stops the flush loop.
func (c *DataCollector) Close() error {
	if c == nil {
		return nil
	}
	if c.stopped.CompareAndSwap(false, true) {
		close(c.stopCh)
		<-c.closedCh
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	written := c.writtenRows.Load()
	dropped := c.droppedRows.Load()
	if c.writer != nil {
		c.writer.Flush()
	}
	if c.file != nil {
		err := c.file.Close()
		c.file = nil
		c.writer = nil
		c.configured = false
		c.logger.Info("smart collector: closed (", written, " rows written, ", dropped, " dropped)")
		return err
	}
	return nil
}

// nopLogger is a minimal fallback when no logger is provided to NewDataCollector.
type nopLogger struct{}

func (nopLogger) Trace(...any) {}
func (nopLogger) Debug(...any) {}
func (nopLogger) Info(...any)  {}
func (nopLogger) Warn(...any)  {}
func (nopLogger) Error(...any) {}
func (nopLogger) Fatal(...any) {}
func (nopLogger) Panic(...any) {}
