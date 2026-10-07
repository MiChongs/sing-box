// Package assetdl provides a reusable periodic asset downloader with
// Etag/Last-Modified conditional requests, atomic on-disk replacement,
// and an on-update hook. Used by Smart's LightGBM model updater and the
// global GeoX service.
package assetdl

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/ntp"
)

// DownloadTimeout caps a single HTTP request.
const DownloadTimeout = 90 * time.Second

// While the file is missing, failed downloads are retried after
// missingRetryMin, doubling up to missingRetryMax, so a download that
// failed at boot (network not up yet) does not wait a full update
// interval or a restart. Variables so tests can shorten them.
var (
	missingRetryMin = 30 * time.Second
	missingRetryMax = 30 * time.Minute
)

// Downloader periodically fetches a single asset to a local path and triggers
// a hook on successful refresh.
type Downloader struct {
	ctx          context.Context
	logger       logger.Logger
	name         string
	url          string
	interval     time.Duration
	path         string
	onUpdate     func(path string) error
	httpClient   *http.Client
	lastEtag     atomic.Value // string
	lastModified atomic.Value // string
	updating     atomic.Bool
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

// Options bundles construction parameters.
type Options struct {
	Context  context.Context
	Logger   logger.Logger
	Name     string        // used in log messages (e.g. "lightgbm", "geox/asn")
	URL      string        // remote URL (required)
	Interval time.Duration // periodic refresh cadence (required)
	Path     string        // absolute on-disk path (required)
	// Transport carries the requests, normally one resolved from an
	// http_client field by ResolveTransport. nil uses a direct transport.
	Transport adapter.HTTPTransport
	OnUpdate  func(path string) error
}

// New constructs a Downloader. Does NOT start the loop — call Start().
func New(opts Options) (*Downloader, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("assetdl: URL is required")
	}
	if opts.Interval <= 0 {
		return nil, fmt.Errorf("assetdl: Interval must be > 0")
	}
	if opts.Path == "" {
		return nil, fmt.Errorf("assetdl: Path is required")
	}
	if opts.Name == "" {
		opts.Name = "asset"
	}
	if opts.Logger == nil {
		opts.Logger = log.StdLogger()
	}
	if opts.Context == nil {
		opts.Context = context.Background()
	}

	var transport http.RoundTripper = opts.Transport
	if opts.Transport == nil {
		transport = &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(opts.Context),
				RootCAs: adapter.RootPoolFromContext(opts.Context),
			},
		}
	}

	return &Downloader{
		ctx:        opts.Context,
		logger:     opts.Logger,
		name:       opts.Name,
		url:        opts.URL,
		interval:   opts.Interval,
		path:       opts.Path,
		onUpdate:   opts.OnUpdate,
		httpClient: &http.Client{Transport: transport, Timeout: DownloadTimeout},
	}, nil
}

// Path returns the local file path where the asset is saved.
func (d *Downloader) Path() string { return d.path }

// Start launches the background ticker. The first fetch runs immediately if
// the local file does not yet exist; otherwise the existing file is used and
// a background refresh is scheduled.
func (d *Downloader) Start() {
	ctx, cancel := context.WithCancel(d.ctx)
	d.cancel = cancel

	if err := os.MkdirAll(filepath.Dir(d.path), 0o755); err != nil {
		d.logger.Warn("assetdl[", d.name, "]: failed to ensure dir: ", err)
		return
	}

	d.wg.Add(1)
	go d.loop(ctx)
}

// StartMissing downloads the file in the background if it does not exist,
// retrying until the download succeeds, without refreshing it afterwards.
// Close stops it.
func (d *Downloader) StartMissing() {
	ctx, cancel := context.WithCancel(d.ctx)
	d.cancel = cancel
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.fetchMissing(ctx, missingRetryMax)
	}()
}

// fetchMissing downloads the file if it does not exist, retrying failures
// with backoff capped at maxDelay.
func (d *Downloader) fetchMissing(ctx context.Context, maxDelay time.Duration) {
	delay := missingRetryMin
	for {
		if _, err := os.Stat(d.path); !os.IsNotExist(err) {
			return
		}
		err := d.FetchOnce(ctx)
		if err == nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
		d.logger.Warn("assetdl[", d.name, "]: download failed, retrying in ", delay, ": ", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, maxDelay)
	}
}

// Close stops the periodic loop and waits for it to exit.
func (d *Downloader) Close() error {
	if d == nil {
		return nil
	}
	if d.cancel != nil {
		d.cancel()
	}
	d.wg.Wait()
	return nil
}

func (d *Downloader) loop(ctx context.Context) {
	defer d.wg.Done()

	// First run: download a missing file now, retrying sooner than the
	// update interval.
	d.fetchMissing(ctx, min(missingRetryMax, d.interval))

	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := d.FetchOnce(ctx); err != nil {
				d.logger.Warn("assetdl[", d.name, "]: refresh failed (will retry next interval): ", err)
			}
		}
	}
}

// FetchOnce performs a single download attempt. Honors If-None-Match and
// If-Modified-Since from previous response to skip unchanged payloads.
// Returns nil on 304 (not modified); writes the file on 200.
func (d *Downloader) FetchOnce(ctx context.Context) error {
	if !d.updating.CompareAndSwap(false, true) {
		return nil // another fetch in progress
	}
	defer d.updating.Store(false)
	// Downloads are hours apart; keep no idle connection between them.
	defer d.httpClient.CloseIdleConnections()
	if err := os.MkdirAll(filepath.Dir(d.path), 0o755); err != nil {
		return fmt.Errorf("create directory: %v", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, DownloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, d.url, nil)
	if err != nil {
		return fmt.Errorf("build request: %v", err)
	}
	if v, ok := d.lastEtag.Load().(string); ok && v != "" {
		req.Header.Set("If-None-Match", v)
	}
	if v, ok := d.lastModified.Load().(string); ok && v != "" {
		req.Header.Set("If-Modified-Since", v)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %v", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		d.logger.Debug("assetdl[", d.name, "]: not modified")
		return nil
	default:
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}

	tmpPath := d.path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open temp file: %v", err)
	}
	n, err := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("download body: %v", err)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %v", closeErr)
	}
	if n == 0 {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("empty response body")
	}

	if err := os.Rename(tmpPath, d.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename: %v", err)
	}

	if e := resp.Header.Get("ETag"); e != "" {
		d.lastEtag.Store(e)
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		d.lastModified.Store(lm)
	}

	d.logger.Info("assetdl[", d.name, "]: downloaded ", n, " bytes → ", d.path)

	if d.onUpdate != nil {
		if err := d.onUpdate(d.path); err != nil {
			d.logger.Warn("assetdl[", d.name, "]: onUpdate hook error: ", err)
		}
	}
	return nil
}
