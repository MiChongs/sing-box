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
	"net"
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
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/ntp"
)

// DownloadTimeout caps a single HTTP request.
const DownloadTimeout = 90 * time.Second

// Dialer abstracts the network dialer used for downloads (optional detour).
type Dialer interface {
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
}

// Downloader periodically fetches a single asset to a local path and triggers
// a hook on successful refresh.
type Downloader struct {
	ctx          context.Context
	logger       logger.Logger
	name         string
	url          string
	interval     time.Duration
	path         string
	dialer       Dialer
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
	Dialer   Dialer        // optional; nil = use plain net dialer
	OnUpdate func(path string) error
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

	client := &http.Client{
		Timeout: DownloadTimeout,
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if opts.Dialer != nil {
					return opts.Dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
				}
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(opts.Context),
				RootCAs: adapter.RootPoolFromContext(opts.Context),
			},
		},
	}

	return &Downloader{
		ctx:        opts.Context,
		logger:     opts.Logger,
		name:       opts.Name,
		url:        opts.URL,
		interval:   opts.Interval,
		path:       opts.Path,
		dialer:     opts.Dialer,
		onUpdate:   opts.OnUpdate,
		httpClient: client,
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

	// First-run: if no local file, download immediately.
	if _, err := os.Stat(d.path); os.IsNotExist(err) {
		if err := d.FetchOnce(ctx); err != nil {
			d.logger.Warn("assetdl[", d.name, "]: initial download failed: ", err)
		}
	}

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
