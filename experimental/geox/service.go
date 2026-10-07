// Package geox hosts the global GeoX service: downloads geoip.dat /
// geosite.dat / country.mmdb / GeoLite2-ASN.mmdb and exposes the local
// file paths to other sing-box components.
//
// Currently the only consumer is the Smart outbound group (ASN and country
// mmdb). Other files are still downloaded for manual use or future
// consumers; absent URLs are simply skipped. Every download goes through
// the configured http client, and a downloaded mmdb is reloaded in place
// for the components that have it open.
package geox

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/assetdl"
	"github.com/sagernet/sing-box/common/geodb"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service/filemanager"
)

var _ adapter.GeoXService = (*Service)(nil)

// DefaultUpdateInterval (24h) matches mihomo's `geo-update-interval: 24`.
const DefaultUpdateInterval = 24 * time.Hour

// Default relative filenames used when saving under filemanager base path.
const (
	DefaultGeoIPFilename   = "geoip.dat"
	DefaultGeoSiteFilename = "geosite.dat"
	DefaultMMDBFilename    = "country.mmdb"
	DefaultASNFilename     = "GeoLite2-ASN.mmdb"
)

// Download sources of the built-in default databases; variables so tests
// can point them at a local server.
var (
	defaultASNURL  = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb"
	defaultMMDBURL = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb"
)

// asset is one file GeoX keeps on disk.
type asset struct {
	name string
	url  string
	path string
	// mmdb marks files opened through geodb, reloaded after each download.
	mmdb bool
}

// Service implements adapter.GeoXService.
type Service struct {
	ctx     context.Context
	logger  logger.ContextLogger
	options option.GeoXOptions

	// Resolved absolute paths. Populated from URL set at construction time;
	// empty string means "this asset is not configured".
	geoipPath   string
	geositePath string
	mmdbPath    string
	// asnPaths holds one absolute path per configured ASN URL — supports
	// multi-source ASN lookup where Smart's lookupASN tries each in order
	// until a hit is found. Single-URL configs produce a single entry,
	// preserving back-compat with the original ASN field.
	asnPaths []string

	access      sync.Mutex
	started     bool
	closed      bool
	pending     []asset // requested before Start
	transport   adapter.HTTPTransport
	resolved    bool
	downloaders map[string]*assetdl.Downloader // by path
}

// NewService constructs but does not start the service. Zero-value options
// (Enabled=false) results in a service that only provides the default
// databases consumers request.
func NewService(ctx context.Context, logger logger.ContextLogger, options option.GeoXOptions) *Service {
	s := &Service{
		ctx:         ctx,
		logger:      logger,
		options:     options,
		downloaders: make(map[string]*assetdl.Downloader),
	}
	if options.Enabled {
		if options.URL.GeoIP != "" {
			s.geoipPath = filemanager.BasePath(ctx, DefaultGeoIPFilename)
		}
		if options.URL.GeoSite != "" {
			s.geositePath = filemanager.BasePath(ctx, DefaultGeoSiteFilename)
		}
		if options.URL.MMDB != "" {
			s.mmdbPath = filemanager.BasePath(ctx, DefaultMMDBFilename)
		}
		// One file per ASN URL. Filename suffix "" for index 0 keeps the
		// pre-existing single-source filename intact (no migration needed
		// for users upgrading from the single-string ASN config).
		for i, u := range options.URL.ASN {
			if u == "" {
				continue
			}
			name := DefaultASNFilename
			if i > 0 {
				name = asnIndexedFilename(i)
			}
			s.asnPaths = append(s.asnPaths, filemanager.BasePath(ctx, name))
		}
	}
	return s
}

// asnIndexedFilename returns the on-disk name for the i-th ASN source.
// Index 0 keeps the original "GeoLite2-ASN.mmdb" filename; index ≥1 gets
// a numeric suffix to avoid collisions when multiple sources are configured.
func asnIndexedFilename(i int) string {
	// e.g. GeoLite2-ASN-1.mmdb, GeoLite2-ASN-2.mmdb
	return "GeoLite2-ASN-" + indexSuffix(i) + ".mmdb"
}

func indexSuffix(i int) string {
	// Avoid importing strconv just for this — small inline impl.
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

// Name returns the service name (lifecycle).
func (s *Service) Name() string { return "geox" }

// Dependencies declares startup ordering — none.
func (s *Service) Dependencies() []string { return nil }

// Start begins downloading the configured files and any default database
// requested earlier. With auto_update each file is fetched when missing
// and refreshed every update_interval; without it a missing file is
// fetched once.
func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(s.close)

	s.access.Lock()
	defer s.access.Unlock()
	s.started = true
	assets := s.pending
	s.pending = nil
	if s.options.Enabled {
		assets = append(assets, s.configuredAssets()...)
		// Configuration errors in http_client surface at startup.
		if err := s.resolveTransportLocked(); err != nil {
			return err
		}
		s.logger.Info("geox: enabled (auto_update=", s.options.AutoUpdate, ", interval=", s.updateInterval(), ", via=", s.via(), ")")
	}
	for _, a := range assets {
		s.ensureLocked(a)
	}
	return nil
}

func (s *Service) configuredAssets() []asset {
	assets := []asset{
		{"geox/geoip", s.options.URL.GeoIP, s.geoipPath, false},
		{"geox/geosite", s.options.URL.GeoSite, s.geositePath, false},
		{"geox/mmdb", s.options.URL.MMDB, s.mmdbPath, true},
	}
	// One downloader per ASN URL. The name encodes the index so users can
	// see which provider failed when multiple are configured.
	for i, u := range s.options.URL.ASN {
		if i >= len(s.asnPaths) || u == "" {
			continue
		}
		name := "geox/asn"
		if i > 0 {
			name = "geox/asn#" + indexSuffix(i)
		}
		assets = append(assets, asset{name, u, s.asnPaths[i], true})
	}
	return assets
}

func (s *Service) updateInterval() time.Duration {
	if interval := time.Duration(s.options.UpdateInterval); interval > 0 {
		return interval
	}
	return DefaultUpdateInterval
}

// via describes the http client downloads go through, for logs.
func (s *Service) via() string {
	switch {
	case s.options.HTTPClient != nil && s.options.HTTPClient.Tag != "":
		return "http_client " + s.options.HTTPClient.Tag
	case s.options.HTTPClient != nil && !s.options.HTTPClient.IsEmpty():
		return "inline http_client"
	case s.options.DownloadDetour != "": //nolint:staticcheck
		return "download_detour " + s.options.DownloadDetour //nolint:staticcheck
	default:
		return "default http client"
	}
}

func (s *Service) resolveTransportLocked() error {
	if s.resolved {
		return nil
	}
	transport, err := assetdl.ResolveTransport(s.ctx, s.logger, s.options.HTTPClient, s.options.DownloadDetour) //nolint:staticcheck
	if err != nil {
		return E.Cause(err, "geox: resolve http client")
	}
	s.transport = transport
	s.resolved = true
	return nil
}

// ensureLocked starts keeping a on disk unless it already is.
func (s *Service) ensureLocked(a asset) {
	if a.url == "" || a.path == "" || s.closed {
		return
	}
	if _, exists := s.downloaders[a.path]; exists {
		return
	}
	if err := s.resolveTransportLocked(); err != nil {
		s.logger.Warn("cannot download ", a.name, ": ", err)
		return
	}
	options := assetdl.Options{
		Context:   s.ctx,
		Logger:    s.logger,
		Name:      a.name,
		URL:       a.url,
		Interval:  s.updateInterval(),
		Path:      a.path,
		Transport: s.transport,
	}
	if a.mmdb {
		options.OnUpdate = func(path string) error {
			return s.reloadDatabase(a.name, path)
		}
	}
	dl, err := assetdl.New(options)
	if err != nil {
		s.logger.Warn("geox: downloader init for ", a.name, " failed: ", err)
		return
	}
	s.downloaders[a.path] = dl
	if s.options.AutoUpdate {
		dl.Start()
	} else {
		dl.StartMissing()
	}
}

// reloadDatabase swaps a freshly downloaded mmdb into every component
// that has it open.
func (s *Service) reloadDatabase(name, path string) error {
	loaded, err := geodb.Reload(path)
	if err != nil {
		return E.Cause(err, "reload ", path)
	}
	if loaded {
		s.logger.Info("geox: reloaded ", name, " from ", path)
	}
	return nil
}

func (s *Service) require(a asset) string {
	s.access.Lock()
	defer s.access.Unlock()
	if s.started {
		s.ensureLocked(a)
	} else {
		s.pending = append(s.pending, a)
	}
	return a.path
}

// RequireDefaultASN returns the path of the default GeoLite2-ASN database
// and starts keeping it downloaded.
func (s *Service) RequireDefaultASN() string {
	return s.require(asset{"geox/asn (default)", defaultASNURL, filemanager.BasePath(s.ctx, DefaultASNFilename), true})
}

// RequireDefaultMMDB returns the path of the default GeoLite2-Country
// database and starts keeping it downloaded.
func (s *Service) RequireDefaultMMDB() string {
	return s.require(asset{"geox/mmdb (default)", defaultMMDBURL, filemanager.BasePath(s.ctx, DefaultMMDBFilename), true})
}

// Close stops all downloaders.
func (s *Service) close() error {
	s.access.Lock()
	defer s.access.Unlock()
	s.closed = true
	for _, dl := range s.downloaders {
		_ = dl.Close()
	}
	clear(s.downloaders)
	return nil
}

// Enabled reports the master switch.
func (s *Service) Enabled() bool { return s.options.Enabled }

// GeoIPPath returns the local geoip.dat path (or "" if not configured).
// Note: the file may not yet exist on disk if download hasn't completed.
func (s *Service) GeoIPPath() string { return s.geoipPath }

// GeoSitePath returns the local geosite.dat path.
func (s *Service) GeoSitePath() string { return s.geositePath }

// MMDBPath returns the local country.mmdb path.
func (s *Service) MMDBPath() string { return s.mmdbPath }

// ASNPath returns the FIRST configured ASN mmdb path. Empty when no ASN URL
// is configured. Single-source compat shim — multi-source consumers should
// use ASNPaths().
func (s *Service) ASNPath() string {
	if len(s.asnPaths) == 0 {
		return ""
	}
	return s.asnPaths[0]
}

// ASNPaths returns every configured ASN mmdb path in priority order.
// Returns nil when no ASN URL was configured.
func (s *Service) ASNPaths() []string {
	if len(s.asnPaths) == 0 {
		return nil
	}
	out := make([]string, len(s.asnPaths))
	copy(out, s.asnPaths)
	return out
}
