// Package geox hosts the global GeoX service: downloads geoip.dat /
// geosite.dat / country.mmdb / GeoLite2-ASN.mmdb periodically and exposes
// the local file paths to other sing-box components.
//
// Currently the only consumer is the Smart outbound group (ASN mmdb via
// use_asn: true). Other files are still downloaded for manual use or
// future consumers; absent URLs are simply skipped.
package geox

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/assetdl"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
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

// Service implements adapter.GeoXService.
type Service struct {
	ctx     context.Context
	logger  logger.Logger
	options option.GeoXOptions

	// Resolved absolute paths. Populated from URL set at construction time;
	// empty string means "this asset is not configured".
	geoipPath   string
	geositePath string
	mmdbPath    string
	asnPath     string

	dlMu  sync.Mutex
	dls   []*assetdl.Downloader
	ready bool
}

// NewService constructs but does not start the service. Zero-value options
// (Enabled=false) results in a no-op service: paths return "", no downloads.
func NewService(ctx context.Context, logger logger.Logger, options option.GeoXOptions) *Service {
	s := &Service{
		ctx:     ctx,
		logger:  logger,
		options: options,
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
		if options.URL.ASN != "" {
			s.asnPath = filemanager.BasePath(ctx, DefaultASNFilename)
		}
	}
	return s
}

// Name returns the service name (lifecycle).
func (s *Service) Name() string { return "geox" }

// Dependencies declares startup ordering — none.
func (s *Service) Dependencies() []string { return nil }

// Start brings up the service. When AutoUpdate is enabled, downloaders are
// spawned for every configured URL. When AutoUpdate is disabled, a single
// best-effort fetch is attempted for any missing file.
func (s *Service) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if !s.options.Enabled {
		return nil
	}

	interval := time.Duration(s.options.UpdateInterval)
	if interval <= 0 {
		interval = DefaultUpdateInterval
	}

	// Resolve download_detour tag → adapter.Outbound. adapter.Outbound's
	// DialContext signature satisfies assetdl.Dialer. An empty tag (or
	// an unresolvable one) falls back to direct connection via net.Dialer
	// inside assetdl.
	dialer := s.resolveDetour()

	type spec struct {
		name string
		url  string
		path string
	}
	specs := []spec{
		{"geox/geoip", s.options.URL.GeoIP, s.geoipPath},
		{"geox/geosite", s.options.URL.GeoSite, s.geositePath},
		{"geox/mmdb", s.options.URL.MMDB, s.mmdbPath},
		{"geox/asn", s.options.URL.ASN, s.asnPath},
	}

	s.dlMu.Lock()
	defer s.dlMu.Unlock()

	for _, sp := range specs {
		if sp.url == "" || sp.path == "" {
			continue
		}
		if s.options.AutoUpdate {
			dl, err := assetdl.New(assetdl.Options{
				Context:  s.ctx,
				Logger:   s.logger,
				Name:     sp.name,
				URL:      sp.url,
				Interval: interval,
				Path:     sp.path,
				Dialer:   dialer,
			})
			if err != nil {
				s.logger.Warn("geox: downloader init for ", sp.name, " failed: ", err)
				continue
			}
			s.dls = append(s.dls, dl)
			dl.Start()
		} else {
			// One-shot fetch only when the file is missing (best-effort).
			if _, err := os.Stat(sp.path); os.IsNotExist(err) {
				dl, err := assetdl.New(assetdl.Options{
					Context:  s.ctx,
					Logger:   s.logger,
					Name:     sp.name,
					URL:      sp.url,
					Interval: interval, // unused (no Start)
					Path:     sp.path,
					Dialer:   dialer,
				})
				if err != nil {
					s.logger.Warn("geox: downloader init for ", sp.name, " failed: ", err)
					continue
				}
				go func(d *assetdl.Downloader, n string) {
					if err := d.FetchOnce(s.ctx); err != nil {
						s.logger.Warn("geox: one-shot fetch ", n, " failed: ", err)
					}
				}(dl, sp.name)
			}
		}
	}

	s.ready = true
	via := "direct"
	if s.options.DownloadDetour != "" {
		via = s.options.DownloadDetour
	}
	s.logger.Info("geox: enabled (auto_update=", s.options.AutoUpdate, ", interval=", interval, ", via=", via, ")")
	return nil
}

// resolveDetour looks up the download_detour outbound tag. Returns nil on
// empty tag or resolution failure — assetdl then falls back to direct net dial.
func (s *Service) resolveDetour() assetdl.Dialer {
	tag := s.options.DownloadDetour
	if tag == "" {
		return nil
	}
	mgr := service.FromContext[adapter.OutboundManager](s.ctx)
	if mgr == nil {
		s.logger.Warn("geox: download_detour=[", tag, "] requested but outbound manager unavailable; using direct")
		return nil
	}
	ob, loaded := mgr.Outbound(tag)
	if !loaded {
		s.logger.Warn("geox: download_detour=[", tag, "] not found; using direct")
		return nil
	}
	return ob
}

// Close stops all downloaders.
func (s *Service) Close() error {
	s.dlMu.Lock()
	defer s.dlMu.Unlock()
	for _, dl := range s.dls {
		_ = dl.Close()
	}
	s.dls = nil
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

// ASNPath returns the local GeoLite2-ASN.mmdb path.
func (s *Service) ASNPath() string { return s.asnPath }
