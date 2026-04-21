// Package smart hosts the global SmartService singleton that owns
// infrastructure shared by Smart outbound groups: the LightGBM model,
// its auto-updater, and the training-sample CSV collector.
package smart

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/assetdl"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/smart/lightgbm"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

// resolveHTTPClientDetour extracts an outbound tag from an http_client option:
//   - inline form with dialer.detour set → returns the detour tag directly
//   - tag form (`"http_client": "foo"`) → looks up foo's detour via Manager
//
// Returns "" when no detour is derivable. Caller should then fall back to
// legacy download_detour.
func resolveHTTPClientDetour(ctx context.Context, opts *option.HTTPClientOptions) string {
	if opts == nil {
		return ""
	}
	if opts.Tag == "" {
		return opts.Detour
	}
	mgr := service.FromContext[adapter.HTTPClientManager](ctx)
	if m, ok := mgr.(*httpclient.Manager); ok {
		return m.LookupDetour(opts.Tag)
	}
	return ""
}

var _ adapter.SmartService = (*Service)(nil)

// Service is the concrete SmartService. Smart outbound groups should
// type-assert to *Service to access WeightModel() / DataCollector().
type Service struct {
	ctx     context.Context
	logger  logger.Logger
	options option.SmartOptions

	lightgbmEnabled  bool
	collectorEnabled bool

	modelOnce sync.Once
	modelErr  error
	model     *lightgbm.WeightModel
	dl        *assetdl.Downloader

	collectorOnce sync.Once
	collectorErr  error
	collector     *lightgbm.DataCollector

	started bool
}

// NewService constructs but does not start the service. Pass the resolved
// SmartOptions (nil-safe: zero value means "use defaults").
//
// Both LightGBM and the training-data collector are ALWAYS enabled at the
// service level — groups that never opt in (via use_lightgbm / collect_data)
// don't trigger any heavy initialization thanks to sync.Once lazy-init.
// This is a behavioural change from earlier versions where a missing
// experimental.smart.lightgbm / experimental.smart.collector block silently
// disabled the feature; now sensible defaults kick in.
func NewService(ctx context.Context, logger logger.Logger, options option.SmartOptions) *Service {
	return &Service{
		ctx:              ctx,
		logger:           logger,
		options:          options,
		lightgbmEnabled:  true,
		collectorEnabled: true,
	}
}

// Name returns the service name for logging / lifecycle management.
func (s *Service) Name() string { return "smart" }

// Dependencies declares startup ordering — currently none.
func (s *Service) Dependencies() []string { return nil }

// Start brings up the service. Heavy resources (model load, downloader,
// collector file) are deferred to first opt-in by a Smart group — this
// avoids spinning up a downloader if no group actually uses ML.
func (s *Service) Start(stage adapter.StartStage) error {
	if stage == adapter.StartStateStart {
		s.started = true
	}
	return nil
}

// Close tears down shared resources.
func (s *Service) Close() error {
	if s.dl != nil {
		_ = s.dl.Close()
	}
	if s.collector != nil {
		_ = s.collector.Close()
	}
	return nil
}

// LightGBMEnabled reports whether ML infrastructure is configured.
func (s *Service) LightGBMEnabled() bool { return s.lightgbmEnabled }

// CollectorEnabled reports whether sample-collection infrastructure is configured.
func (s *Service) CollectorEnabled() bool { return s.collectorEnabled }

// WeightModel returns the shared LightGBM model, initializing it lazily on
// first call. Returns nil if LightGBM was not configured in experimental.smart.
// Safe for concurrent use.
func (s *Service) WeightModel() (*lightgbm.WeightModel, error) {
	if !s.lightgbmEnabled {
		return nil, nil
	}
	s.modelOnce.Do(func() {
		s.modelErr = s.initModel()
	})
	return s.model, s.modelErr
}

func (s *Service) initModel() error {
	// Use configured options when present; fall back to zero-value defaults.
	// This lets a group opt in with just "use_lightgbm": true even when
	// experimental.smart.lightgbm is missing from the config file.
	opts := s.options.LightGBM
	if opts == nil {
		opts = &option.SmartLightGBMOptions{}
	}

	modelPath := opts.ModelPath
	if modelPath == "" {
		modelPath = "smart_lgbm_model.bin"
	}
	modelPath = filemanager.BasePath(s.ctx, modelPath)

	s.model = lightgbm.NewWeightModel(modelPath)
	if err := s.model.Load(); err != nil {
		// Not fatal: downloader may fetch soon. Fallback to CalculateWeight
		// happens inside WeightModel.PredictWeight when model is not loaded.
		s.logger.Debug("lightgbm model not yet available (", err, "); will fallback to traditional algorithm until downloaded")
	} else {
		s.logger.Info("lightgbm model loaded from ", modelPath)
	}

	if opts.AutoUpdate {
		url := opts.URL
		if url == "" {
			url = lightgbm.DefaultModelURL
		}
		interval := defaultDuration(opts.UpdateInterval, lightgbm.DefaultUpdateInterval)

		// Resolve detour outbound tag (assetdl wants an adapter.Outbound as Dialer).
		// Preferred source: http_client (tag ref → Manager.LookupDetour, or inline .Detour).
		// Legacy fallback: download_detour.
		detourTag := resolveHTTPClientDetour(s.ctx, opts.HTTPClient)
		if detourTag == "" {
			detourTag = opts.DownloadDetour //nolint:staticcheck
		}
		var dialer assetdl.Dialer
		if detourTag != "" {
			if mgr := service.FromContext[adapter.OutboundManager](s.ctx); mgr != nil {
				if ob, loaded := mgr.Outbound(detourTag); loaded {
					dialer = ob
				} else {
					s.logger.Warn("lightgbm: detour=[", detourTag, "] not found; using direct")
				}
			} else {
				s.logger.Warn("lightgbm: outbound manager unavailable; using direct")
			}
		}

		dl, err := assetdl.New(assetdl.Options{
			Context:  s.ctx,
			Logger:   s.logger,
			Name:     "lightgbm",
			URL:      url,
			Interval: interval,
			Path:     modelPath,
			Dialer:   dialer,
			OnUpdate: func(path string) error {
				return s.model.Reload()
			},
		})
		if err != nil {
			s.logger.Warn("lightgbm downloader init failed: ", err)
			return err
		}
		s.dl = dl
		via := "direct"
		if detourTag != "" && dialer != nil {
			via = detourTag
		}
		s.logger.Info("lightgbm: auto-update enabled (interval=", interval, ", via=", via, ")")
		s.dl.Start()
	}
	return nil
}

// DataCollector returns the shared sample writer, initializing it lazily.
// Returns nil if collector was not configured in experimental.smart.
func (s *Service) DataCollector() (*lightgbm.DataCollector, error) {
	if !s.collectorEnabled {
		return nil, nil
	}
	s.collectorOnce.Do(func() {
		s.collectorErr = s.initCollector()
	})
	return s.collector, s.collectorErr
}

func (s *Service) initCollector() error {
	// Zero-config path: a group's collect_data: true alone is enough. When
	// experimental.smart.collector is not specified we fall back to default
	// filename smart_weight_data.csv under base path and default 100 MB cap.
	opts := s.options.Collector
	if opts == nil {
		opts = &option.SmartCollectorOptions{}
	}
	path := opts.Path
	if path == "" {
		path = "smart_weight_data.csv"
	}
	path = filemanager.BasePath(s.ctx, path)

	dc, err := lightgbm.NewDataCollector(path, opts.SizeLimitMB, s.logger)
	if err != nil {
		s.logger.Warn("smart collector: init failed: ", err)
		return err
	}
	s.collector = dc
	return nil
}

// ModelAge returns time elapsed since the last successful model (re)load;
// zero if no model is loaded.
func (s *Service) ModelAge() string {
	if s.model == nil {
		return ""
	}
	last := s.model.LastUpdate()
	if last.IsZero() {
		return ""
	}
	return last.Format("2006-01-02T15:04:05")
}
