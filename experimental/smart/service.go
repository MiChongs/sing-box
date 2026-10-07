// Package smart hosts the global SmartService singleton that owns
// infrastructure shared by Smart outbound groups: the LightGBM model,
// its auto-updater, and the training-sample CSV collector.
package smart

import (
	"context"
	"errors"
	"io/fs"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/assetdl"
	"github.com/sagernet/sing-box/common/smart/lightgbm"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service/filemanager"
)

var _ adapter.SmartService = (*Service)(nil)

// Service is the concrete SmartService. Smart outbound groups should
// type-assert to *Service to access WeightModel() / DataCollector().
type Service struct {
	ctx     context.Context
	logger  logger.ContextLogger
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
func NewService(ctx context.Context, logger logger.ContextLogger, options option.SmartOptions) *Service {
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
func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		// The downloader and collector exist from construction on.
		scope.Add(s.close)
	case adapter.StartStateStart:
		s.started = true
	}
	return nil
}

// Close tears down shared resources.
func (s *Service) close() error {
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
	modelMissing := false
	if err := s.model.Load(); err == nil {
		s.logger.Info("lightgbm model loaded from ", modelPath)
	} else if errors.Is(err, fs.ErrNotExist) {
		modelMissing = true
		s.logger.Debug("lightgbm model not yet available; traditional weights until it is downloaded")
	} else {
		s.logger.Warn("lightgbm: cannot use model ", modelPath, ": ", err, "; traditional weights until a usable model replaces it")
	}

	url := opts.URL
	if url == "" {
		url = lightgbm.DefaultModelURL
	}
	interval := defaultDuration(opts.UpdateInterval, lightgbm.DefaultUpdateInterval)

	transport, err := assetdl.ResolveTransport(s.ctx, s.logger, opts.HTTPClient, opts.DownloadDetour) //nolint:staticcheck
	if err != nil {
		s.logger.Warn("lightgbm: cannot download the model: resolve http client: ", err)
		return err
	}
	dl, err := assetdl.New(assetdl.Options{
		Context:   s.ctx,
		Logger:    s.logger,
		Name:      "lightgbm",
		URL:       url,
		Interval:  interval,
		Path:      modelPath,
		Transport: transport,
		OnUpdate: func(path string) error {
			if err := s.model.Reload(); err != nil {
				return err
			}
			s.logger.Info("lightgbm: model reloaded from ", path)
			return nil
		},
	})
	if err != nil {
		s.logger.Warn("lightgbm downloader init failed: ", err)
		return err
	}
	s.dl = dl

	if opts.AutoUpdate {
		s.logger.Info("lightgbm: auto-update enabled (interval=", interval, ")")
		s.dl.Start()
	} else if modelMissing {
		// Only a missing file is fetched. Downloads replace the file
		// atomically, so one that exists is complete, and fetching the
		// same release again on every start cannot make it loadable.
		s.logger.Info("lightgbm: model file missing, fetching once from ", url)
		s.dl.StartMissing()
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

	dc, err := lightgbm.NewDataCollector(path, int64(opts.SizeLimitMB), s.logger)
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
