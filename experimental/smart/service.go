// Package smart hosts the SmartService singleton that owns infrastructure
// shared by Smart outbound groups: the LightGBM model, its updater, and the
// training sample collector.
package smart

import (
	"context"
	"errors"
	"io/fs"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/assetdl"
	"github.com/sagernet/sing-box/common/smart/lightgbm"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service/filemanager"
)

var _ adapter.SmartService = (*Service)(nil)

// Service is the concrete SmartService. Groups type-assert to *Service to
// reach WeightModel and DataCollector. Both are created lazily, the first
// time a group with use_lightgbm or collect_data asks for them.
type Service struct {
	ctx     context.Context
	logger  logger.ContextLogger
	options option.SmartOptions

	modelOnce sync.Once
	modelErr  error
	model     *lightgbm.WeightModel
	dl        *assetdl.Downloader

	collectorOnce sync.Once
	collectorErr  error
	collector     *lightgbm.DataCollector
}

// NewService constructs the service; options may be zero.
func NewService(ctx context.Context, logger logger.ContextLogger, options option.SmartOptions) *Service {
	lightgbm.SetLogger(logger)
	return &Service{ctx: ctx, logger: logger, options: options}
}

func (s *Service) Name() string           { return "smart" }
func (s *Service) Dependencies() []string { return nil }

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(s.close)
	}
	return nil
}

func (s *Service) close() error {
	if s.dl != nil {
		_ = s.dl.Close()
	}
	if s.collector != nil {
		_ = s.collector.Close()
	}
	return nil
}

// LightGBMEnabled reports whether the model is available to groups.
func (s *Service) LightGBMEnabled() bool { return true }

// CollectorEnabled reports whether the collector is available to groups.
func (s *Service) CollectorEnabled() bool { return true }

// WeightModel returns the shared model, loading it on first use and
// downloading it when missing. A nil model means the traditional formula.
func (s *Service) WeightModel() (*lightgbm.WeightModel, error) {
	s.modelOnce.Do(func() {
		s.modelErr = s.initModel()
	})
	return s.model, s.modelErr
}

func (s *Service) initModel() error {
	opts := s.options.LightGBM
	if opts == nil {
		opts = &option.SmartLightGBMOptions{}
	}
	modelPath := opts.ModelPath
	if modelPath == "" {
		modelPath = lightgbm.DefaultModelPath
	}
	modelPath = filemanager.BasePath(s.ctx, modelPath)
	s.model = lightgbm.NewWeightModel(modelPath)
	missing := false
	if err := s.model.Load(); err == nil {
		s.logger.Info("lightgbm model loaded from ", modelPath, " (", s.model.Features(), " features)")
	} else if errors.Is(err, fs.ErrNotExist) {
		missing = true
		s.logger.Debug("lightgbm model not available yet; the traditional formula scores until it is downloaded")
	} else {
		s.logger.Warn("lightgbm: cannot use model ", modelPath, ": ", err)
	}
	url := opts.URL
	if url == "" {
		url = lightgbm.DefaultModelURL
	}
	interval := time.Duration(opts.UpdateInterval)
	if interval <= 0 {
		interval = lightgbm.DefaultUpdateInterval
	}
	transport, err := assetdl.ResolveTransport(s.ctx, s.logger, opts.HTTPClient, opts.DownloadDetour) //nolint:staticcheck
	if err != nil {
		s.logger.Warn("lightgbm: cannot download the model: ", err)
		return nil
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
			if err := s.model.Load(); err != nil {
				return err
			}
			s.logger.Info("lightgbm model reloaded from ", path)
			return nil
		},
	})
	if err != nil {
		s.logger.Warn("lightgbm downloader: ", err)
		return nil
	}
	s.dl = dl
	if opts.AutoUpdate {
		s.dl.Start()
	} else if missing {
		s.logger.Info("lightgbm model missing, downloading from ", url)
		s.dl.StartMissing()
	}
	return nil
}

// DataCollector returns the shared training data collector.
func (s *Service) DataCollector() (*lightgbm.DataCollector, error) {
	s.collectorOnce.Do(func() {
		opts := s.options.Collector
		if opts == nil {
			opts = &option.SmartCollectorOptions{}
		}
		path := opts.Path
		if path == "" {
			path = lightgbm.DefaultCollectorPath
		}
		s.collector = lightgbm.NewDataCollector(filemanager.BasePath(s.ctx, path), opts.SizeLimitMB)
	})
	return s.collector, s.collectorErr
}

// ModelLoadedAt returns when the model was last loaded, zero when it is not.
func (s *Service) ModelLoadedAt() time.Time {
	if s.model == nil {
		return time.Time{}
	}
	return s.model.LastUpdate()
}
