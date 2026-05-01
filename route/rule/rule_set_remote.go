package rule

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/hash"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
	"github.com/sagernet/sing/service/pause"
)

const (
	// ruleSetFetchTimeout 单次 rule-set 远端拉取整体超时（含 dial+TLS+headers+body）。
	// 没有该上限时，DNS 黑洞 / TLS 握手挂死 / 慢响应都会永久卡住 fast-retry 轮次，
	// 同时让 io.ReadAll 的内部 grow 无限堆积。
	ruleSetFetchTimeout = 60 * time.Second
	// ruleSetMaxResponseBytes 响应体硬上限。.srs 通常 KB ~ 数 MB；50 MiB 留足余量
	// 同时防止恶意/异常源拖垮内存。
	ruleSetMaxResponseBytes = 50 * 1024 * 1024
)

var _ adapter.RuleSet = (*RemoteRuleSet)(nil)

type RemoteRuleSet struct {
	abstractRuleSet
	cancel         context.CancelFunc
	outbound       adapter.OutboundManager
	options        option.RemoteRuleSet
	updateInterval time.Duration
	httpClient     *http.Client
	hash           hash.HashType
	lastEtag       string
	updateTicker   *time.Ticker
	cacheFile      adapter.CacheFile
	pauseManager   pause.Manager
}

func NewRemoteRuleSet(ctx context.Context, logger logger.ContextLogger, options option.RuleSet) (*RemoteRuleSet, error) {
	ctx, cancel := context.WithCancel(ctx)
	var path string
	if options.Path != "" {
		path = filemanager.BasePath(ctx, options.Path)
		path, _ = filepath.Abs(path)
	}
	var updateInterval time.Duration
	if options.RemoteOptions.UpdateInterval > 0 {
		updateInterval = time.Duration(options.RemoteOptions.UpdateInterval)
	} else {
		updateInterval = 24 * time.Hour
	}
	return &RemoteRuleSet{
		abstractRuleSet: abstractRuleSet{
			ctx:    ctx,
			logger: logger,
			tag:    options.Tag,
			path:   path,
			format: options.Format,
		},
		outbound:       service.FromContext[adapter.OutboundManager](ctx),
		cancel:         cancel,
		options:        options.RemoteOptions,
		updateInterval: updateInterval,
		pauseManager:   service.FromContext[pause.Manager](ctx),
	}, nil
}

func (s *RemoteRuleSet) String() string {
	return strings.Join(F.MapToString(s.rules), " ")
}

func (s *RemoteRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	transport, err := s.resolveTransport()
	if err != nil {
		return E.Cause(err, "create rule-set http client")
	}
	startContext.Register(transport)
	s.httpClient = &http.Client{Transport: transport}
	if err = s.loadCacheFile(); err != nil {
		// 容错启动：缓存加载失败也不阻塞 box 启动。
		// 典型触发场景：上游升级 / DNS 规则收紧后，旧 IP-only rule_set
		// 缓存触发 ValidateRuleSetMetadataUpdate（如 1.14 起禁止纯 IP_CIDR
		// rule_set 在 DNS 规则中无 match_response 使用）。让 fetch 重新
		// 拉取最新内容覆盖坏缓存，比让整个进程崩溃更友好。
		s.logger.Warn("restore cached rule-set ", s.tag, " failed: ", err,
			" — discarding bad cache, fresh fetch follows")
		s.hash = hash.HashType{}
		s.lastEtag = ""
		s.lastUpdated = time.Time{}
		// 同时主动清空 cache.db 中该 tag 的旧脏数据，避免下次启动若 fetch 仍未成
		// 功时再次吃到旧 IP-only 内容触发同样错误。Save 一个 zero-value SavedBinary
		// 即抹掉旧 Hash/Etag/Content/LastUpdated，等价 evict。
		if s.cacheFile != nil {
			if saveErr := s.cacheFile.SaveRuleSet(s.tag, &adapter.SavedBinary{}); saveErr != nil {
				s.logger.Debug("evict stale rule-set cache ", s.tag, ": ", saveErr)
			}
		}
	}
	if s.lastUpdated.IsZero() {
		err = s.fetch(ctx, true)
		if err != nil {
			// 容错启动：远端拉取失败时，不阻塞 box 启动。
			// PostStart 的 loopUpdate 会按 update_interval 周期性重试，
			// 无网络/订阅源临时不可达不会让整个进程崩溃。空规则集在
			// match 时直接返回 false，等价于"该规则永远不命中"，对路
			// 由分流逻辑安全（命中失败由后续规则兜底）。
			s.logger.Warn("initial rule-set ", s.tag, " fetch failed: ", err,
				" — starting with empty set, will retry every ", s.updateInterval)
		}
	}
	s.updateTicker = time.NewTicker(s.updateInterval)
	return nil
}

func (s *RemoteRuleSet) PostStart() error {
	go s.loopUpdate()
	return nil
}

func (s *RemoteRuleSet) loopUpdate() {
	if time.Since(s.lastUpdated) > s.updateInterval {
		s.update()
	}
	// 容错启动快速重试：lastUpdated 仍为零（首次 fetch 从未成功）时，
	// 不能等到 updateInterval（通常 1d）才重试 —— 在网络刚恢复时启动
	// 的实例会卡在空规则集一整天。改用 60s 间隔的 fastRetryTicker 直
	// 到首次拉取成功，之后切回正常 updateTicker 节流。
	const fastRetryInterval = 60 * time.Second
	var fastRetryTicker *time.Ticker
	if s.lastUpdated.IsZero() {
		fastRetryTicker = time.NewTicker(fastRetryInterval)
		defer fastRetryTicker.Stop()
	}
	for {
		runtime.GC()
		var fastRetryC <-chan time.Time
		if fastRetryTicker != nil {
			fastRetryC = fastRetryTicker.C
		}
		select {
		case <-s.ctx.Done():
			return
		case <-s.updateTicker.C:
			s.update()
		case <-fastRetryC:
			s.update()
			if !s.lastUpdated.IsZero() {
				fastRetryTicker.Stop()
				fastRetryTicker = nil
			}
		}
	}
}

func (s *RemoteRuleSet) update() {
	ctx := log.ContextWithNewID(s.ctx)
	err := s.fetch(ctx, false)
	if err != nil {
		s.logger.ErrorContext(ctx, "fetch rule-set ", s.tag, ": ", err)
	} else if s.refs.Load() == 0 {
		s.rules = nil
	}
}

func (s *RemoteRuleSet) Update(ctx context.Context) error {
	err := s.fetch(log.ContextWithNewID(ctx), false)
	if err != nil {
		return err
	} else if s.refs.Load() == 0 {
		s.rules = nil
	}
	return nil
}

func (s *RemoteRuleSet) fetch(ctx context.Context, isStart bool) error {
	s.logger.DebugContext(ctx, "updating rule-set ", s.tag, " from URL: ", s.options.URL)
	// 给单次拉取套整体超时；防止异常源把 fast-retry 永久卡住或让 io.ReadAll 无限堆积内存。
	reqCtx, cancel := context.WithTimeout(ctx, ruleSetFetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(reqCtx, "GET", s.options.URL, nil)
	if err != nil {
		return err
	}
	if s.lastEtag != "" {
		request.Header.Set("If-None-Match", s.lastEtag)
	}
	if !isStart {
		defer s.httpClient.CloseIdleConnections()
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.lastUpdated = time.Now()
		if s.path != "" {
			os.Chtimes(s.path, s.lastUpdated, s.lastUpdated)
		}
		if s.cacheFile != nil {
			if savedRuleSet := s.cacheFile.LoadRuleSet(s.tag); savedRuleSet != nil {
				savedRuleSet.LastUpdated = s.lastUpdated
				if err = s.cacheFile.SaveRuleSet(s.tag, savedRuleSet); err != nil {
					s.logger.Error("save rule-set updated time: ", err)
				}
			}
		}
		s.logger.InfoContext(ctx, "update rule-set ", s.tag, ": not modified")
		return nil
	default:
		return E.New("unexpected status: ", response.Status)
	}
	// LimitReader 多读 1 字节用于判定是否超限。无 cap 的 io.ReadAll 会让恶意源
	// 通过 chunked 编码持续 grow 内部 buffer 直到 OOM。
	content, err := io.ReadAll(io.LimitReader(response.Body, ruleSetMaxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(content) > ruleSetMaxResponseBytes {
		return E.New("rule-set ", s.tag, " response exceeds size limit ", ruleSetMaxResponseBytes>>20, " MiB")
	}
	if len(content) == 0 {
		return E.New("rule-set ", s.tag, " empty response body")
	}
	err = s.loadBytes(content, s)
	if err != nil {
		return err
	}
	eTagHeader := response.Header.Get("Etag")
	if eTagHeader != "" {
		s.lastEtag = eTagHeader
	}
	s.lastUpdated = time.Now()
	if s.path != "" {
		s.saveCacheFile(content)
	}
	if s.cacheFile != nil {
		savedRuleSet := &adapter.SavedBinary{
			LastUpdated: s.lastUpdated,
			LastEtag:    s.lastEtag,
		}
		if s.path != "" {
			savedRuleSet.Hash = s.hash
		} else {
			savedRuleSet.Content = content
		}
		if err = s.cacheFile.SaveRuleSet(s.tag, savedRuleSet); err != nil {
			s.logger.Error("save rule-set cache: ", err)
		}
	}
	s.logger.InfoContext(ctx, "updated rule-set ", s.tag)
	return nil
}

func (s *RemoteRuleSet) resolveTransport() (adapter.HTTPTransport, error) {
	httpClientManager := service.FromContext[adapter.HTTPClientManager](s.ctx)
	if s.options.HTTPClient != nil && !s.options.HTTPClient.IsEmpty() {
		if s.options.DownloadDetour != "" { //nolint:staticcheck
			return nil, E.New("http_client is conflict with deprecated download_detour field")
		}
		return httpClientManager.ResolveTransport(s.ctx, s.logger, *s.options.HTTPClient)
	}
	if s.options.DownloadDetour != "" { //nolint:staticcheck
		deprecated.Report(s.ctx, deprecated.OptionLegacyRuleSetDownloadDetour)
		return httpClientManager.ResolveTransport(s.ctx, s.logger, option.HTTPClientOptions{
			DialerOptions: option.DialerOptions{
				Detour: s.options.DownloadDetour, //nolint:staticcheck
			},
			DisableEmptyDirectCheck: true,
		})
	}
	defaultTransport := httpClientManager.DefaultTransport()
	if defaultTransport == nil {
		return nil, E.New("default http client transport is not initialized")
	}
	return defaultTransport, nil
}

func (s *RemoteRuleSet) loadCacheFile() error {
	var content []byte
	var lastUpdated time.Time
	var lastEtag string
	var savedSet *adapter.SavedBinary
	if s.cacheFile != nil {
		if savedSet = s.cacheFile.LoadRuleSet(s.tag); savedSet != nil {
			s.hash = savedSet.Hash
		}
	}
	if s.path != "" {
		exists, err := pathExists(s.path)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		file, err := os.Open(s.path)
		if err != nil {
			return err
		}
		content, err = io.ReadAll(file)
		file.Close()
		if err != nil {
			return err
		}
		if savedSet != nil {
			if !s.hash.Equal(hash.MakeHash(content)) {
				s.logger.Error("load rule-set cache file failed: validation failed")
				return nil
			}
			lastUpdated = savedSet.LastUpdated
			lastEtag = savedSet.LastEtag
		} else {
			fs, err := os.Stat(s.path)
			if err != nil {
				return err
			}
			lastUpdated = fs.ModTime()
		}
	} else if savedSet != nil && len(savedSet.Content) > 0 {
		content = savedSet.Content
		lastUpdated = savedSet.LastUpdated
		lastEtag = savedSet.LastEtag
	} else {
		return nil
	}
	if err := s.loadBytes(content, s); err != nil {
		return err
	}
	s.lastUpdated, s.lastEtag = lastUpdated, lastEtag
	return nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	if rw.IsDir(path) {
		return false, E.New("rule_set path is a directory: ", path)
	}
	return false, err
}

func (s *RemoteRuleSet) saveCacheFile(contentRaw []byte) {
	s.hash = hash.MakeHash(contentRaw)
	dir := filepath.Dir(s.path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		filemanager.MkdirAll(s.ctx, dir, 0o755)
	}
	filemanager.WriteFile(s.ctx, s.path, []byte(contentRaw), 0o666)
}

func (s *RemoteRuleSet) Close() error {
	s.rules = nil
	s.cancel()
	if s.updateTicker != nil {
		s.updateTicker.Stop()
	}
	return nil
}
