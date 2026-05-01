package remote

import (
	"bytes"
	"context"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/hash"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/provider/parser"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

func RegisterProvider(registry *provider.Registry) {
	provider.Register[option.ProviderRemoteOptions](registry, C.ProviderTypeRemote, NewProviderRemote)
}

const (
	// fetchTimeout 单次远端拉取整体超时（含 dial + TLS + headers + body 全程）。
	// 没有该上限时，DNS 黑洞 / TLS 握手挂死 / 慢响应都会永久卡住 fast-retry 轮次。
	fetchTimeout = 60 * time.Second
	// maxResponseBytes 订阅响应体硬上限，防止恶意/异常源拖垮内存。
	// 实际订阅文件通常几百 KB 到几 MB，50 MiB 留足余量。
	maxResponseBytes = 50 * 1024 * 1024
	// fastRetryBase 首次拉取失败后 fast-retry 的初始重试间隔。
	fastRetryBase = 60 * time.Second
	// fastRetryCap fast-retry 指数退避封顶；超过即按 cap 周期重试直到成功。
	fastRetryCap = 30 * time.Minute
	// startupJitter 启动初次 fetch 的随机抖动上限，避免多 provider 同时启动雪崩同源服务器。
	startupJitter = 2 * time.Second
)

var _ adapter.Provider = (*ProviderRemote)(nil)

type ProviderRemote struct {
	provider.Adapter
	ctx              context.Context
	cancel           context.CancelFunc
	logger           log.ContextLogger
	outbound         adapter.OutboundManager
	provider         adapter.ProviderManager
	cacheFile        adapter.CacheFile
	httpClient       *http.Client
	hash             hash.HashType
	lastEtag         string
	lastOutOpts      []option.Outbound
	lastEPOpts       []option.Endpoint
	lastUpdated      time.Time
	subscriptionInfo adapter.SubscriptionInfo
	ticker           *time.Ticker
	updating         atomic.Bool
	// consecutiveFailures fast-retry 连续失败次数，用于指数退避计算与可观测日志。
	consecutiveFailures atomic.Int32

	httpClientOptions *option.HTTPClientOptions
	downloadDetour    string
	url               string
	path              string
	userAgent         string
	updateInterval    time.Duration
	exclude           *regexp.Regexp
	include           *regexp.Regexp

	overrideDialer *option.OverrideDialerOptions
	overrideTLS    *option.OverrideTLSOptions
}

func NewProviderRemote(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, options option.ProviderRemoteOptions) (adapter.Provider, error) {
	if options.URL == "" {
		return nil, E.New("provider URL is required")
	}
	var path string
	if options.Path != "" {
		path = filemanager.BasePath(ctx, options.Path)
		path, _ = filepath.Abs(path)
	}
	if rw.IsDir(path) {
		return nil, E.New("provider path is a directory: ", path)
	}
	updateInterval := time.Duration(options.UpdateInterval)
	if updateInterval <= 0 {
		updateInterval = 24 * time.Hour
	}
	if updateInterval < time.Hour {
		updateInterval = time.Hour
	}
	var userAgent string
	if options.UserAgent == "" {
		userAgent = "sing-box " + C.Version
	} else {
		userAgent = options.UserAgent
	}
	ctx, cancel := context.WithCancel(ctx)
	outbound := service.FromContext[adapter.OutboundManager](ctx)
	endpointMgr := service.FromContext[adapter.EndpointManager](ctx)
	logger := logFactory.NewLogger(F.ToString("provider/remote", "[", tag, "]"))
	updateChan := make(chan struct{})
	close(updateChan)
	return &ProviderRemote{
		Adapter:  provider.NewAdapter(ctx, router, outbound, endpointMgr, logFactory, logger, tag, C.ProviderTypeRemote, options.HealthCheck),
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		outbound: outbound,
		provider: service.FromContext[adapter.ProviderManager](ctx),

		httpClientOptions: options.HTTPClient,
		downloadDetour:    options.DownloadDetour,
		url:               options.URL,
		path:              path,
		userAgent:         userAgent,
		updateInterval:    updateInterval,
		exclude:           (*regexp.Regexp)(options.Exclude),
		include:           (*regexp.Regexp)(options.Include),

		overrideDialer: options.OverrideDialer,
		overrideTLS:    options.OverrideTLS,
	}, nil
}

func (s *ProviderRemote) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	if err := s.loadCacheFile(); err != nil {
		// 容错启动：缓存加载失败（损坏 / 解析错误 / 文件 IO 异常）也不阻塞 box 启动。
		// 重置内部状态让后续 fetch 走全量路径。
		s.logger.Warn("restore cached outbound provider ", s.Tag(), " failed: ", err,
			" — starting without cache, fresh fetch follows")
		s.hash = hash.HashType{}
		s.lastEtag = ""
		s.lastUpdated = time.Time{}
		s.lastOutOpts = nil
		s.lastEPOpts = nil
	}
	transport, err := s.resolveTransport()
	if err != nil {
		return E.Cause(err, "create provider http client")
	}
	startContext.Register(transport)
	s.httpClient = &http.Client{Transport: transport}
	if s.lastUpdated.IsZero() {
		// 启动时叠加 0~startupJitter 抖动：多 provider 配置同源订阅 / 同源 CDN 时
		// 避免同一秒并发请求把上游打崩。单实例下抖动不可见，无副作用。
		if startupJitter > 0 {
			delay := time.Duration(mrand.Int64N(int64(startupJitter)))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		fetchCtx := interrupt.ContextWithIsProviderConnection(ctx)
		err := s.fetch(fetchCtx, true)
		if err != nil {
			// 容错启动：远端订阅源拉取失败时，不阻塞 box 启动。
			// loopUpdate 的 fast-retry 路径会按指数退避周期性重试直到成功（之后切回 update_interval）。
			// 空 provider 在 selector / urltest / smart group 中表现为"该 provider 暂无节点"，
			// 不影响其他 provider 节点，订阅源临时不可达不会让整个进程崩溃。
			s.logger.Warn("initial outbound provider ", s.Tag(), " fetch failed: ", err,
				" — starting empty, will retry with exponential backoff until success")
		}
	}
	// 提前同步创建 ticker，避免 Update() 与 loopUpdate goroutine 之间初始化竞态（nil 指针）。
	s.ticker = time.NewTicker(s.updateInterval)
	go s.loopUpdate()
	return s.Adapter.Start()
}

func (s *ProviderRemote) Update() error {
	if t := s.ticker; t != nil {
		t.Reset(s.updateInterval)
	}
	ctx := interrupt.ContextWithIsProviderConnection(s.ctx)
	return s.fetch(ctx, false)
}

func (s *ProviderRemote) UpdatedAt() time.Time {
	return s.lastUpdated
}

func (s *ProviderRemote) SubscriptionInfo() adapter.SubscriptionInfo {
	return s.subscriptionInfo
}

func (s *ProviderRemote) Close() error {
	s.cancel()
	if s.ticker != nil {
		s.ticker.Stop()
	}
	return common.Close(&s.Adapter)
}

func (s *ProviderRemote) resolveTransport() (adapter.HTTPTransport, error) {
	httpClientManager := service.FromContext[adapter.HTTPClientManager](s.ctx)
	if s.httpClientOptions != nil && !s.httpClientOptions.IsEmpty() {
		if s.downloadDetour != "" {
			return nil, E.New("http_client is conflict with deprecated download_detour field")
		}
		return httpClientManager.ResolveTransport(s.ctx, s.logger, *s.httpClientOptions)
	}
	if s.downloadDetour != "" {
		deprecated.Report(s.ctx, deprecated.OptionLegacyProviderDownloadDetour)
		return httpClientManager.ResolveTransport(s.ctx, s.logger, option.HTTPClientOptions{
			DialerOptions: option.DialerOptions{
				Detour: s.downloadDetour,
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

func (s *ProviderRemote) updateOnce() {
	ctx := interrupt.ContextWithIsProviderConnection(s.ctx)
	if err := s.fetch(ctx, false); err != nil {
		s.logger.Error("update outbound provider: ", err)
	}
}

func (s *ProviderRemote) recordSuccess() {
	s.consecutiveFailures.Store(0)
}

func (s *ProviderRemote) recordFailure() {
	s.consecutiveFailures.Add(1)
}

func (s *ProviderRemote) fetch(ctx context.Context, isStart bool) error {
	if s.updating.Swap(true) {
		// 跳过本次（上一次拉取仍在 IO 中），返回 nil 防止 API 触发 spurious 错误；
		// 周期 ticker / fast-retry 都会在下次再尝试。
		s.logger.Debug("skip fetch: previous update still in progress")
		return nil
	}
	defer s.updating.Store(false)
	s.logger.Debug("updating outbound provider ", s.Tag(), " from URL: ", s.url)
	// 给单次拉取套整体超时；防止异常源把 fast-retry 永久卡住。
	reqCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, s.url, nil)
	if err != nil {
		s.recordFailure()
		return err
	}
	if s.lastEtag != "" {
		req.Header.Set("If-None-Match", s.lastEtag)
	}
	req.Header.Set("User-Agent", s.userAgent)
	if !isStart {
		defer s.httpClient.CloseIdleConnections()
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.recordFailure()
		return err
	}
	// 修复：原版 defer 在 switch 之后，304/default 路径会泄漏 body。
	defer resp.Body.Close()
	infoStr := resp.Header.Get("subscription-userinfo")
	info, hasInfo := parseInfo(infoStr)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.subscriptionInfo = info
		now := time.Now()
		if s.cacheFile != nil {
			saveSub := s.cacheFile.LoadSubscription(s.Tag())
			if saveSub != nil {
				if s.path != "" {
					saveSub.Hash = s.hash
				} else if hasInfo {
					index := bytes.IndexByte(saveSub.Content, '\n')
					if index != -1 {
						saveSub.Content = append([]byte(infoStr+"\n"), saveSub.Content[index+1:]...)
					}
				}
				saveSub.LastUpdated = now
				if err := s.cacheFile.SaveSubscription(s.Tag(), saveSub); err != nil {
					s.logger.Error("save outbound provider cache file: ", err)
				}
			}
		}
		if s.path != "" {
			content, _ := json.Marshal(option.Options{
				Outbounds: s.lastOutOpts,
				Endpoints: s.lastEPOpts,
			})
			s.saveCacheFile(hasInfo, info, content)
		}
		s.lastUpdated = now
		s.recordSuccess()
		s.logger.Info("update outbound provider ", s.Tag(), ": not modified")
		return nil
	default:
		err := E.New("unexpected status: ", resp.Status)
		s.recordFailure()
		return err
	}
	// LimitReader 多读 1 字节用于判定是否超限。
	contentRaw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		s.recordFailure()
		return err
	}
	if len(contentRaw) > maxResponseBytes {
		err := E.New("response body exceeds size limit ", maxResponseBytes>>20, " MiB")
		s.recordFailure()
		return err
	}
	if len(contentRaw) == 0 {
		err := E.New("empty response body")
		s.recordFailure()
		return err
	}
	eTagHeader := resp.Header.Get("Etag")
	content, _ := parser.DecodeBase64URLSafe(string(contentRaw))
	if !hasInfo {
		firstLine, others := getFirstLine(content)
		if info, hasInfo = parseInfo(firstLine); hasInfo {
			infoStr = firstLine
			content, _ = parser.DecodeBase64URLSafe(others)
		}
	}
	if err := s.updateProviderFromContent(content); err != nil {
		s.recordFailure()
		return err
	}
	s.UpdateGroups()
	s.subscriptionInfo = info
	now := time.Now()
	if s.path != "" || s.cacheFile != nil {
		out, _ := json.Marshal(option.Options{
			Outbounds: s.lastOutOpts,
			Endpoints: s.lastEPOpts,
		})
		if s.path != "" {
			s.saveCacheFile(hasInfo, info, out)
		} else if hasInfo {
			out = append([]byte(infoStr+"\n"), out...)
		}
		if s.cacheFile != nil {
			saveSub := &adapter.SavedBinary{
				LastUpdated: now,
				LastEtag:    eTagHeader,
			}
			if s.path != "" {
				saveSub.Hash = s.hash
			} else {
				saveSub.Content = out
			}
			if err = s.cacheFile.SaveSubscription(s.Tag(), saveSub); err != nil {
				s.logger.Error("save outbound provider cache file: ", err)
			}
		}
	}
	// 仅在解析+保存全部成功后才更新 lastEtag/lastUpdated，避免中途失败的 fetch
	// 假装成功（防止后续 fast-retry 提前退出 / 304 误判）。
	if eTagHeader != "" {
		s.lastEtag = eTagHeader
	}
	s.lastUpdated = now
	s.recordSuccess()
	s.logger.Info("updated outbound provider ", s.Tag())
	return nil
}

func (s *ProviderRemote) loadCacheFile() error {
	var content []byte
	var lastUpdated time.Time
	var lastEtag string
	var saveSub *adapter.SavedBinary
	if s.cacheFile != nil {
		if saveSub = s.cacheFile.LoadSubscription(s.Tag()); saveSub != nil {
			s.hash = saveSub.Hash
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
		if saveSub != nil {
			if !s.hash.Equal(hash.MakeHash(content)) {
				// 哈希不匹配：缓存文件被外部改写或损坏。返回到 StartContext 让其
				// 走容错路径（清空状态 + fresh fetch），不再静默丢弃数据。
				return E.New("cache file hash mismatch (file modified externally or corrupted)")
			}
			lastUpdated = saveSub.LastUpdated
			lastEtag = saveSub.LastEtag
		} else {
			fs, err := os.Stat(s.path)
			if err != nil {
				return err
			}
			lastUpdated = fs.ModTime()
		}
	} else if saveSub != nil && len(saveSub.Content) > 0 {
		content = saveSub.Content
		lastUpdated = saveSub.LastUpdated
		lastEtag = saveSub.LastEtag
	} else {
		return nil
	}
	if err := s.loadFromContent(content); err != nil {
		return err
	}
	s.UpdateGroups()
	s.lastUpdated, s.lastEtag = lastUpdated, lastEtag
	return nil
}

func (s *ProviderRemote) loadFromContent(contentRaw []byte) error {
	content, _ := parser.DecodeBase64URLSafe(string(contentRaw))
	firstLine, others := getFirstLine(content)
	if info, ok := parseInfo(firstLine); ok {
		s.subscriptionInfo = info
		content, _ = parser.DecodeBase64URLSafe(others)
	}
	outboundOpts, endpointOpts, err := parser.ParseBoxSubscription(s.ctx, content)
	if err != nil {
		return err
	}
	s.UpdateOutbounds(s.lastOutOpts, outboundOpts)
	s.lastOutOpts = outboundOpts
	s.UpdateEndpoints(s.lastEPOpts, endpointOpts)
	s.lastEPOpts = endpointOpts
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
	return false, err
}

// computeFastRetryBackoff 根据连续失败次数计算 fast-retry 下次等待时长：
// base * 2^(failures-1)，封顶 fastRetryCap，叠 ±20% 抖动；下界 base/2。
func computeFastRetryBackoff(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	shift := failures - 1
	if shift > 16 { // 防止整型溢出（base=60s 时 shift=16 = 45 天，已远超 cap）
		shift = 16
	}
	backoff := fastRetryBase << shift
	if backoff <= 0 || backoff > fastRetryCap {
		backoff = fastRetryCap
	}
	jitter := time.Duration(mrand.Int64N(int64(backoff) / 5))
	if mrand.IntN(2) == 0 {
		backoff += jitter
	} else {
		backoff -= jitter
	}
	if backoff < fastRetryBase/2 {
		backoff = fastRetryBase / 2
	}
	return backoff
}

func (s *ProviderRemote) loopUpdate() {
	if time.Since(s.lastUpdated) < s.updateInterval {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(time.Until(s.lastUpdated.Add(s.updateInterval))):
			s.updateOnce()
		}
	} else {
		s.updateOnce()
	}
	// 重置 ticker，让后续周期锚定在"刚刚 update 完成"时间点（StartContext 已预创建，此处只 Reset）。
	s.ticker.Reset(s.updateInterval)
	// 容错启动 fast-retry：lastUpdated 仍为零（首次 fetch 从未成功）时，按指数退避重试。
	// fastRetryBase=60s 起步 → 2 倍递增 → 封顶 fastRetryCap，±20% 抖动。
	// 拉取一旦成功（lastUpdated 非零）即停止 fast-retry，由 ticker 接管正常周期。
	var fastRetryTimer *time.Timer
	defer func() {
		if fastRetryTimer != nil {
			fastRetryTimer.Stop()
		}
	}()
	scheduleFastRetry := func() {
		if !s.lastUpdated.IsZero() {
			return
		}
		failures := int(s.consecutiveFailures.Load())
		backoff := computeFastRetryBackoff(failures)
		s.logger.Debug("fast-retry scheduled in ", backoff, " (failures=", failures, ")")
		if fastRetryTimer == nil {
			fastRetryTimer = time.NewTimer(backoff)
		} else {
			if !fastRetryTimer.Stop() {
				select {
				case <-fastRetryTimer.C:
				default:
				}
			}
			fastRetryTimer.Reset(backoff)
		}
	}
	scheduleFastRetry()
	for {
		runtime.GC()
		var fastRetryC <-chan time.Time
		if fastRetryTimer != nil {
			fastRetryC = fastRetryTimer.C
		}
		select {
		case <-s.ctx.Done():
			return
		case <-s.ticker.C:
			s.updateOnce()
		case <-fastRetryC:
			s.updateOnce()
			if !s.lastUpdated.IsZero() {
				if fastRetryTimer != nil {
					fastRetryTimer.Stop()
					fastRetryTimer = nil
				}
			} else {
				scheduleFastRetry()
			}
		}
	}
}

func (s *ProviderRemote) saveCacheFile(hasInfo bool, info adapter.SubscriptionInfo, contentRaw []byte) {
	content := contentRaw
	if hasInfo {
		infoStr := fmt.Sprint(
			"# upload=", info.Upload,
			"; download=", info.Download,
			"; total=", info.Total,
			"; expire=", info.Expire,
			";")
		content = append([]byte(infoStr+"\n"), content...)
	}
	s.hash = hash.MakeHash(content)
	dir := filepath.Dir(s.path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		filemanager.MkdirAll(s.ctx, dir, 0o755)
	}
	filemanager.WriteFile(s.ctx, s.path, []byte(content), 0o666)
}

func (s *ProviderRemote) updateProviderFromContent(content string) error {
	outboundOpts, endpointOpts, err := parser.ParseSubscription(s.ctx, content, s.overrideDialer, s.overrideTLS, s.Tag())
	if err != nil {
		return err
	}
	outboundOpts = common.Filter(outboundOpts, func(it option.Outbound) bool {
		return (s.exclude == nil || !s.exclude.MatchString(it.Tag)) && (s.include == nil || s.include.MatchString(it.Tag))
	})
	endpointOpts = common.Filter(endpointOpts, func(it option.Endpoint) bool {
		return (s.exclude == nil || !s.exclude.MatchString(it.Tag)) && (s.include == nil || s.include.MatchString(it.Tag))
	})
	s.UpdateOutbounds(s.lastOutOpts, outboundOpts)
	s.lastOutOpts = outboundOpts
	s.UpdateEndpoints(s.lastEPOpts, endpointOpts)
	s.lastEPOpts = endpointOpts
	return nil
}

func getFirstLine(content string) (string, string) {
	lines := strings.Split(content, "\n")
	if len(lines) == 1 {
		return lines[0], ""
	}
	others := strings.Join(lines[1:], "\n")
	return lines[0], others
}

func parseInfo(infoStr string) (adapter.SubscriptionInfo, bool) {
	info := adapter.SubscriptionInfo{}
	if infoStr == "" {
		return info, false
	}
	reg := regexp.MustCompile(`(upload|download|total|expire)[\s\t]*=[\s\t]*(-?\d*);?`)
	matches := reg.FindAllStringSubmatch(infoStr, 4)
	if len(matches) == 0 {
		return info, false
	}
	for _, match := range matches {
		key, value := match[1], match[2]
		switch key {
		case "upload":
			info.Upload = parser.StringToType[int64](value)
		case "download":
			info.Download = parser.StringToType[int64](value)
		case "total":
			info.Total = parser.StringToType[int64](value)
		case "expire":
			info.Expire = parser.StringToType[int64](value)
		default:
			return info, false
		}
	}
	return info, true
}
