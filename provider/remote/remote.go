package remote

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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

// providerFetchTimeout caps a single HTTP subscription fetch.
// Without this the request inherits s.ctx which only cancels on Close,
// so a hanging upstream stalls the entire loopUpdate goroutine forever —
// subsequent ticks would find updating==true and refuse to run, and the
// user sees "订阅半小时没更新". 90s is long enough for slow mobile
// networks yet short enough to surface server issues in one interval.
const providerFetchTimeout = 90 * time.Second

func RegisterProvider(registry *provider.Registry) {
	provider.Register[option.ProviderRemoteOptions](registry, C.ProviderTypeRemote, NewProviderRemote)
}

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
	// loadCacheFile 失败只 warn。cache 坏了视为 "无 cache"，后面初次 fetch 兜底；
	// 强行 fatal 会把"本机 cache 损坏 + 订阅服务器临时挂"这种可恢复故障扩大成
	// 无法启动。
	if err := s.loadCacheFile(); err != nil {
		s.logger.Warn("restore cached outbound provider: ", err)
	}
	transport, err := s.resolveTransport()
	if err != nil {
		return E.Cause(err, "create provider http client")
	}
	startContext.Register(transport)
	s.httpClient = &http.Client{Transport: transport}
	// 初次 fetch 失败不再 fatal。场景:
	//   - 订阅服务端 5xx 临时故障
	//   - DNS 解析失败（机器刚开机网卡还没拿到地址）
	//   - detour 出站自身还没就绪
	// 这些都是可恢复的，不应该阻止 sing-box 启动。
	// 节点列表保持为空（或 cache 里的旧值），Smart / urltest 组会看到 0 个
	// 可用节点，route 层面走 fallback / default outbound。
	// loopUpdate 会按 update_interval 周期性重试，恢复后自动上线。
	if s.lastUpdated.IsZero() {
		ctx = interrupt.ContextWithIsProviderConnection(ctx)
		if err := s.fetch(ctx, true); err != nil {
			s.logger.Warn("initial fetch for outbound provider [", s.Tag(),
				"] failed, will retry in background every ", s.updateInterval, ": ", err)
		}
	}
	go s.loopUpdate()
	return s.Adapter.Start()
}

func (s *ProviderRemote) Update() error {
	if s.ticker != nil {
		s.ticker.Reset(s.updateInterval)
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

func (s *ProviderRemote) fetch(ctx context.Context, isStart bool) error {
	if s.updating.Swap(true) {
		return E.New("provider is updating")
	}
	defer s.updating.Store(false)
	// 防御：httpClient 是 StartContext 里懒初始化的。如果因 upstream 阶段编排
	// 变动导致 StartContext 没跑（Manager.Start 已修，但保留此兜底），直接
	// 返回清晰错误而不是让调用方吞下一个 NPE panic。
	// 典型触发：clash API /providers/proxies/{tag}/update 在 Box.Start 完全
	// 完成之前被调用，此时 provider 可能还没走完 StartContext。
	if s.httpClient == nil {
		return E.New("provider http client not initialized (startup not complete)")
	}
	s.logger.Debug("updating outbound provider ", s.Tag(), " from URL: ", s.url)
	// Apply a bounded per-fetch timeout on top of the caller ctx so a hung
	// upstream can't stall loopUpdate forever. When the user triggered the
	// fetch via /providers/{tag}/update the clash API handler already has
	// its own deadline; our timeout only kicks in for the periodic path.
	fetchCtx, fetchCancel := context.WithTimeout(ctx, providerFetchTimeout)
	defer fetchCancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	if s.lastEtag != "" {
		req.Header.Set("If-None-Match", s.lastEtag)
	}
	req.Header.Set("User-Agent", s.userAgent)
	// 主动声明 gzip 编码 —— 机场/clash-meta 类订阅服务器大多支持，
	// base64 订阅里 URL/密码/UUID 的熵很低，gzip 常能压 70%+。
	// 原逻辑依赖 Go 默认的 "空 Accept-Encoding → transport 自动补 gzip"
	// 行为，但一旦 user 配置了 http_client headers 或 download_detour 走
	// 某些中间件可能就丢了这层隐式压缩。显式声明更稳。
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip")
	}
	// 不再 CloseIdleConnections —— 原实现每次 fetch 后都 close，踩死
	// HTTP/2 连接复用与 TCP keep-alive。虽然 update_interval>=1h，但
	// 用户手动点 clash API refresh 连续两次或初次 fetch 失败快速重试
	// 时都会白白多握手一次。httpClientManager 内部已经管池化生命周期，
	// 我们这里不要越俎代庖。
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	infoStr := resp.Header.Get("subscription-userinfo")
	info, hasInfo := parseInfo(infoStr)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.subscriptionInfo = info
		s.lastUpdated = time.Now()
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
				saveSub.LastUpdated = s.lastUpdated
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
		s.logger.Info("update outbound provider ", s.Tag(), ": not modified")
		return nil
	default:
		return E.New("unexpected status: ", resp.Status)
	}
	defer resp.Body.Close()
	// Server honoured our Accept-Encoding: gzip → transparently wrap. Go
	// stdlib normally does this itself but only when `Accept-Encoding`
	// wasn't set BY THE USER; we now set it explicitly above so the auto
	// path is disabled and the server's `Content-Encoding: gzip` reaches
	// us raw. Detecting once here keeps the rest of the function body
	// unchanged (still reads plain text).
	bodyReader := io.Reader(resp.Body)
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gzr, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			return E.Cause(gzErr, "gzip decode subscription")
		}
		defer gzr.Close()
		bodyReader = gzr
	}
	contentRaw, err := io.ReadAll(bodyReader)
	if err != nil {
		return err
	}
	eTagHeader := resp.Header.Get("Etag")
	if eTagHeader != "" {
		s.lastEtag = eTagHeader
	}
	content, _ := parser.DecodeBase64URLSafe(string(contentRaw))
	if !hasInfo {
		firstLine, others := getFirstLine(content)
		if info, hasInfo = parseInfo(firstLine); hasInfo {
			infoStr = firstLine
			content, _ = parser.DecodeBase64URLSafe(others)
		}
	}
	if err := s.updateProviderFromContent(content); err != nil {
		return err
	}
	s.UpdateGroups()
	s.subscriptionInfo = info
	s.lastUpdated = time.Now()
	if s.path != "" || s.cacheFile != nil {
		content, _ := json.Marshal(option.Options{
			Outbounds: s.lastOutOpts,
			Endpoints: s.lastEPOpts,
		})
		if s.path != "" {
			s.saveCacheFile(hasInfo, info, content)
		} else if hasInfo {
			content = append([]byte(infoStr+"\n"), content...)
		}
		if s.cacheFile != nil {
			saveSub := &adapter.SavedBinary{
				LastUpdated: s.lastUpdated,
				LastEtag:    s.lastEtag,
			}
			if s.path != "" {
				saveSub.Hash = s.hash
			} else {
				saveSub.Content = content
			}
			if err = s.cacheFile.SaveSubscription(s.Tag(), saveSub); err != nil {
				s.logger.Error("save outbound provider cache file: ", err)
			}
		}
	}
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
				s.logger.Error("load outbound provider cache file failed: validation failed")
				return nil
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
	s.ticker = time.NewTicker(s.updateInterval)
	for {
		// 原实现每个 tick 前都 runtime.GC() —— 对 N 个 provider 就是每 N
		// 小时触发 N 次 STW Full GC，Android 手机上能观察到明显卡顿/
		// 丢包（每个 GC pause 10-50ms × N 个 provider 串联）。
		// Go runtime 自己的 GC pacer 已经足够处理订阅解析后那批
		// 短命对象，额外强制 GC 只会抢 CPU、打断业务流。
		// 移除后若真的内存占用飙高，Smart 组里的 pruneStaleMemoryMaps
		// + debug.FreeOSMemory 会兜底。
		select {
		case <-s.ctx.Done():
			return
		case <-s.ticker.C:
			s.updateOnce()
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
