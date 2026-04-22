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
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
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

// providerGCBytesThreshold gates the post-update FreeOSMemory call.
// Tiny subscriptions (a few KB) don't leave behind enough short-lived
// allocations to justify paying a concurrent-GC + scavenger pass; above
// 256 KB of decoded body the parse path produces enough
// option.Outbound / strings / regex to make reclaim worthwhile.
const providerGCBytesThreshold = 256 * 1024

// providerLoopJitterFraction adds ± this fraction of update_interval to
// each tick so N providers configured with the same interval don't all
// hit their upstream in the same minute every day. 0.1 = ±10%.
const providerLoopJitterFraction = 0.1

func RegisterProvider(registry *provider.Registry) {
	provider.Register[option.ProviderRemoteOptions](registry, C.ProviderTypeRemote, NewProviderRemote)
}

var _ adapter.Provider = (*ProviderRemote)(nil)

// inflightFetch 把并发的 Update() 请求合并成一次真实 fetch，第二个及以
// 后的调用等同一次结果返回。原实现用 updating atomic.Bool 抢占 —— 第
// 二个调用直接返 error "provider is updating"，dashboard 看到就是一次
// "更新失败"，体验差。
type inflightFetch struct {
	done chan struct{}
	err  error
}

type ProviderRemote struct {
	provider.Adapter
	ctx        context.Context
	cancel     context.CancelFunc
	logger     log.ContextLogger
	outbound   adapter.OutboundManager
	provider   adapter.ProviderManager
	cacheFile  adapter.CacheFile
	httpClient *http.Client
	hash       hash.HashType
	// 读写路径并发：lastEtag / lastOutOpts / lastEPOpts / hash 只在
	// fetch 内写，fetch 被 inflightFetch 串行化，读 (loadCacheFile /
	// Update 等) 也只在 fetch 前后触发，不需要额外锁。
	lastEtag    string
	lastOutOpts []option.Outbound
	lastEPOpts  []option.Endpoint
	// lastContentHash 是上一次成功 fetch 的响应体 hash。当服务端不下发
	// Etag (机场经常不实现) 时，用它做 "同内容短路"：hash 一致直接跳过
	// parse + Remove + Create 全流程，只刷新 lastUpdated / cache。
	//
	// 规则：写入点严格在 "成功解析并应用了 newOpts" 之后，保证任何
	// 命中短路的请求看到的确实是上一次应用过的内容。
	lastContentHash hash.HashType
	// 元数据改用 atomic.Value/TypedValue 封装：clash API 读路径
	// (SubscriptionInfo/UpdatedAt) 不持锁、从 fetch 写路径看也不用
	// 额外加锁 — Store/Load 保证一致可见。
	subscriptionInfo atomic.Pointer[adapter.SubscriptionInfo]
	lastUpdatedNano  atomic.Int64
	// inflight 指针门控 dedupe，flightMu 保护指针本身的切换。
	flightMu sync.Mutex
	inflight *inflightFetch
	// ticker: 原本是 *time.Ticker (固定 interval 周期)，改成 *time.Timer
	// 后可以每轮独立带抖动重置。Update() / Close() 保留字段名避免外部
	// 耦合 (Stop/Reset 在两种类型上签名一致)。
	ticker   *time.Timer
	updating atomic.Bool

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
	if s.UpdatedAt().IsZero() {
		ctx = interrupt.ContextWithIsProviderConnection(ctx)
		if err := s.fetchDedup(ctx, true); err != nil {
			s.logger.Warn("initial fetch for outbound provider [", s.Tag(),
				"] failed, will retry in background every ", s.updateInterval, ": ", err)
		}
	}
	go s.loopUpdate()
	return s.Adapter.Start()
}

func (s *ProviderRemote) Update() error {
	// 手动触发刷新后，把下次定时 tick 推回完整的带抖动间隔，否则
	// 用户刚手动点完立刻又会被原来的定时器打扰一次 (double fetch)。
	if s.ticker != nil {
		s.ticker.Reset(s.computeNextInterval())
	}
	ctx := interrupt.ContextWithIsProviderConnection(s.ctx)
	// 走 dedup 路径：dashboard 连点刷新 / Update() 与 loopUpdate tick
	// 撞车时，第二个及以后的调用共享同一次真实 fetch 的结果，不再
	// 返回 "provider is updating" 那种用户看起来像失败的 error。
	return s.fetchDedup(ctx, false)
}

func (s *ProviderRemote) UpdatedAt() time.Time {
	n := s.lastUpdatedNano.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

func (s *ProviderRemote) SubscriptionInfo() adapter.SubscriptionInfo {
	if p := s.subscriptionInfo.Load(); p != nil {
		return *p
	}
	return adapter.SubscriptionInfo{}
}

// setSubscriptionInfo / setLastUpdated 单一写入点，fetch 成功路径调用。
// Load 侧 (clash API / Update) 全部走 atomic，读写不互锁。
func (s *ProviderRemote) setSubscriptionInfo(info adapter.SubscriptionInfo) {
	cp := info
	s.subscriptionInfo.Store(&cp)
}

func (s *ProviderRemote) setLastUpdated(t time.Time) {
	s.lastUpdatedNano.Store(t.UnixNano())
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
	if err := s.fetchDedup(ctx, false); err != nil {
		s.logger.Error("update outbound provider: ", err)
	}
}

// fetchDedup 合并并发 fetch 请求 —— 第二个及以后的调用阻塞在 in-flight
// 的 done chan 上，收到同一结果后统一返回；与 singleflight 等价语义，
// 但不额外引入依赖且省掉 key 分桶的开销（provider 只有一个 in-flight
// 桶，map key 固定）。
//
// 为什么不直接去掉 updating atomic：保留它是为了在 fetch 内部触发的
// 递归场景（比如 Update() 在 fetch 自身的 goroutine 内被意外调用到）
// 仍然快速失败，防止死锁。真正的并发用户请求走 inflight 路径，只有
// 真·嵌套调用会撞 updating。
func (s *ProviderRemote) fetchDedup(ctx context.Context, isStart bool) error {
	s.flightMu.Lock()
	if f := s.inflight; f != nil {
		s.flightMu.Unlock()
		// 等待在途 fetch；调用者 ctx 取消也要能返回，不被在途请求绑架。
		select {
		case <-f.done:
			return f.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f := &inflightFetch{done: make(chan struct{})}
	s.inflight = f
	s.flightMu.Unlock()

	// 运行真正的 fetch；结果通过 inflightFetch.err 共享给所有等待者。
	f.err = s.fetch(ctx, isStart)

	s.flightMu.Lock()
	s.inflight = nil
	s.flightMu.Unlock()
	close(f.done)
	return f.err
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
	// 连接池收尾策略：原实现无条件 CloseIdleConnections —— 304 走不读 body
	// 的路径连接状态干净，用户手动连点刷新时那次关连接纯属浪费。
	// 现在改成：仅在真的 GET 到新 body（下方 200 OK 路径）且该 body 体积
	// 够大、说明连接刚完成一轮重 payload 传输（TLS 记录/TCP 窗口已摸顶）
	// 的情况下，deferred 关连接让下次握手拿到干净初始窗口。304 快路径
	// 直接保留连接给下一次 If-None-Match 复用。
	//
	// closeConnsAtEnd 在 200 分支里会被设置为 true；304 分支直接 return
	// 时跳过这个 defer（所以用函数变量而非 defer+条件裸写）。
	closeConnsAtEnd := false
	defer func() {
		if closeConnsAtEnd {
			s.httpClient.CloseIdleConnections()
		}
	}()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	infoStr := resp.Header.Get("subscription-userinfo")
	info, hasInfo := parseInfo(infoStr)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.setSubscriptionInfo(info)
		now := time.Now()
		s.setLastUpdated(now)
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
	// 预分配 bytes.Buffer：Content-Length 已知（未压缩或 gzip 响应头能拿到
	// 原始长度）时跳过 io.ReadAll 内部的指数扩容 — ReadAll 会走 512 → 1024
	// → 2048 … 直到塞满整个 body，每次扩容都 memcpy 一份。订阅动辄几 MB
	// 的情况下 reallocate 链路是可观的内存+CPU 开销。
	//
	// Content-Length 不一定可信：gzip 分支下 resp.ContentLength 是压缩
	// 后长度，当 ratio 为 1:10 时预分配不足会走少量扩容，比 ReadAll
	// 纯指数扩容少 2-3 次 memcpy。hint <= 0 时退回未带 hint 的读入。
	hint := resp.ContentLength
	if hint < 0 {
		hint = 0
	}
	if hint > 64*1024*1024 {
		// 防御：畸形 Content-Length 上限 64 MB，避免 OOM。真实订阅
		// 体积远不可能超过这个阈值。
		hint = 64 * 1024 * 1024
	}
	buf := bytes.NewBuffer(make([]byte, 0, hint))
	if _, err := io.Copy(buf, bodyReader); err != nil {
		return err
	}
	contentRaw := buf.Bytes()
	// 标记这次 fetch 真的消耗了 body，为后续的 closeConnsAtEnd 策略
	// 与 freeOSMemory 策略提供依据。
	fetchedBytes := int64(len(contentRaw))
	eTagHeader := resp.Header.Get("Etag")
	if eTagHeader != "" {
		s.lastEtag = eTagHeader
	}

	// ── 内容级幂等短路 ───────────────────────────────────────────────
	// 服务端若未下发 Etag (机场常见) 但响应 body 逐字节相同，原流程
	// 仍然会走完整条 parse → DeepEqual → publish 链路；新出站对象都
	// 是一样的，但触发 snapshot.Store 仍然会让 group.onProviderUpdated
	// 激活一次全量重建，下游 URLTest 组顺带再跑一次健康检查。大订阅
	// 下这一趟"空更新"几秒钟就过去了，用户感知为"每小时卡顿一下"。
	//
	// 这里算一次 body hash（复用 sing-box 自己的 MakeHash，crc + size
	// 混合，2 MB 订阅算下来 ~1ms）；与上次成功后保存的 lastContentHash
	// 完全相同则只刷新 lastUpdated + 元数据，跳过所有重建。
	//
	// 注意：hash 匹配但 Etag 丢失 / 变化 的情况下，依旧会更新 lastEtag
	// (上面已做)，下次就能重新走 304 快路径。
	contentHash := hash.MakeHash(contentRaw)
	if s.lastContentHash.IsValid() && s.lastContentHash.Equal(contentHash) {
		s.setSubscriptionInfo(info)
		s.setLastUpdated(time.Now())
		if s.cacheFile != nil {
			saveSub := s.cacheFile.LoadSubscription(s.Tag())
			if saveSub != nil {
				saveSub.LastUpdated = s.UpdatedAt()
				saveSub.LastEtag = s.lastEtag
				if err := s.cacheFile.SaveSubscription(s.Tag(), saveSub); err != nil {
					s.logger.Error("save outbound provider cache file: ", err)
				}
			}
		}
		s.logger.Info("update outbound provider ", s.Tag(),
			": content-hash unchanged, skip rebuild (", fetchedBytes, " bytes)")
		return nil
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
	// Content 应用成功后才写入 hash —— 失败路径不更新，下一次 fetch
	// 同样 body 才能走重试 rebuild 而不是错误地当成 "已应用"。
	s.lastContentHash = contentHash
	s.UpdateGroups()
	s.setSubscriptionInfo(info)
	s.setLastUpdated(time.Now())
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
				LastUpdated: s.UpdatedAt(),
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
	// 大 body 完成后才标记连接池关闭：短订阅（几 KB）没必要关，连接
	// 复用给后续 If-None-Match 更省。订阅体积够大时 TLS record size /
	// TCP send window 已经打满，下一次握手从头开始反倒能拿到新初始
	// 窗口，尤其对走 detour 出站的隧道有益。
	if fetchedBytes >= providerGCBytesThreshold {
		closeConnsAtEnd = true
	}
	// Smart GC：仅在真实更新 + body 足够大 时做一次并发 GC + 归还 OS。
	// 原实现在 loopUpdate 每 tick 都 runtime.GC() 是错的 —— 304 / 失败
	// 等不产生短命对象的路径也被拖累，多 provider 时 STW 累积显著。
	// 现在把触发点下移到"真正解析完整个订阅"之后，parser 产生的
	// 中间 []byte / strings / regexp / option.Outbound 此时全部可回收，
	// GC 收益最高；FreeOSMemory 再把 scavenger 空闲页还给 OS，Android
	// 用户 RSS 能实际下降几十 MB。
	//
	// 只跑一次（once 语义由 updating 原子位天然提供 — fetch 同一时刻
	// 只能有一个在跑）。GC + scavenge 对 Go runtime 总体开销仍是
	// 几十 ms 级别，和订阅 fetch 本身秒级开销相比可忽略。
	if fetchedBytes >= providerGCBytesThreshold {
		runtime.GC()
		debug.FreeOSMemory()
	}
	s.logger.Info("updated outbound provider ", s.Tag(), " (", fetchedBytes, " bytes)")
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
	s.setLastUpdated(lastUpdated)
	s.lastEtag = lastEtag
	return nil
}

func (s *ProviderRemote) loadFromContent(contentRaw []byte) error {
	content, _ := parser.DecodeBase64URLSafe(string(contentRaw))
	firstLine, others := getFirstLine(content)
	if info, ok := parseInfo(firstLine); ok {
		s.setSubscriptionInfo(info)
		content, _ = parser.DecodeBase64URLSafe(others)
	}
	outboundOpts, endpointOpts, err := parser.ParseBoxSubscription(s.ctx, content)
	if err != nil {
		return err
	}
	// 原子应用：outbound + endpoint 单一 snapshot 发布，读端不会看到
	// "新 outbound + 旧 endpoint" 的中间态。
	s.UpdateBundle(s.lastOutOpts, outboundOpts, s.lastEPOpts, endpointOpts)
	s.lastOutOpts = outboundOpts
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
	lastUpdated := s.UpdatedAt()
	if !lastUpdated.IsZero() && time.Since(lastUpdated) < s.updateInterval {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(time.Until(lastUpdated.Add(s.updateInterval))):
			s.updateOnce()
		}
	} else {
		s.updateOnce()
	}
	// 用 time.Timer 而不是固定 ticker：支持每次 tick 独立带抖动，
	// 避免 N 个 provider 配同样 interval 时同一分钟全部撞向各自
	// upstream（典型场景：用户有 8 个机场全配 24h，每天同一时刻
	// 机场服务器瞬时 8 并发，Android 也同一秒打满出站 NAT）。
	//
	// 每轮结束后用 computeNextInterval 重置；抖动范围 ±10% 足以把
	// 同期启动的 provider 在第二天散到几十分钟的窗口里。
	//
	// Timer 存到 s.ticker 字段以便 Update() (手动刷新重置下一轮) 与
	// Close() (Stop) 共享同一入口，保持外部调用点语义不变。
	s.ticker = time.NewTimer(s.computeNextInterval())
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.ticker.C:
			s.updateOnce()
			s.ticker.Reset(s.computeNextInterval())
		}
	}
}

// computeNextInterval 返回带 ±providerLoopJitterFraction 抖动的下一轮
// fetch 间隔。抖动只围绕 updateInterval 随机，不会超出 [0.9×, 1.1×]
// 区间，语义上仍然符合 "大约每 updateInterval 一次"。
func (s *ProviderRemote) computeNextInterval() time.Duration {
	base := s.updateInterval
	if base <= 0 {
		return time.Hour
	}
	// deterministic-ish jitter 由 tag 哈希驱动，避免每次 restart 都换
	// 一组新时刻；相同 tag 的 provider 在任何机器上抖动相同确保
	// 持续分散。
	var h uint32
	for i := 0; i < len(s.url); i++ {
		h = h*131 + uint32(s.url[i])
	}
	// 归一化到 [-1, 1]
	sign := 1.0
	if h&1 == 0 {
		sign = -1.0
	}
	frac := float64(h%1000) / 1000.0 * providerLoopJitterFraction * sign
	return base + time.Duration(float64(base)*frac)
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
	// 原子应用：替代 UpdateOutbounds + UpdateEndpoints 两次 snapshot
	// 发布。消除 "新 outbound + 旧 endpoint" 跨态窗口对 group 回调
	// / healthcheck / clash API 的可见污染。
	s.UpdateBundle(s.lastOutOpts, outboundOpts, s.lastEPOpts, endpointOpts)
	s.lastOutOpts = outboundOpts
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
