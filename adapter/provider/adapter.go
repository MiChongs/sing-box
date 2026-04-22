package provider

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"github.com/panjf2000/ants/v2"
)

// providerSnapshot 是 Provider 出站列表的不可变快照。
// 写路径在 writeAccess 锁下构造一个全新的 snapshot 后
// 原子 Store 到 Adapter.snapshot，读路径通过 Load() 拿到
// 当时的快照后即可零锁访问，UpdateOutbounds 再怎么并发也
// 不会破坏读者持有的切片/map 内容。
//
// 不变量：
//   - byTag[tag] == all[i] 对任意某个 i 成立（两个视图一致）
//   - all 和 byTag 都是只读的，写路径永远构造新的而不是原地改
type providerSnapshot struct {
	all   []adapter.Outbound
	byTag map[string]adapter.Outbound
}

var emptySnapshot = &providerSnapshot{byTag: map[string]adapter.Outbound{}}

// getProviderHealthcheckPool 懒初始化进程级共享的 healthcheck worker pool。
//
// 为什么共享：
//   - 多 provider 订阅时每个都有自己的 healthcheck 循环，用户场景里 8 个 provider
//     × 每个 50-200 节点 = 数百个 URLTest 并发。原实现 batch.New(concurrency=10)
//     虽然单个 provider 限到 10，但 8 个 provider 同时跑就是 80 并发，超出很多家宽
//     出口的 NAT 会话表 / 防火墙状态表容量。
//   - 共享一个 64-worker pool 把总并发封顶，避免 goroutine/fd 爆炸。
//   - ants.WithNonblocking(false) → Submit 在满载时阻塞（预期的反压）。
//   - 空闲 worker 30s 回收，低流量场景内存常驻接近零。
//
// 失败降级：ants.NewPool 只在配置非法时返回 error，理论上不会发生；
// 万一失败则返回 nil，调用方检查到 nil 会退到 go func{} 兜底。
var (
	providerWorkerPoolOnce sync.Once
	providerWorkerPool     *ants.Pool
)

func getProviderWorkerPool() *ants.Pool {
	providerWorkerPoolOnce.Do(func() {
		pool, err := ants.NewPool(64,
			ants.WithExpiryDuration(30*time.Second),
			ants.WithNonblocking(false),
			ants.WithPreAlloc(false),
		)
		if err != nil {
			return
		}
		providerWorkerPool = pool
	})
	return providerWorkerPool
}

type Adapter struct {
	ctx          context.Context
	outbound     adapter.OutboundManager
	endpoint     adapter.EndpointManager
	router       adapter.Router
	logFactory   log.Factory
	logger       log.ContextLogger
	providerType string
	providerTag  string

	// snapshot 持有当前出站列表的不可变快照。读路径（Outbounds / Outbound /
	// healthcheck / clash API 所有 /providers/proxies/*）通过 Load() 零锁访问。
	// 写路径（UpdateOutbounds / UpdateEndpoints / Close）在 writeAccess 下
	// 构造新 snapshot 后 Store。
	//
	// 字段是指针而非值：atomic.Pointer 嵌入 noCopy，Adapter 按值返回 (NewAdapter)
	// 会触发 vet 警告。通过 *atomic.Pointer 持有，Adapter 本身只复制一个指针，
	// 两个指针副本指向同一个 atomic.Pointer 对象，语义等价。
	snapshot *atomic.Pointer[providerSnapshot]

	// writeAccess 串行化 UpdateOutbounds / UpdateEndpoints / Close 之间的并发写，
	// 防止两个订阅同时回来时互相覆盖（覆盖会导致 outbound manager 里的
	// Create/Remove 失去配对）。读路径完全不持有此锁。
	//
	// 和 snapshot 字段同理：指针持有以规避 atomic.Pointer noCopy 触发的 vet 警告
	// 扩散到 sync.Mutex — 一旦结构体里有任何 noCopy 字段，vet 对其他非 noCopy
	// 锁字段的复制也会报警。
	writeAccess *sync.Mutex

	ticker         *time.Ticker
	checking       *atomic.Bool
	history        adapter.URLTestHistoryStorage
	callbackAccess *sync.Mutex
	callbacks      list.List[adapter.ProviderUpdateCallback]

	link     string
	enabled  bool
	timeout  time.Duration
	interval time.Duration
}

func NewAdapter(ctx context.Context, router adapter.Router, outbound adapter.OutboundManager, endpoint adapter.EndpointManager, logFactory log.Factory, logger log.ContextLogger, providerTag string, providerType string, options option.ProviderHealthCheckOptions) Adapter {
	timeout := time.Duration(options.Timeout)
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	interval := time.Duration(options.Interval)
	if interval == 0 {
		interval = 10 * time.Minute
	}
	if interval < time.Minute {
		interval = time.Minute
	}
	a := Adapter{
		ctx:          ctx,
		outbound:     outbound,
		endpoint:     endpoint,
		router:       router,
		logFactory:   logFactory,
		logger:       logger,
		providerType: providerType,
		providerTag:  providerTag,
		snapshot:       &atomic.Pointer[providerSnapshot]{},
		writeAccess:    &sync.Mutex{},
		callbackAccess: &sync.Mutex{},
		checking:       &atomic.Bool{},

		enabled:  options.Enabled,
		link:     options.URL,
		timeout:  timeout,
		interval: interval,
	}
	a.snapshot.Store(emptySnapshot)
	return a
}

func (a *Adapter) Start() error {
	a.history = service.FromContext[adapter.URLTestHistoryStorage](a.ctx)
	if a.history == nil {
		if clashServer := service.FromContext[adapter.ClashServer](a.ctx); clashServer != nil {
			a.history = clashServer.HistoryStorage()
		} else {
			a.history = urltest.NewHistoryStorage()
		}
	}
	go a.loopCheck()
	return nil
}

func (a *Adapter) Type() string {
	return a.providerType
}

func (a *Adapter) Tag() string {
	return a.providerTag
}

// loadSnapshot 读当前 snapshot；保证非 nil（Adapter 构造时总是 Store emptySnapshot）。
func (a *Adapter) loadSnapshot() *providerSnapshot {
	snap := a.snapshot.Load()
	if snap == nil {
		return emptySnapshot
	}
	return snap
}

func (a *Adapter) Outbounds() []adapter.Outbound {
	return a.loadSnapshot().all
}

func (a *Adapter) Outbound(tag string) (adapter.Outbound, bool) {
	ob, ok := a.loadSnapshot().byTag[tag]
	return ob, ok
}

func (a *Adapter) resolveOutboundTags(newOpts []option.Outbound) []string {
	tags := make([]string, len(newOpts))
	seen := make(map[string]struct{}, len(newOpts))
	for i, opt := range newOpts {
		var baseTag string
		if opt.Tag != "" {
			baseTag = F.ToString(a.providerTag, "/", opt.Tag)
		} else {
			baseTag = F.ToString(a.providerTag, "/", i)
		}
		tag := baseTag
		for n := 2; ; n++ {
			if _, dup := seen[tag]; !dup {
				break
			}
			tag = F.ToString(baseTag, " (", n, ")")
		}
		if tag != baseTag {
			a.logger.Warn("duplicate outbound tag ", baseTag, " in provider, renamed to ", tag)
		}
		seen[tag] = struct{}{}
		tags[i] = tag
	}
	return tags
}

// UpdateOutbounds 接收订阅最新的 outbound 列表（newOpts），替换当前
// provider 持有的整套出站。整体步骤：
//  1. 为每个 newOpt 解析唯一 tag
//  2. 删除不在 newOpts 里的老 outbound（outbound.Remove）
//  3. 对每个 newOpt：如果已存在且 opts 未变则复用，否则 Create
//  4. 原子 Store 构造好的新 snapshot
//  5. 异步触发一次 HealthCheck（让 clash API 立刻看到新节点的延迟）
//
// 所有 snapshot 构造完成前旧 snapshot 始终有效，读路径不会看到中间态。
func (a *Adapter) UpdateOutbounds(oldOpts []option.Outbound, newOpts []option.Outbound) {
	a.writeAccess.Lock()
	defer a.writeAccess.Unlock()

	newTags := a.resolveOutboundTags(newOpts)
	wanted := make(map[string]struct{}, len(newTags))
	for _, tag := range newTags {
		wanted[tag] = struct{}{}
	}

	// 1. 删除老 outbound 里已不在新列表里的节点
	//    只清理 "非 endpoint" 的部分，endpoint 由 UpdateEndpoints 负责
	//
	// 大订阅刷新时 "去掉的节点数" 经常和 "加的节点数" 在同一量级，
	// outbound.Remove 内部会走 common.Close 触发每个出站的 Close 链
	// (关闭 mux 池 / 释放 reality stream / 回收 xhttp upload pool)，
	// 单个 Remove 0.3-3ms；串行 500 节点 ≈ 1.5s 仍卡在 writeAccess 下。
	// 和下面的 Create 对称并行化，封顶 16 避免挤压文件描述符。
	oldSnap := a.loadSnapshot()
	toRemove := make([]string, 0)
	for _, ob := range oldSnap.all {
		if _, keep := wanted[ob.Tag()]; keep {
			continue
		}
		if _, isEndpoint := a.endpoint.Get(ob.Tag()); isEndpoint {
			// endpoint 归 UpdateEndpoints 管，这里跳过，避免误删
			continue
		}
		toRemove = append(toRemove, ob.Tag())
	}
	if len(toRemove) > 0 {
		const removeParallel = 16
		sem := make(chan struct{}, removeParallel)
		var wg sync.WaitGroup
		for _, tag := range toRemove {
			wg.Add(1)
			sem <- struct{}{}
			t := tag
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				if err := a.outbound.Remove(t); err != nil {
					a.logger.Error(err, "close outbound [", t, "]")
				}
			}()
		}
		wg.Wait()
	}

	// 2. 建 old tag→opts 的索引用于 DeepEqual 判变
	oldOptByTag := make(map[string]option.Outbound, len(oldOpts))
	for _, opt := range oldOpts {
		oldOptByTag[opt.Tag] = opt
	}

	// 3. 创建/复用 newOpts 里的每一个出站
	newAll := make([]adapter.Outbound, 0, len(newOpts))
	newByTag := make(map[string]adapter.Outbound, len(newOpts))
	// 保留 old snapshot 里的 endpoint（它们的生命周期由 UpdateEndpoints 管）
	for _, ob := range oldSnap.all {
		if _, isEndpoint := a.endpoint.Get(ob.Tag()); isEndpoint {
			newAll = append(newAll, ob)
			newByTag[ob.Tag()] = ob
		}
	}

	// 3a. 先遍历一遍判断哪些 opt 需要 Create / 哪些可复用。
	//
	// 复用的直接拿旧对象；需要 Create 的进 needCreate 队列走后面的
	// 并行 Create。拆成两步是为了：
	//   - 大订阅（1000+ 节点）初次加载时 Create 占整个 fetch >90% 的时间；
	//     outbound.Create 内部只有 m.access 下的短 map 写入是串行热点，
	//     registry.CreateOutbound + LegacyStart（TLS/uTLS/reality/xhttp/
	//     ws-mux 等各自的握手准备）才是耗时大头，且完全无共享状态，
	//     可以安全并发。
	//   - 串行 for-loop 直接把 N*T_create 全部累加到 writeAccess 下，
	//     1000 节点 × 5ms = 5s 可直接观测；并行度 16 后 ≈ 300ms。
	type createJob struct {
		index int
		opt   option.Outbound
		tag   string
	}
	needCreate := make([]createJob, 0, len(newOpts))
	// slot 数组长度与 newOpts 对齐；复用位提前填好，待 Create 位会被
	// 并行 worker 填补。这样最终按原序拼装 newAll 不需额外排序。
	slots := make([]adapter.Outbound, len(newOpts))
	for i, opt := range newOpts {
		tag := newTags[i]
		outbound, exist := a.outbound.Outbound(tag)
		if exist && reflect.DeepEqual(opt, oldOptByTag[opt.Tag]) {
			slots[i] = outbound
			continue
		}
		needCreate = append(needCreate, createJob{index: i, opt: opt, tag: tag})
	}

	// 3b. 并行 Create（池化 worker，封顶 16 并发；ants 满载时 Submit 阻塞）。
	//
	// 为何用新开一个 16 worker 的 sync.WaitGroup 而不是 providerWorkerPool：
	//   - providerWorkerPool 是 healthcheck 共用池（64 workers），Create
	//     突发会把它占满导致同时段的健康探测全部排队。
	//   - Create 是 CPU+syscall 混合、可能触发 DNS 解析（reality 预握手
	//     等），16 并发刚好卡在多数家宽 / 云主机的并发出站上限之下。
	//   - 失败统一用 logger.Warn，不 return —— 保留原串行版本 "skip
	//     create this outbound" 的语义，单个节点坏配置不影响其他节点。
	if len(needCreate) > 0 {
		const createParallel = 16
		sem := make(chan struct{}, createParallel)
		var wg sync.WaitGroup
		for _, job := range needCreate {
			wg.Add(1)
			sem <- struct{}{}
			j := job
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				err := a.outbound.Create(
					adapter.WithContext(a.ctx, &adapter.InboundContext{
						Outbound: j.tag,
					}),
					a.router,
					a.logFactory.NewLogger(F.ToString("outbound/", j.opt.Type, "[", j.tag, "]")),
					j.tag,
					j.opt.Type,
					j.opt.Options,
				)
				if err != nil {
					a.logger.Warn(err, " in ", j.tag, ", skip create this outbound")
					return
				}
				// outbound.Create 内部已经把新对象写入 m.outboundByTag，
				// 这里 Lookup 取回即可；Create 成功但 Lookup miss 理论
				// 上不可能，若发生当作失败处理（slot 保持 nil，下面
				// newAll 组装时跳过 nil）。
				ob, _ := a.outbound.Outbound(j.tag)
				slots[j.index] = ob
			}()
		}
		wg.Wait()
	}

	// 3c. 按原序拼装 newAll + newByTag，跳过 Create 失败留下的 nil slot。
	for _, ob := range slots {
		if ob == nil {
			continue
		}
		newAll = append(newAll, ob)
		newByTag[ob.Tag()] = ob
	}

	// 4. 原子发布新 snapshot；读端在此刻之前仍然看到老 snapshot
	a.snapshot.Store(&providerSnapshot{all: newAll, byTag: newByTag})

	// 5. 触发一次 healthcheck 让新节点立刻有延迟数据
	if a.enabled && a.history != nil {
		go a.HealthCheck(a.ctx)
	}
}

// UpdateBundle 原子化地同时应用 outbound + endpoint 两份新列表。
//
// 为什么需要它：原先 remote.go 依次调用 UpdateOutbounds / UpdateEndpoints，
// 中间会发布一次只有新 outbound 但仍然持有旧 endpoint 的 snapshot；
// 该窗口内并发读者（健康检查、clash API、group 的 onProviderUpdated
// 回调）看到的是一个自我矛盾的集合，用户侧偶发表现成 "订阅刷新后节
// 点数忽多忽少" 或 "group 里 endpoint 还是旧的，outbound 已经是新的"。
//
// 本方法把两次 Remove+Create+Publish 折叠到一次 writeAccess 临界区内，
// 只 snapshot.Store 一次，彻底消除中间态可观察窗口。
//
// 性能红利与 UpdateOutbounds / UpdateEndpoints 一致：Remove / Create
// 分别用 16 并发 semaphore 并行，每类只串行一次。
//
// 幂等保障：
//   - opt 与旧 opt DeepEqual → 复用已有实例，不触发 Close / Create
//   - opt 变更 → 旧实例在 Create 路径内部由 manager 自己 Close（不是
//     这里直接 Remove），和 UpdateOutbounds 原有语义一致
//   - 离群 tag (不在 new 列表里的) → 并行 Remove
//   - Create 失败 → 记 Warn、该 slot 留 nil，最终 snapshot 跳过 nil；
//     不会影响其他节点的上线
func (a *Adapter) UpdateBundle(oldOutOpts, newOutOpts []option.Outbound,
	oldEPOpts, newEPOpts []option.Endpoint) {
	a.writeAccess.Lock()
	defer a.writeAccess.Unlock()

	outTags := a.resolveOutboundTags(newOutOpts)
	epTags := a.resolveEndpointTags(newEPOpts)
	wantedOut := make(map[string]struct{}, len(outTags))
	for _, t := range outTags {
		wantedOut[t] = struct{}{}
	}
	wantedEP := make(map[string]struct{}, len(epTags))
	for _, t := range epTags {
		wantedEP[t] = struct{}{}
	}

	// ── Phase 1: 并行 Remove 旧 outbound / 旧 endpoint ────────────────
	// 两类混在同一个 semaphore 下跑以压总并发 —— 去掉大订阅换班场景
	// 两批 wait 串联的延迟（500 outbounds 换 500 outbounds + 50 ep 换
	// 50 ep 时，两阶段串行会吃到 ~3s，合并后 ~1s）。
	oldSnap := a.loadSnapshot()
	type removeJob struct {
		tag      string
		isEndpoint bool
	}
	var toRemove []removeJob
	for _, ob := range oldSnap.all {
		tag := ob.Tag()
		_, isEP := a.endpoint.Get(tag)
		if isEP {
			if _, keep := wantedEP[tag]; !keep {
				toRemove = append(toRemove, removeJob{tag: tag, isEndpoint: true})
			}
		} else {
			if _, keep := wantedOut[tag]; !keep {
				toRemove = append(toRemove, removeJob{tag: tag, isEndpoint: false})
			}
		}
	}
	if len(toRemove) > 0 {
		const removeParallel = 16
		sem := make(chan struct{}, removeParallel)
		var wg sync.WaitGroup
		for _, j := range toRemove {
			wg.Add(1)
			sem <- struct{}{}
			job := j
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				var err error
				if job.isEndpoint {
					err = a.endpoint.Remove(job.tag)
				} else {
					err = a.outbound.Remove(job.tag)
				}
				if err != nil {
					a.logger.Error(err, "close [", job.tag, "]")
				}
			}()
		}
		wg.Wait()
	}

	// ── Phase 2: 分拣 outbound "复用 / 待 Create" ──────────────────────
	oldOutByTag := make(map[string]option.Outbound, len(oldOutOpts))
	for _, opt := range oldOutOpts {
		oldOutByTag[opt.Tag] = opt
	}
	outSlots := make([]adapter.Outbound, len(newOutOpts))
	type outJob struct {
		index int
		opt   option.Outbound
		tag   string
	}
	var outNeedCreate []outJob
	for i, opt := range newOutOpts {
		tag := outTags[i]
		ob, exist := a.outbound.Outbound(tag)
		if exist && reflect.DeepEqual(opt, oldOutByTag[opt.Tag]) {
			outSlots[i] = ob
			continue
		}
		outNeedCreate = append(outNeedCreate, outJob{index: i, opt: opt, tag: tag})
	}

	// ── Phase 3: 分拣 endpoint "复用 / 待 Create" ──────────────────────
	oldEPByTag := make(map[string]option.Endpoint, len(oldEPOpts))
	for _, opt := range oldEPOpts {
		oldEPByTag[opt.Tag] = opt
	}
	epSlots := make([]adapter.Outbound, len(newEPOpts))
	type epCreateJob struct {
		index int
		opt   option.Endpoint
		tag   string
	}
	var epNeedCreate []epCreateJob
	for i, opt := range newEPOpts {
		tag := epTags[i]
		ep, exist := a.endpoint.Get(tag)
		if exist && reflect.DeepEqual(opt, oldEPByTag[opt.Tag]) {
			epSlots[i] = ep
			continue
		}
		epNeedCreate = append(epNeedCreate, epCreateJob{index: i, opt: opt, tag: tag})
	}

	// ── Phase 4: 并行 Create（两类共享 16 slot semaphore） ─────────────
	totalCreate := len(outNeedCreate) + len(epNeedCreate)
	if totalCreate > 0 {
		const createParallel = 16
		sem := make(chan struct{}, createParallel)
		var wg sync.WaitGroup
		for _, j := range outNeedCreate {
			wg.Add(1)
			sem <- struct{}{}
			job := j
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				err := a.outbound.Create(
					adapter.WithContext(a.ctx, &adapter.InboundContext{
						Outbound: job.tag,
					}),
					a.router,
					a.logFactory.NewLogger(F.ToString("outbound/", job.opt.Type, "[", job.tag, "]")),
					job.tag,
					job.opt.Type,
					job.opt.Options,
				)
				if err != nil {
					a.logger.Warn(err, " in ", job.tag, ", skip create this outbound")
					return
				}
				ob, _ := a.outbound.Outbound(job.tag)
				outSlots[job.index] = ob
			}()
		}
		for _, j := range epNeedCreate {
			wg.Add(1)
			sem <- struct{}{}
			job := j
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				err := a.endpoint.Create(
					adapter.WithContext(a.ctx, &adapter.InboundContext{
						Outbound: job.tag,
					}),
					a.router,
					a.logFactory.NewLogger(F.ToString("endpoint/", job.opt.Type, "[", job.tag, "]")),
					job.tag,
					job.opt.Type,
					job.opt.Options,
				)
				if err != nil {
					a.logger.Warn(err, " in ", job.tag, ", skip create this endpoint")
					return
				}
				ep, _ := a.endpoint.Get(job.tag)
				epSlots[job.index] = ep
			}()
		}
		wg.Wait()
	}

	// ── Phase 5: 按原序拼装 newAll + newByTag ──────────────────────────
	newAll := make([]adapter.Outbound, 0, len(outSlots)+len(epSlots))
	newByTag := make(map[string]adapter.Outbound, len(outSlots)+len(epSlots))
	for _, ob := range outSlots {
		if ob == nil {
			continue
		}
		newAll = append(newAll, ob)
		newByTag[ob.Tag()] = ob
	}
	for _, ep := range epSlots {
		if ep == nil {
			continue
		}
		newAll = append(newAll, ep)
		newByTag[ep.Tag()] = ep
	}

	// ── Phase 6: 原子发布单一 snapshot ─────────────────────────────────
	// 读端在此刻之前看到的始终是完整一致的旧 snapshot，之后看到的
	// 是完整一致的新 snapshot —— 不存在 "新 outbound + 旧 endpoint"
	// 的跨态中间窗口。
	a.snapshot.Store(&providerSnapshot{all: newAll, byTag: newByTag})

	// ── Phase 7: 触发一次 healthcheck（异步，不阻塞返回） ────────────
	if a.enabled && a.history != nil {
		go a.HealthCheck(a.ctx)
	}
}

func (a *Adapter) HealthCheck(ctx context.Context) (map[string]uint16, error) {
	if a.ticker != nil {
		a.ticker.Reset(a.interval)
	}
	return a.healthcheck(ctx)
}

func (a *Adapter) RegisterCallback(callback adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	a.callbackAccess.Lock()
	defer a.callbackAccess.Unlock()
	return a.callbacks.PushBack(callback)
}

func (a *Adapter) UnregisterCallback(element *list.Element[adapter.ProviderUpdateCallback]) {
	a.callbackAccess.Lock()
	defer a.callbackAccess.Unlock()
	a.callbacks.Remove(element)
}

func (a *Adapter) UpdateGroups() {
	a.callbackAccess.Lock()
	callbacks := make([]adapter.ProviderUpdateCallback, 0, a.callbacks.Len())
	for element := a.callbacks.Front(); element != nil; element = element.Next() {
		callbacks = append(callbacks, element.Value)
	}
	a.callbackAccess.Unlock()
	// 在锁外调用，避免 callback 若回调到 Register/Unregister 造成死锁
	for _, cb := range callbacks {
		cb(a.providerTag)
	}
}

func (a *Adapter) Close() error {
	if a.ticker != nil {
		a.ticker.Stop()
	}
	a.writeAccess.Lock()
	oldSnap := a.loadSnapshot()
	a.snapshot.Store(emptySnapshot)
	a.writeAccess.Unlock()

	var err error
	for _, ob := range oldSnap.all {
		if _, isEndpoint := a.endpoint.Get(ob.Tag()); isEndpoint {
			if err2 := a.endpoint.Remove(ob.Tag()); err2 != nil {
				err = E.Append(err, err2, func(err error) error {
					return E.Cause(err, "close endpoint [", ob.Tag(), "]")
				})
			}
		} else {
			if err2 := a.outbound.Remove(ob.Tag()); err2 != nil {
				err = E.Append(err, err2, func(err error) error {
					return E.Cause(err, "close outbound [", ob.Tag(), "]")
				})
			}
		}
	}
	return err
}

func (a *Adapter) loopCheck() {
	if !a.enabled {
		return
	}
	a.ticker = time.NewTicker(a.interval)
	a.healthcheck(a.ctx)
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.ticker.C:
			a.healthcheck(a.ctx)
		}
	}
}

// healthcheck 对当前 snapshot 里的每个出站并发探测延迟。
//
//   - checking 原子位防止重入（loopCheck 和 clash API 可能同时触发）
//   - 读 snapshot 零锁，拿到的切片是不可变快照，探测期间 UpdateOutbounds
//     并发来一次也不会影响当前这轮
//   - 通过进程级共享 ants pool 控制总并发（64 workers，满载时 Submit 阻塞）
//   - 去重：同 tag 只探测一次（shadowsocks/hysteria 允许多 outbound 共享 tag？
//     实际 resolveOutboundTags 会保证唯一，这里是多余保险）
func (a *Adapter) healthcheck(ctx context.Context) (map[string]uint16, error) {
	if a.checking.Swap(true) {
		return map[string]uint16{}, nil
	}
	defer a.checking.Store(false)

	outbounds := a.loadSnapshot().all
	if len(outbounds) == 0 {
		return map[string]uint16{}, nil
	}

	pool := getProviderWorkerPool()
	result := make(map[string]uint16, len(outbounds))
	var resultAccess sync.Mutex
	checked := make(map[string]struct{}, len(outbounds))

	var wg sync.WaitGroup
	for _, detour := range outbounds {
		tag := detour.Tag()
		if _, dup := checked[tag]; dup {
			continue
		}
		checked[tag] = struct{}{}

		probe := func() {
			probeCtx, cancel := context.WithTimeout(a.ctx, a.timeout)
			defer cancel()
			t, err := urltest.URLTest(probeCtx, a.link, detour)
			if err != nil {
				a.logger.Debug("outbound ", tag, " unavailable: ", err)
				a.history.DeleteURLTestHistory(tag)
				return
			}
			a.logger.Debug("outbound ", tag, " available: ", t, "ms")
			a.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
				Time:  time.Now(),
				Delay: t,
			})
			resultAccess.Lock()
			result[tag] = t
			resultAccess.Unlock()
		}

		wg.Add(1)
		if pool != nil {
			if err := pool.Submit(func() {
				defer wg.Done()
				probe()
			}); err != nil {
				// Submit 只在 pool 已关闭或参数错误时返回错误，
				// 这种情况下降级到直接起 goroutine 确保不漏探测
				go func() {
					defer wg.Done()
					probe()
				}()
			}
		} else {
			go func() {
				defer wg.Done()
				probe()
			}()
		}
	}
	wg.Wait()

	_ = ctx // 调用方的 ctx 取消不打断已提交任务（与原 batch 语义一致）
	return result, nil
}

func (a *Adapter) RewriteDetourForProvider(opts []option.Outbound) {
	tagMapping := make(map[string]string, len(opts))
	for _, opt := range opts {
		if opt.Tag != "" {
			tagMapping[opt.Tag] = F.ToString(a.providerTag, "/", opt.Tag)
		}
	}
	for _, opt := range opts {
		if dialerWrapper, ok := opt.Options.(option.DialerOptionsWrapper); ok {
			dialerOptions := dialerWrapper.TakeDialerOptions()
			if newDetour, found := tagMapping[dialerOptions.Detour]; found {
				dialerOptions.Detour = newDetour
				dialerWrapper.ReplaceDialerOptions(dialerOptions)
			}
		}
	}
}

func (a *Adapter) RewriteDetourForProviderEndpoints(opts []option.Endpoint) {
	tagMapping := make(map[string]string, len(opts))
	for _, opt := range opts {
		if opt.Tag != "" {
			tagMapping[opt.Tag] = F.ToString(a.providerTag, "/", opt.Tag)
		}
	}
	for _, opt := range opts {
		if dialerWrapper, ok := opt.Options.(option.DialerOptionsWrapper); ok {
			dialerOptions := dialerWrapper.TakeDialerOptions()
			if newDetour, found := tagMapping[dialerOptions.Detour]; found {
				dialerOptions.Detour = newDetour
				dialerWrapper.ReplaceDialerOptions(dialerOptions)
			}
		}
	}
}

func (a *Adapter) resolveEndpointTags(newOpts []option.Endpoint) []string {
	tags := make([]string, len(newOpts))
	seen := make(map[string]struct{}, len(newOpts))
	for i, opt := range newOpts {
		var baseTag string
		if opt.Tag != "" {
			baseTag = F.ToString(a.providerTag, "/", opt.Tag)
		} else {
			baseTag = F.ToString(a.providerTag, "/endpoint-", i)
		}
		tag := baseTag
		for n := 2; ; n++ {
			if _, dup := seen[tag]; !dup {
				break
			}
			tag = F.ToString(baseTag, " (", n, ")")
		}
		if tag != baseTag {
			a.logger.Warn("duplicate endpoint tag ", baseTag, " in provider, renamed to ", tag)
		}
		seen[tag] = struct{}{}
		tags[i] = tag
	}
	return tags
}

// UpdateEndpoints 与 UpdateOutbounds 的设计对称：把 endpoint 部分和 outbound
// 部分在同一个 snapshot 里统一管理，一次 atomic Store 原子切换。
func (a *Adapter) UpdateEndpoints(oldOpts []option.Endpoint, newOpts []option.Endpoint) {
	a.writeAccess.Lock()
	defer a.writeAccess.Unlock()

	newTags := a.resolveEndpointTags(newOpts)
	wanted := make(map[string]struct{}, len(newTags))
	for _, tag := range newTags {
		wanted[tag] = struct{}{}
	}

	// 1. 删除老 endpoint 里不再需要的，并保留所有非 endpoint 出站
	oldSnap := a.loadSnapshot()
	keptNonEndpoint := make([]adapter.Outbound, 0, len(oldSnap.all))
	for _, ob := range oldSnap.all {
		if _, isEndpoint := a.endpoint.Get(ob.Tag()); isEndpoint {
			if _, keep := wanted[ob.Tag()]; !keep {
				if err := a.endpoint.Remove(ob.Tag()); err != nil {
					a.logger.Error(err, "close endpoint [", ob.Tag(), "]")
				}
			}
			continue
		}
		keptNonEndpoint = append(keptNonEndpoint, ob)
	}

	// 2. 对每个 newOpt 创建或复用 endpoint
	oldOptByTag := make(map[string]option.Endpoint, len(oldOpts))
	for _, opt := range oldOpts {
		oldOptByTag[opt.Tag] = opt
	}
	// 对称于 UpdateOutbounds：先分出 "复用 / 需创建"，再并行 Create。
	// 保留原顺序（slots 下标对齐 newOpts 下标）以维持 endpoints 切片的
	// 稳定排序，否则下游依赖 All() / Outbounds() 输出序的 UI（clash
	// dashboard）会每次订阅都看到节点顺序抖动。
	type epJob struct {
		index int
		opt   option.Endpoint
		tag   string
	}
	needCreate := make([]epJob, 0, len(newOpts))
	slots := make([]adapter.Outbound, len(newOpts))
	for i, opt := range newOpts {
		tag := newTags[i]
		ep, exist := a.endpoint.Get(tag)
		if exist && reflect.DeepEqual(opt, oldOptByTag[opt.Tag]) {
			slots[i] = ep
			continue
		}
		needCreate = append(needCreate, epJob{index: i, opt: opt, tag: tag})
	}
	if len(needCreate) > 0 {
		const createParallel = 16
		sem := make(chan struct{}, createParallel)
		var wg sync.WaitGroup
		for _, job := range needCreate {
			wg.Add(1)
			sem <- struct{}{}
			j := job
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				err := a.endpoint.Create(
					adapter.WithContext(a.ctx, &adapter.InboundContext{
						Outbound: j.tag,
					}),
					a.router,
					a.logFactory.NewLogger(F.ToString("endpoint/", j.opt.Type, "[", j.tag, "]")),
					j.tag,
					j.opt.Type,
					j.opt.Options,
				)
				if err != nil {
					a.logger.Warn(err, " in ", j.tag, ", skip create this endpoint")
					return
				}
				ep, _ := a.endpoint.Get(j.tag)
				slots[j.index] = ep
			}()
		}
		wg.Wait()
	}
	endpoints := make([]adapter.Outbound, 0, len(newOpts))
	for _, ep := range slots {
		if ep == nil {
			continue
		}
		endpoints = append(endpoints, ep)
	}

	// 3. 拼装最终 snapshot: 非 endpoint 部分 + 新 endpoints
	newAll := make([]adapter.Outbound, 0, len(keptNonEndpoint)+len(endpoints))
	newAll = append(newAll, keptNonEndpoint...)
	newAll = append(newAll, endpoints...)
	newByTag := make(map[string]adapter.Outbound, len(newAll))
	for _, ob := range newAll {
		newByTag[ob.Tag()] = ob
	}

	// 4. 原子发布
	a.snapshot.Store(&providerSnapshot{all: newAll, byTag: newByTag})
}
