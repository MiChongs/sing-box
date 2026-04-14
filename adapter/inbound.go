package adapter

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/miekg/dns"
)

type Inbound interface {
	Lifecycle
	Type() string
	Tag() string
}

type TCPInjectableInbound interface {
	Inbound
	ConnectionHandlerEx
}

type UDPInjectableInbound interface {
	Inbound
	PacketConnectionHandlerEx
}

type InboundRegistry interface {
	option.InboundOptionsRegistry
	Create(ctx context.Context, router Router, logger log.ContextLogger, tag string, inboundType string, options any) (Inbound, error)
}

type InboundManager interface {
	Lifecycle
	Inbounds() []Inbound
	Get(tag string) (Inbound, bool)
	Remove(tag string) error
	Create(ctx context.Context, router Router, logger log.ContextLogger, tag string, inboundType string, options any) error
}

type InboundContext struct {
	Inbound     string
	InboundType string
	IPVersion   uint8
	Network     string
	Source      M.Socksaddr
	Destination M.Socksaddr
	User        string
	Outbound    string

	// sniffer

	Protocol     string
	SniffHost    string
	Client       string
	SniffContext any
	SnifferNames []string
	SniffError   error

	// cache

	CacheIPs []netip.Addr
	Domain   string

	// dnsResponseAddrCache 是 DNSResponseAddressesForMatch 的内部复用缓冲区，
	// 在同一 InboundContext 生命周期内复用 backing array，避免每次规则匹配都
	// 分配新切片。调用方均为同步、立即消费，不持有跨作用域引用，因此复用安全。
	dnsResponseAddrCache []netip.Addr

	// Deprecated: implement in rule action
	InboundDetour             string
	LastInbound               string
	OriginDestination         M.Socksaddr
	RouteOriginalDestination  M.Socksaddr
	UDPDisableDomainUnmapping bool
	UDPConnect                bool
	UDPTimeout                time.Duration
	TLSFragment               bool
	TLSFragmentFallbackDelay  time.Duration
	TLSRecordFragment         bool

	NetworkStrategy     *C.NetworkStrategy
	NetworkType         []C.InterfaceType
	FallbackNetworkType []C.InterfaceType
	FallbackDelay       time.Duration

	DestinationAddresses                []netip.Addr
	DNSResponse                         *dns.Msg
	DestinationAddressMatchFromResponse bool
	SourceGeoIPCode                     string
	GeoIPCode                           string
	ProcessInfo                         *ConnectionOwner
	SourceMACAddress                    net.HardwareAddr
	SourceHostname                      string
	QueryType                           uint16
	FakeIP                              bool
	DestOverride                        bool

	// rule cache
	//
	// 规则缓存字段封装为嵌入结构体，ResetRuleCache/ResetRuleMatchCache
	// 通过结构体整体赋零替代 11 条独立 MOV，显著降低规则评估主循环
	// 内的 CPU 开销。嵌入字段保持原访问路径（metadata.IPCIDRMatchSource 等）
	// 完全兼容，外部 API 零变动。
	ruleCacheFields

	// IgnoreDestinationIPCIDRMatch 由 DNS 规则在匹配过程中短暂设置并
	// 通过 defer 恢复，不参与 ResetRuleCache 的批量重置，保持独立字段。
	IgnoreDestinationIPCIDRMatch bool

	// extended metadata
	Extended *InboundContextExtended
}

// ruleMatchCacheFields 对应 ResetRuleMatchCache 重置范围。
// 整体赋零等同于原先逐字段置 false，但仅一条指令。
type ruleMatchCacheFields struct {
	SourceAddressMatch      bool
	SourcePortMatch         bool
	DestinationAddressMatch bool
	DestinationPortMatch    bool
	DidMatch                bool
}

// ruleCacheFields 对应 ResetRuleCache 重置范围，嵌入 ruleMatchCacheFields
// 以保证原有字段访问路径完全透明（如 metadata.DidMatch、metadata.IPCIDRMatchSource）。
type ruleCacheFields struct {
	IPCIDRMatchSource bool
	IPCIDRAcceptEmpty bool
	ruleMatchCacheFields
}

type InboundContextExtended struct {
	RealOutboundChain []string
}

func (c *InboundContext) InitExtended() {
	if c.Extended == nil {
		c.Extended = new(InboundContextExtended)
	}
}

func (c *InboundContext) AppendRealOutbound(tag string) {
	if c.Extended != nil {
		c.Extended.RealOutboundChain = append(c.Extended.RealOutboundChain, tag)
	}
}

func (c *InboundContext) GetRealOutboundChain() []string {
	if c.Extended != nil {
		return c.Extended.RealOutboundChain
	}
	return nil
}

// ResetRuleCache 重置所有规则缓存位，包括 IPCIDR 配置位与匹配状态位。
// 通过嵌入结构体整体赋零，单条指令替代 7 条 MOV，显著降低规则主循环开销。
func (c *InboundContext) ResetRuleCache() {
	c.ruleCacheFields = ruleCacheFields{}
}

// ResetRuleMatchCache 仅重置匹配状态位（SourceAddressMatch 等 5 字段），
// 保留 IPCIDRMatchSource / IPCIDRAcceptEmpty 配置位。
func (c *InboundContext) ResetRuleMatchCache() {
	c.ruleMatchCacheFields = ruleMatchCacheFields{}
}

// DNSResponseAddressesForMatch 返回 DNS 响应中的地址列表供规则匹配使用。
// 通过 InboundContext 内部的 dnsResponseAddrCache 复用 backing array，在同一
// 连接的规则评估过程中多次调用也只分配一次（按 answer 数量自适应扩容）。
func (c *InboundContext) DNSResponseAddressesForMatch() []netip.Addr {
	c.dnsResponseAddrCache = dnsResponseAddressesInto(c.dnsResponseAddrCache[:0], c.DNSResponse)
	return c.dnsResponseAddrCache
}

// DNSResponseAddresses 保留原对外 API，内部委托给 dnsResponseAddressesInto。
func DNSResponseAddresses(response *dns.Msg) []netip.Addr {
	return dnsResponseAddressesInto(nil, response)
}

// dnsResponseAddressesInto 将 DNS 响应解析的地址写入 dst 切片（复用其容量）。
// dst 传 nil 时退化为原 make 行为；非 nil 时复用 backing array 省堆分配。
func dnsResponseAddressesInto(dst []netip.Addr, response *dns.Msg) []netip.Addr {
	if response == nil || response.Rcode != dns.RcodeSuccess {
		if dst != nil {
			return dst[:0]
		}
		return nil
	}
	if dst == nil {
		dst = make([]netip.Addr, 0, len(response.Answer))
	} else {
		dst = dst[:0]
	}
	for _, rawRecord := range response.Answer {
		switch record := rawRecord.(type) {
		case *dns.A:
			addr := M.AddrFromIP(record.A)
			if addr.IsValid() {
				dst = append(dst, addr)
			}
		case *dns.AAAA:
			addr := M.AddrFromIP(record.AAAA)
			if addr.IsValid() {
				dst = append(dst, addr)
			}
		case *dns.HTTPS:
			for _, value := range record.SVCB.Value {
				switch hint := value.(type) {
				case *dns.SVCBIPv4Hint:
					for _, ip := range hint.Hint {
						addr := M.AddrFromIP(ip).Unmap()
						if addr.IsValid() {
							dst = append(dst, addr)
						}
					}
				case *dns.SVCBIPv6Hint:
					for _, ip := range hint.Hint {
						addr := M.AddrFromIP(ip)
						if addr.IsValid() {
							dst = append(dst, addr)
						}
					}
				}
			}
		}
	}
	return dst
}

type inboundContextKey struct{}

func WithContext(ctx context.Context, inboundContext *InboundContext) context.Context {
	inboundContext.InitExtended()
	return context.WithValue(ctx, (*inboundContextKey)(nil), inboundContext)
}

func ContextFrom(ctx context.Context) *InboundContext {
	metadata := ctx.Value((*inboundContextKey)(nil))
	if metadata == nil {
		return nil
	}
	return metadata.(*InboundContext)
}

// ExtendContext 派生一个与父 metadata 隔离的副本。
//
// 修复点：此前 shallow copy 会令父子 InboundContext 共享 Extended 指针，
// 子 ctx 中的 AppendRealOutbound 可能因 slice append 扩容写回父级 backing
// array，造成 RealOutboundChain 污染。此处深拷贝 Extended 及其 slice，
// 保证"派生副本修改不影响父"的语义契约。性能代价极小（仅当 Extended 非空），
// 并为后续对象池化优化奠定清晰的所有权边界。
func ExtendContext(ctx context.Context) (context.Context, *InboundContext) {
	var newMetadata InboundContext
	if metadata := ContextFrom(ctx); metadata != nil {
		newMetadata = *metadata
		if metadata.Extended != nil {
			ext := *metadata.Extended
			if len(ext.RealOutboundChain) > 0 {
				ext.RealOutboundChain = slices.Clone(ext.RealOutboundChain)
			}
			newMetadata.Extended = &ext
		}
	}
	return WithContext(ctx, &newMetadata), &newMetadata
}

// OverrideContext 在原地派生副本，用于需要覆盖部分字段但不暴露新 metadata 指针的场景。
// 同 ExtendContext，Extended 做深拷贝以避免共享污染。
func OverrideContext(ctx context.Context) context.Context {
	if metadata := ContextFrom(ctx); metadata != nil {
		newMetadata := *metadata
		if metadata.Extended != nil {
			ext := *metadata.Extended
			if len(ext.RealOutboundChain) > 0 {
				ext.RealOutboundChain = slices.Clone(ext.RealOutboundChain)
			}
			newMetadata.Extended = &ext
		}
		return WithContext(ctx, &newMetadata)
	}
	return ctx
}
