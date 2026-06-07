package adapter

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/sagernet/sing-box/common/tlsspoof"
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
	ConnectionHandler
}

type UDPInjectableInbound interface {
	Inbound
	PacketConnectionHandler
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
	TLSSpoof                  string
	TLSSpoofMethod            tlsspoof.Method

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

	IPCIDRMatchSource bool
	IPCIDRAcceptEmpty bool

	SourceAddressMatch           bool
	SourcePortMatch              bool
	DestinationAddressMatch      bool
	DestinationPortMatch         bool
	DidMatch                     bool
	IgnoreDestinationIPCIDRMatch bool

	// extended metadata
	Extended *InboundContextExtended
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

func (c *InboundContext) ResetRuleCache() {
	c.IPCIDRMatchSource = false
	c.IPCIDRAcceptEmpty = false
	c.ResetRuleMatchCache()
}

func (c *InboundContext) ResetRuleMatchCache() {
	c.SourceAddressMatch = false
	c.SourcePortMatch = false
	c.DestinationAddressMatch = false
	c.DestinationPortMatch = false
	c.DidMatch = false
}

func (c *InboundContext) DNSResponseAddressesForMatch() []netip.Addr {
	return DNSResponseAddresses(c.DNSResponse)
}

func DNSResponseAddresses(response *dns.Msg) []netip.Addr {
	if response == nil || response.Rcode != dns.RcodeSuccess {
		return nil
	}
	addresses := make([]netip.Addr, 0, len(response.Answer))
	for _, rawRecord := range response.Answer {
		switch record := rawRecord.(type) {
		case *dns.A:
			addr := M.AddrFromIP(record.A)
			if addr.IsValid() {
				addresses = append(addresses, addr)
			}
		case *dns.AAAA:
			addr := M.AddrFromIP(record.AAAA)
			if addr.IsValid() {
				addresses = append(addresses, addr)
			}
		case *dns.HTTPS:
			for _, value := range record.SVCB.Value {
				switch hint := value.(type) {
				case *dns.SVCBIPv4Hint:
					for _, ip := range hint.Hint {
						addr := M.AddrFromIP(ip).Unmap()
						if addr.IsValid() {
							addresses = append(addresses, addr)
						}
					}
				case *dns.SVCBIPv6Hint:
					for _, ip := range hint.Hint {
						addr := M.AddrFromIP(ip)
						if addr.IsValid() {
							addresses = append(addresses, addr)
						}
					}
				}
			}
		}
	}
	return addresses
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
