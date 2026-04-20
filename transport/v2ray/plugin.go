package v2ray

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// 插件机制：核心 transport.go 保持不改 —— 插件式 transport（如 XHTTP）
// 在 init() 里通过 RegisterPlugin 把自己注册到包级 map，然后
// NewServerTransport / NewClientTransport 的 switch default 分支
// 会 fallback 到这里查找。这样 XHTTP 实现完全外挂在 transport/v2rayxhttp
// 包，通过 build tag with_xhttp 控制是否链入，核心 v2ray 包无需感知具体
// 插件的存在，未来新增 transport (kcp / mekya / ...) 也走同一路径。
//
// 插件自己负责 JSON 选项解析 —— option/v2ray_transport.go 里的 UnmarshalJSON
// 对未知 type 做同样的 registry lookup（见 option.RegisterV2RayTransportOptions），
// 把匹配的 opts 结构体实例存在 Extra 字段，本包 NewServerTransport /
// NewClientTransport 从 Extra 里取出再传给插件构造函数。

// ServerPluginConstructor 插件 server 端构造器。options 是插件自己的
// 选项结构体类型（由插件注册时通过 option.RegisterV2RayTransportOptions
// 声明出厂函数），runtime 传进来时需要自己 type-assert 到具体类型。
type ServerPluginConstructor func(
	ctx context.Context,
	logger logger.ContextLogger,
	options any,
	tlsConfig tls.ServerConfig,
	handler adapter.V2RayServerTransportHandler,
) (adapter.V2RayServerTransport, error)

// ClientPluginConstructor 插件 client 端构造器。
type ClientPluginConstructor func(
	ctx context.Context,
	dialer N.Dialer,
	serverAddr M.Socksaddr,
	options any,
	tlsConfig tls.Config,
) (adapter.V2RayClientTransport, error)

// TransportPlugin 绑定某个 transport 类型名到 server/client 构造器。
type TransportPlugin struct {
	Server ServerPluginConstructor
	Client ClientPluginConstructor
}

var (
	pluginAccess   sync.RWMutex
	pluginRegistry = map[string]TransportPlugin{}
)

// RegisterPlugin 注册一个新的 transport 类型。name 应与
// option.V2RayTransportOptions.Type 字段的字符串一致（如 "xhttp"）。
// 通常在插件包的 init() 里调用，配合 build tag 控制可见性。
func RegisterPlugin(name string, plugin TransportPlugin) {
	pluginAccess.Lock()
	defer pluginAccess.Unlock()
	pluginRegistry[name] = plugin
}

// LookupPlugin 供核心 transport.go 的 switch default 分支查询。
func LookupPlugin(name string) (TransportPlugin, bool) {
	pluginAccess.RLock()
	defer pluginAccess.RUnlock()
	p, ok := pluginRegistry[name]
	return p, ok
}
