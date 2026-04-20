package v2rayxhttp

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// RegisterPlugin 把 XHTTP 插进 v2ray transport 的 plugin registry。
// 同时在 option 侧注册 UnmarshalJSON 工厂，让 V2RayTransportOptions 能识别
// "type": "xhttp" 的 JSON 配置。
//
// 分两步是因为 option/ 和 transport/v2ray/ 各自有独立 registry：
//   option registry  → 负责 JSON 解码到具体结构体
//   v2ray registry   → 负责从结构体实例化出 Server/Client
//
// 都在这里一次性注册，调用方只需在 include/ 用 build tag 控制导入即可。
func RegisterPlugin() {
	option.RegisterV2RayTransportOptions(C.V2RayTransportTypeXHTTP, func() any {
		return new(option.V2RayXHTTPOptions)
	})
	v2ray.RegisterPlugin(C.V2RayTransportTypeXHTTP, v2ray.TransportPlugin{
		Server: serverAdapter,
		Client: clientAdapter,
	})
}

// serverAdapter / clientAdapter 把 registry 的 any 参数 assert 回具体类型，
// 然后调入实现。
func serverAdapter(
	ctx context.Context,
	logger logger.ContextLogger,
	options any,
	tlsConfig tls.ServerConfig,
	handler adapter.V2RayServerTransportHandler,
) (adapter.V2RayServerTransport, error) {
	opts, ok := options.(*option.V2RayXHTTPOptions)
	if !ok {
		return nil, E.New("xhttp: invalid options type ", options)
	}
	return NewServer(ctx, logger, opts, tlsConfig, handler)
}

func clientAdapter(
	ctx context.Context,
	dialer N.Dialer,
	serverAddr M.Socksaddr,
	options any,
	tlsConfig tls.Config,
) (adapter.V2RayClientTransport, error) {
	opts, ok := options.(*option.V2RayXHTTPOptions)
	if !ok {
		return nil, E.New("xhttp: invalid options type ", options)
	}
	return NewClient(ctx, dialer, serverAddr, opts, tlsConfig)
}
