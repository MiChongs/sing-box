package constant

const (
	V2RayTransportTypeHTTP        = "http"
	V2RayTransportTypeWebsocket   = "ws"
	V2RayTransportTypeQUIC        = "quic"
	V2RayTransportTypeGRPC        = "grpc"
	V2RayTransportTypeHTTPUpgrade = "httpupgrade"
	// V2RayTransportTypeXHTTP: XTLS/Xray XHTTP 协议，详见:
	//   https://github.com/XTLS/Xray-core/discussions/4113
	//   https://github.com/XTLS/Xray-core/discussions/5716
	//   https://www.xhttp.org/
	// 三种模式: packet-up / stream-up / stream-one，可带 xPadding / x_padding_bytes。
	// 实现在 transport/v2rayxhttp 包，通过 init() 注册到 v2ray 插件 registry，
	// 由 build tag with_xhttp 控制是否编入。
	V2RayTransportTypeXHTTP = "xhttp"
)
