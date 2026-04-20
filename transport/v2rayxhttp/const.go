package v2rayxhttp

// XHTTP 模式常量；对应 option.V2RayXHTTPOptions.Mode 字段。
// "auto" 由客户端按 transport 能力（HTTP/2 与否）挑选：
//   有 H2 且支持 duplex → stream-one
//   有 H2 但后端是 CDN 可能不支持上行流式 → stream-up
//   纯 HTTP/1.1 或 CDN 明令禁止长请求 → packet-up
// 当前实现客户端 auto 路径优先选 stream-one (H2) / stream-up (H1)。
const (
	ModeAuto      = "auto"
	ModePacketUp  = "packet-up"
	ModeStreamUp  = "stream-up"
	ModeStreamOne = "stream-one"
)

// XHTTP 协议专用 header / query 名称，保持与 Xray 一致以便互通。
const (
	// 每请求 URL query 附随机 hex padding
	paddingQueryKey = "x_padding"
	// 同上但放 header（某些 CDN 吃掉 query）
	paddingHeaderKey = "X-Padding"

	// packet-up 模式：服务端用 SSE 或普通 chunked 下发下行
	contentTypeSSE       = "text/event-stream"
	contentTypeOctet     = "application/octet-stream"
	contentTypePlainData = "application/grpc" // 某些 CDN 对该类型白名单更友好；与 Xray 对齐

	// packet-up 模式 UP 方向默认 method
	methodPost = "POST"
	// stream-one / stream-up 的 down 方向 method
	methodGet = "GET"

	// SSE chunk 前缀（如果启用 no_sse_header=false）
	sseDataPrefix = "data: "
	sseChunkEnd   = "\n\n"
)

// 服务端 packet-up 会话默认参数
const (
	defaultScMaxBufferedPosts = 30
	// 会话空闲超时：SSE 通道关闭 + 30s 无新 POST 即回收 session 上下文
	sessionIdleTimeoutSeconds = 60
)
