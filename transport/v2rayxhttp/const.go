package v2rayxhttp

import "time"

// XHTTP 协议模式。对齐 mihomo / XTLS-Xray：
//   - auto:       有 TLS → stream-one; 无 TLS → packet-up
//   - stream-one: 单条 H2 duplex POST（请求体上行 / 响应体下行）
//   - stream-up:  POST 上行长流 + 独立 GET/SSE 下行长流
//   - packet-up:  每条写入一次 POST（seq 递增）+ 单条 GET/SSE 下行
const (
	ModeAuto      = "auto"
	ModeStreamOne = "stream-one"
	ModeStreamUp  = "stream-up"
	ModePacketUp  = "packet-up"
)

// 默认 padding 范围与 Xray/mihomo 一致（100-1000 bytes）
const defaultPaddingRange = "100-1000"

// ConnIdleTimeout: tunnel 空闲时上游 HTTP transport 的最大保活时长。
// 与 mihomo 对齐 (300s)，兼顾 CDN idle TCP 回收窗口。
const ConnIdleTimeout = 300 * time.Second

// ChromeH2KeepAlivePeriod: H2 读空闲 keep-alive 周期（Chrome 默认 45s）。
// 对 CDN 身份指纹更自然（相比 quic-go H3 的 10s）。
const ChromeH2KeepAlivePeriod = 45 * time.Second

// packetUp 的默认参数（与 Xray 一致）
const (
	defaultScMaxEachPostBytes   = 1_000_000
	defaultScMinPostsIntervalMs = 30
	defaultScMaxBufferedPosts   = 30
)

// HTTP 方法常量
const (
	methodPost = "POST"
	methodGet  = "GET"
)

// 内容类型
const (
	contentTypeGRPC = "application/grpc" // Xray 默认上行 stream 类型
	contentTypeSSE  = "text/event-stream"
)

// Padding 相关
const (
	paddingQueryKey  = "x_padding"
	paddingRefererHD = "Referer" // default placement: padding 值封装为 URL 放进 Referer
)
