package v2rayxhttp

import "time"

// XHTTP 模式。auto 的客户端解析规则与 Xray Dial() 一致:
//   - REALITY: stream-one；配置了 download_settings 时 stream-up
//   - 其他:    packet-up
//
// 服务端 auto 接受全部三种模式。
const (
	ModeAuto      = "auto"
	ModeStreamOne = "stream-one"
	ModeStreamUp  = "stream-up"
	ModePacketUp  = "packet-up"
)

// 与 Xray common/net 保持一致。
const (
	// ConnIdleTimeout: HTTP transport 空闲连接 / QUIC MaxIdleTimeout。
	ConnIdleTimeout = 300 * time.Second
	// ChromeH2KeepAlivePeriod: H2 ReadIdleTimeout (Chrome 默认 45s)。
	ChromeH2KeepAlivePeriod = 45 * time.Second
	// QuicgoH3KeepAlivePeriod: H3 KeepAlivePeriod (quic-go/http3 默认 10s)。
	QuicgoH3KeepAlivePeriod = 10 * time.Second
)

// Xray GetNormalized* 的默认值。
const (
	defaultPaddingFrom          = 100
	defaultPaddingTo            = 1000
	defaultScMaxEachPostBytes   = 1_000_000
	defaultScMinPostsIntervalMs = 30
	defaultScMaxBufferedPosts   = 30
	defaultScStreamUpSecsFrom   = 20
	defaultScStreamUpSecsTo     = 80
	defaultServerMaxHeaderBytes = 8192
	// session 在 GET 下行到达前的存活时间。
	sessionReapTimeout = 30 * time.Second
	// 服务端读 header 超时 (Xray hub.go: 4s)。
	serverReadHeaderTimeout = 4 * time.Second
)

// HTTP 方法
const (
	methodPost = "POST"
	methodGet  = "GET"
)

// 内容类型
const (
	contentTypeGRPC = "application/grpc"
	contentTypeSSE  = "text/event-stream"
)

// 未开启 x_padding_obfs_mode 时的固定 padding 形态。
const (
	paddingQueryKey  = "x_padding"
	paddingRefererHD = "Referer"
	paddingHeader    = "X-Padding"
)

// HTTP 版本，对应 Xray decideHTTPVersion。
const (
	httpVersion1 = "1.1"
	httpVersion2 = "2"
	httpVersion3 = "3"
)
