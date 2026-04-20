package option

import (
	"github.com/sagernet/sing/common/json/badoption"
)

// V2RayXHTTPOptions 对应 XTLS/Xray XHTTP 协议的配置项。
// Spec: https://github.com/XTLS/Xray-core/discussions/4113
//       https://github.com/XTLS/Xray-core/discussions/5716
//       https://www.xhttp.org/
//
// 字段命名与 Xray 官方 config 对齐，方便用户直接搬运 Xray 配置文件里
// 的 xhttpSettings 过来，只需改外层协议名。
//
// Mode 解释（同 Xray）:
//   - "auto" (默认): 按传输层能力自动挑选；优先 stream-one > stream-up > packet-up
//   - "stream-one": HTTP/2 全双工单流（CONNECT-like），开销最小，要求 H2 服务端
//     + 客户端都支持请求体流式写。客户端必须同时支持 HTTP/2，不能退到 HTTP/1.1。
//   - "stream-up": 客户端用一条长 POST 上传 + 服务端用一条长 GET/POST 下发（SSE）。
//     HTTP/1.1 也能用，适合中间盒吃掉 H2 的场景。
//   - "packet-up": 客户端每个数据包一个 POST（带 seq 号），服务端用 SSE 或者
//     每次 POST 单独 response 下发。兼容性最好（穿透 CDN、WAF），开销也最大。
//
// ScMaxEachPostBytes / ScMinPostsIntervalMs / ScMaxBufferedPosts 控制 packet-up 模式
// 下的上行限流与缓冲，单位为字节 / 毫秒 / 个。客户端/服务端侧含义一致。
//
// XPaddingBytes 为单条消息附加的 padding 字节范围（"min-max"，随机化），
// 客户端在 URL query 加 "x_padding=..." 或 header "X-Padding: ..." 对抗流量指纹。
// 服务端无需解析 —— padding 只是作为 URL/header 字节填充，逻辑上被忽略。
//
// NoSSEHeader = true 时 stream-up 下行用普通 chunked 而非 text/event-stream，
// 绕过某些会重写 SSE 的 proxy。
type V2RayXHTTPOptions struct {
	// Host override. 为空时用 serverAddr 的 hostname。Listable 支持多值轮询。
	Host badoption.Listable[string] `json:"host,omitempty"`
	// Path（URL 路径前缀）。必填；客户端会在其后拼 "/<session-id>" 之类后缀。
	// 例："/your-path-here"。结尾斜杠会被自动补齐。
	Path string `json:"path,omitempty"`
	// Headers 客户端每次请求带的额外 header。常用:
	//   User-Agent（伪装浏览器），Cookie（透过 CDN 粘性路由）
	Headers badoption.HTTPHeader `json:"headers,omitempty"`
	// Mode: "auto" / "packet-up" / "stream-up" / "stream-one"。默认 "auto"。
	Mode string `json:"mode,omitempty"`

	// NoSSEHeader: stream-up 模式下降级不用 text/event-stream 响应。
	NoSSEHeader bool `json:"no_sse_header,omitempty"`

	// ── packet-up 模式参数（其它模式下忽略）──
	// ScMaxEachPostBytes: 单次 POST 最大字节数，超出会拆成多个 POST。
	ScMaxEachPostBytes int `json:"sc_max_each_post_bytes,omitempty"`
	// ScMinPostsIntervalMs: 相邻 POST 最小间隔毫秒，0 = 无限制。
	ScMinPostsIntervalMs int `json:"sc_min_posts_interval_ms,omitempty"`
	// ScMaxBufferedPosts: 服务端对乱序 POST 允许的最大缓冲数，默认 30。
	ScMaxBufferedPosts int `json:"sc_max_buffered_posts,omitempty"`

	// XPaddingBytes: 每请求 padding 范围 "min-max"（字节）。默认 "100-1000"。
	// 为 "0" 或 "0-0" 关闭 padding。
	XPaddingBytes string `json:"x_padding_bytes,omitempty"`

	// ── 下列字段对齐 Xray 但本实现暂不使用 ──
	// （保留 JSON 解析以免用户配置报 "unknown field" 错）
	// 仅 packet-up: 服务端会限制单连接持续时间，默认无限。
	ScStreamUpServerSecs int `json:"sc_stream_up_server_secs,omitempty"`
	// 仅 stream-up 多端口：服务端额外监听端口，客户端随机选一个分流下行。
	DownloadSettings map[string]any `json:"downloadSettings,omitempty"`
	// xmux 选项对象，当前实现不拆分 mux，配置仍能解析但被忽略。
	Xmux map[string]any `json:"xmux,omitempty"`
	// 允许扩展的其他字段（兼容 Xray 升级新增字段不报错）
	Extra map[string]any `json:"extra,omitempty"`
}
