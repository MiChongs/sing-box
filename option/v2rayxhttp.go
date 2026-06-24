package option

import (
	"github.com/sagernet/sing/common/json/badoption"
)

// V2RayXHTTPOptions 对应 XTLS/Xray XHTTP 协议的配置项。
// Spec: https://github.com/XTLS/Xray-core/discussions/4113
//       https://github.com/XTLS/Xray-core/discussions/5716
//       https://github.com/XTLS/Xray-core/pull/5414  (advanced obfuscation)
//       https://www.xhttp.org/
//
// 字段命名与 Xray 官方 config 对齐，方便用户直接搬运 Xray 配置文件里
// 的 xhttpSettings 过来。
//
// Mode 解释（同 Xray）:
//   - "auto" (默认): 按传输层能力自动挑选；优先 stream-one > stream-up > packet-up
//   - "stream-one": HTTP/2 全双工单流（CONNECT-like），开销最小，要求 H2
//   - "stream-up":  POST 上行长流 + 单独 GET/SSE 下行长流
//   - "packet-up":  每条数据 POST + SSE 下行，兼容性最好
//
// ScMaxEachPostBytes / ScMinPostsIntervalMs / ScMaxBufferedPosts 控制 packet-up
// 模式下的上行限流与缓冲，单位为字节 / 毫秒 / 个。
//
// XPaddingBytes 为单条消息附加的 padding 字节范围 ("min-max"，随机化)。
//
// NoSSEHeader = true 时 stream-up 下行用普通 chunked 而非 text/event-stream。
//
// XPaddingObfsMode / XPaddingKey / XPaddingHeader / XPaddingPlacement /
// XPaddingMethod 是 XTLS/Xray-core#5414 引入的反 CDN 探测扩展，允许把
// padding 改名、改位置、改字符集，绕开按 "x_padding=XXX..." 直字符串
// 匹配的 CDN 规则（如 CDNVideo / Cloudflare）。
//
// UplinkHTTPMethod 切换上行 HTTP 方法 (默认 POST)，绕开禁 POST 的 CDN
// (Yandex Cloud / VK Cloud 等)。GET 时数据不能在 body，必须配合
// UplinkDataPlacement 走 header / cookie。
//
// Session{Placement,Key} / Seq{Placement,Key} 控制 session UUID 和包序号
// 在请求里的位置 (默认拼在 path：/path/<uuid>/<seq>)。改成 cookie / header /
// query 后这些值看着像一般 Web 请求的 session token 而非 XHTTP 指纹。
//
// UplinkData{Placement,Key} + UplinkChunkSize: 当 CDN 完全禁用带 body 的方法
// 时把上行数据 base64 编码后切片塞 cookie 或 header (例 X-Data-0, X-Data-1
// + X-Data-Length + X-Data-Upstream)。仅 packet-up 模式有意义。
type V2RayXHTTPOptions struct {
	// Host override. 为空时用 serverAddr 的 hostname。Listable 支持多值轮询。
	Host badoption.Listable[string] `json:"host,omitempty"`
	// Path（URL 路径前缀）。
	Path string `json:"path,omitempty"`
	// Headers 客户端每次请求带的额外 header。
	Headers badoption.HTTPHeader `json:"headers,omitempty"`
	// Mode: "auto" / "packet-up" / "stream-up" / "stream-one"。默认 "auto"。
	Mode string `json:"mode,omitempty"`

	// NoSSEHeader: stream-up 模式下降级不用 text/event-stream 响应。
	NoSSEHeader bool `json:"no_sse_header,omitempty"`

	// ── packet-up 模式参数 ──
	ScMaxEachPostBytes   int `json:"sc_max_each_post_bytes,omitempty"`
	ScMinPostsIntervalMs int `json:"sc_min_posts_interval_ms,omitempty"`
	ScMaxBufferedPosts   int `json:"sc_max_buffered_posts,omitempty"`

	// XPaddingBytes: 每请求 padding 范围 "min-max"（字节）。默认 "100-1000"。
	// 为 "0" 或 "0-0" 关闭 padding。
	XPaddingBytes string `json:"x_padding_bytes,omitempty"`

	// ─── XTLS/Xray PR#5414: 反 CDN 探测扩展 ───
	// XPaddingObfsMode: 启用 padding 混淆模式 (允许改 key/header/placement/method)。
	// 默认 false (向后兼容：x_padding=XXX 放在 Referer 的 query 里)。
	XPaddingObfsMode bool `json:"x_padding_obfs_mode,omitempty"`
	// XPaddingKey: padding 字段名 (默认 "x_padding")。
	XPaddingKey string `json:"x_padding_key,omitempty"`
	// XPaddingHeader: 承载 padding 的 header 名 (默认 "X-Padding")。
	// 仅当 placement = "header" / "queryInHeader" 时使用。
	XPaddingHeader string `json:"x_padding_header,omitempty"`
	// XPaddingPlacement: padding 放在哪。可选 "queryInHeader" / "cookie" /
	// "header" / "query"。默认 "queryInHeader"。
	XPaddingPlacement string `json:"x_padding_placement,omitempty"`
	// XPaddingMethod: padding 生成方式。"repeat-x" (重复 X 字符，默认) /
	// "tokenish" (base62 随机 + huffman 长度修正)。
	XPaddingMethod string `json:"x_padding_method,omitempty"`

	// UplinkHTTPMethod: 上行 HTTP 方法 (默认 POST)。可设 PUT / PATCH / GET。
	// 当设为 "GET" 时必须 Mode = "packet-up" + UplinkDataPlacement != "body"。
	UplinkHTTPMethod string `json:"uplink_http_method,omitempty"`

	// SessionPlacement: session UUID 放在哪。"path" (默认) / "cookie" / "header" / "query"。
	SessionPlacement string `json:"session_placement,omitempty"`
	// SessionKey: session 字段名。默认按 placement 取 "x_session" / "X-Session"。
	SessionKey string `json:"session_key,omitempty"`
	// SeqPlacement: seq 序号放在哪。"path" (默认) / "cookie" / "header" / "query"。
	// 当 SessionPlacement = "path" 时 SeqPlacement 也必须是 "path"。
	SeqPlacement string `json:"seq_placement,omitempty"`
	// SeqKey: seq 字段名。默认按 placement 取 "x_seq" / "X-Seq"。
	SeqKey string `json:"seq_key,omitempty"`

	// UplinkDataPlacement: 上行数据放在哪。"body" / "auto" (默认) / "cookie" / "header"。
	// auto 在客户端等同 body，服务端会从 header+cookie+body 三处收集拼接。
	// 设为 cookie / header 时仅 packet-up 模式有效。
	UplinkDataPlacement string `json:"uplink_data_placement,omitempty"`
	// UplinkDataKey: 上行数据字段基名。默认按 placement 取 "x_data" / "X-Data"。
	UplinkDataKey string `json:"uplink_data_key,omitempty"`
	// UplinkChunkSize: 上行数据每片字节范围 "min-max" (placement != body 时生效)。
	// 默认 cookie=2048-3072 / header=3000-4000；From < 64 时强制提到 64。
	// 单值如 "1024" 等同 "1024-1024"。
	UplinkChunkSize string `json:"uplink_chunk_size,omitempty"`

	// UserAgent: 浏览器伪装策略 (XTLS/Xray-core#5802)。
	//   "" / "chrome"  — Sec-CH-UA + Sec-Fetch-* + Chrome UA (默认)
	//   "firefox"      — Firefox UA + DNT + 'en;q=0.5' Accept-Language
	//   "edge"         — Microsoft Edge UA + Sec-CH-UA
	//   "golang"       — 暴露 net/http 默认 UA (Go-http-client/1.1)，用于完全不伪装
	// 若用户在 headers 里显式塞了 User-Agent，会按该值（chrome/firefox/edge/golang）派发
	// header 集合；其他值会被当作字面 UA 字符串，不再补 Sec-CH-UA。
	UserAgent string `json:"user_agent,omitempty"`

	// ── 下列字段对齐 Xray 但本实现暂不使用 ──
	ScStreamUpServerSecs int `json:"sc_stream_up_server_secs,omitempty"`
	NoGRPCHeader         bool `json:"no_grpc_header,omitempty"`
	// ServerMaxHeaderBytes: http.Server.MaxHeaderBytes，默认 8192。
	// 限制入站请求 header 总大小，防恶意客户端发超大 header 打满内存。
	ServerMaxHeaderBytes int32 `json:"server_max_header_bytes,omitempty"`
	DownloadSettings     map[string]any `json:"downloadSettings,omitempty"`
	Xmux                 map[string]any `json:"xmux,omitempty"`

	// ── XHTTP/3 QUIC 拥塞控制 (XTLS/Xray-core v26.3.27 PR#5711) ──
	// QuicCongestion: "bbr" (默认 H3) / "reno" / "force-brutal"。
	// 仅 alpn=["h3"] 时生效。
	QuicCongestion string `json:"quic_congestion,omitempty"`
	// QuicUp: force-brutal 模式的上行带宽 (bytes/sec)，最小 65536。
	// 仅 QuicCongestion="force-brutal" 时必须。
	QuicUp uint64 `json:"quic_up,omitempty"`

}
