package option

import (
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// V2RayXHTTPOptions 对应 XTLS/Xray-core XHTTP (splithttp) 的 xhttpSettings。
// 对齐版本: Xray-core v26.9.30 transport/internet/splithttp + infra/conf/transport_method.go。
//
// 字段名沿用 sing-box 的 snake_case 风格，与 Xray camelCase 一一对应:
//
//	host                  ↔ host                (sing-box 扩展: 支持数组，客户端每次拨号随机取一)
//	path                  ↔ path                (支持 "/path?query"，query 会原样带上)
//	mode                  ↔ mode                ("auto" / "packet-up" / "stream-up" / "stream-one")
//	headers               ↔ headers             (不允许包含 Host)
//	x_padding_bytes       ↔ xPaddingBytes       (range，默认 100-1000，不可关闭)
//	x_padding_obfs_mode   ↔ xPaddingObfsMode
//	x_padding_key         ↔ xPaddingKey
//	x_padding_header      ↔ xPaddingHeader
//	x_padding_placement   ↔ xPaddingPlacement
//	x_padding_method      ↔ xPaddingMethod
//	uplink_http_method    ↔ uplinkHTTPMethod
//	session_placement     ↔ sessionIDPlacement
//	session_key           ↔ sessionIDKey
//	session_id_table      ↔ sessionIDTable
//	session_id_length     ↔ sessionIDLength
//	seq_placement         ↔ seqPlacement
//	seq_key               ↔ seqKey
//	uplink_data_placement ↔ uplinkDataPlacement
//	uplink_data_key       ↔ uplinkDataKey
//	uplink_chunk_size     ↔ uplinkChunkSize
//	no_grpc_header        ↔ noGRPCHeader
//	no_sse_header         ↔ noSSEHeader
//	sc_max_each_post_bytes   ↔ scMaxEachPostBytes   (range)
//	sc_min_posts_interval_ms ↔ scMinPostsIntervalMs (range)
//	sc_max_buffered_posts    ↔ scMaxBufferedPosts
//	sc_stream_up_server_secs ↔ scStreamUpServerSecs (range)
//	server_max_header_bytes  ↔ serverMaxHeaderBytes
//	xmux                  ↔ xmux
//	download_settings     ↔ downloadSettings    (上下行分离)
//
// 所有 range 字段同时接受整数 (1000) 和字符串 ("100-1000")。
type V2RayXHTTPOptions struct {
	Host    badoption.Listable[string] `json:"host,omitempty"`
	Path    string                     `json:"path,omitempty"`
	Mode    string                     `json:"mode,omitempty"`
	Headers badoption.HTTPHeader       `json:"headers,omitempty"`

	XPaddingBytes     XHTTPRange `json:"x_padding_bytes,omitzero"`
	XPaddingObfsMode  bool       `json:"x_padding_obfs_mode,omitempty"`
	XPaddingKey       string     `json:"x_padding_key,omitempty"`
	XPaddingHeader    string     `json:"x_padding_header,omitempty"`
	XPaddingPlacement string     `json:"x_padding_placement,omitempty"`
	XPaddingMethod    string     `json:"x_padding_method,omitempty"`

	UplinkHTTPMethod string `json:"uplink_http_method,omitempty"`

	SessionPlacement string     `json:"session_placement,omitempty"`
	SessionKey       string     `json:"session_key,omitempty"`
	SessionIDTable   string     `json:"session_id_table,omitempty"`
	SessionIDLength  XHTTPRange `json:"session_id_length,omitzero"`
	SeqPlacement     string     `json:"seq_placement,omitempty"`
	SeqKey           string     `json:"seq_key,omitempty"`

	UplinkDataPlacement string     `json:"uplink_data_placement,omitempty"`
	UplinkDataKey       string     `json:"uplink_data_key,omitempty"`
	UplinkChunkSize     XHTTPRange `json:"uplink_chunk_size,omitzero"`

	NoGRPCHeader bool `json:"no_grpc_header,omitempty"`
	NoSSEHeader  bool `json:"no_sse_header,omitempty"`

	ScMaxEachPostBytes   XHTTPRange `json:"sc_max_each_post_bytes,omitzero"`
	ScMinPostsIntervalMs XHTTPRange `json:"sc_min_posts_interval_ms,omitzero"`
	ScMaxBufferedPosts   int64      `json:"sc_max_buffered_posts,omitempty"`
	ScStreamUpServerSecs XHTTPRange `json:"sc_stream_up_server_secs,omitzero"`
	ServerMaxHeaderBytes int32      `json:"server_max_header_bytes,omitempty"`

	Xmux             *V2RayXHTTPXmuxOptions     `json:"xmux,omitempty"`
	DownloadSettings *V2RayXHTTPDownloadOptions `json:"download_settings,omitempty"`

	// UserAgent 是 sing-box 扩展: 等价于 headers 里写 "User-Agent": "<value>"。
	// 取值 chrome (默认) / firefox / safari / edge / curl / golang 时套用对应的
	// 浏览器伪装 header 集合 (Xray utils.TryDefaultHeadersWith)。
	UserAgent string `json:"user_agent,omitempty"`

	// XHTTP/3 (tls.alpn = ["h3"]) 的 QUIC 拥塞控制: "bbr" (默认) / "reno" / "force-brutal"。
	QuicCongestion string `json:"quic_congestion,omitempty"`
	// QuicUp: force-brutal 的发送带宽 (bytes/s)，至少 65536。
	QuicUp uint64 `json:"quic_up,omitempty"`
}

// V2RayXHTTPXmuxOptions 对应 Xray xmux。全部字段为零时使用 Xray 默认值:
// max_connections=3, h_max_request_times=600-900, h_max_reusable_secs=1800-3000。
type V2RayXHTTPXmuxOptions struct {
	MaxConcurrency   XHTTPRange `json:"max_concurrency,omitzero"`
	MaxConnections   XHTTPRange `json:"max_connections,omitzero"`
	CMaxReuseTimes   XHTTPRange `json:"c_max_reuse_times,omitzero"`
	HMaxRequestTimes XHTTPRange `json:"h_max_request_times,omitzero"`
	HMaxReusableSecs XHTTPRange `json:"h_max_reusable_secs,omitzero"`
	// HKeepAlivePeriod 单位秒；0 = 默认 (H2 45s / H3 10s)，负数 = 关闭。
	HKeepAlivePeriod int64 `json:"h_keep_alive_period,omitempty"`
}

// V2RayXHTTPDownloadOptions 对应 Xray downloadSettings (上下行分离)。
//
// 上行 (POST / stream-up / packet-up) 走外层 outbound 的 server + tls + dialer，
// 下行 (GET stream-down) 走这里配置的 server + tls + dialer + XHTTP 参数。
// 与 Xray 一致，内嵌的 XHTTP 参数 (path / host / headers / padding / xmux ...)
// 不从上行配置继承，需要单独写；server / server_port 为空时沿用上行地址。
// dialer 字段 (detour / bind_interface ...) 全部为空时复用上行 dialer。
type V2RayXHTTPDownloadOptions struct {
	ServerOptions
	OutboundTLSOptionsContainer
	DialerOptions
	V2RayXHTTPOptions
}

// XHTTPRange 是 Xray Int32Range 的等价物: 接受 1000 / "1000" / "100-1000"。
type XHTTPRange struct {
	From int32
	To   int32
}

func (r XHTTPRange) IsZero() bool {
	return r.From == 0 && r.To == 0
}

func (r XHTTPRange) String() string {
	if r.From == r.To {
		return strconv.FormatInt(int64(r.From), 10)
	}
	return strconv.FormatInt(int64(r.From), 10) + "-" + strconv.FormatInt(int64(r.To), 10)
}

func (r XHTTPRange) MarshalJSON() ([]byte, error) {
	if r.From == r.To {
		return json.Marshal(r.From)
	}
	return json.Marshal(r.String())
}

func (r *XHTTPRange) UnmarshalJSON(content []byte) error {
	var number int32
	if json.Unmarshal(content, &number) == nil {
		r.From, r.To = number, number
		return nil
	}
	var value string
	if err := json.Unmarshal(content, &value); err != nil {
		return E.New("invalid range, expected an integer or a string like \"1-2\"")
	}
	parsed, err := ParseXHTTPRange(value)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// ParseXHTTPRange 解析 "N" / "A-B"，保证 From <= To。
func ParseXHTTPRange(value string) (XHTTPRange, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return XHTTPRange{}, nil
	}
	// 从第二个字符起找 '-'，以便支持负数下界。
	separator := strings.IndexByte(value[1:], '-')
	var fromString, toString string
	if separator < 0 {
		fromString, toString = value, value
	} else {
		fromString, toString = value[:separator+1], value[separator+2:]
	}
	from, err := strconv.ParseInt(strings.TrimSpace(fromString), 10, 32)
	if err != nil {
		return XHTTPRange{}, E.Cause(err, "invalid range: ", value)
	}
	to, err := strconv.ParseInt(strings.TrimSpace(toString), 10, 32)
	if err != nil {
		return XHTTPRange{}, E.Cause(err, "invalid range: ", value)
	}
	if from > to {
		from, to = to, from
	}
	return XHTTPRange{From: int32(from), To: int32(to)}, nil
}
