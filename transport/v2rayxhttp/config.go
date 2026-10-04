package v2rayxhttp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"math/rand/v2"
	"net/http"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/gofrs/uuid/v5"
)

// rangeConfig 对应 Xray RangeConfig。
type rangeConfig struct {
	From int32
	To   int32
}

func newRange(r option.XHTTPRange) rangeConfig {
	return rangeConfig{From: r.From, To: r.To}
}

// rand 返回 [From, To] 内的随机值 (Xray crypto.RandBetween)。
func (r rangeConfig) rand() int32 {
	if r.To <= r.From {
		return r.From
	}
	return r.From + rand.Int32N(r.To-r.From+1)
}

// predefinedSessionIDTables 对应 Xray splithttp.PredefinedTable。
var predefinedSessionIDTables = map[string]string{
	"ALPHABET": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"Alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"BASE36":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"Base62":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"HEX":      "0123456789ABCDEF",
	"alphabet": "abcdefghijklmnopqrstuvwxyz",
	"base36":   "0123456789abcdefghijklmnopqrstuvwxyz",
	"hex":      "0123456789abcdef",
	"number":   "0123456789",
}

type xmuxConfig struct {
	maxConcurrency   rangeConfig
	maxConnections   rangeConfig
	cMaxReuseTimes   rangeConfig
	hMaxRequestTimes rangeConfig
	hMaxReusableSecs rangeConfig
	hKeepAlivePeriod int64
}

// config 是 option.V2RayXHTTPOptions 经 Xray SplitHTTPConfig.Build() 规则
// 校验、补默认值之后的形态，客户端与服务端共用。
type config struct {
	hosts []string
	// path 已规范化: 以 '/' 开头；session 或 seq 放在 path 时以 '/' 结尾。
	path string
	// query 是 path 里 '?' 之后的部分，原样附加到每个请求。
	query string
	// mode 为配置值 (空串规范化为 auto)；客户端在拨号时再解析 auto。
	mode    string
	headers http.Header

	xPaddingBytes     rangeConfig
	xPaddingObfsMode  bool
	xPaddingKey       string
	xPaddingHeader    string
	xPaddingPlacement string
	xPaddingMethod    PaddingMethod

	uplinkHTTPMethod string

	sessionPlacement string
	sessionKey       string
	sessionIDTable   string
	sessionIDLength  rangeConfig
	seqPlacement     string
	seqKey           string

	uplinkDataPlacement string
	uplinkDataKey       string
	uplinkChunkSize     rangeConfig

	noGRPCHeader bool
	noSSEHeader  bool

	scMaxEachPostBytes   rangeConfig
	scMinPostsIntervalMs rangeConfig
	scMaxBufferedPosts   int
	scStreamUpServerSecs rangeConfig
	serverMaxHeaderBytes int

	xmux xmuxConfig

	quicCongestion string
	quicUp         uint64
}

func newConfig(options *option.V2RayXHTTPOptions) (*config, error) {
	if options == nil {
		options = &option.V2RayXHTTPOptions{}
	}
	c := &config{
		hosts:            append([]string(nil), options.Host...),
		headers:          http.Header{},
		xPaddingObfsMode: options.XPaddingObfsMode,
		noGRPCHeader:     options.NoGRPCHeader,
		noSSEHeader:      options.NoSSEHeader,
		quicCongestion:   options.QuicCongestion,
		quicUp:           options.QuicUp,
	}

	switch options.Mode {
	case "", ModeAuto:
		c.mode = ModeAuto
	case ModePacketUp, ModeStreamUp, ModeStreamOne:
		c.mode = options.Mode
	default:
		return nil, E.New("xhttp: unsupported mode: ", options.Mode)
	}

	for key, values := range options.Headers.Build() {
		if strings.EqualFold(key, "host") {
			return nil, E.New("xhttp: headers can't contain host")
		}
		for _, value := range values {
			c.headers.Add(key, value)
		}
	}
	if options.UserAgent != "" && c.headers.Get("User-Agent") == "" {
		c.headers.Set("User-Agent", options.UserAgent)
	}

	if !options.XPaddingBytes.IsZero() && (options.XPaddingBytes.From <= 0 || options.XPaddingBytes.To <= 0) {
		return nil, E.New("xhttp: x_padding_bytes cannot be disabled")
	}
	c.xPaddingBytes = newRange(options.XPaddingBytes)
	if c.xPaddingBytes.To == 0 {
		c.xPaddingBytes = rangeConfig{From: defaultPaddingFrom, To: defaultPaddingTo}
	}

	c.xPaddingKey = options.XPaddingKey
	if c.xPaddingKey == "" {
		c.xPaddingKey = paddingQueryKey
	}
	c.xPaddingHeader = options.XPaddingHeader
	if c.xPaddingHeader == "" {
		c.xPaddingHeader = paddingHeader
	}
	switch options.XPaddingPlacement {
	case "":
		c.xPaddingPlacement = PlacementQueryInHeader
	case PlacementCookie, PlacementHeader, PlacementQuery, PlacementQueryInHeader:
		c.xPaddingPlacement = options.XPaddingPlacement
	default:
		return nil, E.New("xhttp: unsupported padding placement: ", options.XPaddingPlacement)
	}
	switch options.XPaddingMethod {
	case "":
		c.xPaddingMethod = PaddingMethodRepeatX
	case string(PaddingMethodRepeatX), string(PaddingMethodTokenish):
		c.xPaddingMethod = PaddingMethod(options.XPaddingMethod)
	default:
		return nil, E.New("xhttp: unsupported padding method: ", options.XPaddingMethod)
	}

	switch options.UplinkDataPlacement {
	case "":
		c.uplinkDataPlacement = PlacementAuto
	case PlacementAuto, PlacementBody:
		c.uplinkDataPlacement = options.UplinkDataPlacement
	case PlacementCookie, PlacementHeader:
		if c.mode != ModePacketUp {
			return nil, E.New("xhttp: uplink_data_placement can be ", options.UplinkDataPlacement, " only in packet-up mode")
		}
		c.uplinkDataPlacement = options.UplinkDataPlacement
	default:
		return nil, E.New("xhttp: unsupported uplink data placement: ", options.UplinkDataPlacement)
	}

	c.uplinkHTTPMethod = strings.ToUpper(options.UplinkHTTPMethod)
	if c.uplinkHTTPMethod == "" {
		c.uplinkHTTPMethod = methodPost
	}
	if c.uplinkHTTPMethod == methodGet && c.mode != ModePacketUp {
		return nil, E.New("xhttp: uplink_http_method can be GET only in packet-up mode")
	}

	switch options.SessionPlacement {
	case "":
		c.sessionPlacement = PlacementPath
	case PlacementPath, PlacementCookie, PlacementHeader, PlacementQuery:
		c.sessionPlacement = options.SessionPlacement
	default:
		return nil, E.New("xhttp: unsupported session placement: ", options.SessionPlacement)
	}
	switch options.SeqPlacement {
	case "":
		c.seqPlacement = PlacementPath
	case PlacementPath, PlacementCookie, PlacementHeader, PlacementQuery:
		c.seqPlacement = options.SeqPlacement
	default:
		return nil, E.New("xhttp: unsupported seq placement: ", options.SeqPlacement)
	}
	c.sessionKey = options.SessionKey
	if c.sessionKey == "" {
		c.sessionKey = defaultMetaKey(c.sessionPlacement, "X-Session", "x_session")
	}
	c.seqKey = options.SeqKey
	if c.seqKey == "" {
		c.seqKey = defaultMetaKey(c.seqPlacement, "X-Seq", "x_seq")
	}

	c.sessionIDLength = newRange(options.SessionIDLength)
	if options.SessionIDTable != "" {
		c.sessionIDTable = options.SessionIDTable
		if predefined, loaded := predefinedSessionIDTables[c.sessionIDTable]; loaded {
			c.sessionIDTable = predefined
		}
		// 2.1B possibilities should be enough
		if sessionIDRoomSize(len(c.sessionIDTable), c.sessionIDLength.From, c.sessionIDLength.To).Cmp(big.NewInt(2<<30)) < 0 {
			return nil, E.New("xhttp: session_id_table or session_id_length is too small")
		}
		if c.sessionIDLength.From <= 0 {
			return nil, E.New("xhttp: session_id_length must be greater than 0")
		}
		for i := 0; i < len(c.sessionIDTable); i++ {
			if c.sessionIDTable[i] >= 0x80 {
				return nil, E.New("xhttp: session_id_table must contain only ASCII characters")
			}
		}
	}

	c.uplinkDataKey = options.UplinkDataKey
	if c.uplinkDataKey == "" {
		switch c.uplinkDataPlacement {
		case PlacementCookie:
			c.uplinkDataKey = "x_data"
		case PlacementAuto, PlacementHeader:
			c.uplinkDataKey = "X-Data"
		}
	}

	if options.ServerMaxHeaderBytes < 0 {
		return nil, E.New("xhttp: invalid negative value of server_max_header_bytes")
	}
	c.serverMaxHeaderBytes = int(options.ServerMaxHeaderBytes)
	if c.serverMaxHeaderBytes == 0 {
		c.serverMaxHeaderBytes = defaultServerMaxHeaderBytes
	}

	c.scMaxEachPostBytes = newRange(options.ScMaxEachPostBytes)
	if c.scMaxEachPostBytes.To == 0 {
		c.scMaxEachPostBytes = rangeConfig{From: defaultScMaxEachPostBytes, To: defaultScMaxEachPostBytes}
	} else if c.scMaxEachPostBytes.From <= 0 {
		return nil, E.New("xhttp: sc_max_each_post_bytes should be bigger than 0")
	}
	c.scMinPostsIntervalMs = newRange(options.ScMinPostsIntervalMs)
	if c.scMinPostsIntervalMs.To == 0 {
		c.scMinPostsIntervalMs = rangeConfig{From: defaultScMinPostsIntervalMs, To: defaultScMinPostsIntervalMs}
	}
	c.scMaxBufferedPosts = int(options.ScMaxBufferedPosts)
	if c.scMaxBufferedPosts <= 0 {
		c.scMaxBufferedPosts = defaultScMaxBufferedPosts
	}
	c.scStreamUpServerSecs = newRange(options.ScStreamUpServerSecs)
	if c.scStreamUpServerSecs.To == 0 {
		c.scStreamUpServerSecs = rangeConfig{From: defaultScStreamUpSecsFrom, To: defaultScStreamUpSecsTo}
	}

	c.uplinkChunkSize = newRange(options.UplinkChunkSize)
	if c.uplinkChunkSize.To == 0 {
		switch c.uplinkDataPlacement {
		case PlacementCookie:
			c.uplinkChunkSize = rangeConfig{From: 2 * 1024, To: 3 * 1024}
		case PlacementHeader:
			c.uplinkChunkSize = rangeConfig{From: 3 * 1000, To: 4 * 1000}
		default:
			c.uplinkChunkSize = c.scMaxEachPostBytes
		}
	} else if c.uplinkChunkSize.From < 64 {
		c.uplinkChunkSize = rangeConfig{From: 64, To: max(64, c.uplinkChunkSize.To)}
	}

	if options.Xmux != nil {
		if options.Xmux.MaxConnections.To > 0 && options.Xmux.MaxConcurrency.To > 0 {
			return nil, E.New("xhttp: xmux max_connections cannot be specified together with max_concurrency")
		}
		c.xmux = xmuxConfig{
			maxConcurrency:   newRange(options.Xmux.MaxConcurrency),
			maxConnections:   newRange(options.Xmux.MaxConnections),
			cMaxReuseTimes:   newRange(options.Xmux.CMaxReuseTimes),
			hMaxRequestTimes: newRange(options.Xmux.HMaxRequestTimes),
			hMaxReusableSecs: newRange(options.Xmux.HMaxReusableSecs),
			hKeepAlivePeriod: options.Xmux.HKeepAlivePeriod,
		}
	}
	if c.xmux == (xmuxConfig{}) {
		c.xmux.maxConnections = rangeConfig{From: 3, To: 3}
		c.xmux.hMaxRequestTimes = rangeConfig{From: 600, To: 900}
		c.xmux.hMaxReusableSecs = rangeConfig{From: 1800, To: 3000}
	}

	switch c.quicCongestion {
	case "", "bbr", "reno":
	case "force-brutal":
		if c.quicUp < 65536 {
			return nil, E.New("xhttp: quic_congestion=force-brutal requires quic_up >= 65536 bytes/s")
		}
	default:
		return nil, E.New("xhttp: unknown quic_congestion: ", c.quicCongestion)
	}

	pathAndQuery := strings.SplitN(options.Path, "?", 2)
	c.path = pathAndQuery[0]
	if c.path == "" || c.path[0] != '/' {
		c.path = "/" + c.path
	}
	if (c.sessionPlacement == PlacementPath || c.seqPlacement == PlacementPath) && !strings.HasSuffix(c.path, "/") {
		c.path += "/"
	}
	if len(pathAndQuery) > 1 {
		c.query = pathAndQuery[1]
	}
	return c, nil
}

func defaultMetaKey(placement, headerKey, otherKey string) string {
	switch placement {
	case PlacementHeader:
		return headerKey
	case PlacementCookie, PlacementQuery:
		return otherKey
	default:
		return ""
	}
}

func sessionIDRoomSize(tableSize int, from, to int32) *big.Int {
	base := big.NewInt(int64(tableSize))
	sum := new(big.Int)
	term := new(big.Int)
	for k := from; k <= to; k++ {
		term.Exp(base, big.NewInt(int64(k)), nil)
		sum.Add(sum, term)
	}
	return sum
}

// generateSessionID 对应 Xray Config.GenerateSessionID: 默认 UUIDv4 字符串，
// 配置了 session_id_table 时按表与长度随机生成。
func (c *config) generateSessionID() string {
	length := c.sessionIDLength.rand()
	if c.sessionIDTable != "" && length > 0 {
		id := make([]byte, length)
		for i := range id {
			id[i] = c.sessionIDTable[rand.IntN(len(c.sessionIDTable))]
		}
		return string(id)
	}
	return uuid.Must(uuid.NewV4()).String()
}

// pickHost 返回本次请求使用的 Host；未配置时由调用方回落到 TLS SNI / 服务器地址。
func (c *config) pickHost() string {
	switch len(c.hosts) {
	case 0:
		return ""
	case 1:
		return c.hosts[0]
	default:
		return c.hosts[rand.IntN(len(c.hosts))]
	}
}

// ──────────────────────────────────────────────────────────────────────
// 客户端请求构造 (Xray config.go FillStreamRequest / FillPacketRequest)
// ──────────────────────────────────────────────────────────────────────

func (c *config) requestHeader() http.Header {
	header := http.Header{}
	for key, values := range c.headers {
		for _, value := range values {
			header.Add(key, value)
		}
	}
	tryDefaultHeadersWith(header, "fetch")
	return header
}

func (c *config) requestHeaderWithPayload(payload []byte) http.Header {
	header := c.requestHeader()
	encodedData := base64.RawURLEncoding.EncodeToString(payload)
	for i := 0; len(encodedData) > 0; i++ {
		chunkSize := min(int(c.uplinkChunkSize.rand()), len(encodedData))
		header.Set(fmt.Sprintf("%s-%d", c.uplinkDataKey, i), encodedData[:chunkSize])
		encodedData = encodedData[chunkSize:]
	}
	return header
}

func (c *config) requestCookiesWithPayload(payload []byte) []*http.Cookie {
	var cookies []*http.Cookie
	encodedData := base64.RawURLEncoding.EncodeToString(payload)
	for i := 0; len(encodedData) > 0; i++ {
		chunkSize := min(int(c.uplinkChunkSize.rand()), len(encodedData))
		cookies = append(cookies, &http.Cookie{Name: fmt.Sprintf("%s_%d", c.uplinkDataKey, i), Value: encodedData[:chunkSize]})
		encodedData = encodedData[chunkSize:]
	}
	return cookies
}

// requestPaddingConfig 生成一次请求的 padding 参数。RawURL 取 session / seq
// 写入之前的 URL，与 Xray 一致 (Referer: https://host/path/?x_padding=XXX)。
func (c *config) requestPaddingConfig(request *http.Request) XPaddingConfig {
	paddingConfig := XPaddingConfig{Length: int(c.xPaddingBytes.rand())}
	if c.xPaddingObfsMode {
		paddingConfig.Placement = XPaddingPlacement{
			Placement: c.xPaddingPlacement,
			Key:       c.xPaddingKey,
			Header:    c.xPaddingHeader,
			RawURL:    request.URL.String(),
		}
		paddingConfig.Method = c.xPaddingMethod
	} else {
		paddingConfig.Placement = XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       paddingQueryKey,
			Header:    paddingRefererHD,
			RawURL:    request.URL.String(),
		}
	}
	return paddingConfig
}

func (c *config) fillStreamRequest(request *http.Request, sessionId string) {
	request.Header = c.requestHeader()
	applyXPaddingToRequest(request, c.requestPaddingConfig(request))
	c.applyMetaToRequest(request, sessionId, "")
	if request.Body != nil && !c.noGRPCHeader { // stream-up/one
		request.Header.Set("Content-Type", contentTypeGRPC)
	}
}

func (c *config) fillPacketRequest(request *http.Request, sessionId, seqStr string, payload []byte) {
	switch c.uplinkDataPlacement {
	case PlacementHeader:
		request.Header = c.requestHeaderWithPayload(payload)
	case PlacementCookie:
		request.Header = c.requestHeader()
		for _, cookie := range c.requestCookiesWithPayload(payload) {
			request.AddCookie(cookie)
		}
	default: // body, auto
		request.Header = c.requestHeader()
		request.Body = io.NopCloser(bytes.NewReader(payload))
		request.ContentLength = int64(len(payload))
		request.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(payload)), nil
		}
	}
	applyXPaddingToRequest(request, c.requestPaddingConfig(request))
	c.applyMetaToRequest(request, sessionId, seqStr)
}

func (c *config) applyMetaToRequest(request *http.Request, sessionId, seqStr string) {
	if sessionId != "" {
		applyMetaValue(request, c.sessionPlacement, c.sessionKey, sessionId)
	}
	if seqStr != "" {
		applyMetaValue(request, c.seqPlacement, c.seqKey, seqStr)
	}
}

func applyMetaValue(request *http.Request, placement, key, value string) {
	switch placement {
	case PlacementPath:
		request.URL.Path = appendToPath(request.URL.Path, value)
	case PlacementQuery:
		query := request.URL.Query()
		query.Set(key, value)
		request.URL.RawQuery = query.Encode()
	case PlacementHeader:
		request.Header.Set(key, value)
	case PlacementCookie:
		request.AddCookie(&http.Cookie{Name: key, Value: value})
	}
}

func appendToPath(path, value string) string {
	if strings.HasSuffix(path, "/") {
		return path + value
	}
	return path + "/" + value
}

// ──────────────────────────────────────────────────────────────────────
// 服务端解析 (Xray config.go ExtractMetaFromRequest / WriteResponseHeader)
// ──────────────────────────────────────────────────────────────────────

func (c *config) extractMetaFromRequest(request *http.Request, path string) (sessionId string, seqStr string) {
	var subpath []string
	pathPart := 0
	if (c.sessionPlacement == PlacementPath || c.seqPlacement == PlacementPath) && len(request.URL.Path) >= len(path) {
		subpath = strings.Split(request.URL.Path[len(path):], "/")
	}
	extract := func(placement, key string) string {
		switch placement {
		case PlacementPath:
			if len(subpath) > pathPart {
				value := subpath[pathPart]
				pathPart++
				return value
			}
		case PlacementQuery:
			return request.URL.Query().Get(key)
		case PlacementHeader:
			return request.Header.Get(key)
		case PlacementCookie:
			if cookie, err := request.Cookie(key); err == nil {
				return cookie.Value
			}
		}
		return ""
	}
	sessionId = extract(c.sessionPlacement, c.sessionKey)
	seqStr = extract(c.seqPlacement, c.seqKey)
	return
}

func (c *config) writeResponseHeader(writer http.ResponseWriter, requestMethod string, requestHeader http.Header) {
	// CORS headers for the browser dialer
	if origin := requestHeader.Get("Origin"); origin == "" {
		writer.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		// Chrome: the value of 'Access-Control-Allow-Origin' must not be the
		// wildcard '*' when the request's credentials mode is 'include'.
		writer.Header().Set("Access-Control-Allow-Origin", origin)
	}
	if c.sessionPlacement == PlacementCookie ||
		c.seqPlacement == PlacementCookie ||
		c.xPaddingPlacement == PlacementCookie ||
		c.uplinkDataPlacement == PlacementCookie {
		writer.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	if requestMethod == http.MethodOptions {
		if requestedMethod := requestHeader.Get("Access-Control-Request-Method"); requestedMethod != "" {
			writer.Header().Set("Access-Control-Allow-Methods", requestedMethod)
		} else {
			writer.Header().Set("Access-Control-Allow-Methods", "*")
		}
		if requestedHeaders := requestHeader.Get("Access-Control-Request-Headers"); requestedHeaders == "" {
			writer.Header().Set("Access-Control-Allow-Headers", "*")
		} else {
			writer.Header().Set("Access-Control-Allow-Headers", requestedHeaders)
		}
	}
}

func (c *config) responsePaddingConfig() XPaddingConfig {
	paddingConfig := XPaddingConfig{Length: int(c.xPaddingBytes.rand())}
	if c.xPaddingObfsMode {
		paddingConfig.Placement = XPaddingPlacement{
			Placement: c.xPaddingPlacement,
			Key:       c.xPaddingKey,
			Header:    c.xPaddingHeader,
		}
		paddingConfig.Method = c.xPaddingMethod
	} else {
		paddingConfig.Placement = XPaddingPlacement{
			Placement: PlacementHeader,
			Header:    paddingHeader,
		}
	}
	return paddingConfig
}
