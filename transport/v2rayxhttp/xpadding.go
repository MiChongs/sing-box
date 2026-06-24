package v2rayxhttp

import (
	"crypto/rand"
	"math"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// Placement constants — 对齐 XTLS/Xray-core PR#5414 transport/internet/splithttp/common.go。
// 用作 XPaddingPlacement / SessionPlacement / SeqPlacement / UplinkDataPlacement 的取值。
const (
	PlacementQueryInHeader = "queryInHeader"
	PlacementCookie        = "cookie"
	PlacementHeader        = "header"
	PlacementQuery         = "query"
	PlacementPath          = "path"
	PlacementBody          = "body"
)

// PaddingMethod 控制 padding 字节怎么生成。
type PaddingMethod string

const (
	// PaddingMethodRepeatX: 重复 X 字符。HTTP/2 HPACK 给 'X' 一个 8-bit huffman
	// 码，wire 长度恒等于字符串长度，用户配置的 100-1000 字节就是实际 padding。
	// 但 "x_padding=XXXX..." 是 CDNVideo 等用来识别 XHTTP 的特征，可被精确匹配。
	PaddingMethodRepeatX PaddingMethod = "repeat-x"
	// PaddingMethodTokenish: base62 随机字符 + 长度修正。huffman 后大约 80% 压缩，
	// 所以生成 N / 0.8 个字符，再迭代追加/截短 X/Z 让 huffman 后长度 ±2 匹配目标。
	// 看起来更像普通 cache buster (例 _dc=abc123) 而非死板的 XXX 序列。
	PaddingMethodTokenish PaddingMethod = "tokenish"
)

const charsetBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Huffman 编码给 base62 字符平均压缩到 ~80%（XTLS/Xray PR#5414 实测值）。
const avgHuffmanBytesPerCharBase62 = 0.8

// PaddingValidationTolerance: tokenish 模式生成时允许的 huffman 长度偏差。
// 服务端校验时也用同一个容忍区间。
const paddingValidationTolerance = 2

// XPaddingPlacement 把 padding 装载到哪里。
type XPaddingPlacement struct {
	Placement string // PlacementHeader / PlacementCookie / PlacementQuery / PlacementQueryInHeader
	Key       string // 字段名 (query key / cookie name / header name 之一)
	Header    string // 仅 PlacementHeader / PlacementQueryInHeader 用：承载 header 名
	RawURL    string // 仅 PlacementQueryInHeader 用：要塞进 header 的 URL
}

// XPaddingConfig 一次性 padding 生成 + 写入参数。
type XPaddingConfig struct {
	Length    int
	Placement XPaddingPlacement
	Method    PaddingMethod
}

// randStringFromCharset 从 charset 随机抽 n 个字节。
// 用 crypto/rand 而不是 math/rand，让 padding 不被 RNG 特征反推。
// 用 rejection sampling 避免 256 % len(charset) 偏差。
func randStringFromCharset(n int, charset string) (string, bool) {
	if n <= 0 || len(charset) == 0 {
		return "", false
	}
	m := len(charset)
	limit := byte(256 - (256 % m))

	result := make([]byte, n)
	i := 0
	buf := make([]byte, 256)
	for i < n {
		if _, err := rand.Read(buf); err != nil {
			return "", false
		}
		for _, rb := range buf {
			if rb >= limit {
				continue
			}
			result[i] = charset[int(rb)%m]
			i++
			if i == n {
				break
			}
		}
	}
	return string(result), true
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// generateTokenishPaddingBase62 生成 base62 padding，让 huffman 后长度近似 targetHuffmanBytes。
// 算法：先按平均压缩率出种子，再用 X/Z 交替追加 / 末尾截短去迫近目标。
func generateTokenishPaddingBase62(targetHuffmanBytes int) string {
	n := int(math.Ceil(float64(targetHuffmanBytes) / avgHuffmanBytesPerCharBase62))
	if n < 1 {
		n = 1
	}
	s, ok := randStringFromCharset(n, charsetBase62)
	if !ok {
		return ""
	}
	const maxIter = 150
	adjustChar := byte('X')
	for iter := 0; iter < maxIter; iter++ {
		current := int(hpack.HuffmanEncodeLength(s))
		diff := current - targetHuffmanBytes
		if absInt(diff) <= paddingValidationTolerance {
			return s
		}
		if diff < 0 {
			s += string(adjustChar)
			if adjustChar == 'X' {
				adjustChar = 'Z'
			} else {
				adjustChar = 'X'
			}
		} else {
			if len(s) <= 1 {
				return s
			}
			s = s[:len(s)-1]
		}
	}
	return s
}

// generatePaddingValue 按 method 出 padding 内容。
// 'X' 和 'Z' 在 HPACK 静态 huffman 表都是 8-bit 编码，wire 长度恒等串长。
func generatePaddingValue(method PaddingMethod, length int) string {
	if length <= 0 {
		return ""
	}
	switch method {
	case PaddingMethodTokenish:
		s := generateTokenishPaddingBase62(length)
		if s == "" {
			return strings.Repeat("X", length)
		}
		return s
	case PaddingMethodRepeatX, "":
		return strings.Repeat("X", length)
	default:
		return strings.Repeat("X", length)
	}
}

// applyPaddingToHeader: 写入到 http.Header。
//
// placement = "header"        → h[Header] = paddingValue
// placement = "queryInHeader" → 把 rawURL 改成 rawURL?<key>=<paddingValue>，再写到 h[Header]
//                               （历史上的默认形式：Referer: <URL>?x_padding=XXX）
func applyPaddingToHeader(h http.Header, p XPaddingPlacement, paddingValue string) {
	if h == nil || paddingValue == "" {
		return
	}
	switch p.Placement {
	case PlacementHeader:
		if p.Header == "" {
			return
		}
		h.Set(p.Header, paddingValue)
	case PlacementQueryInHeader:
		if p.RawURL == "" || p.Header == "" || p.Key == "" {
			return
		}
		u, err := url.Parse(p.RawURL)
		if err != nil || u == nil {
			return
		}
		u.RawQuery = p.Key + "=" + paddingValue
		h.Set(p.Header, u.String())
	}
}

// applyPaddingToRequest 按 XPaddingConfig 把 padding 塞进 request。
// 覆盖 placement 的 4 个分支：header / queryInHeader / cookie / query。
func applyPaddingToRequest(req *http.Request, cfg XPaddingConfig) {
	if req == nil || cfg.Length <= 0 {
		return
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	value := generatePaddingValue(cfg.Method, cfg.Length)
	if value == "" {
		return
	}
	switch cfg.Placement.Placement {
	case PlacementHeader, PlacementQueryInHeader:
		applyPaddingToHeader(req.Header, cfg.Placement, value)
	case PlacementCookie:
		if cfg.Placement.Key == "" {
			return
		}
		req.AddCookie(&http.Cookie{Name: cfg.Placement.Key, Value: value, Path: "/"})
	case PlacementQuery:
		if cfg.Placement.Key == "" || req.URL == nil {
			return
		}
		q := req.URL.Query()
		q.Set(cfg.Placement.Key, value)
		req.URL.RawQuery = q.Encode()
	}
}
