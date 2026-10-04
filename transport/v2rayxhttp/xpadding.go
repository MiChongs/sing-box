package v2rayxhttp

import (
	"crypto/rand"
	"math"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// Placement 取值，对齐 Xray splithttp/common.go。
const (
	PlacementQueryInHeader = "queryInHeader"
	PlacementCookie        = "cookie"
	PlacementHeader        = "header"
	PlacementQuery         = "query"
	PlacementPath          = "path"
	PlacementBody          = "body"
	// PlacementAuto: 客户端等同 body；服务端从 header + cookie + body 三处拼接 payload。
	PlacementAuto = "auto"
)

// PaddingMethod 控制 padding 字符的生成方式 (Xray PR#5414)。
type PaddingMethod string

const (
	// PaddingMethodRepeatX: 重复 'X'。'X' 在 HPACK/QPACK 静态 huffman 表中是 8 bit，
	// 线上长度恒等于字符串长度。
	PaddingMethodRepeatX PaddingMethod = "repeat-x"
	// PaddingMethodTokenish: base62 随机串，按 huffman 编码后长度对齐目标值。
	PaddingMethodTokenish PaddingMethod = "tokenish"
)

const charsetBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Huffman encoding gives ~20% size reduction for base62 sequences
const avgHuffmanBytesPerCharBase62 = 0.8

const paddingValidationTolerance = 2

type XPaddingPlacement struct {
	Placement string
	Key       string
	Header    string
	RawURL    string
}

type XPaddingConfig struct {
	Length    int
	Placement XPaddingPlacement
	Method    PaddingMethod
}

func randStringFromCharset(n int, charset string) (string, bool) {
	if n <= 0 || len(charset) == 0 {
		return "", false
	}
	m := len(charset)
	limit := byte(256 - (256 % m))
	result := make([]byte, n)
	i := 0
	buffer := make([]byte, 256)
	for i < n {
		if _, err := rand.Read(buffer); err != nil {
			return "", false
		}
		for _, randomByte := range buffer {
			if randomByte >= limit {
				continue
			}
			result[i] = charset[int(randomByte)%m]
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

func generateTokenishPaddingBase62(targetHuffmanBytes int) string {
	n := int(math.Ceil(float64(targetHuffmanBytes) / avgHuffmanBytesPerCharBase62))
	if n < 1 {
		n = 1
	}
	randBase62Str, ok := randStringFromCharset(n, charsetBase62)
	if !ok {
		return ""
	}
	const maxIter = 150
	adjustChar := byte('X')
	for iter := 0; iter < maxIter; iter++ {
		diff := int(hpack.HuffmanEncodeLength(randBase62Str)) - targetHuffmanBytes
		if absInt(diff) <= paddingValidationTolerance {
			return randBase62Str
		}
		if diff < 0 {
			randBase62Str += string(adjustChar)
			// Avoid a long run of identical chars
			if adjustChar == 'X' {
				adjustChar = 'Z'
			} else {
				adjustChar = 'X'
			}
		} else {
			if len(randBase62Str) <= 1 {
				return randBase62Str
			}
			randBase62Str = randBase62Str[:len(randBase62Str)-1]
		}
	}
	return randBase62Str
}

func generatePaddingValue(method PaddingMethod, length int) string {
	if length <= 0 {
		return ""
	}
	if method == PaddingMethodTokenish {
		if paddingValue := generateTokenishPaddingBase62(length); paddingValue != "" {
			return paddingValue
		}
	}
	return strings.Repeat("X", length)
}

// applyXPaddingToHeader: header → 直接写值；queryInHeader → 写 "<RawURL 去掉 query>?<key>=<value>"。
func applyXPaddingToHeader(header http.Header, paddingConfig XPaddingConfig) {
	if header == nil {
		return
	}
	paddingValue := generatePaddingValue(paddingConfig.Method, paddingConfig.Length)
	switch placement := paddingConfig.Placement; placement.Placement {
	case PlacementHeader:
		header.Set(placement.Header, paddingValue)
	case PlacementQueryInHeader:
		parsedURL, err := url.Parse(placement.RawURL)
		if err != nil || parsedURL == nil {
			return
		}
		parsedURL.RawQuery = placement.Key + "=" + paddingValue
		header.Set(placement.Header, parsedURL.String())
	}
}

func applyXPaddingToRequest(request *http.Request, paddingConfig XPaddingConfig) {
	if request == nil {
		return
	}
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	placement := paddingConfig.Placement
	if placement.Placement == PlacementHeader || placement.Placement == PlacementQueryInHeader {
		applyXPaddingToHeader(request.Header, paddingConfig)
		return
	}
	paddingValue := generatePaddingValue(paddingConfig.Method, paddingConfig.Length)
	if placement.Key == "" || paddingValue == "" {
		return
	}
	switch placement.Placement {
	case PlacementCookie:
		request.AddCookie(&http.Cookie{Name: placement.Key, Value: paddingValue, Path: "/"})
	case PlacementQuery:
		query := request.URL.Query()
		query.Set(placement.Key, paddingValue)
		request.URL.RawQuery = query.Encode()
	}
}

func applyXPaddingToResponse(writer http.ResponseWriter, paddingConfig XPaddingConfig) {
	placement := paddingConfig.Placement
	if placement.Placement == PlacementHeader || placement.Placement == PlacementQueryInHeader {
		applyXPaddingToHeader(writer.Header(), paddingConfig)
		return
	}
	paddingValue := generatePaddingValue(paddingConfig.Method, paddingConfig.Length)
	if placement.Placement == PlacementCookie && placement.Key != "" && paddingValue != "" {
		http.SetCookie(writer, &http.Cookie{Name: placement.Key, Value: paddingValue, Path: "/"})
	}
}

// extractXPaddingFromRequest 对应 Xray Config.ExtractXPaddingFromRequest。
// 返回 (padding 值, 位置描述)；位置描述只用于日志。
func (c *config) extractXPaddingFromRequest(request *http.Request) (string, string) {
	if request == nil {
		return "", ""
	}
	if !c.xPaddingObfsMode {
		referrer := request.Header.Get("Referer")
		if referrer == "" {
			return request.URL.Query().Get(paddingQueryKey), PlacementQuery + ", key=" + paddingQueryKey
		}
		if referrerURL, err := url.Parse(referrer); err == nil {
			return referrerURL.Query().Get(paddingQueryKey), PlacementQueryInHeader + "=Referer, key=" + paddingQueryKey
		}
	}
	key := c.xPaddingKey
	header := c.xPaddingHeader
	if cookie, err := request.Cookie(key); err == nil && cookie != nil && cookie.Value != "" {
		return cookie.Value, PlacementCookie + ", key=" + key
	}
	if headerValue := request.Header.Get(header); headerValue != "" {
		if c.xPaddingPlacement == PlacementHeader {
			return headerValue, PlacementHeader + "=" + header
		}
		if parsedURL, err := url.Parse(headerValue); err == nil {
			return parsedURL.Query().Get(key), PlacementQueryInHeader + "=" + header + ", key=" + key
		}
	}
	if queryValue := request.URL.Query().Get(key); queryValue != "" {
		return queryValue, PlacementQuery + ", key=" + key
	}
	return "", ""
}

// isPaddingValid: repeat-x 校验字符串长度；tokenish 校验 huffman 编码后长度 (±2)。
func (c *config) isPaddingValid(paddingValue string) bool {
	if paddingValue == "" {
		return false
	}
	from, to := c.xPaddingBytes.From, c.xPaddingBytes.To
	if c.xPaddingMethod == PaddingMethodTokenish {
		n := int32(hpack.HuffmanEncodeLength(paddingValue))
		lower := max(from-paddingValidationTolerance, 0)
		return n >= lower && n <= to+paddingValidationTolerance
	}
	n := int32(len(paddingValue))
	return n >= from && n <= to
}
