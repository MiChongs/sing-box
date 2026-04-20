package v2rayxhttp

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
)

// XHTTP 的 padding 机制：客户端在 URL query 加 x_padding=<随机 hex>，
// header X-Padding=<随机 hex>，服务端完全忽略（只是填字节对抗流量指纹）。
// 范围用 "min-max" 字符串配置，0 或 "0-0" 关闭。
// 默认范围来自 Xray-core v1.8.24+：100-1000。

const (
	defaultPaddingMin = 100
	defaultPaddingMax = 1000
)

type paddingRange struct {
	min int
	max int
}

// parsePaddingRange 解析配置字符串为范围。"100-1000" → (100, 1000)。
// "500" 视为 (500, 500)。"0" 或 "0-0" 或空 → 关闭（返回 (0, 0)）。
// 非法格式退回默认 (100, 1000)，不为此报错以保持向前兼容。
func parsePaddingRange(s string) paddingRange {
	s = strings.TrimSpace(s)
	if s == "" {
		return paddingRange{min: defaultPaddingMin, max: defaultPaddingMax}
	}
	if s == "0" || s == "0-0" {
		return paddingRange{}
	}
	if i := strings.IndexByte(s, '-'); i > 0 {
		lo, errLo := strconv.Atoi(strings.TrimSpace(s[:i]))
		hi, errHi := strconv.Atoi(strings.TrimSpace(s[i+1:]))
		if errLo == nil && errHi == nil && lo >= 0 && hi >= lo {
			return paddingRange{min: lo, max: hi}
		}
	} else {
		n, err := strconv.Atoi(s)
		if err == nil && n >= 0 {
			return paddingRange{min: n, max: n}
		}
	}
	return paddingRange{min: defaultPaddingMin, max: defaultPaddingMax}
}

// randomHex 生成 [min,max] 字节数的随机 hex 字符串。长度 0 时返回空串。
// 用 crypto/rand 避免弱随机让流量指纹重现可预测模式。
func (p paddingRange) randomHex() string {
	if p.max == 0 {
		return ""
	}
	// 均匀挑一个长度
	size := p.min
	if p.max > p.min {
		var buf [4]byte
		_, _ = rand.Read(buf[:])
		span := uint32(p.max - p.min + 1)
		size += int(uint32(buf[0])<<24|uint32(buf[1])<<16|uint32(buf[2])<<8|uint32(buf[3])) % int(span)
		if size < 0 {
			size = -size
		}
	}
	if size == 0 {
		return ""
	}
	raw := make([]byte, size)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)[:size]
}
