package v2rayxhttp

import (
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 浏览器伪装实现 — 对齐 XTLS/Xray-core PR#5802。
//
// 三件套:
//  1. Chrome major version 用日期外推（避免编译期常量留指纹）
//  2. Sec-CH-UA 走 GREASE：随机 "Not?A?Brand" + Chromium + Google Chrome|Microsoft Edge，
//     三项顺序按 majorVersion 索引 shuffle 表打散
//  3. variant ("fetch" / "ws" / "nav") 决定 Sec-Fetch-* / Accept / Priority / Cache-Control
//     XHTTP 都用 "fetch"

// ── Chrome major version 外推 ──

// chromeMajorVersion 基准 Chrome 120 (2023-12-06)，每 ~4 周一个大版本。
func chromeMajorVersion() int {
	const baseline = 120
	const baselineTs = int64(1701820800) // 2023-12-06 UTC
	elapsed := time.Now().Unix() - baselineTs
	if elapsed <= 0 {
		return baseline
	}
	weeks := elapsed / (7 * 86400)
	return baseline + int(weeks/4)
}

// 浏览器 UA 字符串（CPU-seeded 通过 chromeMajorVersion 外推，全局共享）。
var (
	anchoredChromeVersion = chromeMajorVersion()
	chromeUA              = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" +
		strconv.Itoa(anchoredChromeVersion) + ".0.0.0 Safari/537.36"
	msEdgeUA = chromeUA + " Edg/" + strconv.Itoa(anchoredChromeVersion) + ".0.0.0"
	// 钉死在 ESR；uTLS 的 Firefox 指纹和这里要匹配，每个新 ESR 出来要手工更新。
	firefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"

	chromeUACH = getGreasedChUa(anchoredChromeVersion, "chrome")
	msEdgeUACH = getGreasedChUa(anchoredChromeVersion, "edge")
)

// ── GREASE：Sec-CH-UA 内的 "Not A Brand" + 顺序随机化 ──

var (
	greaseNA      = []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	greaseVerNA   = []string{"8", "99", "24"}
	greaseShuf3   = [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	greaseShuf4 = [][4]int{
		{0, 1, 2, 3}, {0, 1, 3, 2}, {0, 2, 1, 3}, {0, 2, 3, 1}, {0, 3, 1, 2}, {0, 3, 2, 1},
		{1, 0, 2, 3}, {1, 0, 3, 2}, {1, 2, 0, 3}, {1, 2, 3, 0}, {1, 3, 0, 2}, {1, 3, 2, 0},
		{2, 0, 1, 3}, {2, 0, 3, 1}, {2, 1, 0, 3}, {2, 1, 3, 0}, {2, 3, 0, 1}, {2, 3, 1, 0},
		{3, 0, 1, 2}, {3, 0, 2, 1}, {3, 1, 0, 2}, {3, 1, 2, 0}, {3, 2, 0, 1}, {3, 2, 1, 0},
	}
)

func getGreasedChInvalidBrand(seed int) string {
	return `"Not` + greaseNA[seed%len(greaseNA)] + "A" +
		greaseNA[(seed+1)%len(greaseNA)] + `Brand";v="` +
		greaseVerNA[seed%len(greaseVerNA)] + `"`
}

func getGreasedChOrder(brandLength, seed int) []int {
	switch brandLength {
	case 1:
		return []int{0}
	case 2:
		return []int{seed % 2, (seed + 1) % 2}
	case 3:
		s := greaseShuf3[seed%len(greaseShuf3)]
		return []int{s[0], s[1], s[2]}
	default:
		s := greaseShuf4[seed%len(greaseShuf4)]
		return []int{s[0], s[1], s[2], s[3]}
	}
}

// getUngreasedChUa 出 Sec-CH-UA 的原始品牌串（按 chrome / edge / chromium-only）。
func getUngreasedChUa(majorVersion int, fork string) []string {
	base := make([]string, 0, 4)
	base = append(base,
		getGreasedChInvalidBrand(majorVersion),
		`"Chromium";v="`+strconv.Itoa(majorVersion)+`"`)
	switch fork {
	case "chrome":
		base = append(base, `"Google Chrome";v="`+strconv.Itoa(majorVersion)+`"`)
	case "edge":
		base = append(base, `"Microsoft Edge";v="`+strconv.Itoa(majorVersion)+`"`)
	}
	return base
}

func getGreasedChUa(majorVersion int, fork string) string {
	un := getUngreasedChUa(majorVersion, fork)
	order := getGreasedChOrder(len(un), majorVersion)
	out := make([]string, len(un))
	for i, dst := range order {
		out[dst] = un[i]
	}
	return strings.Join(out, ", ")
}

// ── variant 适用：把浏览器 + 上下文专属的 header 套一遍 ──

// applyMasqueradedHeaders 按 browser 和 variant 把伪装 header 覆盖进去。
// browser 取值: "chrome" / "firefox" / "edge" / "golang"
// variant 取值: "nav" / "ws" / "fetch"
func applyMasqueradedHeaders(header http.Header, browser, variant string) {
	// 浏览器维度
	switch browser {
	case "chrome":
		header["Sec-CH-UA"] = []string{chromeUACH}
		header["Sec-CH-UA-Mobile"] = []string{"?0"}
		header["Sec-CH-UA-Platform"] = []string{`"Windows"`}
		header["DNT"] = []string{"1"}
		header.Set("User-Agent", chromeUA)
		header.Set("Accept-Language", "en-US,en;q=0.9")
	case "edge":
		header["Sec-CH-UA"] = []string{msEdgeUACH}
		header["Sec-CH-UA-Mobile"] = []string{"?0"}
		header["Sec-CH-UA-Platform"] = []string{`"Windows"`}
		header["DNT"] = []string{"1"}
		header.Set("User-Agent", msEdgeUA)
		header.Set("Accept-Language", "en-US,en;q=0.9")
	case "firefox":
		header.Set("User-Agent", firefoxUA)
		header["DNT"] = []string{"1"}
		header.Set("Accept-Language", "en-US,en;q=0.5")
	case "golang":
		// 暴露 net/http 默认 UA — 完全不伪装。
		header.Del("User-Agent")
		return
	}

	// variant 维度
	switch variant {
	case "nav":
		if header.Get("Cache-Control") == "" {
			switch browser {
			case "chrome", "edge":
				header.Set("Cache-Control", "max-age=0")
			}
		}
		header.Set("Upgrade-Insecure-Requests", "1")
		if header.Get("Accept") == "" {
			switch browser {
			case "chrome", "edge":
				header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
			case "firefox":
				header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			}
		}
		header.Set("Sec-Fetch-Site", "none")
		header.Set("Sec-Fetch-Mode", "navigate")
		header.Set("Sec-Fetch-User", "?1")
		header.Set("Sec-Fetch-Dest", "document")
		header.Set("Priority", "u=0, i")
	case "ws":
		header.Set("Sec-Fetch-Mode", "websocket")
		header.Set("Sec-Fetch-Dest", "empty")
		header.Set("Sec-Fetch-Site", "same-origin")
		if header.Get("Cache-Control") == "" {
			header.Set("Cache-Control", "no-cache")
		}
		if header.Get("Pragma") == "" {
			header.Set("Pragma", "no-cache")
		}
		if header.Get("Accept") == "" {
			header.Set("Accept", "*/*")
		}
	case "fetch":
		header.Set("Sec-Fetch-Mode", "cors")
		header.Set("Sec-Fetch-Dest", "empty")
		header.Set("Sec-Fetch-Site", "same-origin")
		if header.Get("Priority") == "" {
			switch browser {
			case "chrome", "edge":
				header.Set("Priority", "u=1, i")
			case "firefox":
				header.Set("Priority", "u=4")
			}
		}
		if header.Get("Cache-Control") == "" {
			header.Set("Cache-Control", "no-cache")
		}
		if header.Get("Pragma") == "" {
			header.Set("Pragma", "no-cache")
		}
		if header.Get("Accept") == "" {
			header.Set("Accept", "*/*")
		}
	}
}

// tryDefaultHeadersWith — 与 Xray 的 utils.TryDefaultHeadersWith 等价。
//
// 调用语义:
//   - header.Get("User-Agent") == "" → 默认走 chrome
//   - header.Get("User-Agent") ∈ {chrome,firefox,edge,golang} → 用该浏览器集合
//   - 其他（已被用户设置的真 UA 字符串）→ 不动 UA，也不补 Sec-CH-UA / Sec-Fetch-*
//
// XHTTP 全部调用都传 variant="fetch"。
func tryDefaultHeadersWith(header http.Header, variant string) {
	if len(header.Values("User-Agent")) < 1 {
		applyMasqueradedHeaders(header, "chrome", variant)
		return
	}
	switch header.Get("User-Agent") {
	case "chrome":
		applyMasqueradedHeaders(header, "chrome", variant)
	case "firefox":
		applyMasqueradedHeaders(header, "firefox", variant)
	case "edge":
		applyMasqueradedHeaders(header, "edge", variant)
	case "golang":
		applyMasqueradedHeaders(header, "golang", variant)
	}
}

// 注意: 这里不直接用 math/rand 全局；只在 V2 包内的非 padding 路径用，避免和
// crypto/rand 出来的 padding 字节产生指纹关联。
var _ = rand.Uint32
