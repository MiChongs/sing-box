package v2rayxhttp

import (
	"hash/fnv"
	"math"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// 浏览器伪装 header，对齐 Xray-core v26.9.30 common/utils/browser.go
// (utils.TryDefaultHeadersWith)。
//
// 版本号按发布节奏从日期外推，并叠加一个按机器稳定的随机偏移 (Xray 用 CPU
// 信息做种子)，同一台机器上 UA 保持稳定、不同机器之间自然分散。

func getRandomizer() *rand.Rand {
	hostname, _ := os.Hostname()
	fnvHash := fnv.New64()
	fnvHash.Write([]byte(hostname + runtime.GOOS + runtime.GOARCH + strconv.Itoa(runtime.NumCPU())))
	return rand.New(rand.NewSource(int64(fnvHash.Sum64())))
}

var globalRng = getRandomizer()

func daysSince(year int, month time.Month, day int) int64 {
	return time.Now().Unix()/86400 - time.Date(year, month, day, 0, 0, 0, 0, time.UTC).Unix()/86400
}

// chromeVersion: Chrome 144 发布于 2026-01-13，约 35 天一个大版本。
func chromeVersion() int {
	timeDiff := int(daysSince(2026, 1, 13)-35) - int(math.Floor(math.Pow(globalRng.Float64(), 2)*105))
	return 144 + timeDiff/35
}

// curlVersion: curl 8.0.0 发布于 2023-03-20，约 57 天一个小版本。
func curlVersion() string {
	timeDiff := int(daysSince(2023, 3, 20)-60) - int(math.Floor(math.Pow(globalRng.Float64(), 2)*165))
	return "8." + strconv.Itoa(timeDiff/57) + ".0"
}

func firefoxVersion() int {
	timeDiff := daysSince(2024, 7, 29) - 25 - int64(math.Floor(math.Pow(globalRng.Float64(), 2)*50))
	return int(timeDiff/30) + 128
}

var safariMinorMap = [25]int{
	0, 0, 0, 1, 1,
	1, 2, 2, 2, 2, 3, 3, 3, 4, 4,
	4, 5, 5, 5, 5, 5, 6, 6, 6, 6,
}

func safariVersion() string {
	anchoredTime := time.Now()
	releaseYear := anchoredTime.Year()
	delayedDays := int(math.Floor(math.Pow(globalRng.Float64(), 3) * 75))
	splitPoint := time.Date(releaseYear, 9, 23, 0, 0, 0, 0, time.UTC).AddDate(0, 0, delayedDays)
	if anchoredTime.Compare(splitPoint) < 0 {
		releaseYear--
		splitPoint = time.Date(releaseYear, 9, 23, 0, 0, 0, 0, time.UTC).AddDate(0, 0, delayedDays)
	}
	index := min(int((anchoredTime.Unix()-splitPoint.Unix())/1296000), len(safariMinorMap)-1)
	return strconv.Itoa(releaseYear-1999) + "." + strconv.Itoa(safariMinorMap[index])
}

// Chromium Sec-CH-UA GREASE
var (
	clientHintGreaseNA  = []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	clientHintVersionNA = []string{"8", "99", "24"}
	clientHintShuffle3  = [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	clientHintShuffle4  = [][4]int{
		{0, 1, 2, 3}, {0, 1, 3, 2}, {0, 2, 1, 3}, {0, 2, 3, 1}, {0, 3, 1, 2}, {0, 3, 2, 1},
		{1, 0, 2, 3}, {1, 0, 3, 2}, {1, 2, 0, 3}, {1, 2, 3, 0}, {1, 3, 0, 2}, {1, 3, 2, 0},
		{2, 0, 1, 3}, {2, 0, 3, 1}, {2, 1, 0, 3}, {2, 1, 3, 0}, {2, 3, 0, 1}, {2, 3, 1, 0},
		{3, 0, 1, 2}, {3, 0, 2, 1}, {3, 1, 0, 2}, {3, 1, 2, 0}, {3, 2, 0, 1}, {3, 2, 1, 0},
	}
)

func getGreasedChInvalidBrand(seed int) string {
	return `"Not` + clientHintGreaseNA[seed%len(clientHintGreaseNA)] + "A" +
		clientHintGreaseNA[(seed+1)%len(clientHintGreaseNA)] + `Brand";v="` +
		clientHintVersionNA[seed%len(clientHintVersionNA)] + `"`
}

func getGreasedChOrder(brandLength, seed int) []int {
	switch brandLength {
	case 1:
		return []int{0}
	case 2:
		return []int{seed % brandLength, (seed + 1) % brandLength}
	case 3:
		return clientHintShuffle3[seed%len(clientHintShuffle3)][:]
	default:
		return clientHintShuffle4[seed%len(clientHintShuffle4)][:]
	}
}

func getUngreasedChUa(majorVersion int, forkName string) []string {
	baseChUa := make([]string, 0, 4)
	baseChUa = append(baseChUa, getGreasedChInvalidBrand(majorVersion),
		`"Chromium";v="`+strconv.Itoa(majorVersion)+`"`)
	switch forkName {
	case "chrome":
		baseChUa = append(baseChUa, `"Google Chrome";v="`+strconv.Itoa(majorVersion)+`"`)
	case "edge":
		baseChUa = append(baseChUa, `"Microsoft Edge";v="`+strconv.Itoa(majorVersion)+`"`)
	}
	return baseChUa
}

func getGreasedChUa(majorVersion int, forkName string) string {
	ungreasedCh := getUngreasedChUa(majorVersion, forkName)
	shuffleMap := getGreasedChOrder(len(ungreasedCh), majorVersion)
	shuffledCh := make([]string, len(ungreasedCh))
	for i, e := range shuffleMap {
		shuffledCh[e] = ungreasedCh[i]
	}
	return strings.Join(shuffledCh, ", ")
}

var (
	curlUA                 = "curl/" + curlVersion()
	anchoredFirefoxVersion = strconv.Itoa(firefoxVersion())
	firefoxUA              = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + anchoredFirefoxVersion + ".0) Gecko/20100101 Firefox/" + anchoredFirefoxVersion + ".0"
	safariUA               = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + safariVersion() + " Safari/605.1.15"
	anchoredChromeVersion  = chromeVersion()
	chromeUA               = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(anchoredChromeVersion) + ".0.0.0 Safari/537.36"
	chromeUACH             = getGreasedChUa(anchoredChromeVersion, "chrome")
	// 真实 Edge UA 在 "Safari/537.36" 与 "Edg/" 之间有空格 (Xray 漏了这个空格)。
	msEdgeUA   = chromeUA + " Edg/" + strconv.Itoa(anchoredChromeVersion) + ".0.0.0"
	msEdgeUACH = getGreasedChUa(anchoredChromeVersion, "edge")
)

func applyMasqueradedHeaders(header http.Header, browser string, variant string) {
	// Browser-specific.
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
	case "safari":
		header.Set("User-Agent", safariUA)
		header.Set("Accept-Language", "en-US,en;q=0.9")
	case "golang":
		// Expose the default net/http header.
		header.Del("User-Agent")
		return
	case "curl":
		header.Set("User-Agent", curlUA)
		return
	}
	// Context-specific.
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
			case "firefox", "safari":
				header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			}
		}
		header.Set("Sec-Fetch-Site", "none")
		header.Set("Sec-Fetch-Mode", "navigate")
		if browser != "safari" {
			header.Set("Sec-Fetch-User", "?1")
		}
		header.Set("Sec-Fetch-Dest", "document")
		header.Set("Priority", "u=0, i")
	case "ws":
		header.Set("Sec-Fetch-Mode", "websocket")
		if browser == "safari" {
			// Safari is NOT web-compliant here!
			header.Set("Sec-Fetch-Dest", "websocket")
		} else {
			header.Set("Sec-Fetch-Dest", "empty")
		}
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
			case "safari":
				header.Set("Priority", "u=3, i")
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

// tryDefaultHeadersWith 对应 Xray utils.TryDefaultHeadersWith:
// 没有 User-Agent 时按 chrome 伪装；User-Agent 为 chrome / firefox / safari /
// edge / curl / golang 时套用对应集合；其他值视为字面 UA，不做改动。
func tryDefaultHeadersWith(header http.Header, variant string) {
	if len(header.Values("User-Agent")) < 1 {
		applyMasqueradedHeaders(header, "chrome", variant)
		return
	}
	switch userAgent := header.Get("User-Agent"); userAgent {
	case "chrome", "firefox", "safari", "edge", "curl", "golang":
		applyMasqueradedHeaders(header, userAgent, variant)
	}
}
