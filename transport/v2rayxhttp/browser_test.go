package v2rayxhttp

import (
	"net/http"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// 浏览器伪装测试 — 对齐 XTLS/Xray-core PR#5802。

func TestMasquerade_Chrome_FetchVariant(t *testing.T) {
	h := http.Header{}
	tryDefaultHeadersWith(h, "fetch")
	if !strings.Contains(h.Get("User-Agent"), "Chrome/") {
		t.Errorf("Chrome UA missing: %q", h.Get("User-Agent"))
	}
	// Sec-CH-UA 是直接 map 写入（保留原始 case，匹配真实 Chrome），
	// canonicalized 的 Header.Get() 不会命中，必须用直接索引。
	ch := h["Sec-CH-UA"]
	if len(ch) == 0 {
		t.Error("Sec-CH-UA missing for chrome")
	} else if !strings.Contains(ch[0], `"Google Chrome"`) {
		t.Errorf("Sec-CH-UA must contain Google Chrome brand: %q", ch[0])
	}
	if h["Sec-CH-UA-Platform"] == nil || h["Sec-CH-UA-Platform"][0] != `"Windows"` {
		t.Errorf("Sec-CH-UA-Platform=%v", h["Sec-CH-UA-Platform"])
	}
	if h.Get("Sec-Fetch-Mode") != "cors" {
		t.Errorf("Sec-Fetch-Mode=%q want cors", h.Get("Sec-Fetch-Mode"))
	}
	if h.Get("Sec-Fetch-Dest") != "empty" {
		t.Errorf("Sec-Fetch-Dest=%q want empty", h.Get("Sec-Fetch-Dest"))
	}
	if h.Get("Sec-Fetch-Site") != "same-origin" {
		t.Errorf("Sec-Fetch-Site=%q want same-origin", h.Get("Sec-Fetch-Site"))
	}
	if h.Get("Priority") != "u=1, i" {
		t.Errorf("Priority=%q want u=1, i", h.Get("Priority"))
	}
	if h.Get("Accept-Language") != "en-US,en;q=0.9" {
		t.Errorf("Accept-Language=%q", h.Get("Accept-Language"))
	}
}

func TestMasquerade_Firefox(t *testing.T) {
	h := http.Header{}
	h.Set("User-Agent", "firefox")
	tryDefaultHeadersWith(h, "fetch")
	if !strings.Contains(h.Get("User-Agent"), "Firefox/") {
		t.Errorf("Firefox UA missing: %q", h.Get("User-Agent"))
	}
	if h["Sec-CH-UA"] != nil {
		t.Error("Sec-CH-UA must NOT be set for firefox (not a chromium fork)")
	}
	if h.Get("Accept-Language") != "en-US,en;q=0.5" {
		t.Errorf("Firefox Accept-Language=%q want en-US,en;q=0.5", h.Get("Accept-Language"))
	}
	if h.Get("Priority") != "u=4" {
		t.Errorf("Firefox Priority=%q want u=4", h.Get("Priority"))
	}
	if h["DNT"] == nil || h["DNT"][0] != "1" {
		t.Error("DNT=1 missing for firefox")
	}
}

func TestMasquerade_Edge(t *testing.T) {
	h := http.Header{}
	h.Set("User-Agent", "edge")
	tryDefaultHeadersWith(h, "fetch")
	if !strings.Contains(h.Get("User-Agent"), "Edg/") {
		t.Errorf("Edge UA missing 'Edg/': %q", h.Get("User-Agent"))
	}
	ce := h["Sec-CH-UA"]
	if len(ce) == 0 || !strings.Contains(ce[0], `"Microsoft Edge"`) {
		t.Errorf("Sec-CH-UA must contain Microsoft Edge brand: %v", ce)
	}
}

func TestMasquerade_Golang_StripsUA(t *testing.T) {
	h := http.Header{}
	h.Set("User-Agent", "golang")
	tryDefaultHeadersWith(h, "fetch")
	if h.Get("User-Agent") != "" {
		t.Errorf("Golang mode should strip UA; got %q", h.Get("User-Agent"))
	}
	if h.Get("Sec-CH-UA") != "" {
		t.Error("Golang mode should not add Sec-CH-UA")
	}
	if h.Get("Sec-Fetch-Mode") != "" {
		t.Error("Golang mode should not add Sec-Fetch-*")
	}
}

func TestMasquerade_GreasedChUaContainsNotABrand(t *testing.T) {
	// Sec-CH-UA 三个槽位之一一定是 "Not?A?Brand" 形式 (GREASE)
	h := http.Header{}
	tryDefaultHeadersWith(h, "fetch")
	vals := h["Sec-CH-UA"]
	if len(vals) == 0 {
		t.Fatal("Sec-CH-UA absent")
	}
	if !strings.Contains(vals[0], "Not") {
		t.Errorf("Sec-CH-UA missing GREASE 'Not...A...Brand': %q", vals[0])
	}
}

func TestMasquerade_CustomUA_NoSecChUaOverride(t *testing.T) {
	h := http.Header{}
	h.Set("User-Agent", "Mozilla/5.0 (My Custom Bot)")
	tryDefaultHeadersWith(h, "fetch")
	if h.Get("User-Agent") != "Mozilla/5.0 (My Custom Bot)" {
		t.Errorf("user's UA overwritten: %q", h.Get("User-Agent"))
	}
	// 未知 UA 时不补 Sec-CH-UA / Sec-Fetch-*
	if h["Sec-CH-UA"] != nil {
		t.Errorf("Sec-CH-UA should be skipped for unknown UA: %v", h["Sec-CH-UA"])
	}
}

func TestMasquerade_NavVariant_HasUpgradeInsecureRequests(t *testing.T) {
	h := http.Header{}
	tryDefaultHeadersWith(h, "nav")
	if h.Get("Upgrade-Insecure-Requests") != "1" {
		t.Errorf("nav variant should set Upgrade-Insecure-Requests")
	}
	if h.Get("Sec-Fetch-Mode") != "navigate" {
		t.Errorf("nav variant Sec-Fetch-Mode=%q want navigate", h.Get("Sec-Fetch-Mode"))
	}
	if h.Get("Sec-Fetch-Dest") != "document" {
		t.Errorf("nav variant Sec-Fetch-Dest=%q want document", h.Get("Sec-Fetch-Dest"))
	}
}

func TestMasquerade_WsVariant(t *testing.T) {
	h := http.Header{}
	tryDefaultHeadersWith(h, "ws")
	if h.Get("Sec-Fetch-Mode") != "websocket" {
		t.Errorf("ws variant Sec-Fetch-Mode=%q want websocket", h.Get("Sec-Fetch-Mode"))
	}
}

func TestMasquerade_SafariAndCurl(t *testing.T) {
	h := http.Header{}
	h.Set("User-Agent", "safari")
	tryDefaultHeadersWith(h, "fetch")
	if !strings.Contains(h.Get("User-Agent"), "Safari/605.1.15") || h.Get("Priority") != "u=3, i" || h["Sec-CH-UA"] != nil {
		t.Errorf("safari headers: %v", h)
	}
	h = http.Header{}
	h.Set("User-Agent", "curl")
	tryDefaultHeadersWith(h, "fetch")
	if !strings.HasPrefix(h.Get("User-Agent"), "curl/8.") || h.Get("Sec-Fetch-Mode") != "" {
		t.Errorf("curl headers: %v", h)
	}
}

func TestMasquerade_VersionsAreCurrent(t *testing.T) {
	// Chrome 144 发布于 2026-01-13；外推出来的版本不能比它旧。
	if anchoredChromeVersion < 144 {
		t.Errorf("chrome version %d is outdated", anchoredChromeVersion)
	}
	if !strings.Contains(msEdgeUA, "Safari/537.36 Edg/") {
		t.Errorf("edge UA %q", msEdgeUA)
	}
}

func TestConfig_UserAgent(t *testing.T) {
	for _, userAgent := range []string{"chrome", "firefox", "safari", "edge", "curl", "golang", "MyAgent/1.0"} {
		c := mustNewConfig(t, &option.V2RayXHTTPOptions{UserAgent: userAgent})
		header := c.requestHeader()
		switch userAgent {
		case "golang":
			if header.Get("User-Agent") != "" {
				t.Errorf("golang: UA=%q", header.Get("User-Agent"))
			}
		case "MyAgent/1.0":
			if header.Get("User-Agent") != userAgent || header["Sec-CH-UA"] != nil {
				t.Errorf("literal UA: %v", header)
			}
		default:
			if header.Get("User-Agent") == userAgent || header.Get("User-Agent") == "" {
				t.Errorf("%s: UA not expanded: %q", userAgent, header.Get("User-Agent"))
			}
		}
	}
	// headers 里显式写的 User-Agent 优先于 user_agent
	c := mustNewConfig(t, &option.V2RayXHTTPOptions{UserAgent: "chrome", Headers: badoption.HTTPHeader{"User-Agent": {"firefox"}}})
	if !strings.Contains(c.requestHeader().Get("User-Agent"), "Firefox/") {
		t.Errorf("headers User-Agent should win: %q", c.requestHeader().Get("User-Agent"))
	}
}
