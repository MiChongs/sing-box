package v2rayxhttp

import (
	"net/http"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
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

func TestConfig_UserAgent_ValidValues(t *testing.T) {
	for _, ua := range []string{"", "chrome", "firefox", "edge", "golang"} {
		t.Run("ua="+ua, func(t *testing.T) {
			opts := &option.V2RayXHTTPOptions{Path: "/p", UserAgent: ua}
			c, err := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
			if err != nil {
				t.Fatalf("newConfig %q: %v", ua, err)
			}
			if c.userAgent != ua {
				t.Errorf("c.userAgent=%q want %q", c.userAgent, ua)
			}
		})
	}
}

func TestConfig_UserAgent_InvalidValue(t *testing.T) {
	opts := &option.V2RayXHTTPOptions{Path: "/p", UserAgent: "safari"}
	_, err := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
	if err == nil {
		t.Fatal("expected error for unsupported user_agent")
	}
	if !strings.Contains(err.Error(), "user_agent") {
		t.Errorf("err=%v want user_agent msg", err)
	}
}

func TestConfig_FillRequest_Firefox(t *testing.T) {
	opts := &option.V2RayXHTTPOptions{Path: "/p", UserAgent: "firefox"}
	c, err := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "https://example.com/p/", nil)
	c.fillRequest(req, "example.com", "", "")
	if !strings.Contains(req.Header.Get("User-Agent"), "Firefox/") {
		t.Errorf("Firefox UA not propagated to req: %q", req.Header.Get("User-Agent"))
	}
	if req.Header["Sec-CH-UA"] != nil {
		t.Error("Firefox shouldn't have Sec-CH-UA")
	}
}

// PR#5720 — UplinkDataPlacement="auto" 在客户端等同 body（applyUplinkData 返回 false）。
func TestConfig_UplinkData_AutoBehavesAsBody(t *testing.T) {
	opts := &option.V2RayXHTTPOptions{
		Path:                "/p",
		Mode:                "packet-up",
		UplinkDataPlacement: PlacementAuto,
	}
	c, err := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.uplinkDataPlacement != PlacementAuto {
		t.Errorf("placement=%q want auto", c.uplinkDataPlacement)
	}
	req, _ := http.NewRequest("POST", "https://example.com/", nil)
	if c.applyUplinkData(req, []byte("hello world")) {
		t.Error("applyUplinkData on auto must return false (data stays in body)")
	}
}

// PR#5720 — UplinkChunkSize 是 range，每次切片大小在区间里抽。
func TestConfig_UplinkChunkSize_Range(t *testing.T) {
	opts := &option.V2RayXHTTPOptions{
		Path:                "/p",
		Mode:                "packet-up",
		UplinkDataPlacement: PlacementHeader,
		UplinkChunkSize:     "100-500",
	}
	c, err := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.uplinkChunkSize.Min != 100 || c.uplinkChunkSize.Max != 500 {
		t.Errorf("uplinkChunkSize=%+v want {100,500}", c.uplinkChunkSize)
	}
	// rand 多次落在 [100,500]
	for i := 0; i < 20; i++ {
		r := c.uplinkChunkSize.rand()
		if r < 100 || r > 500 {
			t.Errorf("rand=%d out of [100,500]", r)
		}
	}
}

// PR#5720 — From < 64 时强制提到 64。
func TestConfig_UplinkChunkSize_BumpsBelow64(t *testing.T) {
	opts := &option.V2RayXHTTPOptions{
		Path:                "/p",
		Mode:                "packet-up",
		UplinkDataPlacement: PlacementHeader,
		UplinkChunkSize:     "10-32",
	}
	c, err := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.uplinkChunkSize.Min < 64 {
		t.Errorf("Min=%d should be bumped to ≥64", c.uplinkChunkSize.Min)
	}
}
