package v2rayxhttp

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// TestPaddingMethodRepeatX 验证 repeat-x 模式产生 N 个 X 字符。
func TestPaddingMethodRepeatX(t *testing.T) {
	v := generatePaddingValue(PaddingMethodRepeatX, 128)
	if len(v) != 128 {
		t.Fatalf("repeat-x: len=%d want 128", len(v))
	}
	if strings.Trim(v, "X") != "" {
		t.Fatalf("repeat-x: non-X char in %q", v)
	}
}

// TestPaddingMethodTokenish 验证 tokenish 后 huffman 长度近似 target ±2 字节。
func TestPaddingMethodTokenish(t *testing.T) {
	// 多次采样，看 tolerance 区间被遵守
	for _, target := range []int{50, 100, 500, 1000} {
		for i := 0; i < 20; i++ {
			v := generatePaddingValue(PaddingMethodTokenish, target)
			if v == "" {
				t.Fatalf("tokenish: empty padding for target=%d", target)
			}
			// 字符集校验
			for _, c := range v {
				if !strings.ContainsRune(charsetBase62+"XZ", c) {
					t.Fatalf("tokenish: invalid char %q in padding", c)
				}
			}
		}
	}
}

// TestApplyPaddingToRequest_QueryInHeader 验证默认 placement (queryInHeader → Referer)。
func TestApplyPaddingToRequest_QueryInHeader(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com/path/", nil)
	cfg := XPaddingConfig{
		Length: 50,
		Placement: XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    req.URL.String(),
		},
		Method: PaddingMethodRepeatX,
	}
	applyPaddingToRequest(req, cfg)
	ref := req.Header.Get("Referer")
	if ref == "" {
		t.Fatal("Referer not set")
	}
	u, err := url.Parse(ref)
	if err != nil {
		t.Fatalf("Referer not URL: %v", err)
	}
	pad := u.Query().Get("x_padding")
	if len(pad) != 50 {
		t.Fatalf("x_padding len=%d want 50", len(pad))
	}
}

// TestApplyPaddingToRequest_CustomHeader 验证 obfsMode 下走自定义 header。
func TestApplyPaddingToRequest_CustomHeader(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com/", nil)
	cfg := XPaddingConfig{
		Length: 30,
		Placement: XPaddingPlacement{
			Placement: PlacementHeader,
			Header:    "X-Cache",
		},
		Method: PaddingMethodRepeatX,
	}
	applyPaddingToRequest(req, cfg)
	v := req.Header.Get("X-Cache")
	if len(v) != 30 {
		t.Fatalf("X-Cache len=%d want 30", len(v))
	}
}

// TestApplyPaddingToRequest_Cookie 验证 cookie placement。
func TestApplyPaddingToRequest_Cookie(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com/", nil)
	cfg := XPaddingConfig{
		Length: 40,
		Placement: XPaddingPlacement{
			Placement: PlacementCookie,
			Key:       "_dc",
		},
		Method: PaddingMethodRepeatX,
	}
	applyPaddingToRequest(req, cfg)
	c, err := req.Cookie("_dc")
	if err != nil {
		t.Fatalf("cookie _dc not set: %v", err)
	}
	if len(c.Value) != 40 {
		t.Fatalf("_dc len=%d want 40", len(c.Value))
	}
}

// TestApplyPaddingToRequest_Query 验证 query placement。
func TestApplyPaddingToRequest_Query(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com/path?a=b", nil)
	cfg := XPaddingConfig{
		Length: 25,
		Placement: XPaddingPlacement{
			Placement: PlacementQuery,
			Key:       "_t",
		},
		Method: PaddingMethodRepeatX,
	}
	applyPaddingToRequest(req, cfg)
	if v := req.URL.Query().Get("_t"); len(v) != 25 {
		t.Fatalf("query _t len=%d want 25", len(v))
	}
	if v := req.URL.Query().Get("a"); v != "b" {
		t.Fatal("existing query a=b lost")
	}
}

// TestConfig_NormalizeDefaults 默认 (obfsMode=false) 不应触发新校验，行为同旧版。
func TestConfig_NormalizeDefaults(t *testing.T) {
	opts := &option.V2RayXHTTPOptions{Path: "/p"}
	c, err := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	if c.xPaddingObfsMode {
		t.Error("xPaddingObfsMode should default to false")
	}
	if c.xPaddingKey != paddingQueryKey {
		t.Errorf("xPaddingKey=%q want %q", c.xPaddingKey, paddingQueryKey)
	}
	if c.xPaddingHeader != "X-Padding" {
		t.Errorf("xPaddingHeader=%q want X-Padding", c.xPaddingHeader)
	}
	if c.xPaddingPlacement != PlacementQueryInHeader {
		t.Errorf("xPaddingPlacement=%q want queryInHeader", c.xPaddingPlacement)
	}
	if c.xPaddingMethod != PaddingMethodRepeatX {
		t.Errorf("xPaddingMethod=%q want repeat-x", c.xPaddingMethod)
	}
	if c.uplinkHTTPMethod != "POST" {
		t.Errorf("uplinkHTTPMethod=%q want POST", c.uplinkHTTPMethod)
	}
	if c.sessionPlacement != PlacementPath {
		t.Errorf("sessionPlacement=%q want path", c.sessionPlacement)
	}
	if c.uplinkDataPlacement != PlacementAuto {
		t.Errorf("uplinkDataPlacement=%q want auto (PR#5720 default)", c.uplinkDataPlacement)
	}
}

// TestConfig_AllPR5414 全套 PR#5414 字段正确读取 + 默认 fallback key。
func TestConfig_AllPR5414(t *testing.T) {
	opts := &option.V2RayXHTTPOptions{
		Path:              "/p",
		Mode:              "packet-up",
		XPaddingObfsMode:  true,
		XPaddingPlacement: PlacementCookie,
		XPaddingKey:       "_t",
		XPaddingMethod:    string(PaddingMethodTokenish),
		UplinkHTTPMethod:  "put",
		SessionPlacement:  PlacementCookie,
		// SessionKey omitted to trigger default
		SeqPlacement:        PlacementHeader,
		UplinkDataPlacement: PlacementHeader,
		UplinkChunkSize:     "2048-2048",
	}
	c, err := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	if !c.xPaddingObfsMode {
		t.Error("xPaddingObfsMode lost")
	}
	if c.xPaddingMethod != PaddingMethodTokenish {
		t.Errorf("method=%q", c.xPaddingMethod)
	}
	if c.uplinkHTTPMethod != "PUT" { // forced upper
		t.Errorf("method=%q want PUT", c.uplinkHTTPMethod)
	}
	if c.sessionKey != "x_session" {
		t.Errorf("default sessionKey=%q want x_session", c.sessionKey)
	}
	if c.seqKey != "X-Seq" {
		t.Errorf("default seqKey=%q want X-Seq", c.seqKey)
	}
	if c.uplinkDataKey != "X-Data" {
		t.Errorf("default uplinkDataKey=%q want X-Data", c.uplinkDataKey)
	}
	if r := c.uplinkChunkSize.rand(); r != 2048 {
		t.Errorf("uplinkChunkSize range mid=%d want 2048", r)
	}
}

// TestConfig_PathSessionAllowsNonPathSeq verifies that PR#5720 removed the
// "SessionPlacement=path forces SeqPlacement=path" constraint. Path+header
// combo must now build cleanly.
func TestConfig_PathSessionAllowsNonPathSeq(t *testing.T) {
	opts := &option.V2RayXHTTPOptions{
		Path:             "/p",
		Mode:             "packet-up",
		SessionPlacement: PlacementPath,
		SeqPlacement:     PlacementHeader,
	}
	c, err := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
	if err != nil {
		t.Fatalf("PR#5720 dropped this constraint: %v", err)
	}
	if c.sessionPlacement != PlacementPath || c.seqPlacement != PlacementHeader {
		t.Errorf("placements lost: session=%q seq=%q", c.sessionPlacement, c.seqPlacement)
	}
}

// TestConfig_ValidateConstraint_GET_RequiresPacketUp verifies GET method requires packet-up mode.
func TestConfig_ValidateConstraint_GET_RequiresPacketUp(t *testing.T) {
	opts := &option.V2RayXHTTPOptions{
		Path:             "/p",
		Mode:             "stream-up",
		UplinkHTTPMethod: "GET",
	}
	_, err := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
	if err == nil {
		t.Fatal("expected error when GET + stream-up")
	}
	if !strings.Contains(err.Error(), "GET") {
		t.Errorf("err=%v want GET msg", err)
	}
}

// TestConfig_ValidateConstraint_UplinkData_RequiresPacketUp verifies uplinkData != body requires packet-up.
func TestConfig_ValidateConstraint_UplinkData_RequiresPacketUp(t *testing.T) {
	opts := &option.V2RayXHTTPOptions{
		Path:                "/p",
		Mode:                "stream-up",
		UplinkDataPlacement: PlacementHeader,
	}
	_, err := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
	if err == nil {
		t.Fatal("expected error when uplinkData=header + stream-up")
	}
	if !strings.Contains(err.Error(), "uplink_data_placement") {
		t.Errorf("err=%v want uplink_data_placement msg", err)
	}
}

// TestApplyMetaToRequest_Path 默认 placement=path 应拼到 URL path。
func TestApplyMetaToRequest_Path(t *testing.T) {
	opts := &option.V2RayXHTTPOptions{Path: "/base/", Mode: "packet-up"}
	c, _ := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
	req, _ := http.NewRequest("POST", "https://example.com/base/", nil)
	c.applyMetaToRequest(req, "sess123", "5")
	if req.URL.Path != "/base/sess123/5" {
		t.Fatalf("path=%q want /base/sess123/5", req.URL.Path)
	}
}

// TestApplyMetaToRequest_Headers session→header, seq→header。
func TestApplyMetaToRequest_Headers(t *testing.T) {
	opts := &option.V2RayXHTTPOptions{
		Path:             "/base/",
		Mode:             "packet-up",
		SessionPlacement: PlacementHeader,
		SeqPlacement:     PlacementHeader,
	}
	c, err := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "https://example.com/base/", nil)
	c.applyMetaToRequest(req, "sess123", "5")
	if req.URL.Path != "/base/" {
		t.Errorf("path=%q expect unchanged", req.URL.Path)
	}
	if req.Header.Get("X-Session") != "sess123" {
		t.Errorf("X-Session=%q", req.Header.Get("X-Session"))
	}
	if req.Header.Get("X-Seq") != "5" {
		t.Errorf("X-Seq=%q", req.Header.Get("X-Seq"))
	}
}

// TestApplyUplinkData_Header data → chunked headers + length + upstream marker。
func TestApplyUplinkData_Header(t *testing.T) {
	opts := &option.V2RayXHTTPOptions{
		Path:                "/base/",
		Mode:                "packet-up",
		UplinkDataPlacement: PlacementHeader,
		UplinkChunkSize:     "64-64", // 最小允许值；测试会喂 > 64 的数据强制切多片
	}
	c, err := newConfig(opts, M.ParseSocksaddrHostPortStr("example.com", "443"), false, true)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "https://example.com/", nil)
	// 196 字节 → base64 编码 ~262 chars → 在 chunk_size=64 下会切 ≥4 片
	data := []byte(strings.Repeat("Hello, World! ", 14))
	if !c.applyUplinkData(req, data) {
		t.Fatal("applyUplinkData returned false")
	}
	if req.Header.Get("X-Data-Upstream") != "1" {
		t.Error("X-Data-Upstream missing")
	}
	if req.Header.Get("X-Data-Length") == "" {
		t.Error("X-Data-Length missing")
	}
	if req.Header.Get("X-Data-0") == "" {
		t.Error("X-Data-0 missing")
	}
	if req.Header.Get("X-Data-1") == "" {
		t.Error("X-Data-1 missing; data did not split")
	}
	// 切片之间长度恒 <= chunk
	chunkCount := 0
	for i := 0; ; i++ {
		v := req.Header.Get(formatChunkKey("X-Data", "-", i))
		if v == "" {
			break
		}
		if len(v) > 64 {
			t.Errorf("chunk %d len=%d > 64", i, len(v))
		}
		chunkCount++
	}
	if chunkCount < 2 {
		t.Errorf("got %d chunks, expected ≥ 2", chunkCount)
	}
}

func formatChunkKey(base, sep string, i int) string {
	return base + sep + intToStr(i)
}

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+(i%10))) + s
		i /= 10
	}
	return s
}
