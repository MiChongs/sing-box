package v2rayxhttp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"golang.org/x/net/http2/hpack"
)

func mustNewConfig(t *testing.T, options *option.V2RayXHTTPOptions) *config {
	t.Helper()
	c, err := newConfig(options)
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	return c
}

func TestPaddingMethodRepeatX(t *testing.T) {
	v := generatePaddingValue(PaddingMethodRepeatX, 128)
	if len(v) != 128 || strings.Trim(v, "X") != "" {
		t.Fatalf("repeat-x: got %q", v)
	}
}

func TestPaddingMethodTokenish(t *testing.T) {
	for _, target := range []int{50, 100, 500, 1000} {
		for i := 0; i < 20; i++ {
			v := generatePaddingValue(PaddingMethodTokenish, target)
			for _, c := range v {
				if !strings.ContainsRune(charsetBase62, c) {
					t.Fatalf("tokenish: invalid char %q", c)
				}
			}
			n := int(hpack.HuffmanEncodeLength(v))
			if n < target-paddingValidationTolerance || n > target+paddingValidationTolerance {
				t.Fatalf("tokenish: huffman length %d not within %d±%d", n, target, paddingValidationTolerance)
			}
		}
	}
}

func TestApplyXPaddingToRequest_QueryInHeader(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com/path/?a=b", nil)
	applyXPaddingToRequest(req, XPaddingConfig{
		Length: 50,
		Placement: XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    req.URL.String(),
		},
	})
	u, err := url.Parse(req.Header.Get("Referer"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/path/" || len(u.Query().Get("x_padding")) != 50 || u.Query().Get("a") != "" {
		t.Fatalf("Referer=%q", req.Header.Get("Referer"))
	}
}

func TestApplyXPaddingToRequest_Placements(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com/path?a=b", nil)
	applyXPaddingToRequest(req, XPaddingConfig{Length: 30, Placement: XPaddingPlacement{Placement: PlacementHeader, Header: "X-Cache"}})
	if len(req.Header.Get("X-Cache")) != 30 {
		t.Errorf("header: %q", req.Header.Get("X-Cache"))
	}
	applyXPaddingToRequest(req, XPaddingConfig{Length: 40, Placement: XPaddingPlacement{Placement: PlacementCookie, Key: "_dc"}})
	if cookie, err := req.Cookie("_dc"); err != nil || len(cookie.Value) != 40 {
		t.Errorf("cookie: %v %v", cookie, err)
	}
	applyXPaddingToRequest(req, XPaddingConfig{Length: 25, Placement: XPaddingPlacement{Placement: PlacementQuery, Key: "_t"}})
	if len(req.URL.Query().Get("_t")) != 25 || req.URL.Query().Get("a") != "b" {
		t.Errorf("query: %q", req.URL.RawQuery)
	}
}

func TestApplyXPaddingToResponse(t *testing.T) {
	recorder := httptest.NewRecorder()
	applyXPaddingToResponse(recorder, XPaddingConfig{Length: 20, Placement: XPaddingPlacement{Placement: PlacementHeader, Header: "X-Padding"}})
	if len(recorder.Header().Get("X-Padding")) != 20 {
		t.Errorf("header: %q", recorder.Header().Get("X-Padding"))
	}
	recorder = httptest.NewRecorder()
	applyXPaddingToResponse(recorder, XPaddingConfig{Length: 20, Placement: XPaddingPlacement{Placement: PlacementCookie, Key: "_p"}})
	if !strings.HasPrefix(recorder.Header().Get("Set-Cookie"), "_p=XXXXXXXXXXXXXXXXXXXX") {
		t.Errorf("cookie: %q", recorder.Header().Get("Set-Cookie"))
	}
	recorder = httptest.NewRecorder()
	applyXPaddingToResponse(recorder, XPaddingConfig{Length: 20, Placement: XPaddingPlacement{Placement: PlacementQueryInHeader, Key: "k", Header: "X-Ref"}})
	if recorder.Header().Get("X-Ref") != "?k="+strings.Repeat("X", 20) {
		t.Errorf("queryInHeader: %q", recorder.Header().Get("X-Ref"))
	}
}

func TestConfig_Defaults(t *testing.T) {
	c := mustNewConfig(t, &option.V2RayXHTTPOptions{Path: "/p"})
	if c.mode != ModeAuto ||
		c.path != "/p/" ||
		c.xPaddingObfsMode ||
		c.xPaddingKey != "x_padding" ||
		c.xPaddingHeader != "X-Padding" ||
		c.xPaddingPlacement != PlacementQueryInHeader ||
		c.xPaddingMethod != PaddingMethodRepeatX ||
		c.uplinkHTTPMethod != "POST" ||
		c.sessionPlacement != PlacementPath ||
		c.seqPlacement != PlacementPath ||
		c.uplinkDataPlacement != PlacementAuto ||
		c.uplinkDataKey != "X-Data" ||
		c.xPaddingBytes != (rangeConfig{100, 1000}) ||
		c.scMaxEachPostBytes != (rangeConfig{1000000, 1000000}) ||
		c.scMinPostsIntervalMs != (rangeConfig{30, 30}) ||
		c.scMaxBufferedPosts != 30 ||
		c.scStreamUpServerSecs != (rangeConfig{20, 80}) ||
		c.uplinkChunkSize != c.scMaxEachPostBytes ||
		c.serverMaxHeaderBytes != 8192 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if c.xmux.maxConnections != (rangeConfig{3, 3}) ||
		c.xmux.hMaxRequestTimes != (rangeConfig{600, 900}) ||
		c.xmux.hMaxReusableSecs != (rangeConfig{1800, 3000}) {
		t.Fatalf("unexpected xmux defaults: %+v", c.xmux)
	}
}

func TestConfig_PathAndQuery(t *testing.T) {
	c := mustNewConfig(t, &option.V2RayXHTTPOptions{Path: "xhttp?ed=2048&a=b"})
	if c.path != "/xhttp/" || c.query != "ed=2048&a=b" {
		t.Fatalf("path=%q query=%q", c.path, c.query)
	}
	// session 与 seq 都不在 path 时不补尾斜杠 (Xray GetNormalizedPath)
	c = mustNewConfig(t, &option.V2RayXHTTPOptions{Path: "/xhttp", SessionPlacement: "header", SeqPlacement: "query"})
	if c.path != "/xhttp" {
		t.Fatalf("path=%q", c.path)
	}
}

func TestConfig_AllObfsFields(t *testing.T) {
	c := mustNewConfig(t, &option.V2RayXHTTPOptions{
		Mode:                "packet-up",
		XPaddingObfsMode:    true,
		XPaddingPlacement:   PlacementCookie,
		XPaddingKey:         "_t",
		XPaddingMethod:      string(PaddingMethodTokenish),
		UplinkHTTPMethod:    "put",
		SessionPlacement:    PlacementCookie,
		SeqPlacement:        PlacementHeader,
		UplinkDataPlacement: PlacementCookie,
		UplinkChunkSize:     option.XHTTPRange{From: 2048, To: 2048},
	})
	if !c.xPaddingObfsMode || c.xPaddingMethod != PaddingMethodTokenish || c.uplinkHTTPMethod != "PUT" ||
		c.sessionKey != "x_session" || c.seqKey != "X-Seq" || c.uplinkDataKey != "x_data" ||
		c.uplinkChunkSize != (rangeConfig{2048, 2048}) {
		t.Fatalf("unexpected config: %+v", c)
	}
}

func TestConfig_Validation(t *testing.T) {
	for name, options := range map[string]option.V2RayXHTTPOptions{
		"bad mode":                    {Mode: "stream-down"},
		"GET needs packet-up":         {Mode: "stream-up", UplinkHTTPMethod: "GET"},
		"GET needs explicit mode":     {UplinkHTTPMethod: "GET"},
		"header data needs packet-up": {Mode: "auto", UplinkDataPlacement: "header"},
		"padding cannot be disabled":  {XPaddingBytes: option.XHTTPRange{From: 0, To: 100}},
		"host in headers":             {Headers: badoption.HTTPHeader{"Host": {"a.com"}}},
		"bad padding placement":       {XPaddingPlacement: "body"},
		"bad session placement":       {SessionPlacement: "body"},
		"xmux conflict":               {Xmux: &option.V2RayXHTTPXmuxOptions{MaxConnections: option.XHTTPRange{From: 1, To: 1}, MaxConcurrency: option.XHTTPRange{From: 1, To: 1}}},
		"session table too small":     {SessionIDTable: "hex", SessionIDLength: option.XHTTPRange{From: 4, To: 4}},
		"brutal without quic_up":      {QuicCongestion: "force-brutal"},
	} {
		options := options
		if _, err := newConfig(&options); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestConfig_UplinkChunkSize(t *testing.T) {
	c := mustNewConfig(t, &option.V2RayXHTTPOptions{Mode: "packet-up", UplinkDataPlacement: PlacementHeader})
	if c.uplinkChunkSize != (rangeConfig{3000, 4000}) {
		t.Errorf("header default=%+v", c.uplinkChunkSize)
	}
	c = mustNewConfig(t, &option.V2RayXHTTPOptions{Mode: "packet-up", UplinkDataPlacement: PlacementCookie})
	if c.uplinkChunkSize != (rangeConfig{2048, 3072}) {
		t.Errorf("cookie default=%+v", c.uplinkChunkSize)
	}
	c = mustNewConfig(t, &option.V2RayXHTTPOptions{Mode: "packet-up", UplinkDataPlacement: PlacementHeader, UplinkChunkSize: option.XHTTPRange{From: 10, To: 32}})
	if c.uplinkChunkSize != (rangeConfig{64, 64}) {
		t.Errorf("bumped=%+v", c.uplinkChunkSize)
	}
	for i := 0; i < 20; i++ {
		if r := (rangeConfig{100, 500}).rand(); r < 100 || r > 500 {
			t.Fatalf("rand=%d", r)
		}
	}
}

func TestConfig_GenerateSessionID(t *testing.T) {
	c := mustNewConfig(t, &option.V2RayXHTTPOptions{})
	if id := c.generateSessionID(); len(id) != 36 || strings.Count(id, "-") != 4 {
		t.Errorf("default session id should be a UUID, got %q", id)
	}
	c = mustNewConfig(t, &option.V2RayXHTTPOptions{SessionIDTable: "number", SessionIDLength: option.XHTTPRange{From: 12, To: 16}})
	for i := 0; i < 20; i++ {
		id := c.generateSessionID()
		if len(id) < 12 || len(id) > 16 || strings.Trim(id, "0123456789") != "" {
			t.Fatalf("session id %q", id)
		}
	}
}

func TestFillStreamRequest(t *testing.T) {
	c := mustNewConfig(t, &option.V2RayXHTTPOptions{Path: "/base?ed=1"})
	req, _ := http.NewRequest("POST", "https://example.com/base/?ed=1", strings.NewReader("x"))
	c.fillStreamRequest(req, "sess")
	if req.URL.Path != "/base/sess" || req.URL.RawQuery != "ed=1" {
		t.Errorf("url=%s", req.URL)
	}
	if req.Header.Get("Content-Type") != "application/grpc" {
		t.Errorf("Content-Type=%q", req.Header.Get("Content-Type"))
	}
	// Referer 取 session 写入之前的 URL，query 被替换为 x_padding
	referer, _ := url.Parse(req.Header.Get("Referer"))
	if referer.Path != "/base/" || len(referer.Query().Get("x_padding")) < 100 || referer.Query().Get("ed") != "" {
		t.Errorf("Referer=%q", req.Header.Get("Referer"))
	}

	c = mustNewConfig(t, &option.V2RayXHTTPOptions{NoGRPCHeader: true})
	req, _ = http.NewRequest("POST", "https://example.com/", strings.NewReader("x"))
	c.fillStreamRequest(req, "")
	if req.Header.Get("Content-Type") != "" {
		t.Errorf("no_grpc_header: Content-Type=%q", req.Header.Get("Content-Type"))
	}
}

func TestFillPacketRequest_Placements(t *testing.T) {
	payload := []byte(strings.Repeat("Hello, World! ", 14))
	for _, placement := range []string{PlacementHeader, PlacementCookie} {
		c := mustNewConfig(t, &option.V2RayXHTTPOptions{
			Mode:                "packet-up",
			UplinkDataPlacement: placement,
			UplinkChunkSize:     option.XHTTPRange{From: 64, To: 64},
			SessionPlacement:    PlacementHeader,
			SeqPlacement:        PlacementQuery,
		})
		req, _ := http.NewRequest("POST", "https://example.com/", nil)
		c.fillPacketRequest(req, "sess", "7", payload)
		if req.Body != nil {
			t.Errorf("%s: body should be empty", placement)
		}
		if req.Header.Get("X-Session") != "sess" || req.URL.Query().Get("x_seq") != "7" {
			t.Errorf("%s: meta lost: %v %s", placement, req.Header, req.URL)
		}
		// Xray 不发送 -Length / -Upstream 之类的额外字段
		if req.Header.Get("X-Data-Length") != "" || req.Header.Get("X-Data-Upstream") != "" {
			t.Errorf("%s: unexpected extra uplink fields", placement)
		}
		// 交给服务端解析，验证往返一致
		server := mustNewConfig(t, &option.V2RayXHTTPOptions{Mode: "packet-up", UplinkDataPlacement: placement})
		var decoded []byte
		var err error
		if placement == PlacementHeader {
			decoded, err = decodeChunkedPayload(func(i int) (string, bool) {
				chunk := req.Header.Get(server.uplinkDataKey + "-" + strconv.Itoa(i))
				if len(chunk) > 64 {
					t.Errorf("chunk %d too large: %d", i, len(chunk))
				}
				return chunk, chunk != ""
			})
		} else {
			decoded, err = decodeChunkedPayload(func(i int) (string, bool) {
				cookie, _ := req.Cookie(server.uplinkDataKey + "_" + strconv.Itoa(i))
				if cookie == nil {
					return "", false
				}
				return cookie.Value, true
			})
		}
		if err != nil || string(decoded) != string(payload) {
			t.Errorf("%s: decoded=%q err=%v", placement, decoded, err)
		}
	}
}

func TestApplyMetaToRequest(t *testing.T) {
	c := mustNewConfig(t, &option.V2RayXHTTPOptions{Path: "/base/"})
	req, _ := http.NewRequest("POST", "https://example.com/base/", nil)
	c.applyMetaToRequest(req, "sess123", "5")
	if req.URL.Path != "/base/sess123/5" {
		t.Fatalf("path=%q", req.URL.Path)
	}
	c = mustNewConfig(t, &option.V2RayXHTTPOptions{Path: "/base/", SessionPlacement: PlacementPath, SeqPlacement: PlacementHeader, SeqKey: "X-Page"})
	req, _ = http.NewRequest("POST", "https://example.com/base/", nil)
	c.applyMetaToRequest(req, "sess123", "5")
	if req.URL.Path != "/base/sess123" || req.Header.Get("X-Page") != "5" {
		t.Fatalf("path=%q header=%v", req.URL.Path, req.Header)
	}
}
