package v2rayxhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestServer_ExtractMeta(t *testing.T) {
	c := mustNewConfig(t, &option.V2RayXHTTPOptions{Path: "/base"})
	req := httptest.NewRequest("GET", "/base/sess123/5", nil)
	if sessionId, seqStr := c.extractMetaFromRequest(req, c.path); sessionId != "sess123" || seqStr != "5" {
		t.Errorf("path: %q %q", sessionId, seqStr)
	}
	req = httptest.NewRequest("GET", "/base/", nil)
	if sessionId, seqStr := c.extractMetaFromRequest(req, c.path); sessionId != "" || seqStr != "" {
		t.Errorf("stream-one: %q %q", sessionId, seqStr)
	}

	c = mustNewConfig(t, &option.V2RayXHTTPOptions{Path: "/base/", SessionPlacement: "header", SeqPlacement: "query", SeqKey: "page"})
	req = httptest.NewRequest("GET", "/base/?page=3", nil)
	req.Header.Set("X-Session", "abc")
	if sessionId, seqStr := c.extractMetaFromRequest(req, c.path); sessionId != "abc" || seqStr != "3" {
		t.Errorf("header/query: %q %q", sessionId, seqStr)
	}

	c = mustNewConfig(t, &option.V2RayXHTTPOptions{Path: "/base/", SessionPlacement: "cookie", SessionKey: "sid", SeqPlacement: "cookie", SeqKey: "seq"})
	req = httptest.NewRequest("GET", "/base/", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "cook-sess"})
	req.AddCookie(&http.Cookie{Name: "seq", Value: "7"})
	if sessionId, seqStr := c.extractMetaFromRequest(req, c.path); sessionId != "cook-sess" || seqStr != "7" {
		t.Errorf("cookie: %q %q", sessionId, seqStr)
	}
}

func TestServer_IsPaddingValid(t *testing.T) {
	c := mustNewConfig(t, &option.V2RayXHTTPOptions{})
	if !c.isPaddingValid(strings.Repeat("X", 100)) || c.isPaddingValid(strings.Repeat("X", 50)) || c.isPaddingValid("") {
		t.Error("repeat-x validation")
	}
	c = mustNewConfig(t, &option.V2RayXHTTPOptions{XPaddingMethod: "tokenish"})
	if !c.isPaddingValid(generatePaddingValue(PaddingMethodTokenish, 500)) {
		t.Error("tokenish validation")
	}
}

func TestServer_UploadQueue_Ordering(t *testing.T) {
	q := newUploadQueue(30)
	_ = q.push(packet{payload: []byte("BB"), seq: 2})
	_ = q.push(packet{payload: []byte("AAAA"), seq: 0})
	_ = q.push(packet{payload: []byte("A"), seq: 0}) // 重复 seq 被丢弃
	_ = q.push(packet{payload: []byte("CC"), seq: 1})
	var result []byte
	buf := make([]byte, 3)
	for len(result) < 8 {
		n, err := q.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, buf[:n]...)
	}
	if string(result) != "AAAACCBB" {
		t.Errorf("got %q", result)
	}
	_ = q.Close()
	if _, err := q.Read(buf); err != io.EOF {
		t.Errorf("read after close: %v", err)
	}
	if err := q.push(packet{payload: []byte("x"), seq: 3}); err == nil {
		t.Error("push after close should fail")
	}
}

func TestServer_UploadQueue_PushDoesNotDeadlockWhenFull(t *testing.T) {
	q := newUploadQueue(1)
	_ = q.push(packet{payload: []byte("a"), seq: 5})
	done := make(chan error, 1)
	go func() { done <- q.push(packet{payload: []byte("b"), seq: 6}) }()
	time.Sleep(50 * time.Millisecond)
	_ = q.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Error("blocked push should fail after close")
		}
	case <-time.After(time.Second):
		t.Fatal("push still blocked after Close")
	}
}

func TestServer_UploadQueue_StreamUpReader(t *testing.T) {
	q := newUploadQueue(30)
	reader := newHTTPServerConn(strings.NewReader("HELLO STREAM"), httptest.NewRecorder())
	if err := q.push(packet{reader: reader}); err != nil {
		t.Fatal(err)
	}
	if err := q.push(packet{reader: reader}); err == nil {
		t.Error("second reader should be rejected")
	}
	data, err := io.ReadAll(q)
	if err != nil || string(data) != "HELLO STREAM" {
		t.Errorf("data=%q err=%v", data, err)
	}
}

func TestServer_DecodeChunkedPayload(t *testing.T) {
	chunks := []string{"SGVsbG8s", "IFdvcmxkIQ"}
	data, err := decodeChunkedPayload(func(i int) (string, bool) {
		if i < len(chunks) {
			return chunks[i], true
		}
		return "", false
	})
	if err != nil || string(data) != "Hello, World!" {
		t.Errorf("decoded=%q err=%v", data, err)
	}
}

func validReferer() string {
	return "https://example.com/x/?x_padding=" + strings.Repeat("X", 200)
}

func serve(server *Server, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(request.Context(), 300*time.Millisecond)
	defer cancel()
	server.ServeHTTP(recorder, request.WithContext(ctx))
	return recorder
}

func TestServer_ServeHTTP_HostPathOptions(t *testing.T) {
	server := mustNewTestServer(t, &option.V2RayXHTTPOptions{Path: "/x/", Host: []string{"a.com", "B.com"}})
	req := httptest.NewRequest("GET", "/x/session1", nil)
	req.Host = "wrong.com"
	if code := serve(server, req).Code; code != http.StatusNotFound {
		t.Errorf("bad host: %d", code)
	}
	req = httptest.NewRequest("GET", "/wrong/session1", nil)
	req.Host = "a.com"
	if code := serve(server, req).Code; code != http.StatusNotFound {
		t.Errorf("bad path: %d", code)
	}
	req = httptest.NewRequest("OPTIONS", "/x/session1", nil)
	req.Host = "b.com:8443"
	req.Header.Set("Access-Control-Request-Method", "POST")
	recorder := serve(server, req)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Access-Control-Allow-Methods") != "POST" || recorder.Header().Get("X-Padding") == "" {
		t.Errorf("OPTIONS: %d %v", recorder.Code, recorder.Header())
	}
}

func TestServer_ServeHTTP_Padding(t *testing.T) {
	server := mustNewTestServer(t, &option.V2RayXHTTPOptions{Path: "/x/"})
	if code := serve(server, httptest.NewRequest("GET", "/x/session1", nil)).Code; code != http.StatusBadRequest {
		t.Errorf("no padding: %d", code)
	}
	req := httptest.NewRequest("GET", "/x/session1", nil)
	req.Header.Set("Referer", validReferer())
	if code := serve(server, req).Code; code != http.StatusOK {
		t.Errorf("valid padding: %d", code)
	}
}

// 回归: 服务端 mode 曾被规范化成 packet-up，默认配置下 stream-up 上行被 400。
func TestServer_ServeHTTP_AutoAcceptsAllModes(t *testing.T) {
	server := mustNewTestServer(t, &option.V2RayXHTTPOptions{Path: "/x/"})
	// stream-up 上行
	req := httptest.NewRequest("POST", "/x/session-up", strings.NewReader("data"))
	req.Header.Set("Referer", validReferer())
	if code := serve(server, req).Code; code != http.StatusOK {
		t.Errorf("stream-up: %d", code)
	}
	// packet-up 上行，且上行方法不必与服务端 uplink_http_method 相同 (Xray 接受任意非 GET 方法)
	req = httptest.NewRequest("PUT", "/x/session-packet/0", strings.NewReader("data"))
	req.Header.Set("Referer", validReferer())
	if code := serve(server, req).Code; code != http.StatusOK {
		t.Errorf("packet-up PUT: %d", code)
	}
}

func TestServer_ServeHTTP_ModeRestrictions(t *testing.T) {
	server := mustNewTestServer(t, &option.V2RayXHTTPOptions{Path: "/x/", Mode: "packet-up"})
	req := httptest.NewRequest("POST", "/x/session", strings.NewReader("data"))
	req.Header.Set("Referer", validReferer())
	if code := serve(server, req).Code; code != http.StatusBadRequest {
		t.Errorf("stream-up on packet-up server: %d", code)
	}
	req = httptest.NewRequest("POST", "/x/", strings.NewReader("data"))
	req.Header.Set("Referer", validReferer())
	if code := serve(server, req).Code; code != http.StatusBadRequest {
		t.Errorf("stream-one on packet-up server: %d", code)
	}
	server = mustNewTestServer(t, &option.V2RayXHTTPOptions{Path: "/x/", Mode: "stream-up"})
	req = httptest.NewRequest("POST", "/x/session/0", strings.NewReader("data"))
	req.Header.Set("Referer", validReferer())
	if code := serve(server, req).Code; code != http.StatusBadRequest {
		t.Errorf("packet-up on stream-up server: %d", code)
	}
}

func TestServer_ServeHTTP_TooLarge(t *testing.T) {
	server := mustNewTestServer(t, &option.V2RayXHTTPOptions{Path: "/x/", ScMaxEachPostBytes: option.XHTTPRange{From: 10, To: 10}})
	req := httptest.NewRequest("POST", "/x/session/0", strings.NewReader(strings.Repeat("a", 11)))
	req.Header.Set("Referer", validReferer())
	if code := serve(server, req).Code; code != http.StatusRequestEntityTooLarge {
		t.Errorf("too large: %d", code)
	}
}

func TestServer_ServeHTTP_NoSSEHeader(t *testing.T) {
	for _, noSSEHeader := range []bool{false, true} {
		server := mustNewTestServer(t, &option.V2RayXHTTPOptions{Path: "/x/", NoSSEHeader: noSSEHeader})
		req := httptest.NewRequest("GET", "/x/session", nil)
		req.Header.Set("Referer", validReferer())
		recorder := serve(server, req)
		if (recorder.Header().Get("Content-Type") == contentTypeSSE) == noSSEHeader {
			t.Errorf("no_sse_header=%v: Content-Type=%q", noSSEHeader, recorder.Header().Get("Content-Type"))
		}
		if recorder.Header().Get("X-Accel-Buffering") != "no" || recorder.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("missing anti-buffering headers: %v", recorder.Header())
		}
	}
}

// ── helpers ──

type echoHandler struct{}

func (echoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		_, err := io.Copy(conn, conn)
		_ = conn.Close()
		onClose(err)
	}()
}

func mustNewTestServer(t *testing.T, options *option.V2RayXHTTPOptions) *Server {
	t.Helper()
	server, err := NewServer(context.Background(), logger.NOP(), options, nil, echoHandler{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server.(*Server)
}
