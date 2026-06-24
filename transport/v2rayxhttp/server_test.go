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
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestServer_ExtractMeta_Path 验证默认 path placement 下从 URL 解 session/seq。
func TestServer_ExtractMeta_Path(t *testing.T) {
	req := httptest.NewRequest("GET", "/base/sess123/5", nil)
	sessionId, seqStr := extractMetaFromRequest(req, "/base/", PlacementPath, "", PlacementPath, "")
	if sessionId != "sess123" {
		t.Errorf("sessionId=%q want sess123", sessionId)
	}
	if seqStr != "5" {
		t.Errorf("seqStr=%q want 5", seqStr)
	}
}

func TestServer_ExtractMeta_HeaderQuery(t *testing.T) {
	req := httptest.NewRequest("GET", "/base/", nil)
	req.Header.Set("X-Session", "abc")
	q := req.URL.Query()
	q.Set("page", "3")
	req.URL.RawQuery = q.Encode()
	sessionId, seqStr := extractMetaFromRequest(req, "/base/",
		PlacementHeader, "X-Session",
		PlacementQuery, "page")
	if sessionId != "abc" {
		t.Errorf("sessionId=%q want abc", sessionId)
	}
	if seqStr != "3" {
		t.Errorf("seqStr=%q want 3", seqStr)
	}
}

func TestServer_ExtractMeta_Cookie(t *testing.T) {
	req := httptest.NewRequest("GET", "/base/", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "cook-sess"})
	req.AddCookie(&http.Cookie{Name: "seq", Value: "7"})
	sessionId, seqStr := extractMetaFromRequest(req, "/base/",
		PlacementCookie, "sid",
		PlacementCookie, "seq")
	if sessionId != "cook-sess" {
		t.Errorf("sessionId=%q want cook-sess", sessionId)
	}
	if seqStr != "7" {
		t.Errorf("seqStr=%q want 7", seqStr)
	}
}

// TestServer_IsPaddingValid 验证两种 padding method 的校验。
func TestServer_IsPaddingValid_RepeatX(t *testing.T) {
	if !isPaddingValid(strings.Repeat("X", 100), 100, 1000, PaddingMethodRepeatX) {
		t.Error("100 X chars should be valid in [100,1000]")
	}
	if isPaddingValid(strings.Repeat("X", 50), 100, 1000, PaddingMethodRepeatX) {
		t.Error("50 X chars should NOT be valid in [100,1000]")
	}
	if isPaddingValid("", 100, 1000, PaddingMethodRepeatX) {
		t.Error("empty padding should NOT be valid")
	}
}

// TestServer_UploadQueue_Ordering 验证 uploadQueue 的 seq 重排。
func TestServer_UploadQueue_Ordering(t *testing.T) {
	q := newUploadQueue(30)

	// 乱序 push: seq 2, 0, 1
	_ = q.push(packet{payload: []byte("BB"), seq: 2})
	_ = q.push(packet{payload: []byte("AA"), seq: 0})
	_ = q.push(packet{payload: []byte("CC"), seq: 1})

	buf := make([]byte, 10)
	n, err := q.Read(buf)
	if err != nil || string(buf[:n]) != "AA" {
		t.Errorf("first read: n=%d err=%v data=%q want AA", n, err, buf[:n])
	}
	n, err = q.Read(buf)
	if err != nil || string(buf[:n]) != "CC" {
		t.Errorf("second read: n=%d err=%v data=%q want CC", n, err, buf[:n])
	}
	n, err = q.Read(buf)
	if err != nil || string(buf[:n]) != "BB" {
		t.Errorf("third read: n=%d err=%v data=%q want BB", n, err, buf[:n])
	}
}

// TestServer_UploadQueue_StreamUpReader 验证 stream-up 模式下 push reader 后
// Read 全部走 reader。
func TestServer_UploadQueue_StreamUpReader(t *testing.T) {
	q := newUploadQueue(30)
	rc := io.NopCloser(strings.NewReader("HELLO STREAM"))
	_ = q.push(packet{reader: rc})

	buf := make([]byte, 20)
	n, err := q.Read(buf)
	if err != nil {
		t.Fatalf("Read err=%v", err)
	}
	if string(buf[:n]) != "HELLO STREAM" {
		t.Errorf("data=%q want HELLO STREAM", buf[:n])
	}
}

// TestServer_ServeHTTP_BadHost 验证 host 校验。
func TestServer_ServeHTTP_BadHost(t *testing.T) {
	srv := mustNewTestServer(t, &option.V2RayXHTTPOptions{
		Path: "/x/",
		Host: []string{"expected.com"},
	})
	req := httptest.NewRequest("GET", "/x/session1", nil)
	req.Host = "wrong.com"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("bad host: status=%d want 404", w.Code)
	}
}

// TestServer_ServeHTTP_BadPath 验证 path 前缀校验。
func TestServer_ServeHTTP_BadPath(t *testing.T) {
	srv := mustNewTestServer(t, &option.V2RayXHTTPOptions{Path: "/x/"})
	req := httptest.NewRequest("GET", "/wrong/session1", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("bad path: status=%d want 404", w.Code)
	}
}

// TestServer_ServeHTTP_OPTIONS 验证 CORS preflight。
func TestServer_ServeHTTP_OPTIONS(t *testing.T) {
	srv := mustNewTestServer(t, &option.V2RayXHTTPOptions{Path: "/x/"})
	req := httptest.NewRequest("OPTIONS", "/x/session1", nil)
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("OPTIONS: status=%d want 200", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Methods") != "POST" {
		t.Errorf("ACAM=%q want POST", w.Header().Get("Access-Control-Allow-Methods"))
	}
}

// TestServer_ServeHTTP_PaddingRejection 验证 padding 缺失时返回 400。
func TestServer_ServeHTTP_PaddingRejection(t *testing.T) {
	srv := mustNewTestServer(t, &option.V2RayXHTTPOptions{Path: "/x/"})
	// GET base path (stream-one) 不带 padding → 应该被 reject
	req := httptest.NewRequest("GET", "/x/session1", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	// 默认 padding 100-1000, 没给 padding → 400
	if w.Code != http.StatusBadRequest {
		t.Errorf("no padding: status=%d want 400", w.Code)
	}
}

// TestServer_ServeHTTP_PaddingAccepted 验证带合法 padding 时不返回 400。
func TestServer_ServeHTTP_PaddingAccepted(t *testing.T) {
	srv := mustNewTestServer(t, &option.V2RayXHTTPOptions{Path: "/x/"})
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/x/session1", nil).WithContext(ctx)
	req.Header.Set("Referer", "https://example.com/x/?x_padding="+strings.Repeat("X", 200))
	w := httptest.NewRecorder()
	// 在另一个 goroutine 里跑，0.5s 后 cancel context 让 ServeHTTP 返回
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()
	srv.ServeHTTP(w, req)
	// padding 合法 → 进了 handleDownlink → 不该返回 400
	if w.Code == http.StatusBadRequest {
		t.Error("valid padding was rejected")
	}
}

// TestServer_DecodeChunkedPayload 验证从 header/cookie 拼接 base64 分片。
func TestServer_DecodeChunkedPayload(t *testing.T) {
	encoded := "SGVsbG8sIFdvcmxkIQ"
	chunk0 := encoded[:8]
	chunk1 := encoded[8:]

	data, err := decodeChunkedPayload(func(i int) string {
		switch i {
		case 0:
			return chunk0
		case 1:
			return chunk1
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "Hello, World!" {
		t.Errorf("decoded=%q want Hello, World!", data)
	}
}

// ── helpers ──

type testHandler struct {
	onConnect func(ctx context.Context, conn net.Conn, source M.Socksaddr, dest M.Socksaddr, onClose func())
}

func (h *testHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if h.onConnect != nil {
		// 在 goroutine 里 echo "HELLO" 然后保持连接
		go func() {
			conn.Write([]byte("HELLO"))
			time.Sleep(100 * time.Millisecond)
			conn.Close()
		}()
	}
}

func mustNewTestServer(t *testing.T, opts *option.V2RayXHTTPOptions) *Server {
	t.Helper()
	s, err := NewServer(context.Background(), &testLogger{t: t}, opts, nil, &testHandler{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s.(*Server)
}

type testLogger struct{ t *testing.T }

func (l *testLogger) TraceContext(_ context.Context, _ ...any)   {}
func (l *testLogger) DebugContext(_ context.Context, msg ...any) { l.t.Logf("DEBUG: %v", msg) }
func (l *testLogger) InfoContext(_ context.Context, _ ...any)    {}
func (l *testLogger) WarnContext(_ context.Context, msg ...any)  { l.t.Logf("WARN: %v", msg) }
func (l *testLogger) ErrorContext(_ context.Context, msg ...any) { l.t.Logf("ERR: %v", msg) }
func (l *testLogger) FatalContext(_ context.Context, msg ...any) { l.t.Fatalf("FATAL: %v", msg) }
func (l *testLogger) PanicContext(_ context.Context, msg ...any) { l.t.Fatalf("PANIC: %v", msg) }
func (l *testLogger) Trace(_ ...any)                              {}
func (l *testLogger) Debug(_ ...any)                              {}
func (l *testLogger) Info(_ ...any)                               {}
func (l *testLogger) Warn(_ ...any)                               {}
func (l *testLogger) Error(_ ...any)                              {}
func (l *testLogger) Fatal(_ ...any)                              {}
func (l *testLogger) Panic(_ ...any)                              {}
