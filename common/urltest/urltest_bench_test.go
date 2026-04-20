package urltest

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkDrainResponse_HEAD204 模拟 generate_204 场景，验证热路径分配量
func BenchmarkDrainResponse_HEAD204(b *testing.B) {
	raw := "HTTP/1.1 204 No Content\r\n" +
		"Content-Length: 0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"Date: Mon, 01 Jan 2026 00:00:00 GMT\r\n" +
		"Server: gws\r\n" +
		"X-Content-Type-Options: nosniff\r\n" +
		"\r\n"
	req, _ := http.NewRequest(http.MethodHead, "https://www.gstatic.com/generate_204", nil)
	reader := bufio.NewReaderSize(nil, bufioSize)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(strings.NewReader(raw))
		if err := drainResponse(reader, req, false, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDrainResponse_HEADWithBody 违规 HEAD+body 的防御路径
func BenchmarkDrainResponse_HEADWithBody(b *testing.B) {
	body := strings.Repeat("x", 512)
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 512\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" + body
	req, _ := http.NewRequest(http.MethodHead, "https://example.com/", nil)
	reader := bufio.NewReaderSize(nil, bufioSize)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader.Reset(strings.NewReader(raw))
		if err := drainResponse(reader, req, false, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkIsGenerate204 verifies the captive-portal detection
// check stays O(1) and alloc-free. Called once per probe on the
// hot path — regressions here multiply across every probe.
func BenchmarkIsGenerate204(b *testing.B) {
	u, _ := url.Parse("https://www.gstatic.com/generate_204")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = isGenerate204(u)
	}
}

// BenchmarkReaderPool 验证 bufio.Reader 池稳态零分配
func BenchmarkReaderPool(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := readerPool.Get().(*bufio.Reader)
		r.Reset(nil)
		readerPool.Put(r)
	}
}

// TestDrainResponse_NoBodyRead 验证 204 响应不会越界读取
func TestDrainResponse_NoBodyRead(t *testing.T) {
	raw := "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\nLEFTOVER"
	req, _ := http.NewRequest(http.MethodHead, "http://x/", nil)
	reader := bufio.NewReader(strings.NewReader(raw))
	if err := drainResponse(reader, req, false, nil); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(reader)
	if string(rest) != "LEFTOVER" {
		t.Fatalf("leftover mismatch: got %q", rest)
	}
}

// TestDrainResponse_HEADResidualDrain 验证违规 HEAD+body 被完整 drain
func TestDrainResponse_HEADResidualDrain(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLOTAIL"
	req, _ := http.NewRequest(http.MethodHead, "http://x/", nil)
	reader := bufio.NewReader(strings.NewReader(raw))
	if err := drainResponse(reader, req, false, nil); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(reader)
	if string(rest) != "TAIL" {
		t.Fatalf("residual not drained; got %q", rest)
	}
}

// TestDrainResponse_BodyTooLarge 验证内存屏障
func TestDrainResponse_BodyTooLarge(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n"
	req, _ := http.NewRequest(http.MethodHead, "http://x/", nil)
	reader := bufio.NewReader(strings.NewReader(raw))
	if err := drainResponse(reader, req, false, nil); err != errBodyTooLarge {
		t.Fatalf("expected errBodyTooLarge, got %v", err)
	}
}

// TestDrainResponse_4xx 验证错误状态传播
func TestDrainResponse_4xx(t *testing.T) {
	raw := "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
	req, _ := http.NewRequest(http.MethodHead, "http://x/", nil)
	reader := bufio.NewReader(strings.NewReader(raw))
	err := drainResponse(reader, req, false, nil)
	if err == nil {
		t.Fatal("expected error for 4xx")
	}
	if hs, ok := err.(*httpStatusError); !ok || hs.code != 404 {
		t.Fatalf("expected HTTP 404 status error, got %v", err)
	}
}

// ════════════════ measureRequest 测试 ════════════════

// mockConn 模拟可控的 net.Conn，用于测试 first-byte RTT 测量
type mockConn struct {
	net.Conn
	writeBuf   []byte
	readSrc    io.Reader
	writeDelay time.Duration // 模拟 Write 之后 first-byte 到达的延迟
	writeErr   error
	readErr    error
	// timing 记录
	writeTime atomic.Pointer[time.Time]
}

func newMockConn(response string, rtt time.Duration) *mockConn {
	return &mockConn{
		readSrc:    strings.NewReader(response),
		writeDelay: rtt,
	}
}

func (c *mockConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writeBuf = append(c.writeBuf, p...)
	t := time.Now()
	c.writeTime.Store(&t)
	return len(p), nil
}

func (c *mockConn) Read(p []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	// 首次 Read 前等待模拟的 RTT
	if wt := c.writeTime.Load(); wt != nil && c.writeDelay > 0 {
		elapsed := time.Since(*wt)
		if elapsed < c.writeDelay {
			time.Sleep(c.writeDelay - elapsed)
		}
	}
	return c.readSrc.Read(p)
}

func (c *mockConn) Close() error                       { return nil }
func (c *mockConn) LocalAddr() net.Addr                { return nil }
func (c *mockConn) RemoteAddr() net.Addr               { return nil }
func (c *mockConn) SetDeadline(t time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// farDeadline is a timestamp safely past any test's wall-clock RTT,
// so the Peek deadline doesn't interfere with the intended behaviour.
func farDeadline() time.Time { return time.Now().Add(10 * time.Second) }

// TestMeasureRequest_FirstByteRTT 验证 first-byte 计时精度
func TestMeasureRequest_FirstByteRTT(t *testing.T) {
	resp := "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
	mc := newMockConn(resp, 50*time.Millisecond)
	reader := bufio.NewReader(mc)
	req, _ := http.NewRequest(http.MethodHead, "http://x/", nil)

	rtt, err := measureRequest(mc, reader, []byte("HEAD / HTTP/1.1\r\n\r\n"), req, farDeadline(), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 允许 ±20ms 抖动容差
	if rtt < 40*time.Millisecond || rtt > 100*time.Millisecond {
		t.Fatalf("RTT out of range: %v (expected ~50ms)", rtt)
	}
}

// TestMeasureRequest_WriteError 验证写错误传播
func TestMeasureRequest_WriteError(t *testing.T) {
	mc := &mockConn{writeErr: io.ErrUnexpectedEOF}
	reader := bufio.NewReader(strings.NewReader(""))
	req, _ := http.NewRequest(http.MethodHead, "http://x/", nil)

	_, err := measureRequest(mc, reader, []byte("HEAD / HTTP/1.1\r\n\r\n"), req, farDeadline(), false, nil)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("expected write error, got %v", err)
	}
}

// TestMeasureRequest_ResponseError 验证响应错误时仍返回已测 RTT
func TestMeasureRequest_ResponseError(t *testing.T) {
	resp := "HTTP/1.1 500 Server Error\r\nContent-Length: 0\r\n\r\n"
	mc := newMockConn(resp, 30*time.Millisecond)
	reader := bufio.NewReader(mc)
	req, _ := http.NewRequest(http.MethodHead, "http://x/", nil)

	rtt, err := measureRequest(mc, reader, []byte("HEAD / HTTP/1.1\r\n\r\n"), req, farDeadline(), false, nil)
	if err == nil {
		t.Fatal("expected error for 5xx")
	}
	// 即使响应错，RTT 应已测得
	if rtt < 20*time.Millisecond {
		t.Fatalf("RTT should be measured even on response error, got %v", rtt)
	}
}

// BenchmarkMeasureRequest 验证热路径分配
func BenchmarkMeasureRequest(b *testing.B) {
	resp := "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
	req, _ := http.NewRequest(http.MethodHead, "http://x/", nil)
	reqBytes := []byte("HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	reader := bufio.NewReaderSize(nil, bufioSize)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mc := &mockConn{readSrc: strings.NewReader(resp)}
		reader.Reset(mc)
		if _, err := measureRequest(mc, reader, reqBytes, req, farDeadline(), false, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// TestIsGenerate204 pin-points the captive-portal-detection criteria.
// The previous contains-based check false-positived on IPs / paths
// that merely contained "204" as a substring; the new check should
// only accept canonical generate_204 / gen_204 paths.
func TestIsGenerate204(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://www.gstatic.com/generate_204", true},
		{"https://clients3.google.com/generate_204", true},
		{"http://connectivitycheck.gstatic.com/generate_204", true},
		{"https://www.google.com/gen_204", true},
		{"https://cdn.example.com/api/v1/generate_204", true},  // suffix match
		// Previously false-positive cases — must return false now.
		{"http://204.1.2.3/", false},
		{"https://example.com/docs/204-error", false},
		{"https://204foo.example.com/", false},
		{"https://example.com/?redirect=generate_204", false}, // query not path
		{"", false},
	}
	for _, c := range cases {
		u, _ := url.Parse(c.url)
		if got := isGenerate204(u); got != c.want {
			t.Errorf("isGenerate204(%q) = %v, want %v", c.url, got, c.want)
		}
	}
	// nil URL must not panic.
	if isGenerate204(nil) {
		t.Fatal("isGenerate204(nil) must be false")
	}
}

// TestIsHEADRejected validates the HEAD→GET fallback trigger: only
// a 405 status error from our own httpStatusError type counts.
// Transport errors (nil / write error / generic error) must not
// trigger the fallback — the conn is unusable for a second try.
func TestIsHEADRejected(t *testing.T) {
	if isHEADRejected(nil) {
		t.Fatal("nil error should not trigger GET fallback")
	}
	if isHEADRejected(io.ErrUnexpectedEOF) {
		t.Fatal("transport error should not trigger GET fallback")
	}
	if !isHEADRejected(&httpStatusError{code: 405}) {
		t.Fatal("405 should trigger GET fallback")
	}
	if isHEADRejected(&httpStatusError{code: 500}) {
		t.Fatal("500 should NOT trigger GET fallback (conn may be bad)")
	}
	if isHEADRejected(&httpStatusError{code: 404}) {
		t.Fatal("404 should NOT trigger GET fallback")
	}
}

// TestSessionCacheFor_SameHost covers the session-cache hot path:
// repeated lookups for the same hostname hit the cached instance;
// distinct hosts get distinct caches. This is what enables
// back-to-back TLS-resume on probe bursts.
func TestSessionCacheFor_SameHost(t *testing.T) {
	a1 := sessionCacheFor("www.gstatic.com")
	a2 := sessionCacheFor("www.gstatic.com")
	if a1 != a2 {
		t.Fatal("sessionCacheFor should reuse per-host cache instance")
	}
	b := sessionCacheFor("cp.cloudflare.com")
	if a1 == b {
		t.Fatal("different hosts must get distinct session caches")
	}
}
