package urltest

import (
	"bufio"
	"bytes"
	"net/http"
	"testing"
)

// TestDrainResponseMatcherPasses 用户显式 expected-status 允许 500
// （比如对 CDN 后端的"存在即活跃"健康探测），500 应被视为成功。
func TestDrainResponseMatcherPasses(t *testing.T) {
	matcher, err := ParseExpectedStatus("500")
	if err != nil {
		t.Fatal(err)
	}
	body := "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"
	req, _ := http.NewRequest(http.MethodHead, "http://x/y", nil)
	if err := drainResponse(bufio.NewReader(bytes.NewReader([]byte(body))), req, false, matcher); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

// TestDrainResponseMatcherRejects 同一响应，matcher 只认 200-299 → 应报错。
func TestDrainResponseMatcherRejects(t *testing.T) {
	matcher, err := ParseExpectedStatus("200-299")
	if err != nil {
		t.Fatal(err)
	}
	body := "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"
	req, _ := http.NewRequest(http.MethodHead, "http://x/y", nil)
	err = drainResponse(bufio.NewReader(bytes.NewReader([]byte(body))), req, false, matcher)
	if err == nil {
		t.Fatal("expected error for status 500 outside 200-299, got nil")
	}
}

// TestDrainResponseMatcherNilKeepsLegacy matcher=nil 时回退到旧启发式:
//   require204=true 且状态码非 204 → 报错（captive portal detect）
//   状态码 < 400 通过，>= 400 报错
func TestDrainResponseMatcherNilKeepsLegacy(t *testing.T) {
	// 200 OK: require204=true → 报错 (legacy captive portal check)
	body200 := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	req, _ := http.NewRequest(http.MethodHead, "http://x/y", nil)
	err := drainResponse(bufio.NewReader(bytes.NewReader([]byte(body200))), req, true, nil)
	if err == nil {
		t.Fatal("require204+200 should error (captive portal)")
	}

	// 204 OK: require204=true → 通过
	body204 := "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
	req2, _ := http.NewRequest(http.MethodHead, "http://x/y", nil)
	if err := drainResponse(bufio.NewReader(bytes.NewReader([]byte(body204))), req2, true, nil); err != nil {
		t.Fatalf("require204+204 should pass, got %v", err)
	}

	// 500 不 require204 但 >= 400 → 报错
	body500 := "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"
	req3, _ := http.NewRequest(http.MethodHead, "http://x/y", nil)
	if err := drainResponse(bufio.NewReader(bytes.NewReader([]byte(body500))), req3, false, nil); err == nil {
		t.Fatal("status 500 should error under legacy rules")
	}
}

// TestDrainResponseMatcherOverridesRequire204 matcher 非 nil 时，require204
// 的 captive-portal 启发式被 bypass，matcher 说了算。
func TestDrainResponseMatcherOverridesRequire204(t *testing.T) {
	// URL 是 generate_204 (require204=true)，但用户声明 expected-status=200
	// → 200 应该通过（matcher 说了算）
	matcher, err := ParseExpectedStatus("200")
	if err != nil {
		t.Fatal(err)
	}
	body := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	req, _ := http.NewRequest(http.MethodHead, "http://x/y", nil)
	if err := drainResponse(bufio.NewReader(bytes.NewReader([]byte(body))), req, true, matcher); err != nil {
		t.Fatalf("matcher=200 should override require204 for status 200, got %v", err)
	}
}
