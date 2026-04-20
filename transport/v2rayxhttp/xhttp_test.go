package v2rayxhttp_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayxhttp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// echoHandler: v2ray handler 实现，对每条连接把收到的字节原封不动回写。
// 仅用于路由 / 校验测试，未做 goroutine 同步，测结束会 leak echo goroutine
// —— 测试通过 httptest.Server.Close 和 srv.Close 回收；handler goroutine
// 对 pipe 的 Read 会在 pipe close 时解除阻塞。
type echoHandler struct {
	wg sync.WaitGroup
}

func (h *echoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		defer conn.Close()
		defer func() {
			if onClose != nil {
				onClose(nil)
			}
		}()
		_, _ = io.Copy(conn, conn)
	}()
}

func (h *echoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
}

// setupServer 启动一个 XHTTP Server（不带 TLS），挂在 httptest.NewServer 上。
// 返回 URL 基地址 + teardown 清理函数。
func setupServer(t *testing.T) (*url.URL, func()) {
	t.Helper()
	h := &echoHandler{}
	logger := log.NewNOPFactory().NewLogger("xhttp-test")
	srv, err := v2rayxhttp.NewServer(context.Background(), logger, &option.V2RayXHTTPOptions{
		Path: "/x",
	}, nil, h)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	parsed, _ := url.Parse(ts.URL)
	return parsed, func() {
		ts.Close()
		_ = srv.Close()
	}
}

// TestServerBadPath: path 前缀不匹配时应该 404。
func TestServerBadPath(t *testing.T) {
	u, teardown := setupServer(t)
	defer teardown()
	resp, err := http.Get(u.String() + "/notx/abc")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expect 404, got %s", resp.Status)
	}
}

// TestServerMissingSessionID: path 对但缺 session id 段应 404。
func TestServerMissingSessionID(t *testing.T) {
	u, teardown := setupServer(t)
	defer teardown()
	resp, err := http.Get(u.String() + "/x/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expect 404, got %s", resp.Status)
	}
}

// TestServerBadHost: 配置了白名单 host 但请求 Host 不在列表 → 400。
func TestServerBadHost(t *testing.T) {
	t.Helper()
	h := &echoHandler{}
	logger := log.NewNOPFactory().NewLogger("xhttp-test")
	srv, err := v2rayxhttp.NewServer(context.Background(), logger, &option.V2RayXHTTPOptions{
		Path: "/x",
		Host: []string{"allowed.example.com"},
	}, nil, h)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	defer srv.Close()

	// httptest server 的默认 Host header 是 127.0.0.1:port，不在白名单
	resp, err := http.Get(ts.URL + "/x/abc")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expect 400, got %s", resp.Status)
	}
}

// TestPaddingParsing: option 解析 + V2RayTransportOptions 的 xhttp type 路由。
// 直接走 JSON -> option 解析链，验证 plugin registry 注册生效。
func TestXHTTPOptionParsing(t *testing.T) {
	// 触发 RegisterPlugin，让 option registry 知道 "xhttp" 类型
	// 注意：include/xhttp.go 在 with_xhttp build tag 下才注册；测试环境没有
	// 这个 tag，我们手动调用以模拟 include 路径被导入的效果。
	v2rayxhttp.RegisterPlugin()

	input := `{
		"type": "xhttp",
		"path": "/abcd",
		"mode": "packet-up",
		"no_sse_header": true,
		"x_padding_bytes": "100-1000",
		"sc_max_each_post_bytes": 8192,
		"sc_min_posts_interval_ms": 10
	}`
	var o option.V2RayTransportOptions
	if err := o.UnmarshalJSON([]byte(input)); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if o.Type != "xhttp" {
		t.Fatalf("type=%q, want xhttp", o.Type)
	}
	extra, ok := o.Extra.(*option.V2RayXHTTPOptions)
	if !ok {
		t.Fatalf("extra=%T, want *V2RayXHTTPOptions", o.Extra)
	}
	if extra.Path != "/abcd" {
		t.Errorf("path=%q, want /abcd", extra.Path)
	}
	if extra.Mode != "packet-up" {
		t.Errorf("mode=%q", extra.Mode)
	}
	if !extra.NoSSEHeader {
		t.Errorf("no_sse_header not parsed")
	}
	if extra.ScMaxEachPostBytes != 8192 {
		t.Errorf("sc_max_each_post_bytes=%d", extra.ScMaxEachPostBytes)
	}
	if !strings.Contains(extra.XPaddingBytes, "-") {
		t.Errorf("x_padding_bytes=%q", extra.XPaddingBytes)
	}
}
