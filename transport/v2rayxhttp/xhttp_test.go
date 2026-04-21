package v2rayxhttp_test

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayxhttp"
)

// TestXHTTPOptionParsing 验证 option registry 注册 + "type":"xhttp" JSON 路由
// 仍然能把 V2RayTransportOptions 正确解码到 *V2RayXHTTPOptions。
// (server 行为验证以前靠 httptest.NewServer(srv) 直接驱动，但新 server 是
// 一个 "return 501" 的 stub — 真正 server 端移植 Xray/mihomo 完整实现之前
// 不做端到端握手测试，避免测到错误的行为被锁死。)
func TestXHTTPOptionParsing(t *testing.T) {
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
