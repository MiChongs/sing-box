package parser_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/provider/parser"
	"github.com/sagernet/sing-box/transport/v2rayxhttp"

	"gopkg.in/yaml.v3"
)

func stdB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// 链接格式 XHTTP 解析 —— VLESS / VMess / Trojan 三种协议

func TestVLESSLinkXHTTP(t *testing.T) {
	// vless://uuid@host:443?security=tls&type=xhttp&path=/xyz&host=a.com&mode=packet-up#tag
	link := "vless://11111111-1111-1111-1111-111111111111@example.com:443?" +
		"encryption=none&security=tls&type=xhttp&path=%2Fxyz&host=a.com&mode=packet-up#mytag"
	out, err := parser.ParseSubscriptionLink(link)
	if err != nil {
		t.Fatalf("parse vless: %v", err)
	}
	if out.Type != "vless" {
		t.Fatalf("type=%q want vless", out.Type)
	}
	opts, ok := out.Options.(*option.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("options=%T", out.Options)
	}
	if opts.Transport == nil || opts.Transport.Type != "xhttp" {
		t.Fatalf("transport=%+v, want xhttp", opts.Transport)
	}
	x, ok := opts.Transport.Extra.(*option.V2RayXHTTPOptions)
	if !ok {
		t.Fatalf("extra=%T", opts.Transport.Extra)
	}
	if x.Path != "/xyz" {
		t.Errorf("path=%q", x.Path)
	}
	if len(x.Host) != 1 || x.Host[0] != "a.com" {
		t.Errorf("host=%v", x.Host)
	}
	if x.Mode != "packet-up" {
		t.Errorf("mode=%q", x.Mode)
	}
}

func TestVMessLinkXHTTP(t *testing.T) {
	// vmess:// 顶层 net=xhttp + path/host/mode。不测试 extra=<json> 嵌套
	// （VMess 链接的 JSON 解析链里有个正则 re-quote 数字值的阶段，对嵌套
	// 转义 JSON 容错不佳，用户端极少这么写 —— 主流用法是 VLESS 链接带 extra）。
	vmessJSON := `{"v":"2","ps":"xhttp-test","add":"cdn.example.com","port":"443",` +
		`"id":"11111111-1111-1111-1111-111111111111","aid":"0","scy":"auto",` +
		`"net":"xhttp","path":"/top","host":"top.com","mode":"stream-up","tls":"tls"}`
	link := "vmess://" + stdB64(vmessJSON)
	out, err := parser.ParseSubscriptionLink(link)
	if err != nil {
		t.Fatalf("parse vmess: %v", err)
	}
	opts := out.Options.(*option.VMessOutboundOptions)
	if opts.Transport == nil || opts.Transport.Type != "xhttp" {
		t.Fatalf("transport=%+v", opts.Transport)
	}
	x := opts.Transport.Extra.(*option.V2RayXHTTPOptions)
	if x.Path != "/top" {
		t.Errorf("path=%q", x.Path)
	}
	if x.Mode != "stream-up" {
		t.Errorf("mode=%q", x.Mode)
	}
	if len(x.Host) != 1 || x.Host[0] != "top.com" {
		t.Errorf("host=%v", x.Host)
	}
}

// VLESS 链接支持 extra=<url-encoded json>，测试 extra 覆盖字段
func TestVLESSLinkXHTTPWithExtra(t *testing.T) {
	// extra 里 urlencode 一个 xhttp JSON
	// {"xPaddingBytes":"200-800","scMaxEachPostBytes":4096,"noSSEHeader":true}
	extra := `%7B%22xPaddingBytes%22%3A%22200-800%22%2C%22scMaxEachPostBytes%22%3A4096%2C%22noSSEHeader%22%3Atrue%7D`
	link := "vless://11111111-1111-1111-1111-111111111111@example.com:443?" +
		"encryption=none&security=tls&type=xhttp&path=%2Fxyz&host=a.com&mode=packet-up&extra=" + extra + "#tag"
	out, err := parser.ParseSubscriptionLink(link)
	if err != nil {
		t.Fatalf("parse vless: %v", err)
	}
	opts := out.Options.(*option.VLESSOutboundOptions)
	x := opts.Transport.Extra.(*option.V2RayXHTTPOptions)
	if x.XPaddingBytes != "200-800" {
		t.Errorf("x_padding_bytes=%q", x.XPaddingBytes)
	}
	if x.ScMaxEachPostBytes != 4096 {
		t.Errorf("sc_max_each_post_bytes=%d", x.ScMaxEachPostBytes)
	}
	if !x.NoSSEHeader {
		t.Errorf("no_sse_header not parsed from extra")
	}
}


// Clash yaml 格式 XHTTP 解析

func TestClashVLESSXHTTP(t *testing.T) {
	// 模拟 mihomo subscription yaml 里一个 vless+xhttp 节点
	yamlStr := `
name: xh
type: vless
server: s.com
port: 443
uuid: 11111111-1111-1111-1111-111111111111
tls: true
network: xhttp
xhttp-opts:
  path: /abc
  host: s.com
  mode: packet-up
  x-padding-bytes: "100-1000"
  no-sse-header: true
  sc-max-each-post-bytes: 8192
  sc-min-posts-interval-ms: 20
  headers:
    User-Agent: test-agent
`
	var v parser.VlessOption
	if err := yaml.Unmarshal([]byte(yamlStr), &v); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	built := v.Build()
	opts := built.(*option.VLESSOutboundOptions)
	if opts.Transport == nil || opts.Transport.Type != "xhttp" {
		t.Fatalf("transport=%+v", opts.Transport)
	}
	x := opts.Transport.Extra.(*option.V2RayXHTTPOptions)
	if x.Path != "/abc" || x.Mode != "packet-up" {
		t.Errorf("parsed wrong: path=%q mode=%q", x.Path, x.Mode)
	}
	if x.ScMaxEachPostBytes != 8192 {
		t.Errorf("sc_max_each_post_bytes=%d", x.ScMaxEachPostBytes)
	}
	if !x.NoSSEHeader {
		t.Errorf("no_sse_header not parsed")
	}
	if len(x.Headers) == 0 || len(x.Headers["User-Agent"]) == 0 || x.Headers["User-Agent"][0] != "test-agent" {
		t.Errorf("headers=%+v", x.Headers)
	}
}

// 验证 xhttp 节点经由 sing-box 配置 JSON 往返能 roundtrip
// (需要先让 plugin registry 注册 xhttp 类型)
func TestXHTTPOptionRoundtrip(t *testing.T) {
	v2rayxhttp.RegisterPlugin()
	input := `{"type":"xhttp","path":"/r","mode":"stream-one","x_padding_bytes":"50-500"}`
	var o option.V2RayTransportOptions
	if err := o.UnmarshalJSON([]byte(input)); err != nil {
		t.Fatal(err)
	}
	out, err := o.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	// badjson 输出带空格分隔符，检查语义包含即可
	s := string(out)
	if !strings.Contains(s, `"path"`) || !strings.Contains(s, `"/r"`) {
		t.Errorf("path missing in %s", s)
	}
	if !strings.Contains(s, `"mode"`) || !strings.Contains(s, `"stream-one"`) {
		t.Errorf("mode missing in %s", s)
	}
}
