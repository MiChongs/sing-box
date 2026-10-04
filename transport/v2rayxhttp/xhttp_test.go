package v2rayxhttp_test

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayxhttp"
)

// TestXHTTPOptionParsing 验证 "type":"xhttp" 经插件 registry 解码到
// *V2RayXHTTPOptions，range 字段同时接受整数与 "a-b" 字符串，并能往返序列化。
func TestXHTTPOptionParsing(t *testing.T) {
	v2rayxhttp.RegisterPlugin()

	input := `{
		"type": "xhttp",
		"path": "/abcd",
		"mode": "packet-up",
		"no_sse_header": true,
		"x_padding_bytes": "100-1000",
		"sc_max_each_post_bytes": 8192,
		"sc_min_posts_interval_ms": "10-50",
		"session_id_table": "Base62",
		"session_id_length": "16-24",
		"xmux": {"max_concurrency": "16-32", "h_keep_alive_period": 30},
		"download_settings": {
			"server": "cdn.example.com",
			"server_port": 443,
			"tls": {"enabled": true, "server_name": "cdn.example.com"},
			"detour": "direct",
			"path": "/abcd",
			"host": "cdn.example.com"
		}
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
	if extra.Path != "/abcd" || extra.Mode != "packet-up" || !extra.NoSSEHeader {
		t.Errorf("basic fields: %+v", extra)
	}
	if extra.ScMaxEachPostBytes != (option.XHTTPRange{From: 8192, To: 8192}) ||
		extra.XPaddingBytes != (option.XHTTPRange{From: 100, To: 1000}) ||
		extra.ScMinPostsIntervalMs != (option.XHTTPRange{From: 10, To: 50}) ||
		extra.SessionIDLength != (option.XHTTPRange{From: 16, To: 24}) {
		t.Errorf("range fields: %+v", extra)
	}
	if extra.Xmux == nil || extra.Xmux.MaxConcurrency != (option.XHTTPRange{From: 16, To: 32}) || extra.Xmux.HKeepAlivePeriod != 30 {
		t.Errorf("xmux: %+v", extra.Xmux)
	}
	download := extra.DownloadSettings
	if download == nil || download.Server != "cdn.example.com" || download.ServerPort != 443 ||
		download.TLS == nil || !download.TLS.Enabled || download.Detour != "direct" ||
		download.Path != "/abcd" || len(download.Host) != 1 {
		t.Fatalf("download_settings: %+v", download)
	}

	output, err := o.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"x_padding_bytes":"100-1000"`, `"sc_max_each_post_bytes":8192`, `"download_settings"`} {
		if !strings.Contains(strings.ReplaceAll(string(output), " ", ""), expected) {
			t.Errorf("marshal output missing %s: %s", expected, output)
		}
	}
	var roundTrip option.V2RayTransportOptions
	if err = roundTrip.UnmarshalJSON(output); err != nil {
		t.Fatalf("round trip: %v", err)
	}

	var invalid option.V2RayTransportOptions
	if err = invalid.UnmarshalJSON([]byte(`{"type":"xhttp","x_padding_bytes":"abc"}`)); err == nil {
		t.Error("invalid range should fail")
	}
}
