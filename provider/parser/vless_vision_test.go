package parser_test

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/provider/parser"
	"github.com/sagernet/sing/service"

	// Force VLESS outbound registration.
	_ "github.com/sagernet/sing-box/protocol/vless"
)

// TestParseClashFlowStyleProxies 真实订阅样本：proxies 的每一项是单行
// JSON flow-style mapping（不是标准 YAML 展开格式），含 hysteria2 / vmess /
// vless+reality+vision / vless+xhttp 等多种类型混合。
func TestParseClashFlowStyleProxies(t *testing.T) {
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), include.OutboundRegistry())
	ctx = service.ContextWith[option.EndpointOptionsRegistry](ctx, include.EndpointRegistry())

	yaml := `proxies:
  - {"name":"HY2-US","server":"usjk1.tkvip.xyz","port":443,"sni":"usjk1.tkvip.xyz","skip-cert-verify":false,"type":"hysteria2","password":"a87e5fda-d35f-4fe2-892e-7e2f9ac0f672"}
  - {"name":"TW-HY2-UPDOWN","server":"taiwan.tkvip.xyz","port":443,"sni":"taiwan.tkvip.xyz","up":1000,"down":1000,"skip-cert-verify":false,"type":"hysteria2","password":"a87e5fda-d35f-4fe2-892e-7e2f9ac0f672"}
  - {"name":"VMESS-US","type":"vmess","server":"ali-us-wave.tkvip.xyz","port":443,"uuid":"a87e5fda-d35f-4fe2-892e-7e2f9ac0f672","alterId":0,"cipher":"auto","udp":true,"tls":true,"skip-cert-verify":false,"network":"tcp","servername":"ali-us-wave.tkvip.xyz"}
  - {"name":"VLESS-VISION","type":"vless","server":"38.55.106.232","port":8080,"uuid":"81b903e5-850b-4925-8279-497edfe3e2fe","alterId":0,"cipher":"auto","udp":true,"flow":"xtls-rprx-vision","tls":true,"skip-cert-verify":false,"reality-opts":{"public-key":"Wh8UquI4JZ2WOn1HkwLDMxfbvPFjXHN33PJcC6s-92c","short-id":"5b647d18"},"client-fingerprint":"firefox","network":"tcp","servername":"gateway.icloud.com"}
  - {"type":"vless","name":"VLESS-XHTTP","server":"202.6.204.166","port":30013,"uuid":"28c0e792-1fdc-44b5-be60-d00e10ad1c55","udp":true,"tls":true,"client-fingerprint":"","skip-cert-verify":true,"xudp":true,"network":"xhttp","xhttp-opts":{"path":"/","mode":"auto"},"encryption":"none","servername":"b.ckocf.eu.cc"}
`
	outs, _, err := parser.ParseSubscription(ctx, yaml, nil, nil, "Clash")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(outs) != 5 {
		t.Fatalf("want 5 outbounds, got %d", len(outs))
	}
	byTag := map[string]option.Outbound{}
	for _, o := range outs {
		byTag[o.Tag] = o
	}
	if o, ok := byTag["TW-HY2-UPDOWN"].Options.(*option.Hysteria2OutboundOptions); !ok || o.UpMbps != 1000 || o.DownMbps != 1000 {
		t.Errorf("hy2 up/down not preserved: %+v", byTag["TW-HY2-UPDOWN"].Options)
	}
	if o, ok := byTag["VLESS-VISION"].Options.(*option.VLESSOutboundOptions); !ok ||
		o.Flow != "xtls-rprx-vision" || o.TLS == nil || o.TLS.Reality == nil || !o.TLS.Reality.Enabled {
		t.Errorf("vless+reality+vision parse failed: %+v", byTag["VLESS-VISION"].Options)
	}
	if o, ok := byTag["VLESS-XHTTP"].Options.(*option.VLESSOutboundOptions); !ok ||
		o.Transport == nil || o.Transport.Type != "xhttp" {
		t.Errorf("vless xhttp transport not picked up: %+v", byTag["VLESS-XHTTP"].Options)
	}
}

// TestParseVLESSRealityVisionClash 验证 clash yaml 订阅里
// VLESS + reality-opts + flow: xtls-rprx-vision 节点可解析。
func TestParseVLESSRealityVisionClash(t *testing.T) {
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), include.OutboundRegistry())
	ctx = service.ContextWith[option.EndpointOptionsRegistry](ctx, include.EndpointRegistry())

	yaml := `proxies:
  - name: "LA-Vision"
    type: vless
    server: 38.95.79.197
    port: 443
    uuid: 81b903e5-850b-4925-8279-497edfe3e2fe
    tls: true
    servername: gateway.icloud.com
    skip-cert-verify: false
    reality-opts:
      public-key: jTHlQc3ahcU7ieengsY4V_2FL7Ql3AdlrM8G6iWLMjU
      short-id: f54d5d7e
    client-fingerprint: firefox
    flow: xtls-rprx-vision
`
	outs, _, err := parser.ParseSubscription(ctx, yaml, nil, nil, "Clash")
	if err != nil {
		t.Fatalf("clash parse failed: %v", err)
	}
	if len(outs) != 1 {
		t.Fatalf("want 1 outbound, got %d", len(outs))
	}
	o, ok := outs[0].Options.(*option.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("want VLESSOutboundOptions, got %T", outs[0].Options)
	}
	if o.Flow != "xtls-rprx-vision" {
		t.Errorf("flow not preserved, got %q", o.Flow)
	}
	if o.TLS == nil || o.TLS.Reality == nil || !o.TLS.Reality.Enabled {
		t.Errorf("reality not enabled")
	}
}

// TestParseSingBoxJSONMixedProviders 真实 sing-box JSON 订阅样本：
// hysteria2 (含 up_mbps/down_mbps) + vmess (含 utls.fingerprint) +
// vless+reality+vision (多 utls.fingerprint 变体)。注意机场给 sing-box
// 格式时常丢弃 xhttp transport 节点 — 想保留 xhttp 请订阅 clash yaml URL。
func TestParseSingBoxJSONMixedProviders(t *testing.T) {
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), include.OutboundRegistry())
	ctx = service.ContextWith[option.EndpointOptionsRegistry](ctx, include.EndpointRegistry())

	content := `{
  "outbounds": [
    {"tag":"HY2-TW","type":"hysteria2","server":"taiwan.tkvip.xyz","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"taiwan.tkvip.xyz"},"up_mbps":1000,"down_mbps":1000},
    {"tag":"VMESS-SG-UTLS","type":"vmess","server":"sg-jk.tkvip.xyz","server_port":4443,"uuid":"81b903e5-850b-4925-8279-497edfe3e2fe","security":"auto","alter_id":0,"tls":{"enabled":true,"server_name":"sg-jk.tkvip.xyz","utls":{"enabled":true,"fingerprint":"chrome"}}},
    {"tag":"VLESS-VISION-QQ","type":"vless","server":"38.55.106.232","server_port":8080,"uuid":"81b903e5-850b-4925-8279-497edfe3e2fe","tls":{"enabled":true,"server_name":"gateway.icloud.com","reality":{"enabled":true,"public_key":"Wh8UquI4JZ2WOn1HkwLDMxfbvPFjXHN33PJcC6s-92c","short_id":"5b647d18"},"utls":{"enabled":true,"fingerprint":"qq"}},"flow":"xtls-rprx-vision"}
  ],
  "endpoints": []
}`
	outs, _, err := parser.ParseSubscription(ctx, content, nil, nil, "Box")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(outs) != 3 {
		t.Fatalf("want 3, got %d", len(outs))
	}
	byTag := map[string]option.Outbound{}
	for _, o := range outs {
		byTag[o.Tag] = o
	}
	if o := byTag["HY2-TW"].Options.(*option.Hysteria2OutboundOptions); o.UpMbps != 1000 || o.DownMbps != 1000 {
		t.Errorf("hy2 up/down lost: %+v", o)
	}
	if o := byTag["VMESS-SG-UTLS"].Options.(*option.VMessOutboundOptions); o.TLS == nil || o.TLS.UTLS == nil || o.TLS.UTLS.Fingerprint != "chrome" {
		t.Errorf("vmess utls fingerprint lost")
	}
	if o := byTag["VLESS-VISION-QQ"].Options.(*option.VLESSOutboundOptions); o.Flow != "xtls-rprx-vision" ||
		o.TLS.UTLS == nil || o.TLS.UTLS.Fingerprint != "qq" ||
		o.TLS.Reality == nil || !o.TLS.Reality.Enabled {
		t.Errorf("vless reality+vision+qq fingerprint chain broken")
	}
}

// TestParseVLESSRealityVision 验证 sing-box JSON provider (outbounds+endpoints)
// 能解析 VLESS + Reality + xtls-rprx-vision flow 节点。
func TestParseVLESSRealityVision(t *testing.T) {
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), include.OutboundRegistry())
	ctx = service.ContextWith[option.EndpointOptionsRegistry](ctx, include.EndpointRegistry())

	content := `{
  "outbounds": [
    {
      "tag": "test-vless-vision",
      "type": "vless",
      "server": "38.95.79.197",
      "server_port": 443,
      "uuid": "81b903e5-850b-4925-8279-497edfe3e2fe",
      "tls": {
        "enabled": true,
        "server_name": "gateway.icloud.com",
        "reality": {"enabled": true, "public_key": "jTHlQc3ahcU7ieengsY4V_2FL7Ql3AdlrM8G6iWLMjU", "short_id": "f54d5d7e"},
        "utls": {"enabled": true, "fingerprint": "firefox"}
      },
      "flow": "xtls-rprx-vision"
    }
  ],
  "endpoints": []
}`
	outs, eps, err := parser.ParseSubscription(ctx, content, nil, nil, "TestProv")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(outs) != 1 {
		t.Fatalf("want 1 outbound, got %d", len(outs))
	}
	if eps == nil {
		// endpoints:[] should yield empty or nil; both acceptable
	}
	if outs[0].Type != "vless" {
		t.Fatalf("want vless, got %s", outs[0].Type)
	}
}
