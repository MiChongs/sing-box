package parser

import (
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestOverrideRealityOption(t *testing.T) {
	reality := &option.OutboundRealityOptions{
		PublicKey: "original-key",
		KeyShare:  "classical",
		Version:   "1.0.0",
	}

	override := &option.OverrideRealityOptions{
		KeyShare: common.Ptr("hybrid"),
		Version:  common.Ptr("26.3.27"),
	}

	overrideRealityOption(reality, override)

	if reality.KeyShare != "hybrid" {
		t.Errorf("expected KeyShare to be overridden to 'hybrid', got '%s'", reality.KeyShare)
	}
	if reality.Version != "26.3.27" {
		t.Errorf("expected Version to be overridden to '26.3.27', got '%s'", reality.Version)
	}
	if reality.PublicKey != "original-key" {
		t.Errorf("PublicKey should remain untouched")
	}
}

func TestOverrideTransportOption(t *testing.T) {
	downloadSettings := &option.V2RayXHTTPDownloadOptions{
		DialerOptions: option.DialerOptions{
			Detour: "outbound-proxy",
		},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Reality: &option.OutboundRealityOptions{
					KeyShare: "classical",
					Version:  "1.0.0",
				},
			},
		},
	}
	downloadSettings.Enabled = common.Ptr(false)

	xhttpOpts := &option.V2RayXHTTPOptions{
		DownloadSettings: downloadSettings,
	}

	transport := &option.V2RayTransportOptions{
		Type:  C.V2RayTransportTypeXHTTP,
		Extra: xhttpOpts,
	}

	overrideTransport := &option.OverrideTransportOptions{
		XHTTPDownloadEnabled: common.Ptr(true),
		XHTTPDownloadDetour:  common.Ptr("direct"),
	}

	overrideTLS := &option.OverrideTLSOptions{
		Reality: &option.OverrideRealityOptions{
			KeyShare: common.Ptr("hybrid"),
			Version:  common.Ptr("28.0.0"),
		},
	}

	res := overrideTransportOption(transport, overrideTLS, overrideTransport)
	if res == nil || res.Extra == nil {
		t.Fatalf("Extra must not be nil")
	}

	resXHTTP := res.Extra.(*option.V2RayXHTTPOptions)
	ds := resXHTTP.DownloadSettings

	if ds == nil {
		t.Fatalf("DownloadSettings must not be nil")
	}
	if ds.Enabled == nil || !*ds.Enabled {
		t.Errorf("expected DownloadSettings.Enabled == true")
	}
	if ds.Detour != "direct" {
		t.Errorf("expected DownloadSettings.Detour == 'direct', got '%s'", ds.Detour)
	}
	if ds.TLS == nil || ds.TLS.Reality == nil {
		t.Fatalf("inner TLS Reality must not be nil")
	}
	if ds.TLS.Reality.KeyShare != "hybrid" {
		t.Errorf("expected inner Reality KeyShare == 'hybrid', got '%s'", ds.TLS.Reality.KeyShare)
	}
	if ds.TLS.Reality.Version != "28.0.0" {
		t.Errorf("expected inner Reality Version == '28.0.0', got '%s'", ds.TLS.Reality.Version)
	}
}

func TestOverrideOutbounds_FullChain(t *testing.T) {
	vlessOut := option.Outbound{
		Type: C.TypeVLESS,
		Tag:  "node-1",
		Options: &option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server: "1.1.1.1",
			},
			Transport: &option.V2RayTransportOptions{
				Type: C.V2RayTransportTypeXHTTP,
				Extra: &option.V2RayXHTTPOptions{
					DownloadSettings: &option.V2RayXHTTPDownloadOptions{
						DialerOptions: option.DialerOptions{
							Detour: "old-detour",
						},
					},
				},
			},
		},
	}

	overrideTransport := &option.OverrideTransportOptions{
		XHTTPDownloadDetour: common.Ptr("new-detour"),
	}

	outbounds := overrideOutbounds(
		[]option.Outbound{vlessOut},
		nil,
		nil,
		nil,
		overrideTransport,
		[]string{"node-1"},
		"test-provider",
	)

	if len(outbounds) != 1 {
		t.Fatalf("expected 1 outbound returned")
	}

	parsedVless := outbounds[0].Options.(*option.VLESSOutboundOptions)
	xhttpOpts := parsedVless.Transport.Extra.(*option.V2RayXHTTPOptions)
	if xhttpOpts.DownloadSettings.Detour != "new-detour" {
		t.Errorf("expected Detour overridden to 'new-detour', got '%s'", xhttpOpts.DownloadSettings.Detour)
	}
}

func TestOverrideOutbounds_AnyTLSToAnyX(t *testing.T) {
	anytlsOut := option.Outbound{
		Type: C.TypeAnyTLS,
		Tag:  "anytls-node",
		Options: &option.AnyTLSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     "1.1.1.1",
				ServerPort: 443,
			},
			Password:           "node-password",
			IdleSessionTimeout: badoption.Duration(30 * time.Second),
			MinIdleSession:     1,
		},
	}

	override := &option.OverrideAnyTLSOptions{
		UseAnyX:               common.Ptr(true),
		PaddingScheme:         common.Ptr(badoption.Listable[string]{"auto"}),
		PaddingSchemeInterval: common.Ptr(badoption.Duration(15 * time.Minute)),
		IdleSessionMinTimeout: common.Ptr(badoption.Duration(10 * time.Second)),
		IdleSessionTimeout:    common.Ptr(badoption.Duration(20 * time.Second)),
		MinIdleSession:        common.Ptr(3),
	}

	outbounds := overrideOutbounds(
		[]option.Outbound{anytlsOut},
		nil,
		nil,
		override,
		nil,
		[]string{"anytls-node"},
		"test-provider",
	)

	if len(outbounds) != 1 {
		t.Fatalf("expected 1 outbound returned, got %d", len(outbounds))
	}
	if outbounds[0].Type != C.TypeAnyX {
		t.Fatalf("expected outbound type to be converted to %s, got %s", C.TypeAnyX, outbounds[0].Type)
	}

	anyxOpts, ok := outbounds[0].Options.(*option.AnyXOutboundOptions)
	if !ok {
		t.Fatalf("expected options to be *option.AnyXOutboundOptions")
	}
	if anyxOpts.Server != "1.1.1.1" || anyxOpts.ServerPort != 443 {
		t.Errorf("ServerOptions not preserved: %s:%d", anyxOpts.Server, anyxOpts.ServerPort)
	}
	if anyxOpts.Password != "node-password" {
		t.Errorf("Password not preserved: got %s", anyxOpts.Password)
	}
	if len(anyxOpts.PaddingScheme) != 1 || anyxOpts.PaddingScheme[0] != "auto" {
		t.Errorf("expected PaddingScheme ['auto'], got %v", anyxOpts.PaddingScheme)
	}
	if anyxOpts.PaddingSchemeInterval.Build() != 15*time.Minute {
		t.Errorf("expected PaddingSchemeInterval 15m, got %v", anyxOpts.PaddingSchemeInterval)
	}
	if anyxOpts.IdleSessionMinTimeout.Build() != 10*time.Second {
		t.Errorf("expected IdleSessionMinTimeout 10s, got %v", anyxOpts.IdleSessionMinTimeout)
	}
	if anyxOpts.IdleSessionTimeout.Build() != 20*time.Second {
		t.Errorf("expected IdleSessionTimeout 20s, got %v", anyxOpts.IdleSessionTimeout)
	}
	if anyxOpts.MinIdleSession != 3 {
		t.Errorf("expected MinIdleSession 3, got %d", anyxOpts.MinIdleSession)
	}
}

func TestOverrideOutbounds_AnyTLSWithoutUseAnyX(t *testing.T) {
	anytlsOut := option.Outbound{
		Type: C.TypeAnyTLS,
		Tag:  "anytls-node",
		Options: &option.AnyTLSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     "1.1.1.1",
				ServerPort: 443,
			},
			Password:           "node-password",
			IdleSessionTimeout: badoption.Duration(30 * time.Second),
			MinIdleSession:     1,
		},
	}

	override := &option.OverrideAnyTLSOptions{
		UseAnyX:               nil,
		PaddingScheme:         common.Ptr(badoption.Listable[string]{"auto"}),
		PaddingSchemeInterval: common.Ptr(badoption.Duration(15 * time.Minute)),
		IdleSessionMinTimeout: common.Ptr(badoption.Duration(10 * time.Second)),
		IdleSessionTimeout:    common.Ptr(badoption.Duration(45 * time.Second)),
		MinIdleSession:        common.Ptr(2),
	}

	outbounds := overrideOutbounds(
		[]option.Outbound{anytlsOut},
		nil,
		nil,
		override,
		nil,
		[]string{"anytls-node"},
		"test-provider",
	)

	if len(outbounds) != 1 {
		t.Fatalf("expected 1 outbound returned, got %d", len(outbounds))
	}
	if outbounds[0].Type != C.TypeAnyTLS {
		t.Fatalf("expected outbound type to remain %s, got %s", C.TypeAnyTLS, outbounds[0].Type)
	}

	anytlsOpts, ok := outbounds[0].Options.(*option.AnyTLSOutboundOptions)
	if !ok {
		t.Fatalf("expected options to be *option.AnyTLSOutboundOptions")
	}
	if anytlsOpts.IdleSessionTimeout.Build() != 45*time.Second {
		t.Errorf("expected IdleSessionTimeout overridden to 45s, got %v", anytlsOpts.IdleSessionTimeout)
	}
	if anytlsOpts.MinIdleSession != 2 {
		t.Errorf("expected MinIdleSession overridden to 2, got %d", anytlsOpts.MinIdleSession)
	}
}

func TestOverrideOutbounds_AnyXDirect(t *testing.T) {
	anyxOut := option.Outbound{
		Type: C.TypeAnyX,
		Tag:  "anyx-node",
		Options: &option.AnyXOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     "2.2.2.2",
				ServerPort: 8443,
			},
			Password: "anyx-password",
		},
	}

	override := &option.OverrideAnyTLSOptions{
		PaddingScheme:         common.Ptr(badoption.Listable[string]{"stop=4", "0=30-30"}),
		PaddingSchemeInterval: common.Ptr(badoption.Duration(20 * time.Minute)),
		IdleSessionMinTimeout: common.Ptr(badoption.Duration(12 * time.Second)),
		IdleSessionTimeout:    common.Ptr(badoption.Duration(24 * time.Second)),
		MinIdleSession:        common.Ptr(4),
	}

	outbounds := overrideOutbounds(
		[]option.Outbound{anyxOut},
		nil,
		nil,
		override,
		nil,
		[]string{"anyx-node"},
		"test-provider",
	)

	if len(outbounds) != 1 {
		t.Fatalf("expected 1 outbound returned, got %d", len(outbounds))
	}
	if outbounds[0].Type != C.TypeAnyX {
		t.Fatalf("expected outbound type %s, got %s", C.TypeAnyX, outbounds[0].Type)
	}

	anyxOpts, ok := outbounds[0].Options.(*option.AnyXOutboundOptions)
	if !ok {
		t.Fatalf("expected options to be *option.AnyXOutboundOptions")
	}
	if len(anyxOpts.PaddingScheme) != 2 || anyxOpts.PaddingScheme[0] != "stop=4" {
		t.Errorf("expected PaddingScheme overridden, got %v", anyxOpts.PaddingScheme)
	}
	if anyxOpts.PaddingSchemeInterval.Build() != 20*time.Minute {
		t.Errorf("expected PaddingSchemeInterval 20m, got %v", anyxOpts.PaddingSchemeInterval)
	}
	if anyxOpts.IdleSessionMinTimeout.Build() != 12*time.Second {
		t.Errorf("expected IdleSessionMinTimeout 12s, got %v", anyxOpts.IdleSessionMinTimeout)
	}
	if anyxOpts.IdleSessionTimeout.Build() != 24*time.Second {
		t.Errorf("expected IdleSessionTimeout 24s, got %v", anyxOpts.IdleSessionTimeout)
	}
	if anyxOpts.MinIdleSession != 4 {
		t.Errorf("expected MinIdleSession 4, got %d", anyxOpts.MinIdleSession)
	}
}
