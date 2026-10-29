package bundle

import (
	"testing"

	"github.com/sagernet/sing-box/protocol/nowhere/core/nw2/wire"
)

func TestResolvesAllConfiguredPairs(t *testing.T) {
	T, Q := wire.CarrierTLSTCP, wire.CarrierQUIC
	cases := []struct {
		up, down         CarrierMode
		wantUp, wantDown wire.Carrier
	}{
		{ModeTCP, ModeTCP, T, T},
		{ModeTCP, ModeUDP, T, Q},
		{ModeUDP, ModeTCP, Q, T},
		{ModeUDP, ModeUDP, Q, Q},
	}
	for _, tc := range cases {
		got := planRoute(tc.up, tc.down)
		if got.uplink != tc.wantUp || got.downlink != tc.wantDown {
			t.Errorf("up=%s down=%s = %s, want %s",
				tc.up, tc.down, got.label(), resolvedRoute{tc.wantUp, tc.wantDown}.label())
		}
	}
}

func TestParseCarrierMode(t *testing.T) {
	if mode, err := ParseCarrierMode("tcp"); err != nil || mode != ModeTCP {
		t.Fatalf("tcp: %v %v", mode, err)
	}
	if mode, err := ParseCarrierMode("udp"); err != nil || mode != ModeUDP {
		t.Fatalf("udp: %v %v", mode, err)
	}
	if _, err := ParseCarrierMode("mix"); err == nil {
		t.Fatal("mix mode should fail")
	}
	if _, err := ParseCarrierMode(""); err == nil {
		t.Fatal("empty mode should fail")
	}
	if _, err := ParseCarrierMode("quic"); err == nil {
		t.Fatal("unknown mode should fail")
	}
}
