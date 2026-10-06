package bundle

import (
	"testing"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

func TestResolvesAllConfiguredPairs(t *testing.T) {
	T, Q := wire.CarrierTLSTCP, wire.CarrierQUIC
	cases := []struct {
		up, down         CarrierMode
		tcpUp, tcpDown   wire.Carrier
		quicUp, quicDown wire.Carrier
	}{
		{ModeTCP, ModeTCP, T, T, T, T},
		{ModeTCP, ModeUDP, T, Q, T, Q},
		{ModeUDP, ModeTCP, Q, T, Q, T},
		{ModeUDP, ModeUDP, Q, Q, Q, Q},
		{ModeMix, ModeTCP, T, T, Q, T},
		{ModeMix, ModeUDP, T, Q, Q, Q},
		{ModeTCP, ModeMix, T, T, T, Q},
		{ModeUDP, ModeMix, Q, T, Q, Q},
		{ModeMix, ModeMix, T, T, Q, Q},
	}
	for _, tc := range cases {
		gotTCP := resolveWithChoice(tc.up, tc.down, false)
		gotQUIC := resolveWithChoice(tc.up, tc.down, true)
		if gotTCP.uplink != tc.tcpUp || gotTCP.downlink != tc.tcpDown {
			t.Errorf("up=%s down=%s tcp = %s, want %s%s", tc.up, tc.down, gotTCP.label(),
				resolvedRoute{tc.tcpUp, tc.tcpDown}.label(), "")
		}
		if gotQUIC.uplink != tc.quicUp || gotQUIC.downlink != tc.quicDown {
			t.Errorf("up=%s down=%s quic = %s, want %s", tc.up, tc.down, gotQUIC.label(),
				resolvedRoute{tc.quicUp, tc.quicDown}.label())
		}
	}
}

func TestRoutePlanIsStableAndUsesTheOtherAllowedRouteAsFallback(t *testing.T) {
	var session wire.SessionID
	for i := range session {
		session[i] = 0x5a
	}
	seed := seedFromSession(session)
	first := planRoute(ModeMix, ModeTCP, seed, 7)
	repeated := planRoute(ModeMix, ModeTCP, seed, 7)
	if first != repeated {
		t.Fatalf("plan not stable: %+v vs %+v", first, repeated)
	}
	if !first.hasFallback || first.primary == first.fallback {
		t.Fatalf("fallback should be the other allowed route: %+v", first)
	}

	fixed := planRoute(ModeTCP, ModeTCP, seed, 7)
	if fixed.primary.uplink != wire.CarrierTLSTCP || fixed.primary.downlink != wire.CarrierTLSTCP {
		t.Fatalf("fixed primary = %s", fixed.primary.label())
	}
	if fixed.hasFallback {
		t.Fatal("fixed route must not fall back")
	}
}

func TestMixMixNeverResolvesToASplitRoute(t *testing.T) {
	for flowID := wire.FlowID(1); flowID <= 1024; flowID++ {
		plan := planRoute(ModeMix, ModeMix, 0x1234, flowID)
		if plan.primary.split() || !plan.hasFallback || plan.fallback.split() {
			t.Fatalf("flow %d split: primary=%s fallback=%s", flowID, plan.primary.label(), plan.fallback.label())
		}
		if plan.primary == plan.fallback {
			t.Fatalf("flow %d primary equals fallback", flowID)
		}
	}
}

func TestParseCarrierMode(t *testing.T) {
	if mode, err := ParseCarrierMode("mix"); err != nil || mode != ModeMix {
		t.Fatalf("mix: %v %v", mode, err)
	}
	if _, err := ParseCarrierMode(""); err == nil {
		t.Fatal("empty mode should fail")
	}
	if _, err := ParseCarrierMode("quic"); err == nil {
		t.Fatal("unknown mode should fail")
	}
}
