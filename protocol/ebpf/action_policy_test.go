//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"reflect"
	"testing"

	commonEBPF "github.com/MiChongs/sing-ebpf"
)

func TestCompileActionPolicyKeepsDestinationSemanticsInSync(t *testing.T) {
	var local, shared commonEBPF.ActionScope
	fakeIPv4 := netip.MustParsePrefix("198.18.0.0/15")
	fakeIPv6 := netip.MustParsePrefix("fd00:eb0f::/48")
	ports := []portRange{{Start: 443, End: 443}}
	appendDestinationPolicy(&local, true, ports, dnsModeRespectPolicy, fakeIPv4, fakeIPv6, nil, true, true)
	appendDestinationPolicy(&shared, true, ports, dnsModeRespectPolicy, fakeIPv4, fakeIPv6, nil, true, true)
	if !reflect.DeepEqual(local.DestinationCIDR, shared.DestinationCIDR) {
		t.Fatalf("local/shared destination CIDR semantics diverged:\nlocal=%+v\nshared=%+v", local.DestinationCIDR, shared.DestinationCIDR)
	}
	if !reflect.DeepEqual(local.DestinationPort, shared.DestinationPort) {
		t.Fatalf("local/shared destination port semantics diverged:\nlocal=%+v\nshared=%+v", local.DestinationPort, shared.DestinationPort)
	}
}

func TestCompileProcessUIDPolicySubtractsExcludedRanges(t *testing.T) {
	inbound := &Inbound{
		localPolicy: localUIDPolicy{
			IncludeUIDConfigured: true,
			IncludeUID:           []uidRange{{Start: 1000, End: 1999}},
			ExcludeUID:           []uidRange{{Start: 1400, End: 1499}},
		},
	}
	decisions, defaultAction := inbound.compileProcessUIDPolicy()
	if defaultAction != commonEBPF.DecisionPass {
		t.Fatalf("default action = %v, want pass", defaultAction)
	}
	want := []commonEBPF.UIDDecision{
		{Start: 1000, End: 1399, Action: commonEBPF.DecisionIntercept},
		{Start: 1500, End: 1999, Action: commonEBPF.DecisionIntercept},
	}
	if len(decisions) != len(want) {
		t.Fatalf("decisions = %+v, want %+v", decisions, want)
	}
	for index := range want {
		if decisions[index] != want[index] {
			t.Fatalf("decisions = %+v, want %+v", decisions, want)
		}
	}
}

func TestCompileProcessUIDPolicyUsesExcludeActionsByDefault(t *testing.T) {
	inbound := &Inbound{localPolicy: localUIDPolicy{
		ExcludeUID: []uidRange{{Start: 10000, End: 10010}},
	}}
	decisions, defaultAction := inbound.compileProcessUIDPolicy()
	if defaultAction != commonEBPF.DecisionIntercept {
		t.Fatalf("default action = %v, want intercept", defaultAction)
	}
	if len(decisions) != 1 || decisions[0].Action != commonEBPF.DecisionPass {
		t.Fatalf("decisions = %+v, want one pass decision", decisions)
	}
}

func TestCombineDestinationDecisionsRetainsStaticPasses(t *testing.T) {
	inbound := &Inbound{}
	combined, err := inbound.combineDestinationDecisions(
		[]commonEBPF.CIDRDecision{{
			Prefix: netip.MustParsePrefix("192.168.0.0/16"), Action: commonEBPF.DecisionPass,
		}},
		[]commonEBPF.CIDRDecision{{
			Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: commonEBPF.DecisionPass,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(combined) != 2 {
		t.Fatalf("combined decisions = %+v, want static and dynamic pass entries", combined)
	}
}

func TestValidateActionPolicyScope(t *testing.T) {
	tests := []struct {
		name   string
		local  commonEBPF.ActionScope
		shared commonEBPF.ActionScope
	}{
		{
			name:  "local source CIDR",
			local: commonEBPF.ActionScope{SourceCIDR: []commonEBPF.CIDRDecision{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Action: commonEBPF.DecisionPass}}},
		},
		{
			name:  "local source MAC",
			local: commonEBPF.ActionScope{SourceMAC: []commonEBPF.MACDecision{{Address: commonEBPF.MACAddress{2, 0, 0, 0, 0, 1}, Action: commonEBPF.DecisionPass}}},
		},
		{
			name:   "shared UID",
			shared: commonEBPF.ActionScope{UID: []commonEBPF.UIDDecision{{Start: 1000, End: 1000, Action: commonEBPF.DecisionPass}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateActionPolicyScope(commonEBPF.ActionPolicy{Local: test.local, Shared: test.shared}); err == nil {
				t.Fatal("unsupported action scope was accepted")
			}
		})
	}
}

func TestAppendDestinationPolicyForcesBypassExclude(t *testing.T) {
	var scope commonEBPF.ActionScope
	appendDestinationPolicy(&scope, true, nil, dnsModeRespectPolicy,
		netip.Prefix{}, netip.Prefix{},
		[]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		true, true)
	var forced bool
	for _, decision := range scope.DestinationCIDR {
		if decision.Prefix == netip.MustParsePrefix("100.64.0.0/10") && decision.Action == commonEBPF.DecisionIntercept {
			forced = true
		}
	}
	if !forced {
		t.Fatalf("bypass_exclude prefix was not emitted as force-intercept: %+v", scope.DestinationCIDR)
	}
}

func TestNormalizeBypassExclude(t *testing.T) {
	v4 := netip.MustParsePrefix("100.64.0.0/10")
	v6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	if got, err := normalizeBypassExclude("local.bypass_exclude", []netip.Prefix{v4, v6}); err != nil || len(got) != 2 {
		t.Fatalf("valid v4+v6 rejected: %v, %v", got, err)
	}
	if _, err := normalizeBypassExclude("local.bypass_exclude", []netip.Prefix{v4, netip.MustParsePrefix("10.0.0.0/8")}); err == nil {
		t.Fatal("two IPv4 prefixes accepted")
	}
	if _, err := normalizeBypassExclude("local.bypass_exclude", []netip.Prefix{v6, netip.MustParsePrefix("fd00::/8")}); err == nil {
		t.Fatal("two IPv6 prefixes accepted")
	}
	// IPv4-mapped IPv6 is converted to its IPv4 form, not rejected outright.
	mapped, err := normalizeBypassExclude("local.bypass_exclude", []netip.Prefix{netip.MustParsePrefix("::ffff:100.64.0.0/104")})
	if err != nil || len(mapped) != 1 || mapped[0].String() != "100.0.0.0/8" {
		t.Fatalf("IPv4-mapped IPv6 not converted to IPv4: %v, %v", mapped, err)
	}
	if got, err := normalizeBypassExclude("local.bypass_exclude", nil); err != nil || got != nil {
		t.Fatalf("empty input: got %v, %v", got, err)
	}
}

func TestValidateForceInterceptPrefixes(t *testing.T) {
	prefix := netip.MustParsePrefix
	for _, testCase := range []struct {
		name          string
		fakeIPv4      string
		fakeIPv6      string
		localExclude  []string
		sharedExclude []string
		accepted      bool
	}{
		{"bypass_exclude without fake-ip", "", "", []string{"100.64.0.0/10"}, []string{"fd7a:115c:a1e0::/48"}, true},
		{"IPv4 fake-ip beside local bypass_exclude", "198.18.0.0/16", "", []string{"100.64.0.0/10"}, nil, true},
		{"same bypass_exclude on both paths", "198.18.0.0/16", "", []string{"100.64.0.0/10"}, []string{"100.64.0.0/10"}, true},
		{"three IPv4 prefixes", "198.18.0.0/16", "", []string{"100.64.0.0/10"}, []string{"10.0.0.0/8"}, false},
		{"three IPv6 prefixes", "", "fdfe:dcba:9876::/64", []string{"fd00::/8"}, []string{"fd7a:115c:a1e0::/48"}, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			i := &Inbound{}
			if testCase.fakeIPv4 != "" {
				i.fakeIPIPv4Prefix = prefix(testCase.fakeIPv4)
			}
			if testCase.fakeIPv6 != "" {
				i.fakeIPIPv6Prefix = prefix(testCase.fakeIPv6)
			}
			for _, value := range testCase.localExclude {
				i.localBypassExclude = append(i.localBypassExclude, prefix(value))
			}
			for _, value := range testCase.sharedExclude {
				i.sharedBypassExclude = append(i.sharedBypassExclude, prefix(value))
			}
			err := i.validateForceInterceptPrefixes()
			if (err == nil) != testCase.accepted {
				t.Fatalf("accepted = %v, want %v: %v", err == nil, testCase.accepted, err)
			}
		})
	}
}

// TestBuildActionPolicyCombinesFakeIPAndBypassExclude covers fake-ip DNS with
// a Tailscale bypass_exclude prefix, which share the IPv4 force-intercept
// slots; only the fake-ip range is answered by the ICMP echo responder.
func TestBuildActionPolicyCombinesFakeIPAndBypassExclude(t *testing.T) {
	fakeIP := netip.MustParsePrefix("198.18.0.0/16")
	tailnet := netip.MustParsePrefix("100.64.0.0/10")
	inbound := &Inbound{
		enableTCP:          true,
		enableUDP:          true,
		fakeIPIPv4Prefix:   fakeIP,
		localBypassExclude: []netip.Prefix{tailnet},
	}
	inbound.localPolicy.BypassPrivateAddress = true
	policy, err := inbound.buildActionPolicy()
	if err != nil {
		t.Fatal(err)
	}
	echoReply := make(map[netip.Prefix]bool)
	for _, decision := range policy.Local.DestinationCIDR {
		if decision.Action == commonEBPF.DecisionIntercept {
			echoReply[decision.Prefix] = decision.EchoReply
		}
	}
	if want := map[netip.Prefix]bool{fakeIP: true, tailnet: false}; !reflect.DeepEqual(echoReply, want) {
		t.Fatalf("local intercept decisions = %v, want %v", echoReply, want)
	}
	if _, err = commonEBPF.CompileActionPolicy(policy); err != nil {
		t.Fatal(err)
	}
}

func TestBuildActionPolicySubtractsExcludedUIDsFromIncludes(t *testing.T) {
	inbound := &Inbound{localPolicy: localUIDPolicy{
		IncludeUIDConfigured: true,
		IncludeUID:           []uidRange{{Start: 10000, End: 19999}},
		ExcludeUID:           []uidRange{{Start: 10123, End: 10123}},
	}}
	policy, err := inbound.buildActionPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if policy.Local.Default != commonEBPF.DecisionPass {
		t.Fatalf("local default = %v, want pass", policy.Local.Default)
	}
	want := []commonEBPF.UIDDecision{
		{Start: 10000, End: 10122, Action: commonEBPF.DecisionIntercept},
		{Start: 10124, End: 19999, Action: commonEBPF.DecisionIntercept},
	}
	if !reflect.DeepEqual(policy.Local.UID, want) {
		t.Fatalf("local UID decisions = %+v, want %+v", policy.Local.UID, want)
	}
	if _, err = commonEBPF.CompileActionPolicy(policy); err != nil {
		t.Fatal(err)
	}
}

func TestBuildActionPolicyPassesExcludedUIDsByDefault(t *testing.T) {
	inbound := &Inbound{localPolicy: localUIDPolicy{
		ExcludeUID: []uidRange{{Start: 10123, End: 10123}},
	}}
	policy, err := inbound.buildActionPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if policy.Local.Default != commonEBPF.DecisionIntercept {
		t.Fatalf("local default = %v, want intercept", policy.Local.Default)
	}
	want := []commonEBPF.UIDDecision{{Start: 10123, End: 10123, Action: commonEBPF.DecisionPass}}
	if !reflect.DeepEqual(policy.Local.UID, want) {
		t.Fatalf("local UID decisions = %+v, want %+v", policy.Local.UID, want)
	}
}
