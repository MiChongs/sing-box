//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	commonEBPF "github.com/MiChongs/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

func newBypassTestRuleSet(t *testing.T, tag string, rules string) adapter.RuleSet {
	t.Helper()
	headless, err := json.UnmarshalExtended[[]option.HeadlessRule]([]byte(rules))
	if err != nil {
		t.Fatal(err)
	}
	ruleSet, err := R.NewLocalRuleSet(context.Background(), log.NewNOPFactory().Logger(), tag, option.RuleSet{
		Type:          C.RuleSetTypeInline,
		InlineOptions: option.PlainRuleSet{Rules: headless},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ruleSet
}

type bypassTestOutbound struct{ adapter.Outbound }

func (*bypassTestOutbound) Tag() string { return "bypass" }

func newBypassTestInbound(t *testing.T, ruleSets ...adapter.RuleSet) *Inbound {
	t.Helper()
	inbound := &Inbound{
		fakeIPIPv4Prefix:   netip.MustParsePrefix("198.18.0.0/15"),
		localBypassExclude: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		bypassOutbound:     &bypassTestOutbound{},
	}
	inbound.logger = log.NewNOPFactory().Logger()
	inbound.policyWake = make(chan struct{}, 1)
	inbound.localBypassRules.ruleSets = ruleSets
	inbound.localBypassRules.learned = newBypassLearnedTable(bypassLearnedCapacity)
	inbound.sharedBypassRules.learned = newBypassLearnedTable(bypassLearnedCapacity)
	inbound.localBypassRules.started = true
	if err := inbound.refreshRuleSetsLocked(false, true); err != nil {
		t.Fatal(err)
	}
	return inbound
}

func bypassPolicyContains(policy []commonEBPF.CIDRDecision, address string) bool {
	addr := netip.MustParseAddr(address)
	for _, decision := range policy {
		if decision.Prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func dnsAnswer(name string, ttl uint32, addresses ...string) (*mDNS.Msg, *mDNS.Msg) {
	message := new(mDNS.Msg)
	message.SetQuestion(mDNS.Fqdn(name), mDNS.TypeA)
	response := new(mDNS.Msg)
	response.SetReply(message)
	for _, address := range addresses {
		addr := netip.MustParseAddr(address)
		header := mDNS.RR_Header{Name: mDNS.Fqdn(name), Class: mDNS.ClassINET, Ttl: ttl}
		if addr.Is4() {
			header.Rrtype = mDNS.TypeA
			response.Answer = append(response.Answer, &mDNS.A{Hdr: header, A: net.IP(addr.AsSlice())})
		} else {
			header.Rrtype = mDNS.TypeAAAA
			response.Answer = append(response.Answer, &mDNS.AAAA{Hdr: header, AAAA: net.IP(addr.AsSlice())})
		}
	}
	return message, response
}

func TestBypassRuleSetPurelyKernelPolicy(t *testing.T) {
	t.Parallel()
	inbound := newBypassTestInbound(t, newBypassTestRuleSet(t, "cn", `[{"ip_cidr": ["203.0.113.0/24"]}]`))
	state := &inbound.localBypassRules
	if !bypassPolicyContains(state.policy, "203.0.113.7") {
		t.Fatal("pure ip_cidr rule must reach the kernel policy")
	}
	if inbound.preRouteBypass(false) != nil || state.domainMatcher.Load() != nil {
		t.Fatal("a pure ip_cidr rule-set needs no userspace matching or DNS learning")
	}
}

func TestBypassRuleSetCombinedRuleStaysInUserspace(t *testing.T) {
	t.Parallel()
	inbound := newBypassTestInbound(t, newBypassTestRuleSet(t, "web", `[{"ip_cidr": ["203.0.113.0/24"], "port": [443]}]`))
	state := &inbound.localBypassRules
	if bypassPolicyContains(state.policy, "203.0.113.7") {
		t.Fatal("ip_cidr AND port must not bypass the whole prefix in the kernel")
	}
	bypass := inbound.preRouteBypass(false)
	if bypass == nil {
		t.Fatal("combined rule needs userspace matching")
	}
	metadata := adapter.InboundContext{Network: N.NetworkTCP, Destination: M.ParseSocksaddr("203.0.113.7:443")}
	if !bypass.Rule.Match(&metadata) {
		t.Fatal("userspace matcher must accept ip_cidr + port")
	}
	metadata.Destination = M.ParseSocksaddr("203.0.113.7:80")
	if bypass.Rule.Match(&metadata) {
		t.Fatal("userspace matcher must reject another port")
	}
	if state.userspaceBypasses.Load() != 1 {
		t.Fatalf("userspace bypasses = %d, want 1", state.userspaceBypasses.Load())
	}
}

func TestBypassRuleSetLearnsDomainAddresses(t *testing.T) {
	t.Parallel()
	inbound := newBypassTestInbound(t, newBypassTestRuleSet(t, "direct", `[{"domain_suffix": ["example.com"]}]`))
	state := &inbound.localBypassRules
	bypass := inbound.preRouteBypass(false)
	if bypass == nil || !bypass.NeedDomain || bypass.LookupDomain == nil {
		t.Fatal("domain rule-set needs userspace matching with domain recovery")
	}

	inbound.observeBypassDNSResponse(dnsAnswer("WWW.Example.com", 30, "192.0.2.10", "2001:db8::10", "198.18.0.5", "100.64.1.1"))
	inbound.observeBypassDNSResponse(dnsAnswer("example.org", 30, "192.0.2.99"))
	if !state.dirty || !state.learnedDirty {
		t.Fatal("a learned address must schedule a policy refresh")
	}
	select {
	case <-inbound.policyWake:
	default:
		t.Fatal("a learned address must wake the policy worker")
	}
	if learned := inbound.refreshDirtyRuleSets(); !learned {
		t.Fatal("refresh must report the learned change for the cooldown")
	}
	for _, address := range []string{"192.0.2.10", "2001:db8::10"} {
		if !bypassPolicyContains(state.policy, address) {
			t.Fatalf("learned %s missing from kernel policy", address)
		}
	}
	for _, address := range []string{"198.18.0.5", "100.64.1.1", "192.0.2.99"} {
		if bypassPolicyContains(state.policy, address) {
			t.Fatalf("%s must not be learned", address)
		}
	}
	if domain, loaded := bypass.LookupDomain(netip.MustParseAddr("192.0.2.10")); !loaded || domain != "www.example.com" {
		t.Fatalf("LookupDomain = %q, %v", domain, loaded)
	}

	// A repeated answer only extends the lifetime: no kernel update.
	state.dirty = false
	inbound.observeBypassDNSResponse(dnsAnswer("www.example.com", 30, "192.0.2.10"))
	if state.dirty {
		t.Fatal("refreshing a learned address must not rebuild the kernel policy")
	}

	// Expiry removes the address from the kernel policy.
	state.learned.now = func() time.Time { return time.Now().Add(bypassLearnedMaxLifetime + time.Minute) }
	inbound.sweepBypassLearned()
	inbound.refreshDirtyRuleSets()
	if bypassPolicyContains(state.policy, "192.0.2.10") {
		t.Fatal("expired address still in kernel policy")
	}
}

func TestBypassRuleSetUpdateRetainsOnlyMatchingAddresses(t *testing.T) {
	t.Parallel()
	inbound := newBypassTestInbound(t, newBypassTestRuleSet(t, "direct", `[{"domain_suffix": ["example.com"]}]`))
	state := &inbound.localBypassRules
	inbound.observeBypassDNSResponse(dnsAnswer("a.example.com", 300, "192.0.2.20"))
	inbound.refreshDirtyRuleSets()
	state.ruleSets = []adapter.RuleSet{newBypassTestRuleSet(t, "direct", `[{"domain_suffix": ["example.net"]}]`)}
	inbound.updateRuleSet(false)
	inbound.refreshDirtyRuleSets()
	if bypassPolicyContains(state.policy, "192.0.2.20") || state.learned.len() != 0 {
		t.Fatal("an address learned for a domain the new rule-set no longer matches must be dropped")
	}
}

func TestBypassLearnedTable(t *testing.T) {
	t.Parallel()
	if bypassLearnedLifetime(1) != bypassLearnedMinLifetime || bypassLearnedLifetime(1<<31) != bypassLearnedMaxLifetime {
		t.Fatal("lifetime must be clamped")
	}
	table := newBypassLearnedTable(2)
	base := time.Now()
	table.now = func() time.Time { return base }
	table.learn(netip.MustParseAddr("192.0.2.1"), "a", time.Hour)
	table.learn(netip.MustParseAddr("192.0.2.2"), "b", 2*time.Hour)
	if !table.learn(netip.MustParseAddr("::ffff:192.0.2.3"), "c", 3*time.Hour) {
		t.Fatal("a new address must be reported")
	}
	if table.len() != 2 {
		t.Fatalf("capacity not enforced: %d", table.len())
	}
	if _, loaded := table.lookup(netip.MustParseAddr("192.0.2.1")); loaded {
		t.Fatal("the entry closest to expiry must be evicted first")
	}
	if domain, loaded := table.lookup(netip.MustParseAddr("192.0.2.3")); !loaded || domain != "c" {
		t.Fatal("IPv4-mapped addresses must be stored unmapped")
	}
}

// An address that also answers a domain outside the rule-set (a CDN edge)
// must never stay bypassed in the kernel: that would bypass every site on it.
func TestBypassRuleSetSharedAddressIsWithdrawn(t *testing.T) {
	t.Parallel()
	inbound := newBypassTestInbound(t, newBypassTestRuleSet(t, "direct", `[{"domain_suffix": ["cn.example"]}]`))
	state := &inbound.localBypassRules
	inbound.observeBypassDNSResponse(dnsAnswer("www.cn.example", 300, "104.21.4.123"))
	inbound.refreshDirtyRuleSets()
	if !bypassPolicyContains(state.policy, "104.21.4.123") {
		t.Fatal("exclusive address must be learned")
	}
	// Another site on the same edge resolves: the bypass is withdrawn before
	// the answer reaches its client, without waiting for the worker.
	inbound.observeBypassDNSResponse(dnsAnswer("video.foreign.example", 300, "104.21.4.123"))
	if bypassPolicyContains(state.policy, "104.21.4.123") {
		t.Fatal("shared address still bypassed in the kernel")
	}
	if _, loaded := inbound.preRouteBypass(false).LookupDomain(netip.MustParseAddr("104.21.4.123")); loaded {
		t.Fatal("a shared address must not name a domain")
	}
	inbound.observeBypassDNSResponse(dnsAnswer("www.cn.example", 300, "104.21.4.123"))
	if state.learned.len() != 0 {
		t.Fatal("a shared address must not be learned again")
	}

	// Seen for an unrelated domain first: never learned.
	inbound.observeBypassDNSResponse(dnsAnswer("cdn.foreign.example", 300, "172.67.1.1"))
	inbound.observeBypassDNSResponse(dnsAnswer("img.cn.example", 300, "172.67.1.1"))
	inbound.refreshDirtyRuleSets()
	if bypassPolicyContains(state.policy, "172.67.1.1") {
		t.Fatal("an address first seen for another domain must not be learned")
	}
}
