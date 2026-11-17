//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

const (
	// A DNS answer is cached by clients beyond its TTL, and a domain that
	// stops bypassing for a short-TTL record would make established clients
	// fall back to the proxy, so learned addresses live at least this long.
	bypassLearnedMinLifetime = 5 * time.Minute
	bypassLearnedMaxLifetime = 24 * time.Hour
	// bypassLearnedCapacity bounds learned addresses per scope. It leaves the
	// destination LPM (65536 entries per family) to configured prefixes.
	bypassLearnedCapacity      = 16384
	bypassLearnedSweepInterval = 30 * time.Second
	// bypassLearnedRefreshCooldown coalesces kernel policy updates caused by
	// bursts of DNS answers. Connections made meanwhile are still bypassed in
	// userspace.
	bypassLearnedRefreshCooldown = 100 * time.Millisecond
)

// bypassScopePlan is the compiled bypass_rule_set policy of one scope.
type bypassScopePlan struct {
	prefixes    []netip.Prefix
	matchDomain func(string) bool
	userspace   bool
	needDomain  bool
}

func compileBypassScopePlan(ruleSets []adapter.RuleSet) bypassScopePlan {
	var (
		plan     bypassScopePlan
		matchers []func(string) bool
	)
	for _, ruleSet := range ruleSets {
		planner, isPlanner := ruleSet.(adapter.RuleSetPreMatchPlanner)
		if !isPlanner {
			for _, ipSet := range ruleSet.ExtractIPSet() {
				plan.prefixes = append(plan.prefixes, ipSet.Prefixes()...)
			}
			plan.userspace = true
			plan.needDomain = true
			continue
		}
		ruleSetPlan := planner.PreMatchPlan()
		for _, ipSet := range ruleSetPlan.DestinationIPSets {
			plan.prefixes = append(plan.prefixes, ipSet.Prefixes()...)
		}
		if ruleSetPlan.MatchDomain != nil {
			matchers = append(matchers, ruleSetPlan.MatchDomain)
		}
		plan.userspace = plan.userspace || ruleSetPlan.Residual
		plan.needDomain = plan.needDomain || ruleSetPlan.NeedDomain
	}
	switch len(matchers) {
	case 0:
	case 1:
		plan.matchDomain = matchers[0]
	default:
		plan.matchDomain = func(domain string) bool {
			for _, match := range matchers {
				if match(domain) {
					return true
				}
			}
			return false
		}
	}
	return plan
}

// bypassRuleSetMatcher is the userspace half of a scope's bypass_rule_set:
// the whole rule-sets, matched with full connection metadata by the router.
type bypassRuleSetMatcher struct {
	ruleSets []adapter.RuleSet
	matched  *atomic.Uint64
}

func (m *bypassRuleSetMatcher) Match(metadata *adapter.InboundContext) bool {
	for _, ruleSet := range m.ruleSets {
		metadata.ResetRuleCache()
		if ruleSet.Match(metadata) {
			m.matched.Add(1)
			return true
		}
	}
	return false
}

func (m *bypassRuleSetMatcher) RuleCount() uint64 {
	var count uint64
	for _, ruleSet := range m.ruleSets {
		count += ruleSet.RuleCount()
	}
	return count
}

func (m *bypassRuleSetMatcher) String() string {
	names := make([]string, 0, len(m.ruleSets))
	for _, ruleSet := range m.ruleSets {
		names = append(names, ruleSet.Name())
	}
	return "rule_set=[" + strings.Join(names, " ") + "]"
}

type bypassLearnedEntry struct {
	domain   string
	expireAt time.Time
}

// bypassLearnedTable holds the addresses DNS answered for domains a scope's
// bypass_rule_set matches. It is written from the DNS path and read when the
// kernel policy is rebuilt and when the router recovers a destination domain.
type bypassLearnedTable struct {
	access   sync.Mutex
	entries  map[netip.Addr]bypassLearnedEntry
	capacity int
	now      func() time.Time
}

func newBypassLearnedTable(capacity int) *bypassLearnedTable {
	return &bypassLearnedTable{capacity: capacity, now: time.Now}
}

func bypassLearnedLifetime(ttl uint32) time.Duration {
	return min(max(time.Duration(ttl)*time.Second, bypassLearnedMinLifetime), bypassLearnedMaxLifetime)
}

// learn records address for domain and reports whether the set of learned
// addresses changed. Refreshing an existing address only extends it.
func (t *bypassLearnedTable) learn(address netip.Addr, domain string, lifetime time.Duration) bool {
	address = address.Unmap()
	t.access.Lock()
	defer t.access.Unlock()
	now := t.now()
	expireAt := now.Add(lifetime)
	if entry, loaded := t.entries[address]; loaded {
		if expireAt.After(entry.expireAt) {
			entry.expireAt = expireAt
		}
		entry.domain = domain
		t.entries[address] = entry
		return false
	}
	if t.entries == nil {
		t.entries = make(map[netip.Addr]bypassLearnedEntry)
	}
	if len(t.entries) >= t.capacity {
		t.evictLocked(now)
	}
	t.entries[address] = bypassLearnedEntry{domain: domain, expireAt: expireAt}
	return true
}

// evictLocked frees one slot: expired entries first, otherwise the entry
// closest to expiry.
func (t *bypassLearnedTable) evictLocked(now time.Time) {
	var (
		victim   netip.Addr
		earliest time.Time
	)
	for address, entry := range t.entries {
		if !entry.expireAt.After(now) {
			delete(t.entries, address)
			continue
		}
		if !victim.IsValid() || entry.expireAt.Before(earliest) {
			victim, earliest = address, entry.expireAt
		}
	}
	if len(t.entries) >= t.capacity && victim.IsValid() {
		delete(t.entries, victim)
	}
}

func (t *bypassLearnedTable) lookup(address netip.Addr) (string, bool) {
	address = address.Unmap()
	t.access.Lock()
	defer t.access.Unlock()
	entry, loaded := t.entries[address]
	if !loaded || !entry.expireAt.After(t.now()) {
		return "", false
	}
	return entry.domain, true
}

// sweep drops expired addresses and reports whether any was dropped.
func (t *bypassLearnedTable) sweep() bool {
	t.access.Lock()
	defer t.access.Unlock()
	now := t.now()
	removed := false
	for address, entry := range t.entries {
		if !entry.expireAt.After(now) {
			delete(t.entries, address)
			removed = true
		}
	}
	return removed
}

// retain keeps only the addresses whose domain match still accepts, after a
// rule-set update.
func (t *bypassLearnedTable) retain(match func(string) bool) bool {
	t.access.Lock()
	defer t.access.Unlock()
	removed := false
	for address, entry := range t.entries {
		if match == nil || !match(entry.domain) {
			delete(t.entries, address)
			removed = true
		}
	}
	return removed
}

func (t *bypassLearnedTable) prefixes() []netip.Prefix {
	t.access.Lock()
	defer t.access.Unlock()
	now := t.now()
	prefixes := make([]netip.Prefix, 0, len(t.entries))
	for address, entry := range t.entries {
		if entry.expireAt.After(now) {
			prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
		}
	}
	return prefixes
}

func (t *bypassLearnedTable) len() int {
	t.access.Lock()
	defer t.access.Unlock()
	return len(t.entries)
}

// bypassDomainMatcher is published for the DNS path, which must not take the
// rule-set lock.
type bypassDomainMatcher struct {
	match func(string) bool
}

func (i *Inbound) startBypassDNSObserverLocked() {
	if i.bypassDNSUnregister != nil {
		return
	}
	if len(i.localBypassRules.ruleSets) == 0 && len(i.sharedBypassRules.ruleSets) == 0 {
		return
	}
	registry, loaded := service.FromContext[adapter.DNSRouter](i.ctx).(adapter.DNSResponseObserverRegistry)
	if !loaded {
		return
	}
	i.bypassDNSUnregister = registry.RegisterDNSResponseObserver(i.observeBypassDNSResponse)
}

func (i *Inbound) stopBypassDNSObserverLocked() {
	if i.bypassDNSUnregister != nil {
		i.bypassDNSUnregister()
		i.bypassDNSUnregister = nil
	}
}

func (i *Inbound) observeBypassDNSResponse(message *mDNS.Msg, response *mDNS.Msg) {
	if len(message.Question) == 0 {
		return
	}
	domain := strings.ToLower(strings.TrimSuffix(message.Question[0].Name, "."))
	if domain == "" {
		return
	}
	for _, shared := range []bool{false, true} {
		state, _, _ := i.ruleSetScope(shared)
		matcher := state.domainMatcher.Load()
		if matcher == nil || !matcher.match(domain) {
			continue
		}
		changed := false
		for _, answer := range response.Answer {
			var (
				address netip.Addr
				ttl     uint32
			)
			switch record := answer.(type) {
			case *mDNS.A:
				address, _ = netip.AddrFromSlice(record.A.To4())
				ttl = record.Hdr.Ttl
			case *mDNS.AAAA:
				address, _ = netip.AddrFromSlice(record.AAAA)
				ttl = record.Hdr.Ttl
			default:
				continue
			}
			if !i.bypassLearnable(shared, address) {
				continue
			}
			if state.learned.learn(address, domain, bypassLearnedLifetime(ttl)) {
				changed = true
			}
		}
		if changed {
			i.markBypassLearnedDirty(shared)
		}
	}
}

// bypassLearnable rejects addresses the scope must keep intercepting: FakeIP
// addresses have no real host, and bypass_exclude prefixes are forced in.
func (i *Inbound) bypassLearnable(shared bool, address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	if i.fakeIPIPv4Prefix.IsValid() && i.fakeIPIPv4Prefix.Contains(address) ||
		i.fakeIPIPv6Prefix.IsValid() && i.fakeIPIPv6Prefix.Contains(address) {
		return false
	}
	exclude := i.localBypassExclude
	if shared {
		exclude = i.sharedBypassExclude
	}
	for _, prefix := range exclude {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func (i *Inbound) markBypassLearnedDirty(shared bool) {
	i.bypassRuleSetAccess.Lock()
	state, _, _ := i.ruleSetScope(shared)
	if !state.started {
		i.bypassRuleSetAccess.Unlock()
		return
	}
	state.dirty = true
	state.learnedDirty = true
	i.bypassRuleSetAccess.Unlock()
	select {
	case i.policyWake <- struct{}{}:
	default:
	}
}

func (i *Inbound) sweepBypassLearned() {
	for _, shared := range []bool{false, true} {
		state, _, _ := i.ruleSetScope(shared)
		if state.learned != nil && state.learned.sweep() {
			i.markBypassLearnedDirty(shared)
		}
	}
}

// preRouteBypass returns the userspace bypass of a scope for a connection the
// data plane intercepted, or nil when the kernel enforces the whole policy.
func (i *Inbound) preRouteBypass(shared bool) *adapter.PreRouteBypass {
	state, _, _ := i.ruleSetScope(shared)
	return state.preRouteBypass.Load()
}

func (s *bypassRuleSetState) fillDiagnostics(diagnostics *scopedBypassRuleSetDiagnostics) {
	diagnostics.KernelPrefixes = len(s.plan.prefixes)
	if s.learned != nil {
		diagnostics.LearnedAddresses = s.learned.len()
	}
	diagnostics.UserspaceMatching = s.preRouteBypass.Load() != nil
	diagnostics.UserspaceBypasses = s.userspaceBypasses.Load()
}
