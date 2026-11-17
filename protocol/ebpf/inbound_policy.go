//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	commonEBPF "github.com/MiChongs/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
	"go4.org/netipx"
)

// Each scope owns its callbacks, expected generation, confirmed generation and
// retry state. A failed apply never advances the confirmed policy.
type bypassRuleSetState struct {
	ruleSets                                   []adapter.RuleSet
	callbacks                                  []*list.Element[adapter.RuleSetUpdateCallback]
	started                                    bool
	policy, expectedPolicy                     []commonEBPF.CIDRDecision
	policyVersion, expectedVersion, retryCount uint64
	generation, appliedGeneration              uint64
	dirty                                      bool
	needsRetry, inconsistent                   bool
	tc, cgroup, shared                         bypassRuleSetBackendVersion

	// plan is recompiled when the rule-sets change (generation moves);
	// learned-address changes reuse it.
	plan           bypassScopePlan
	planGeneration uint64
	planValid      bool
	learned        *bypassLearnedTable
	learnedDirty   bool
	// domainMatcher and preRouteBypass are read without the rule-set lock by
	// the DNS path and the connection path.
	domainMatcher     atomic.Pointer[bypassDomainMatcher]
	preRouteBypass    atomic.Pointer[adapter.PreRouteBypass]
	userspaceBypasses atomic.Uint64
}

type bypassRuleSetBackendVersion struct {
	version uint64
	known   bool
}

type destinationDecisionApply func([]commonEBPF.CIDRDecision) (bool, error)
type bypassPolicyBackend struct {
	name            string
	apply           destinationDecisionApply
	requiresRebuild func() bool
	state           *bypassRuleSetBackendVersion
}
type bypassCIDRAppliedBackend struct {
	name   string
	revert func() error
}

func (i *Inbound) policyBackends(shared bool) []bypassPolicyBackend {
	var targets []bypassPolicyBackend
	if shared {
		if backend := i.tcBackend(); i.sharedSocketAssignEnabled() && backend != nil {
			targets = append(targets, bypassPolicyBackend{"TC", backend.UpdateSharedDestinationDecisions, backend.RequiresRebuild, &i.sharedBypassRules.tc})
		}
		if runtime := i.sharedRewriteInstance(); i.sharedRewriteEnabled() && runtime != nil {
			if backend := runtime.sharedBackendInstance(); backend != nil {
				targets = append(targets, bypassPolicyBackend{"packet_rewrite", backend.UpdateDestinationDecisions, backend.RequiresRebuild, &i.sharedBypassRules.shared})
			}
		}
	} else {
		if backend := i.tcBackend(); i.localSocketAssignEnabled() && backend != nil {
			targets = append(targets, bypassPolicyBackend{"TC", backend.UpdateLocalDestinationDecisions, backend.RequiresRebuild, &i.localBypassRules.tc})
		}
		if backend := i.cgroupBackendInstance(); i.localCgroupEnabled() && backend != nil {
			targets = append(targets, bypassPolicyBackend{"cgroup", backend.UpdateDestinationDecisions, backend.RequiresRebuild, &i.localBypassRules.cgroup})
		}
	}
	return targets
}

func (i *Inbound) ruleSetScope(shared bool) (*bypassRuleSetState, string, []commonEBPF.CIDRDecision) {
	if shared {
		return &i.sharedBypassRules, "shared.bypass_rule_set", i.sharedInitialDestinations
	}
	return &i.localBypassRules, "local.bypass_rule_set", i.localInitialDestinations
}

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	for _, shared := range []bool{false, true} {
		state, _, _ := i.ruleSetScope(shared)
		if state.started {
			continue
		}
		for _, ruleSet := range state.ruleSets {
			ruleSet.IncRef()
			state.callbacks = append(state.callbacks, ruleSet.RegisterCallback(func(adapter.RuleSet) { i.updateRuleSet(shared) }))
		}
		state.started = true
		if err := i.refreshRuleSetsLocked(shared, true); err != nil {
			i.stopBypassRuleSetsLocked()
			i.bypassRuleSetAccess.Unlock()
			return err
		}
	}
	i.startBypassDNSObserverLocked()
	i.startBypassRuleSetWorkerLocked()
	i.bypassRuleSetAccess.Unlock()
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.stopBypassRuleSetWorker()
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) startBypassRuleSetWorkerLocked() {
	if i.policyCancel != nil || i.policyWake == nil {
		return
	}
	ctx, cancel := context.WithCancel(i.ctx)
	i.policyCancel = cancel
	i.policyDone = make(chan struct{})
	go i.bypassRuleSetWorker(ctx, i.policyDone)
}

func (i *Inbound) stopBypassRuleSetWorker() {
	i.bypassRuleSetAccess.Lock()
	cancel, done := i.policyCancel, i.policyDone
	i.policyCancel = nil
	i.policyDone = nil
	i.bypassRuleSetAccess.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (i *Inbound) bypassRuleSetWorker(ctx context.Context, done chan struct{}) {
	defer close(done)
	sweepTicker := time.NewTicker(bypassLearnedSweepInterval)
	defer sweepTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweepTicker.C:
			i.sweepBypassLearned()
			continue
		case <-i.policyWake:
		}
		if !i.refreshDirtyRuleSets() {
			continue
		}
		// DNS answers arrive in bursts; let them accumulate into the next
		// kernel update instead of rebuilding the policy for each one.
		cooldown := time.NewTimer(bypassLearnedRefreshCooldown)
		select {
		case <-ctx.Done():
			cooldown.Stop()
			return
		case <-cooldown.C:
		}
	}
}

// refreshDirtyRuleSets reports whether a learned-address change was applied.
func (i *Inbound) refreshDirtyRuleSets() (learned bool) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	for _, shared := range []bool{false, true} {
		state, name, _ := i.ruleSetScope(shared)
		if !state.started || !state.dirty {
			continue
		}
		learned = learned || state.learnedDirty
		state.dirty = false
		if err := i.refreshRuleSetsLocked(shared, false); err != nil {
			state.needsRetry = true
			i.policyWarnings.warn(i.logger, "refresh ", name, ": ", err)
			i.notifyTCInterfaceUpdate()
		}
	}
	return
}
func (i *Inbound) stopBypassRuleSetsLocked() {
	i.stopBypassDNSObserverLocked()
	for _, state := range []*bypassRuleSetState{&i.localBypassRules, &i.sharedBypassRules} {
		if !state.started {
			continue
		}
		for index, ruleSet := range state.ruleSets {
			ruleSet.UnregisterCallback(state.callbacks[index])
			ruleSet.DecRef()
		}
		state.callbacks = nil
		state.started = false
		state.planValid = false
		state.domainMatcher.Store(nil)
		state.preRouteBypass.Store(nil)
	}
}

func (i *Inbound) updateBypassRuleSet(adapter.RuleSet)       { i.updateRuleSet(false) }
func (i *Inbound) updateSharedBypassRuleSet(adapter.RuleSet) { i.updateRuleSet(true) }
func (i *Inbound) updateRuleSet(shared bool) {
	i.bypassRuleSetAccess.Lock()
	state, _, _ := i.ruleSetScope(shared)
	if !state.started {
		i.bypassRuleSetAccess.Unlock()
		return
	}
	state.generation++
	state.dirty = true
	i.bypassRuleSetAccess.Unlock()
	select {
	case i.policyWake <- struct{}{}:
	default:
	}
}

func (i *Inbound) retryBypassRuleSetIfNeededLocked() tcSharedRewriteOutcome {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	return max(i.retryRuleSetLocked(false), i.retryRuleSetLocked(true))
}
func (i *Inbound) retryLocalBypassRuleSetIfNeededLocked() tcSharedRewriteOutcome {
	return i.retryRuleSetLocked(false)
}
func (i *Inbound) retryRuleSetLocked(shared bool) tcSharedRewriteOutcome {
	state, name, _ := i.ruleSetScope(shared)
	if !state.started {
		return tcSharedRewriteSettled
	}
	requiresRebuild := func() bool {
		for _, backend := range i.policyBackends(shared) {
			if backend.requiresRebuild() {
				return true
			}
		}
		return false
	}
	if requiresRebuild() {
		state.needsRetry = false
		return tcSharedRewriteUnrecoverable
	}
	if !state.needsRetry {
		return tcSharedRewriteSettled
	}
	state.retryCount++
	if err := i.refreshRuleSetsLocked(shared, false); err != nil {
		i.policyWarnings.warn(i.logger, "retry ", name, ": ", err)
		if requiresRebuild() {
			state.needsRetry = false
			return tcSharedRewriteUnrecoverable
		}
		return tcSharedRewriteRecoverable
	}
	state.needsRetry = false
	return tcSharedRewriteSettled
}

func (i *Inbound) refreshBypassRuleSetsLocked(startup bool) error {
	return i.refreshRuleSetsLocked(false, startup)
}
func (i *Inbound) refreshSharedBypassRuleSetsLocked(startup bool) error {
	return i.refreshRuleSetsLocked(true, startup)
}
func (i *Inbound) refreshRuleSetsLocked(shared, startup bool) error {
	state, name, initial := i.ruleSetScope(shared)
	if startup || !state.planValid || state.planGeneration != state.generation {
		i.updateBypassScopePlanLocked(state, name, startup)
	}
	state.learnedDirty = false
	prefixes := slices.Clone(state.plan.prefixes)
	if state.learned != nil {
		prefixes = append(prefixes, state.learned.prefixes()...)
	}
	dynamic, err := i.compileBypassCIDRDecisions(prefixes)
	if err != nil {
		return err
	}
	policy, err := i.combineDestinationDecisions(initial, dynamic)
	if err != nil {
		return err
	}
	if err := i.applyRuleSetPolicyLocked(shared, policy); err != nil {
		return err
	}
	state.appliedGeneration = state.generation
	return nil
}

// updateBypassScopePlanLocked recompiles a scope's rule-sets into kernel
// prefixes, the DNS learning matcher and the userspace bypass.
func (i *Inbound) updateBypassScopePlanLocked(state *bypassRuleSetState, name string, startup bool) {
	plan := compileBypassScopePlan(state.ruleSets)
	state.plan = plan
	state.planGeneration = state.generation
	state.planValid = true
	if state.learned != nil {
		state.learned.retain(plan.matchDomain)
	}
	if plan.matchDomain != nil {
		state.domainMatcher.Store(&bypassDomainMatcher{match: plan.matchDomain})
	} else {
		state.domainMatcher.Store(nil)
	}
	if (plan.userspace || plan.matchDomain != nil) && i.bypassOutbound != nil && len(state.ruleSets) > 0 {
		bypass := &adapter.PreRouteBypass{
			Rule:        &bypassRuleSetMatcher{ruleSets: state.ruleSets, matched: &state.userspaceBypasses},
			Outbound:    i.bypassOutbound,
			Description: "ebpf " + name,
			NeedDomain:  plan.needDomain,
		}
		if learned := state.learned; learned != nil {
			bypass.LookupDomain = learned.lookup
		}
		state.preRouteBypass.Store(bypass)
	} else {
		state.preRouteBypass.Store(nil)
	}
	if startup && len(state.ruleSets) > 0 {
		i.logger.Info(name, ": ", len(plan.prefixes), " destination prefixes enforced in kernel, domain learning ",
			enabledString(plan.matchDomain != nil), ", userspace matching ", enabledString(plan.userspace || plan.matchDomain != nil))
	}
}

func enabledString(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}

func revertBypassCIDRBackends(applied []bypassCIDRAppliedBackend, warn func(string, error)) []string {
	var failed []string
	for index := len(applied) - 1; index >= 0; index-- {
		if err := applied[index].revert(); err != nil {
			failed = append(failed, applied[index].name)
			warn(applied[index].name, err)
		}
	}
	return failed
}
func (i *Inbound) applyBypassCIDRPolicyLocked(policy []commonEBPF.CIDRDecision) error {
	return i.applyRuleSetPolicyLocked(false, policy)
}
func (i *Inbound) applySharedBypassCIDRPolicyLocked(policy []commonEBPF.CIDRDecision) error {
	return i.applyRuleSetPolicyLocked(true, policy)
}
func (i *Inbound) applyRuleSetPolicyLocked(shared bool, policy []commonEBPF.CIDRDecision) error {
	state, name, _ := i.ruleSetScope(shared)
	return i.applyRuleSetPolicyToBackends(state, name, policy, i.policyBackends(shared))
}

func (i *Inbound) applyRuleSetPolicyToBackends(state *bypassRuleSetState, name string, policy []commonEBPF.CIDRDecision, targets []bypassPolicyBackend) error {
	if !reflect.DeepEqual(state.expectedPolicy, policy) {
		state.expectedVersion++
	}
	state.expectedPolicy = policy
	var applied []bypassCIDRAppliedBackend
	for _, backend := range targets {
		if _, err := backend.apply(policy); err != nil {
			if backend.requiresRebuild() {
				backend.state.known = false
				state.inconsistent = true
			}
			failed := revertBypassCIDRBackends(applied, func(target string, err error) {
				i.policyWarnings.warn(i.logger, name, ": revert ", target, ": ", err)
			})
			if len(failed) > 0 {
				state.inconsistent = true
				return E.Cause(err, name+" left inconsistent on: "+strings.Join(failed, ", "))
			}
			return err
		}
		*backend.state = bypassRuleSetBackendVersion{version: state.expectedVersion, known: true}
		applied = append(applied, bypassCIDRAppliedBackend{name: backend.name, revert: func() error {
			if _, err := backend.apply(state.policy); err != nil {
				backend.state.known = false
				return err
			}
			*backend.state = bypassRuleSetBackendVersion{version: state.policyVersion, known: true}
			return nil
		}})
	}
	state.policy, state.policyVersion = policy, state.expectedVersion
	state.inconsistent = false
	return nil
}

func (i *Inbound) compileBypassCIDRDecisions(prefixes []netip.Prefix) ([]commonEBPF.CIDRDecision, error) {
	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		builder.AddPrefix(prefix.Masked())
	}
	set, err := builder.IPSet()
	if err != nil {
		return nil, E.Cause(err, "compile eBPF bypass CIDR decisions")
	}
	canonical := set.Prefixes()
	decisions := make([]commonEBPF.CIDRDecision, 0, len(canonical))
	for _, prefix := range canonical {
		decisions = append(decisions, commonEBPF.CIDRDecision{Prefix: prefix, Action: commonEBPF.DecisionPass})
	}
	return decisions, nil
}

func (i *Inbound) combineDestinationDecisions(
	static, dynamic []commonEBPF.CIDRDecision,
) ([]commonEBPF.CIDRDecision, error) {
	prefixes := make([]netip.Prefix, 0, len(static)+len(dynamic))
	for _, decision := range append(append([]commonEBPF.CIDRDecision(nil), static...), dynamic...) {
		if decision.Action != commonEBPF.DecisionPass || !decision.Prefix.IsValid() {
			return nil, E.New("invalid eBPF destination pass decision")
		}
		prefixes = append(prefixes, decision.Prefix)
	}
	return i.compileBypassCIDRDecisions(prefixes)
}
