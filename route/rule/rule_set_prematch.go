package rule

import (
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"go4.org/netipx"
)

var _ adapter.RuleSetPreMatchPlanner = (*abstractRuleSet)(nil)

func (s *abstractRuleSet) PreMatchPlan() adapter.RuleSetPreMatchPlan {
	s.access.RLock()
	rules := s.rules
	metadata := s.metadata
	s.access.RUnlock()
	plan := buildPreMatchPlan(rules)
	plan.NeedProcess = metadata.ContainsProcessRule
	return plan
}

type preMatchPlanBuilder struct {
	ipSets      []*netipx.IPSet
	domainRules []*DefaultHeadlessRule
	residual    bool
	needDomain  bool
}

func buildPreMatchPlan(rules []adapter.HeadlessRule) adapter.RuleSetPreMatchPlan {
	var builder preMatchPlanBuilder
	for _, rule := range rules {
		builder.add(rule)
	}
	plan := adapter.RuleSetPreMatchPlan{
		DestinationIPSets: builder.ipSets,
		Residual:          builder.residual,
		NeedDomain:        builder.needDomain,
	}
	if domainRules := builder.domainRules; len(domainRules) > 0 {
		plan.MatchDomain = func(domain string) bool {
			if domain == "" {
				return false
			}
			metadata := adapter.InboundContext{
				Destination: M.Socksaddr{Fqdn: domain},
				Domain:      domain,
				SniffHost:   domain,
			}
			for _, rule := range domainRules {
				if matchAnyItem(rule.destinationAddressItems, &metadata) {
					return true
				}
			}
			return false
		}
	}
	return plan
}

func (b *preMatchPlanBuilder) add(rawRule adapter.HeadlessRule) {
	switch rule := rawRule.(type) {
	case *DefaultHeadlessRule:
		if len(rule.destinationAddressItems) > 0 {
			b.needDomain = true
		}
		if rule.invert || len(rule.items) > 0 || len(rule.sourceAddressItems) > 0 ||
			len(rule.sourcePortItems) > 0 || len(rule.destinationPortItems) > 0 ||
			len(rule.destinationAddressItems)+len(rule.destinationIPCIDRItems) == 0 {
			b.residual = true
			return
		}
		var ipSets []*netipx.IPSet
		for _, rawItem := range rule.destinationIPCIDRItems {
			item, isIPCIDR := rawItem.(*IPCIDRItem)
			if !isIPCIDR || item.isSource {
				b.residual = true
				return
			}
			ipSets = append(ipSets, item.ipSet.IPSet())
		}
		b.ipSets = append(b.ipSets, ipSets...)
		if len(rule.destinationAddressItems) > 0 {
			b.domainRules = append(b.domainRules, rule)
		}
	case *LogicalHeadlessRule:
		if rule.invert || rule.mode != C.LogicalTypeOr {
			b.residual = true
			if containsDomainRule(rule) {
				b.needDomain = true
			}
			return
		}
		for _, child := range rule.rules {
			b.add(child)
		}
	default:
		b.residual = true
	}
}

func containsDomainRule(rawRule adapter.HeadlessRule) bool {
	switch rule := rawRule.(type) {
	case *DefaultHeadlessRule:
		return len(rule.destinationAddressItems) > 0
	case *LogicalHeadlessRule:
		for _, child := range rule.rules {
			if containsDomainRule(child) {
				return true
			}
		}
	}
	return false
}
