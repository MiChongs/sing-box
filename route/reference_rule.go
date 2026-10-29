package route

import (
	"reflect"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type staticMatch uint8

const (
	staticMatchUnknown staticMatch = iota
	staticMatchNever
	staticMatchAlways
)

func (m staticMatch) invert() staticMatch {
	switch m {
	case staticMatchNever:
		return staticMatchAlways
	case staticMatchAlways:
		return staticMatchNever
	default:
		return staticMatchUnknown
	}
}

func evaluateClashMode(clashModes []string, mode string, invert bool, otherConditions bool) staticMatch {
	match := staticMatchUnknown
	if len(clashModes) > 0 && !slices.ContainsFunc(clashModes, func(clashMode string) bool { return strings.EqualFold(clashMode, mode) }) {
		match = staticMatchNever
	} else if !otherConditions {
		match = staticMatchAlways
	}
	if invert {
		match = match.invert()
	}
	return match
}

// staticCondition is the clash-mode-only view of a rule's conditions, compiled
// once so reference collection does not deep-compare rule options on every
// outbound or clash-mode change.
type staticCondition struct {
	clashModes      []string
	invert          bool
	otherConditions bool
	logicalMode     string
	subRules        []staticCondition
	unknown         bool
}

func (c *staticCondition) evaluate(mode string) staticMatch {
	if c.unknown {
		return staticMatchUnknown
	}
	if c.logicalMode == "" {
		return evaluateClashMode(c.clashModes, mode, c.invert, c.otherConditions)
	}
	var match staticMatch
	if c.logicalMode == C.LogicalTypeAnd {
		match = staticMatchAlways
	} else {
		match = staticMatchNever
	}
	for i := range c.subRules {
		ruleMatch := c.subRules[i].evaluate(mode)
		if c.logicalMode == C.LogicalTypeAnd && ruleMatch == staticMatchNever {
			match = staticMatchNever
			break
		}
		if c.logicalMode == C.LogicalTypeOr && ruleMatch == staticMatchAlways {
			match = staticMatchAlways
			break
		}
		if ruleMatch == staticMatchUnknown {
			match = staticMatchUnknown
		}
	}
	if c.invert {
		match = match.invert()
	}
	return match
}

func compileRuleCondition(rule option.Rule) staticCondition {
	switch rule.Type {
	case C.RuleTypeDefault:
		conditions := rule.DefaultOptions.RawDefaultRule
		conditions.ClashMode = nil
		conditions.Invert = false
		return staticCondition{
			clashModes:      rule.DefaultOptions.ClashMode,
			invert:          rule.DefaultOptions.Invert,
			otherConditions: !reflect.DeepEqual(conditions, option.RawDefaultRule{}),
		}
	case C.RuleTypeLogical:
		subRules := make([]staticCondition, 0, len(rule.LogicalOptions.Rules))
		for _, subRule := range rule.LogicalOptions.Rules {
			subRules = append(subRules, compileRuleCondition(subRule))
		}
		return staticCondition{
			invert:      rule.LogicalOptions.Invert,
			logicalMode: rule.LogicalOptions.Mode,
			subRules:    subRules,
		}
	default:
		return staticCondition{unknown: true}
	}
}

func compileDNSRuleCondition(rule option.DNSRule) staticCondition {
	switch rule.Type {
	case C.RuleTypeDefault:
		conditions := rule.DefaultOptions.RawDefaultDNSRule
		conditions.ClashMode = nil
		conditions.Invert = false
		return staticCondition{
			clashModes:      rule.DefaultOptions.ClashMode,
			invert:          rule.DefaultOptions.Invert,
			otherConditions: !reflect.DeepEqual(conditions, option.RawDefaultDNSRule{}),
		}
	case C.RuleTypeLogical:
		subRules := make([]staticCondition, 0, len(rule.LogicalOptions.Rules))
		for _, subRule := range rule.LogicalOptions.Rules {
			subRules = append(subRules, compileDNSRuleCondition(subRule))
		}
		return staticCondition{
			invert:      rule.LogicalOptions.Invert,
			logicalMode: rule.LogicalOptions.Mode,
			subRules:    subRules,
		}
	default:
		return staticCondition{unknown: true}
	}
}

type routeReferenceRule struct {
	condition staticCondition
	action    *option.RuleAction
}

type dnsReferenceRule struct {
	condition staticCondition
	action    *option.DNSRuleAction
}

func compileRouteReferenceRules(rules []option.Rule) []routeReferenceRule {
	compiled := make([]routeReferenceRule, len(rules))
	for i := range rules {
		compiled[i].condition = compileRuleCondition(rules[i])
		switch rules[i].Type {
		case C.RuleTypeDefault:
			compiled[i].action = &rules[i].DefaultOptions.RuleAction
		case C.RuleTypeLogical:
			compiled[i].action = &rules[i].LogicalOptions.RuleAction
		default:
			compiled[i].action = &option.RuleAction{}
		}
	}
	return compiled
}

func compileDNSReferenceRules(rules []option.DNSRule) []dnsReferenceRule {
	compiled := make([]dnsReferenceRule, len(rules))
	for i := range rules {
		compiled[i].condition = compileDNSRuleCondition(rules[i])
		switch rules[i].Type {
		case C.RuleTypeDefault:
			compiled[i].action = &rules[i].DefaultOptions.DNSRuleAction
		case C.RuleTypeLogical:
			compiled[i].action = &rules[i].LogicalOptions.DNSRuleAction
		default:
			compiled[i].action = &option.DNSRuleAction{}
		}
	}
	return compiled
}

func collectRuleReferences(rules []routeReferenceRule, mode string, manager adapter.OutboundManager, outbounds *[]string, transports *[]string) (shadowed bool) {
	for i := range rules {
		match := rules[i].condition.evaluate(mode)
		if match == staticMatchNever {
			continue
		}
		action := rules[i].action
		var final bool
		switch action.Action {
		case C.RuleActionTypeRoute:
			*outbounds = append(*outbounds, action.RouteOptions.Outbound)
			final = !isPassOutbound(manager, action.RouteOptions.Outbound)
		case C.RuleActionTypeBypass:
			if action.BypassOptions.Outbound != "" {
				*outbounds = append(*outbounds, action.BypassOptions.Outbound)
				final = true
			}
		case C.RuleActionTypeReject, C.RuleActionTypeHijackDNS:
			final = true
		case C.RuleActionTypeResolve:
			*transports = append(*transports, action.ResolveOptions.Server)
		}
		if final && match == staticMatchAlways {
			return true
		}
	}
	return false
}

func collectDNSRuleReferences(rules []dnsReferenceRule, mode string, transports *[]string) (shadowed bool) {
	for i := range rules {
		match := rules[i].condition.evaluate(mode)
		if match == staticMatchNever {
			continue
		}
		action := rules[i].action
		var final bool
		switch action.Action {
		case C.RuleActionTypeRoute:
			*transports = append(*transports, action.RouteOptions.Server)
			final = true
		case C.RuleActionTypeEvaluate:
			*transports = append(*transports, action.EvaluateOptions.Server)
		case C.RuleActionTypeRespond, C.RuleActionTypeReject, C.RuleActionTypePredefined:
			final = true
		}
		if final && match == staticMatchAlways {
			return true
		}
	}
	return false
}
