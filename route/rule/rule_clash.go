package rule

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/miekg/dns"
)

// Clash API 按 mihomo 的形式展示规则：类型对应 mihomo C.RuleType.String()，
// 载荷对应 Rule.Payload()，多个条件按 mihomo rules/logic 的 AND / OR / NOT
// 载荷格式组合，目标对应 Rule.Adapter()。sing-box 特有的条件沿用同样的驼峰命名。
const (
	clashRuleTypeDomain                  = "Domain"
	clashRuleTypeDomainSuffix            = "DomainSuffix"
	clashRuleTypeDomainKeyword           = "DomainKeyword"
	clashRuleTypeDomainRegex             = "DomainRegex"
	clashRuleTypeAdGuardDomain           = "AdGuardDomain"
	clashRuleTypeGeoIP                   = "GeoIP"
	clashRuleTypeSrcGeoIP                = "SrcGeoIP"
	clashRuleTypeIPCIDR                  = "IPCIDR"
	clashRuleTypeSrcIPCIDR               = "SrcIPCIDR"
	clashRuleTypeIPAcceptAny             = "IPAcceptAny"
	clashRuleTypeIPVersion               = "IPVersion"
	clashRuleTypeSrcPort                 = "SrcPort"
	clashRuleTypeDstPort                 = "DstPort"
	clashRuleTypeInName                  = "InName"
	clashRuleTypeInUser                  = "InUser"
	clashRuleTypeNetwork                 = "Network"
	clashRuleTypeProtocol                = "Protocol"
	clashRuleTypeClient                  = "Client"
	clashRuleTypeProcessName             = "ProcessName"
	clashRuleTypeProcessPath             = "ProcessPath"
	clashRuleTypeProcessPathRegex        = "ProcessPathRegex"
	clashRuleTypePackageName             = "PackageName"
	clashRuleTypePackageNameRegex        = "PackageNameRegex"
	clashRuleTypeUser                    = "User"
	clashRuleTypeUid                     = "Uid"
	clashRuleTypeOutbound                = "Outbound"
	clashRuleTypeClashMode               = "ClashMode"
	clashRuleTypeNetworkType             = "NetworkType"
	clashRuleTypeNetworkIsExpensive      = "NetworkIsExpensive"
	clashRuleTypeNetworkIsConstrained    = "NetworkIsConstrained"
	clashRuleTypeWiFiSSID                = "WiFiSSID"
	clashRuleTypeWiFiBSSID               = "WiFiBSSID"
	clashRuleTypeInterfaceAddress        = "InterfaceAddress"
	clashRuleTypeNetworkInterfaceAddress = "NetworkInterfaceAddress"
	clashRuleTypeDefaultInterfaceAddress = "DefaultInterfaceAddress"
	clashRuleTypeSrcMACAddress           = "SrcMACAddress"
	clashRuleTypeSrcHostname             = "SrcHostname"
	clashRuleTypePreferredBy             = "PreferredBy"
	clashRuleTypeDNSServerAddress        = "DNSServerAddress"
	clashRuleTypeDNSSearchDomain         = "DNSSearchDomain"
	clashRuleTypeQueryType               = "QueryType"
	clashRuleTypeQueryClientSubnet       = "QueryClientSubnet"
	clashRuleTypeQueryDNSSEC             = "QueryDNSSEC"
	clashRuleTypeResponseRcode           = "ResponseRcode"
	clashRuleTypeResponseAnswer          = "ResponseAnswer"
	clashRuleTypeResponseNs              = "ResponseNs"
	clashRuleTypeResponseExtra           = "ResponseExtra"
	clashRuleTypeRuleSet                 = "RuleSet"
	clashRuleTypeMatch                   = "Match"
	clashRuleTypeAnd                     = "AND"
	clashRuleTypeOr                      = "OR"
	clashRuleTypeNot                     = "NOT"
	clashRuleTypeUnknown                 = "Unknown"
)

type clashRule struct {
	ruleType string
	payload  string
}

type clashRuleDescriber interface {
	clashRule() clashRule
}

// ClashRule 返回规则在 Clash API 中的类型与载荷，对应 mihomo C.Rule 的
// RuleType().String() 与 Payload()。结果在首次调用时生成并缓存。
func ClashRule(rule adapter.HeadlessRule) (ruleType string, payload string) {
	described := clashRuleOf(rule)
	return described.ruleType, described.payload
}

// ClashProxy 返回规则动作在 Clash API 中的目标，对应 mihomo Rule.Adapter()：
// 指向出站或 DNS 服务器的动作返回其标签，其余动作返回大写的动作名，
// 与 mihomo 内置的 DIRECT / REJECT / REJECT-DROP 写法一致。
func ClashProxy(action adapter.RuleAction) string {
	switch action := action.(type) {
	case *RuleActionRoute:
		return action.Outbound
	case *RuleActionBypass:
		if action.Outbound != "" {
			return action.Outbound
		}
	case *RuleActionDNSRoute:
		return action.Server
	case *RuleActionEvaluate:
		return action.Server
	case *RuleActionReject:
		if action.Method == C.RuleActionRejectMethodDrop {
			return "REJECT-DROP"
		}
	}
	return strings.ToUpper(action.Type())
}

func clashRuleOf(rule adapter.HeadlessRule) clashRule {
	if describer, isDescriber := rule.(clashRuleDescriber); isDescriber {
		return describer.clashRule()
	}
	return clashRule{clashRuleTypeUnknown, rule.String()}
}

func (r *abstractDefaultRule) clashRule() clashRule {
	r.clashOnce.Do(func() {
		r.clash = r.buildClashRule()
	})
	return r.clash
}

// buildClashRule 按 sing-box 的匹配逻辑组合条件：源地址、源端口、目标地址
// (含 ip_cidr)、目标端口各自组内为 OR，组与其余条件之间为 AND；条件按配置中的
// 先后顺序排列，同组条件出现在该组首个条件的位置。
func (r *abstractDefaultRule) buildClashRule() clashRule {
	var (
		conditions [][]clashRule
		groupIndex = make(map[ruleMatchState]int)
	)
	for _, item := range r.allItems {
		rules := clashItemRules(item)
		group := r.clashGroupOf(item)
		if group != 0 {
			if index, loaded := groupIndex[group]; loaded {
				conditions[index] = append(conditions[index], rules...)
				continue
			}
			groupIndex[group] = len(conditions)
		}
		conditions = append(conditions, rules)
	}
	components := make([]clashRule, 0, len(conditions))
	for _, rules := range conditions {
		if len(rules) > 0 {
			components = append(components, clashAny(rules))
		}
	}
	var described clashRule
	switch len(components) {
	case 0:
		described = clashRule{clashRuleTypeMatch, ""}
	case 1:
		described = components[0]
	default:
		described = clashLogic(clashRuleTypeAnd, components)
	}
	if r.invert {
		return clashNot(described)
	}
	return described
}

func (r *abstractDefaultRule) clashGroupOf(item RuleItem) ruleMatchState {
	switch {
	case slices.Contains(r.sourceAddressItems, item):
		return ruleMatchSourceAddress
	case slices.Contains(r.sourcePortItems, item):
		return ruleMatchSourcePort
	case slices.Contains(r.destinationAddressItems, item), slices.Contains(r.destinationIPCIDRItems, item):
		return ruleMatchDestinationAddress
	case slices.Contains(r.destinationPortItems, item):
		return ruleMatchDestinationPort
	default:
		return 0
	}
}

func (r *abstractLogicalRule) clashRule() clashRule {
	r.clashOnce.Do(func() {
		rules := make([]clashRule, 0, len(r.rules))
		for _, rule := range r.rules {
			rules = append(rules, clashRuleOf(rule))
		}
		ruleType := clashRuleTypeAnd
		if r.mode == C.LogicalTypeOr {
			ruleType = clashRuleTypeOr
		}
		r.clash = clashLogic(ruleType, rules)
		if r.invert {
			r.clash = clashNot(r.clash)
		}
	})
	return r.clash
}

// clashAny 组合同一组内的条件 (OR)：mihomo 原生以 "/" 分隔多值的类型合并为
// 一条，只剩一条时直接返回该条件。
func clashAny(rules []clashRule) clashRule {
	merged := make([]clashRule, 0, len(rules))
	for _, rule := range rules {
		if clashJoinable(rule.ruleType) {
			index := slices.IndexFunc(merged, func(it clashRule) bool {
				return it.ruleType == rule.ruleType
			})
			if index >= 0 {
				merged[index].payload += "/" + rule.payload
				continue
			}
		}
		merged = append(merged, rule)
	}
	if len(merged) == 1 {
		return merged[0]
	}
	return clashLogic(clashRuleTypeOr, merged)
}

// clashJoinable 报告该类型的多个值能否以 "/" 合并：mihomo 的 IN-NAME、IN-USER、
// DST-PORT、SRC-PORT、UID 原生支持，sing-box 特有的枚举型条件沿用该写法；
// 其余类型的值可能含 "/"（CIDR、路径、正则）或 mihomo 只接受单值，展开为 OR。
func clashJoinable(ruleType string) bool {
	switch ruleType {
	case clashRuleTypeInName, clashRuleTypeInUser, clashRuleTypeDstPort, clashRuleTypeSrcPort, clashRuleTypeUid,
		clashRuleTypeProtocol, clashRuleTypeClient, clashRuleTypeClashMode, clashRuleTypeNetworkType, clashRuleTypeQueryType:
		return true
	default:
		return false
	}
}

// clashLogic 同 mihomo Logic.Payload：AND 为 "((T1,P1) && (T2,P2))"，OR 以 " || " 连接。
func clashLogic(ruleType string, rules []clashRule) clashRule {
	separator := " && "
	if ruleType == clashRuleTypeOr {
		separator = " || "
	}
	var payload strings.Builder
	payload.WriteByte('(')
	for index, rule := range rules {
		if index > 0 {
			payload.WriteString(separator)
		}
		rule.writeSubRule(&payload)
	}
	payload.WriteByte(')')
	return clashRule{ruleType, payload.String()}
}

// clashNot 同 mihomo Logic.Payload 的 NOT 形式 "(!(T,P))"。
func clashNot(rule clashRule) clashRule {
	var payload strings.Builder
	payload.WriteString("(!")
	rule.writeSubRule(&payload)
	payload.WriteByte(')')
	return clashRule{clashRuleTypeNot, payload.String()}
}

func (r clashRule) writeSubRule(builder *strings.Builder) {
	builder.WriteByte('(')
	builder.WriteString(r.ruleType)
	builder.WriteByte(',')
	builder.WriteString(r.payload)
	builder.WriteByte(')')
}

func clashRules[T any](ruleType string, values []T, format func(T) string) []clashRule {
	rules := make([]clashRule, 0, len(values))
	for _, value := range values {
		rules = append(rules, clashRule{ruleType, format(value)})
	}
	return rules
}

func clashStrings(ruleType string, values []string) []clashRule {
	return clashRules(ruleType, values, func(it string) string { return it })
}

func clashFlag(ruleType string) []clashRule {
	return []clashRule{{ruleType, ""}}
}

func clashItemRules(item RuleItem) []clashRule {
	switch item := item.(type) {
	case *DomainItem:
		domains, domainSuffixes := item.domains, item.domainSuffixes
		if domains == nil && domainSuffixes == nil {
			domains, domainSuffixes = item.matcher.Dump()
		}
		return append(clashStrings(clashRuleTypeDomain, domains), clashStrings(clashRuleTypeDomainSuffix, domainSuffixes)...)
	case *DomainKeywordItem:
		return clashStrings(clashRuleTypeDomainKeyword, item.keywords)
	case *DomainRegexItem:
		return clashRules(clashRuleTypeDomainRegex, item.matchers, (*regexp.Regexp).String)
	case *AdGuardDomainItem:
		return clashFlag(clashRuleTypeAdGuardDomain)
	case *IPCIDRItem:
		ruleType := clashRuleTypeIPCIDR
		if item.isSource {
			ruleType = clashRuleTypeSrcIPCIDR
		}
		if item.prefixes != nil {
			return clashRules(ruleType, item.prefixes, func(it *badoption.Prefixable) string {
				return it.Build(netip.Prefix{}).String()
			})
		}
		return clashRules(ruleType, item.ipSet.Prefixes(), netip.Prefix.String)
	case *IPIsPrivateItem:
		// mihomo 以伪 GeoIP 代码 lan 匹配私有地址
		if item.isSource {
			return []clashRule{{clashRuleTypeSrcGeoIP, "lan"}}
		}
		return []clashRule{{clashRuleTypeGeoIP, "lan"}}
	case *IPAcceptAnyItem:
		return clashFlag(clashRuleTypeIPAcceptAny)
	case *IPVersionItem:
		if item.isIPv6 {
			return []clashRule{{clashRuleTypeIPVersion, "6"}}
		}
		return []clashRule{{clashRuleTypeIPVersion, "4"}}
	case *PortItem:
		return clashRules(clashPortType(item.isSource), item.ports, F.ToString0[uint16])
	case *PortRangeItem:
		return clashRules(clashPortType(item.isSource), item.portRangeList, func(it rangeItem) string {
			if it.start == it.end {
				return F.ToString(it.start)
			}
			return F.ToString(it.start, "-", it.end)
		})
	case *InboundItem:
		return clashStrings(clashRuleTypeInName, item.inbounds)
	case *AuthUserItem:
		return clashStrings(clashRuleTypeInUser, item.users)
	case *NetworkItem:
		return clashStrings(clashRuleTypeNetwork, item.networks)
	case *ProtocolItem:
		return clashStrings(clashRuleTypeProtocol, item.protocols)
	case *ClientItem:
		return clashStrings(clashRuleTypeClient, item.clients)
	case *ProcessItem:
		return clashStrings(clashRuleTypeProcessName, item.processes)
	case *ProcessPathItem:
		return clashStrings(clashRuleTypeProcessPath, item.processes)
	case *ProcessPathRegexItem:
		return clashRules(clashRuleTypeProcessPathRegex, item.matchers, (*regexp.Regexp).String)
	case *PackageNameItem:
		return clashStrings(clashRuleTypePackageName, item.packageNames)
	case *PackageNameRegexItem:
		return clashRules(clashRuleTypePackageNameRegex, item.matchers, (*regexp.Regexp).String)
	case *UserItem:
		return clashStrings(clashRuleTypeUser, item.users)
	case *UserIdItem:
		return clashRules(clashRuleTypeUid, item.userIds, F.ToString0[int32])
	case *OutboundItem:
		return clashStrings(clashRuleTypeOutbound, item.outbounds)
	case *ClashModeItem:
		return clashStrings(clashRuleTypeClashMode, item.modes)
	case *NetworkTypeItem:
		return clashRules(clashRuleTypeNetworkType, item.networkType, C.InterfaceType.String)
	case *NetworkIsExpensiveItem:
		return clashFlag(clashRuleTypeNetworkIsExpensive)
	case *NetworkIsConstrainedItem:
		return clashFlag(clashRuleTypeNetworkIsConstrained)
	case *WIFISSIDItem:
		return clashStrings(clashRuleTypeWiFiSSID, item.ssidList)
	case *WIFIBSSIDItem:
		return clashStrings(clashRuleTypeWiFiBSSID, item.bssidList)
	case *InterfaceAddressItem:
		return clashKeyedPrefixes(clashRuleTypeInterfaceAddress, item.interfaceAddresses, func(it string) string { return it })
	case *NetworkInterfaceAddressItem:
		return clashKeyedPrefixes(clashRuleTypeNetworkInterfaceAddress, item.interfaceAddresses, C.InterfaceType.String)
	case *DefaultInterfaceAddressItem:
		return clashRules(clashRuleTypeDefaultInterfaceAddress, item.interfaceAddresses, netip.Prefix.String)
	case *SourceMACAddressItem:
		return clashStrings(clashRuleTypeSrcMACAddress, item.addresses)
	case *SourceHostnameItem:
		return clashStrings(clashRuleTypeSrcHostname, item.hostnames)
	case *PreferredByItem:
		return clashStrings(clashRuleTypePreferredBy, item.outboundTags)
	case *PreferredByDNSItem:
		return clashStrings(clashRuleTypePreferredBy, item.transportTags)
	case *DNSServerAddressItem:
		var rules []clashRule
		for index, tag := range item.transportTags {
			for _, prefix := range item.serverAddresses[index] {
				rules = append(rules, clashRule{clashRuleTypeDNSServerAddress, tag + "=" + prefix.String()})
			}
		}
		return rules
	case *DNSSearchDomainItem:
		var rules []clashRule
		for index, tag := range item.transportTags {
			for _, searchDomain := range item.searchDomains[index] {
				rules = append(rules, clashRule{clashRuleTypeDNSSearchDomain, tag + "=" + strings.TrimSuffix(searchDomain, ".")})
			}
		}
		return rules
	case *QueryTypeItem:
		return clashRules(clashRuleTypeQueryType, item.typeList, option.DNSQueryTypeToString)
	case *QueryClientSubnetItem:
		return clashRules(clashRuleTypeQueryClientSubnet, item.prefixes, netip.Prefix.String)
	case *QueryDNSSECItem:
		return clashFlag(clashRuleTypeQueryDNSSEC)
	case *DNSResponseRCodeItem:
		return []clashRule{{clashRuleTypeResponseRcode, dns.RcodeToString[item.rcode]}}
	case *DNSResponseRecordItem:
		var ruleType string
		switch item.field {
		case "response_answer":
			ruleType = clashRuleTypeResponseAnswer
		case "response_ns":
			ruleType = clashRuleTypeResponseNs
		default:
			ruleType = clashRuleTypeResponseExtra
		}
		var rules []clashRule
		for _, record := range item.records {
			if record.RR != nil {
				// dns.RR.String 以制表符分隔字段
				rules = append(rules, clashRule{ruleType, strings.Join(strings.Fields(record.RR.String()), " ")})
			}
		}
		return rules
	case *RuleSetItem:
		return clashStrings(clashRuleTypeRuleSet, item.tagList)
	default:
		return []clashRule{{clashRuleTypeUnknown, item.String()}}
	}
}

func clashPortType(isSource bool) string {
	if isSource {
		return clashRuleTypeSrcPort
	}
	return clashRuleTypeDstPort
}

// clashKeyedPrefixes 展开 interface_address 一类按键分组的地址，键按字典序排列。
func clashKeyedPrefixes[K comparable](ruleType string, prefixMap map[K][]netip.Prefix, keyString func(K) string) []clashRule {
	keys := make([]K, 0, len(prefixMap))
	for key := range prefixMap {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b K) int {
		return strings.Compare(keyString(a), keyString(b))
	})
	var rules []clashRule
	for _, key := range keys {
		for _, prefix := range prefixMap[key] {
			rules = append(rules, clashRule{ruleType, keyString(key) + "=" + prefix.String()})
		}
	}
	return rules
}
