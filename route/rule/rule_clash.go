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
// 载荷对应 Rule.Payload()，目标对应 Rule.Adapter()；sing-box 特有的条件沿用同样的
// 驼峰命名。多个条件组合时类型为 AND / OR / NOT，载荷写作易读的条件表达式。
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

// clashRule 是规则的 mihomo 形式：条件为类型加值（多个值之间为“或”），
// AND / OR / NOT 持有子规则；先组合成树再输出载荷，便于展平与合并。
type clashRule struct {
	ruleType string
	values   []string
	rules    []clashRule
}

type clashRuleDescriber interface {
	clashRule() (described clashRule, payload string)
}

// ClashRule 返回规则在 Clash API 中的类型与载荷，对应 mihomo C.Rule 的
// RuleType().String() 与 Payload()。结果在首次调用时生成并缓存。
func ClashRule(rule adapter.HeadlessRule) (ruleType string, payload string) {
	if describer, isDescriber := rule.(clashRuleDescriber); isDescriber {
		described, payload := describer.clashRule()
		return described.ruleType, payload
	}
	return clashRuleTypeUnknown, rule.String()
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
		described, _ := describer.clashRule()
		return described
	}
	return clashRule{ruleType: clashRuleTypeUnknown, values: []string{rule.String()}}
}

func (r *abstractRule) describeClash(build func() clashRule) (clashRule, string) {
	r.clashOnce.Do(func() {
		r.clash = build()
		r.clashPayload = r.clash.payload()
	})
	return r.clash, r.clashPayload
}

func (r *abstractDefaultRule) clashRule() (clashRule, string) {
	return r.describeClash(r.buildClashRule)
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
	return clashInvert(clashAll(components), r.invert)
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

func (r *abstractLogicalRule) clashRule() (clashRule, string) {
	return r.describeClash(r.buildClashRule)
}

func (r *abstractLogicalRule) buildClashRule() clashRule {
	rules := make([]clashRule, 0, len(r.rules))
	for _, rule := range r.rules {
		rules = append(rules, clashRuleOf(rule))
	}
	if r.mode == C.LogicalTypeOr {
		return clashInvert(clashAny(rules), r.invert)
	}
	return clashInvert(clashAll(rules), r.invert)
}

// clashAny 以 OR 组合：子 OR 展开到同一层，同类型条件的值合并为一条，
// 只剩一条时直接返回，因此只有不同类型的条件才以 OR 并列。
func clashAny(rules []clashRule) clashRule {
	var merged []clashRule
	for _, rule := range clashFlatten(clashRuleTypeOr, rules) {
		if rule.rules == nil {
			index := slices.IndexFunc(merged, func(it clashRule) bool {
				return it.rules == nil && it.ruleType == rule.ruleType
			})
			if index >= 0 {
				// values 可能与配置共用底层数组，Clip 后追加以免写入原数组
				merged[index].values = append(slices.Clip(merged[index].values), rule.values...)
				continue
			}
		}
		merged = append(merged, rule)
	}
	if len(merged) == 1 {
		return merged[0]
	}
	return clashRule{ruleType: clashRuleTypeOr, rules: merged}
}

// clashAll 以 AND 组合：子 AND 展开到同一层，没有条件时为 Match。
func clashAll(rules []clashRule) clashRule {
	flattened := clashFlatten(clashRuleTypeAnd, rules)
	switch len(flattened) {
	case 0:
		return clashRule{ruleType: clashRuleTypeMatch}
	case 1:
		return flattened[0]
	default:
		return clashRule{ruleType: clashRuleTypeAnd, rules: flattened}
	}
}

func clashFlatten(ruleType string, rules []clashRule) []clashRule {
	flattened := make([]clashRule, 0, len(rules))
	for _, rule := range rules {
		if rule.ruleType == ruleType && rule.rules != nil {
			flattened = append(flattened, rule.rules...)
		} else {
			flattened = append(flattened, rule)
		}
	}
	return flattened
}

func clashInvert(rule clashRule, invert bool) clashRule {
	if !invert {
		return rule
	}
	return clashRule{ruleType: clashRuleTypeNot, rules: []clashRule{rule}}
}

// payload 返回规则的载荷，运算符已由类型给出：条件为其值，以 ", " 分隔；
// AND / OR 为以 " & " / " | " 连接的子条件；NOT 为被取反的条件。
// 子条件写作 Type(值)，复合子条件加括号，如 "Network(tcp) & (DomainSuffix(a.com) | IPCIDR(1.1.1.1/32))"。
func (r clashRule) payload() string {
	var builder strings.Builder
	switch r.ruleType {
	case clashRuleTypeAnd, clashRuleTypeOr:
		r.writeOperands(&builder)
	case clashRuleTypeNot:
		r.rules[0].writeExpression(&builder)
	default:
		r.writeValues(&builder)
	}
	return builder.String()
}

func (r clashRule) writeExpression(builder *strings.Builder) {
	switch r.ruleType {
	case clashRuleTypeAnd, clashRuleTypeOr:
		builder.WriteByte('(')
		r.writeOperands(builder)
		builder.WriteByte(')')
	case clashRuleTypeNot:
		builder.WriteByte('!')
		r.rules[0].writeExpression(builder)
	default:
		builder.WriteString(r.ruleType)
		if len(r.values) > 0 {
			builder.WriteByte('(')
			r.writeValues(builder)
			builder.WriteByte(')')
		}
	}
}

func (r clashRule) writeOperands(builder *strings.Builder) {
	operator := " & "
	if r.ruleType == clashRuleTypeOr {
		operator = " | "
	}
	for index, rule := range r.rules {
		if index > 0 {
			builder.WriteString(operator)
		}
		rule.writeExpression(builder)
	}
}

func (r clashRule) writeValues(builder *strings.Builder) {
	for index, value := range r.values {
		if index > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(value)
	}
}

func clashRules[T any](ruleType string, values []T, format func(T) string) []clashRule {
	formatted := make([]string, 0, len(values))
	for _, value := range values {
		formatted = append(formatted, format(value))
	}
	return clashStrings(ruleType, formatted)
}

func clashStrings(ruleType string, values []string) []clashRule {
	if len(values) == 0 {
		return nil
	}
	return []clashRule{{ruleType: ruleType, values: values}}
}

func clashValue(ruleType string, value string) []clashRule {
	return []clashRule{{ruleType: ruleType, values: []string{value}}}
}

func clashFlag(ruleType string) []clashRule {
	return []clashRule{{ruleType: ruleType}}
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
			return clashValue(clashRuleTypeSrcGeoIP, "lan")
		}
		return clashValue(clashRuleTypeGeoIP, "lan")
	case *IPAcceptAnyItem:
		return clashFlag(clashRuleTypeIPAcceptAny)
	case *IPVersionItem:
		if item.isIPv6 {
			return clashValue(clashRuleTypeIPVersion, "6")
		}
		return clashValue(clashRuleTypeIPVersion, "4")
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
		var values []string
		for index, tag := range item.transportTags {
			for _, prefix := range item.serverAddresses[index] {
				values = append(values, tag+"="+prefix.String())
			}
		}
		return clashStrings(clashRuleTypeDNSServerAddress, values)
	case *DNSSearchDomainItem:
		var values []string
		for index, tag := range item.transportTags {
			for _, searchDomain := range item.searchDomains[index] {
				values = append(values, tag+"="+strings.TrimSuffix(searchDomain, "."))
			}
		}
		return clashStrings(clashRuleTypeDNSSearchDomain, values)
	case *QueryTypeItem:
		return clashRules(clashRuleTypeQueryType, item.typeList, option.DNSQueryTypeToString)
	case *QueryClientSubnetItem:
		return clashRules(clashRuleTypeQueryClientSubnet, item.prefixes, netip.Prefix.String)
	case *QueryDNSSECItem:
		return clashFlag(clashRuleTypeQueryDNSSEC)
	case *DNSResponseRCodeItem:
		return clashValue(clashRuleTypeResponseRcode, dns.RcodeToString[item.rcode])
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
		var values []string
		for _, record := range item.records {
			if record.RR != nil {
				// dns.RR.String 以制表符分隔字段
				values = append(values, strings.Join(strings.Fields(record.RR.String()), " "))
			}
		}
		return clashStrings(ruleType, values)
	case *RuleSetItem:
		return clashStrings(clashRuleTypeRuleSet, item.tagList)
	default:
		return clashValue(clashRuleTypeUnknown, item.String())
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
	var values []string
	for _, key := range keys {
		for _, prefix := range prefixMap[key] {
			values = append(values, keyString(key)+"="+prefix.String())
		}
	}
	return clashStrings(ruleType, values)
}
