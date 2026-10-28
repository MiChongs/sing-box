package rule

import (
	"github.com/sagernet/sing-box/adapter"
)

// 规则条目计数，对齐 mihomo rule-provider 的 ruleCount：每个具体条目（一个域名、
// 一个 CIDR、一个端口、一个进程名……）记一条，逻辑规则累加子规则。
// 二进制（SRS / iOS mmap）规则集的域名、AdGuard、IP 只以压缩结构保存，计数要整体展开，
// 代价与条目数成正比，因此规则不在加载时计数，只在 Clash API 查询时由规则集计算并缓存。

type ruleItemCounter interface {
	ruleCount() uint64
}

func countRuleItems(items []RuleItem) uint64 {
	var count uint64
	for _, item := range items {
		if counter, isCounter := item.(ruleItemCounter); isCounter {
			count += counter.ruleCount()
		} else {
			count++
		}
	}
	return count
}

func (r *abstractDefaultRule) RuleCount() uint64 {
	count := countRuleItems(r.allItems)
	if count == 0 {
		return 1
	}
	return count
}

func (r *abstractLogicalRule) RuleCount() uint64 {
	var count uint64
	for _, rule := range r.rules {
		count += rule.RuleCount()
	}
	if count == 0 {
		return 1
	}
	return count
}

func (r *DomainItem) ruleCount() uint64 {
	if r.entryCount > 0 {
		return r.entryCount
	}
	domains, domainSuffixes := r.matcher.Dump()
	return uint64(len(domains) + len(domainSuffixes))
}

func (r *AdGuardDomainItem) ruleCount() uint64 {
	if r.entryCount > 0 {
		return r.entryCount
	}
	return uint64(len(r.matcher.Dump()))
}

func (r *IPCIDRItem) ruleCount() uint64 {
	if r.entryCount > 0 {
		return r.entryCount
	}
	return uint64(len(r.ipSet.Prefixes()))
}

func (r *DomainKeywordItem) ruleCount() uint64 {
	return uint64(len(r.keywords))
}

func (r *DomainRegexItem) ruleCount() uint64 {
	return uint64(len(r.matchers))
}

func (r *PortItem) ruleCount() uint64 {
	return uint64(len(r.ports))
}

func (r *PortRangeItem) ruleCount() uint64 {
	return uint64(len(r.portRangeList))
}

func (r *ProcessItem) ruleCount() uint64 {
	return uint64(len(r.processes))
}

func (r *ProcessPathItem) ruleCount() uint64 {
	return uint64(len(r.processes))
}

func (r *ProcessPathRegexItem) ruleCount() uint64 {
	return uint64(len(r.matchers))
}

func (r *PackageNameItem) ruleCount() uint64 {
	return uint64(len(r.packageNames))
}

func (r *PackageNameRegexItem) ruleCount() uint64 {
	return uint64(len(r.matchers))
}

func (r *NetworkItem) ruleCount() uint64 {
	return uint64(len(r.networks))
}

func (r *QueryTypeItem) ruleCount() uint64 {
	return uint64(len(r.typeList))
}

func (r *NetworkTypeItem) ruleCount() uint64 {
	return uint64(len(r.networkType))
}

func (r *WIFISSIDItem) ruleCount() uint64 {
	return uint64(len(r.ssidList))
}

func (r *WIFIBSSIDItem) ruleCount() uint64 {
	return uint64(len(r.bssidList))
}

func (r *NetworkInterfaceAddressItem) ruleCount() uint64 {
	var count uint64
	for _, prefixes := range r.interfaceAddresses {
		count += uint64(len(prefixes))
	}
	return count
}

func (r *DefaultInterfaceAddressItem) ruleCount() uint64 {
	return uint64(len(r.interfaceAddresses))
}

// mihomo rule-provider behavior
const (
	RuleSetBehaviorDomain    = "Domain"
	RuleSetBehaviorIPCIDR    = "IPCIDR"
	RuleSetBehaviorClassical = "Classical"
)

// ruleSetBehavior 按内容推断 mihomo behavior：只有 domain/domain_suffix 为 Domain，
// 只有目标 ip_cidr 为 IPCIDR，其余（含关键字、正则、逻辑规则、反转规则）为 Classical。
func ruleSetBehavior(rules []adapter.HeadlessRule) string {
	var behavior string
	for _, rule := range rules {
		current := RuleSetBehaviorClassical
		if defaultRule, isDefault := rule.(*DefaultHeadlessRule); isDefault {
			current = defaultRule.behavior()
		}
		if behavior == "" {
			behavior = current
		} else if behavior != current {
			return RuleSetBehaviorClassical
		}
	}
	if behavior == "" {
		return RuleSetBehaviorClassical
	}
	return behavior
}

func (r *DefaultHeadlessRule) behavior() string {
	if r.invert || len(r.allItems) == 0 {
		return RuleSetBehaviorClassical
	}
	domainOnly, ipCIDROnly := true, true
	for _, item := range r.allItems {
		switch it := item.(type) {
		case *DomainItem:
			ipCIDROnly = false
		case *IPCIDRItem:
			domainOnly = false
			if it.isSource {
				ipCIDROnly = false
			}
		default:
			return RuleSetBehaviorClassical
		}
	}
	switch {
	case domainOnly:
		return RuleSetBehaviorDomain
	case ipCIDROnly:
		return RuleSetBehaviorIPCIDR
	default:
		return RuleSetBehaviorClassical
	}
}
