package rule

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/domain"
)

var _ RuleItem = (*AdGuardDomainItem)(nil)

type AdGuardDomainItem struct {
	matcher             *domain.AdGuardMatcher
	domainMatchStrategy C.DomainMatchStrategy
	// 配置条目数，二进制规则集为 0，按需从 matcher 展开
	entryCount uint64
}

func NewAdGuardDomainItem(ruleLines []string, domainMatchStrategy C.DomainMatchStrategy) *AdGuardDomainItem {
	return &AdGuardDomainItem{
		matcher:             domain.NewAdGuardMatcher(ruleLines),
		domainMatchStrategy: domainMatchStrategy,
		entryCount:          uint64(len(ruleLines)),
	}
}

func NewRawAdGuardDomainItem(matcher *domain.AdGuardMatcher, domainMatchStrategy C.DomainMatchStrategy) *AdGuardDomainItem {
	return &AdGuardDomainItem{
		matcher:             matcher,
		domainMatchStrategy: domainMatchStrategy,
	}
}

func (r *AdGuardDomainItem) Match(metadata *adapter.InboundContext) bool {
	var domainHost string
	switch r.domainMatchStrategy {
	case C.DomainMatchStrategyPreferFQDN:
		if metadata.Destination.IsDomain() {
			domainHost = metadata.Destination.Fqdn
		} else if metadata.SniffHost != "" {
			domainHost = metadata.SniffHost
		} else {
			domainHost = metadata.Domain
		}
	case C.DomainMatchStrategyFQDNOnly:
		if metadata.Destination.IsDomain() {
			domainHost = metadata.Destination.Fqdn
		}
	case C.DomainMatchStrategySniffHostOnly:
		if metadata.SniffHost != "" {
			domainHost = metadata.SniffHost
		}
	default:
		if metadata.SniffHost != "" {
			domainHost = metadata.SniffHost
		} else if metadata.Destination.IsDomain() {
			domainHost = metadata.Destination.Fqdn
		} else {
			domainHost = metadata.Domain
		}
	}
	if domainHost == "" {
		return false
	}
	return r.matcher.Match(strings.ToLower(domainHost))
}

func (r *AdGuardDomainItem) String() string {
	return "!adguard_domain_rules=<binary>"
}
