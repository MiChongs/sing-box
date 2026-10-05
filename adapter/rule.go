package adapter

import (
	"time"

	C "github.com/sagernet/sing-box/constant"

	"github.com/miekg/dns"
)

type HeadlessRule interface {
	Match(metadata *InboundContext) bool
	RuleCount() uint64
	String() string
}

type Rule interface {
	HeadlessRule
	SimpleLifecycle
	RuleStatistics
	Disabled() bool
	SetDisabled(disabled bool)
	UUID() string
	ChangeStatus()
	Type() string
	Action() RuleAction
}

// RuleStatistics 对齐 mihomo RuleWrapper 的命中统计：路由器每次对顶层规则求值
// 计一次 Hit 或 Miss（被禁用的规则跳过不计），子规则不单独计数。
type RuleStatistics interface {
	Hit()
	Miss()
	HitCount() uint64
	HitAt() time.Time
	MissCount() uint64
	MissAt() time.Time
}

type DNSRule interface {
	Rule
	LegacyPreMatch(metadata *InboundContext) bool
	WithAddressLimit() bool
	MatchAddressLimit(metadata *InboundContext, response *dns.Msg) bool
	MatchResponseTag() string
	MatchResponseTags() []string
	MatchResponseAnonymous() bool
	Race() bool
}

type RuleAction interface {
	Type() string
	String() string
}

func IsFinalAction(action RuleAction) bool {
	switch action.Type() {
	case C.RuleActionTypeSniff, C.RuleActionTypeSniffOverrideDestination, C.RuleActionTypeResolve, C.RuleActionTypeEvaluate:
		return false
	default:
		return true
	}
}
