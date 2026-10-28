package rule

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"go4.org/netipx"
)

type abstractRuleSet struct {
	ctx         context.Context
	logger      logger.ContextLogger
	tag         string
	access      sync.RWMutex
	sType       string
	path        string
	format      string
	rules       []adapter.HeadlessRule
	ruleCount   uint64
	behavior    string
	counted     bool // ruleCount / behavior 是否已按当前 rules 计算
	metadata    adapter.RuleSetMetadata
	lastUpdated time.Time
	callbacks   list.List[adapter.RuleSetUpdateCallback]
	refs        atomic.Int32
}

func (s *abstractRuleSet) Name() string {
	return s.tag
}

func (s *abstractRuleSet) Type() string {
	return s.sType
}

func (s *abstractRuleSet) Format() string {
	return s.format
}

func (s *abstractRuleSet) RuleCount() uint64 {
	s.access.Lock()
	defer s.access.Unlock()
	s.countRules()
	return s.ruleCount
}

// Behavior 返回 mihomo 口径的 rule-provider behavior（Domain / IPCIDR / Classical）。
func (s *abstractRuleSet) Behavior() string {
	s.access.Lock()
	defer s.access.Unlock()
	s.countRules()
	return s.behavior
}

// countRules 需持有写锁。二进制规则集计数要展开压缩结构，故只在首次查询时计算。
func (s *abstractRuleSet) countRules() {
	if s.counted {
		return
	}
	var ruleCount uint64
	for _, rule := range s.rules {
		ruleCount += rule.RuleCount()
	}
	s.ruleCount = ruleCount
	s.behavior = ruleSetBehavior(s.rules)
	s.counted = true
}

// dropRules 释放未被引用规则集的规则，释放前先算好计数，Clash API 仍能展示真实条目数。
func (s *abstractRuleSet) dropRules() {
	s.access.Lock()
	defer s.access.Unlock()
	s.countRules()
	s.rules = nil
}

func (s *abstractRuleSet) UpdatedTime() time.Time {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.lastUpdated
}

func (s *abstractRuleSet) setUpdatedTime(updatedAt time.Time) {
	s.access.Lock()
	defer s.access.Unlock()
	s.lastUpdated = updatedAt
}

func (s *abstractRuleSet) String() string {
	return strings.Join(F.MapToString(s.rules), " ")
}

func (s *abstractRuleSet) Metadata() adapter.RuleSetMetadata {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.metadata
}

func (s *abstractRuleSet) ExtractIPSet() []*netipx.IPSet {
	s.access.RLock()
	defer s.access.RUnlock()
	return common.FlatMap(s.rules, extractIPSetFromRule)
}

func (s *abstractRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *abstractRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *abstractRuleSet) Cleanup() {
	if s.refs.Load() == 0 {
		s.dropRules()
	}
}

func (s *abstractRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *abstractRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *abstractRuleSet) loadBytes(content []byte, ruleset adapter.RuleSet) error {
	var (
		ruleSet option.PlainRuleSetCompat
		err     error
	)
	switch s.format {
	case C.RuleSetFormatSource:
		ruleSet, err = json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return err
		}
	case C.RuleSetFormatBinary:
		ruleSet, err = srs.Read(bytes.NewReader(content), false)
		if err != nil {
			return err
		}
	default:
		return E.New("unknown rule-set format: ", s.format)
	}
	plainRuleSet, err := mmapRuleSet(s.ctx, s.logger, s.tag, ruleSet).Upgrade()
	if err != nil {
		return err
	}
	return s.reloadRules(plainRuleSet.Rules, ruleset)
}

func (s *abstractRuleSet) reloadRules(headlessRules []option.HeadlessRule, ruleSet adapter.RuleSet) error {
	rules := make([]adapter.HeadlessRule, len(headlessRules))
	var err error
	for i, ruleOptions := range headlessRules {
		rule, err := NewHeadlessRule(s.ctx, ruleOptions)
		if err != nil {
			return E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
		rules[i] = rule
	}
	metadata := buildRuleSetMetadata(headlessRules)
	err = validateRuleSetMetadataUpdate(s.ctx, s.tag, metadata)
	if err != nil {
		return err
	}
	s.access.Lock()
	s.rules = rules
	s.counted = false
	s.metadata = metadata
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(ruleSet)
	}
	return nil
}

func (s *abstractRuleSet) Match(metadata *adapter.InboundContext) bool {
	return matchAnyHeadlessRule(s.rules, metadata)
}

func (s *abstractRuleSet) mergeableRule() *DefaultHeadlessRule {
	return mergeableRuleIn(s.rules)
}
