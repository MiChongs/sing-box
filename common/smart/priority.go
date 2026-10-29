package smart

import (
	"regexp"
	"strconv"
	"strings"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
)

// PriorityRule is one "pattern:factor" entry of policy_priority.
type PriorityRule struct {
	Pattern string
	Factor  float64
	regex   *regexp.Regexp
}

// Priority maps node names to policy_priority factors. The first rule whose
// pattern matches a name wins; a pattern that compiles as a regular
// expression matches anywhere in the name, otherwise it is a substring.
type Priority struct {
	rules []PriorityRule
	cache sync.Map // name -> float64
}

// ParsePriority parses "pattern:factor;pattern:factor". A colon inside a
// pattern is escaped as "\:"; factors must be positive.
func ParsePriority(text string) (*Priority, error) {
	p := &Priority{}
	for _, pair := range strings.Split(text, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		idx := lastUnescapedColon(pair)
		if idx <= 0 || idx == len(pair)-1 {
			return nil, E.New("policy_priority: ", strconv.Quote(pair), " must be in 'pattern:factor' format")
		}
		factor, err := strconv.ParseFloat(strings.TrimSpace(pair[idx+1:]), 64)
		if err != nil {
			return nil, E.Cause(err, "policy_priority: ", strconv.Quote(pair))
		}
		if factor <= 0 {
			return nil, E.New("policy_priority: ", strconv.Quote(pair), ": factor must be positive")
		}
		pattern := unescapePattern(strings.TrimSpace(pair[:idx]))
		rule := PriorityRule{Pattern: pattern, Factor: factor}
		if re, err := regexp.Compile(pattern); err == nil {
			rule.regex = re
		}
		p.rules = append(p.rules, rule)
	}
	return p, nil
}

func lastUnescapedColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != ':' {
			continue
		}
		backslashes := 0
		for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
			backslashes++
		}
		if backslashes%2 == 0 {
			return i
		}
	}
	return -1
}

func unescapePattern(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Empty reports whether no rule is configured.
func (p *Priority) Empty() bool { return p == nil || len(p.rules) == 0 }

// Rules returns the parsed rules.
func (p *Priority) Rules() []PriorityRule {
	if p == nil {
		return nil
	}
	return p.rules
}

// Factor returns the factor of name, 1 when no rule matches.
func (p *Priority) Factor(name string) float64 {
	if p.Empty() {
		return 1
	}
	if v, ok := p.cache.Load(name); ok {
		return v.(float64)
	}
	factor := 1.0
	for _, rule := range p.rules {
		if rule.regex != nil && rule.regex.MatchString(name) || rule.regex == nil && strings.Contains(name, rule.Pattern) {
			factor = rule.Factor
			break
		}
	}
	p.cache.Store(name, factor)
	return factor
}
