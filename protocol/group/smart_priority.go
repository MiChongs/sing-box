package group

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/puzpuzpuz/xsync/v3"
	"github.com/sagernet/sing-box/adapter"
)

// policy_priority parsing & evaluation.
//
// User-facing syntax (each rule separated by `;`, key/value by `:`):
//
//	prefix? pattern : factor
//
//	(no prefix)  → substring match (default; mihomo-compatible)
//	`=` prefix   → exact tag match (`=US-1:1.5`)
//	`~` prefix   → explicit regex (`~^HK\d+$:1.5`)
//	`!` prefix   → negate the match (factor applies to non-matches)
//	contains `*` or `?` → glob, auto-converted to regex
//
// Prefix combination: `!=`, `!~`, `!*` all valid (negate first, then
// match kind). Whitespace around the pattern and factor is trimmed.
// Empty patterns are rejected. Factors must be positive, finite floats
// and != 1.0 (1.0 is identity and would only burn CPU per dial).
//
// Aggregation: every rule that matches a tag contributes its factor
// MULTIPLICATIVELY. So given rules `HK:1.5;VIP:1.2`, a tag named
// "HK-VIP-01" evaluates to 1.5 × 1.2 = 1.8. The previous "first match
// wins" semantic was order-sensitive and gave surprising results for
// compositional configs.

// parsePolicyPriority replaces s.policyPriority with the parsed rules
// from raw. Empty raw clears the slice. Logs a warning for each rule
// that fails to parse so misconfigurations surface during boot.
func (s *Smart) parsePolicyPriority(raw string) {
	s.policyPriority = nil
	s.priorityFactorCache = nil
	if raw == "" {
		return
	}

	rules := make([]priorityRule, 0, 8)
	for _, pair := range strings.Split(raw, ";") {
		rule, ok := parsePriorityRule(pair)
		if !ok {
			if strings.TrimSpace(pair) != "" && s.logger != nil {
				s.logger.Warn("smart[", s.Tag(), "] policy_priority: ignored invalid rule [", pair, "]")
			}
			continue
		}
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return
	}
	s.policyPriority = rules
	s.priorityFactorCache = xsync.NewMapOf[string, float64]()
	if s.logger != nil {
		s.logger.Info("smart[", s.Tag(), "] policy_priority: ", len(rules), " rule(s) loaded")
	}
}

// parsePriorityRule turns a single "pattern:factor" pair into a rule.
// Returns ok=false on any parse error (the caller logs and skips).
//
// The grammar is intentionally tolerant of stray whitespace because
// users frequently format the long single-line PolicyPriority string
// across multiple visual columns.
func parsePriorityRule(pair string) (priorityRule, bool) {
	idx := strings.LastIndex(pair, ":")
	if idx < 0 {
		return priorityRule{}, false
	}
	patPart := strings.TrimSpace(pair[:idx])
	facPart := strings.TrimSpace(pair[idx+1:])
	if patPart == "" || facPart == "" {
		return priorityRule{}, false
	}
	factor, err := strconv.ParseFloat(facPart, 64)
	if err != nil || factor <= 0 || factor == 1.0 {
		// 0/negative is invalid; 1.0 is identity (drop to save CPU).
		return priorityRule{}, false
	}

	rule := priorityRule{factor: factor, raw: patPart}

	// Strip leading negation, then leading match-kind prefix. Order
	// matters because "!=" is "negate + exact", not "exact + literal !".
	if strings.HasPrefix(patPart, "!") {
		rule.negate = true
		patPart = patPart[1:]
	}
	switch {
	case strings.HasPrefix(patPart, "="):
		rule.kind = priorityMatchExact
		rule.pattern = patPart[1:]
	case strings.HasPrefix(patPart, "~"):
		rule.kind = priorityMatchRegex
		rule.pattern = patPart[1:]
		re, rerr := regexp.Compile(rule.pattern)
		if rerr != nil {
			return priorityRule{}, false
		}
		rule.regex = re
	case strings.ContainsAny(patPart, "*?"):
		rule.kind = priorityMatchGlob
		rule.pattern = patPart
		re, rerr := regexp.Compile("^" + globToRegex(patPart) + "$")
		if rerr != nil {
			return priorityRule{}, false
		}
		rule.regex = re
	default:
		rule.kind = priorityMatchSubstring
		rule.pattern = patPart
	}
	if rule.pattern == "" {
		return priorityRule{}, false
	}
	return rule, true
}

// globToRegex translates the glob mini-language (* matches any run,
// ? matches any single char) into a Go regexp. Other regex
// metacharacters are escaped so `HK-1` isn't interpreted as a range.
//
// Kept very small on purpose — adding bracket-class support invites
// confusion with the explicit `~regex` form. Users who need brackets
// should use the regex form.
func globToRegex(g string) string {
	var b strings.Builder
	b.Grow(len(g) + 4)
	for _, r := range g {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		case '.', '+', '(', ')', '[', ']', '{', '}', '^', '$', '|', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// matches reports whether this rule applies to the given tag, taking
// the negate flag into account. Pure function — safe to call from any
// goroutine.
func (r *priorityRule) matches(tag string) bool {
	hit := false
	switch r.kind {
	case priorityMatchSubstring:
		hit = strings.Contains(tag, r.pattern)
	case priorityMatchExact:
		hit = tag == r.pattern
	case priorityMatchRegex, priorityMatchGlob:
		if r.regex != nil {
			hit = r.regex.MatchString(tag)
		}
	}
	if r.negate {
		return !hit
	}
	return hit
}

// getPriorityFactor returns the cumulative multiplicative factor
// applied to a node tag by the configured policy_priority rules.
// Defaults to 1.0 when no rule matches (identity). Cached per tag to
// avoid re-walking the rules slice on every dial — node tag set is
// effectively static so the cache stays small.
//
// Replaces the previous "first match wins" semantic with multiplicative
// composition: rules `HK:1.5;VIP:1.2` give a tag matching both a
// factor of 1.8.
func (s *Smart) getPriorityFactor(tag string) float64 {
	if len(s.policyPriority) == 0 || tag == "" {
		return 1.0
	}
	if s.priorityFactorCache != nil {
		if v, ok := s.priorityFactorCache.Load(tag); ok {
			return v
		}
	}
	factor := 1.0
	for i := range s.policyPriority {
		if s.policyPriority[i].matches(tag) {
			factor *= s.policyPriority[i].factor
		}
	}
	if s.priorityFactorCache != nil {
		s.priorityFactorCache.Store(tag, factor)
	}
	return factor
}

// invalidatePriorityCache clears the per-tag factor cache. Called when
// the rule set changes mid-process (currently only via tests; future
// hot-reload of policy_priority could reuse it).
//
//nolint:unused
func (s *Smart) invalidatePriorityCache() {
	if s.priorityFactorCache != nil {
		s.priorityFactorCache.Clear()
	}
}

// PolicyPriorityRules returns a JSON-friendly snapshot of the parsed
// rules so Clash API surfaces (and operators staring at /smart/groups)
// can verify what the runtime actually parsed. Read-only.
func (s *Smart) PolicyPriorityRules() []map[string]any {
	if len(s.policyPriority) == 0 {
		return nil
	}
	out := make([]map[string]any, len(s.policyPriority))
	for i, r := range s.policyPriority {
		kind := "substring"
		switch r.kind {
		case priorityMatchExact:
			kind = "exact"
		case priorityMatchRegex:
			kind = "regex"
		case priorityMatchGlob:
			kind = "glob"
		}
		out[i] = map[string]any{
			"pattern": r.pattern,
			"kind":    kind,
			"negate":  r.negate,
			"factor":  r.factor,
			"raw":     r.raw,
		}
	}
	return out
}

// reorderByPriority is the "all-tier" priority application: takes the
// candidate slice produced by selectProxiesTraced and stably sorts so
// higher-priority nodes appear first. Tied factors preserve input
// order (the original weight ordering remains the tiebreaker).
//
// Applied BEFORE reorderForAlgorithm so algorithm reorderers see a
// priority-respecting baseline. Composite effect: priority moves the
// allowed-set; algorithm picks within it.
func (s *Smart) reorderByPriority(candidates []adapter.Outbound, meta *smartDialMeta) []adapter.Outbound {
	if len(candidates) <= 1 || (len(s.policyPriority) == 0 && s.pinEndorsements == nil) {
		return candidates
	}
	// Pre-compute factors so the comparator doesn't recompute on every
	// less() call. Slice is recycled through factorsPool so the
	// per-dial path stays allocation-free even on the priority path.
	pf := acquireFactorsSlice(len(candidates))
	defer releaseFactorsSlice(pf)
	factors := *pf
	hasNonOne := false
	for i, ob := range candidates {
		var currentRTT float64
		if s.history != nil {
			if h := s.history.LoadURLTestHistory(ob.Tag()); h != nil && h.Delay > 0 {
				currentRTT = float64(h.Delay)
			}
		}
		// Composite effect: static policy_priority config × dynamic pin_endorsement learning
		factors[i] = s.getPriorityFactor(ob.Tag()) * s.applyPinEndorsementBoost(ob.Tag(), meta, currentRTT)
		if factors[i] != 1.0 {
			hasNonOne = true
		}
	}
	if !hasNonOne {
		return candidates // nothing to do; every candidate sits at identity
	}
	// Insertion-sort style stable sort tuned for N ≤ smartMaxSelected.
	stableSortByFactorDesc(candidates, factors)
	return candidates
}

// stableSortByFactorDesc is a tiny, allocation-free stable sort tuned
// for our typical input size (≤ smartMaxSelected = 10). For N ≤ 16
// insertion sort outperforms sort.Slice (no reflection, no closure
// allocation) and is naturally stable.
func stableSortByFactorDesc(candidates []adapter.Outbound, factors []float64) {
	for i := 1; i < len(candidates); i++ {
		obI, fI := candidates[i], factors[i]
		j := i - 1
		for j >= 0 && factors[j] < fI {
			candidates[j+1] = candidates[j]
			factors[j+1] = factors[j]
			j--
		}
		candidates[j+1] = obI
		factors[j+1] = fI
	}
}
