package smart

import (
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

var (
	validLabel = regexp.MustCompile(`^[a-z0-9-]+$`)
	hexRandom  = regexp.MustCompile(`^[0-9a-f]{8,}$`)
)

// GetEffectiveTarget normalizes a host/IP to a wildcard key for grouping.
// Examples:
//
//	"a1b2.example.com" → "*.example.com"
//	"192.168.1.100"    → the raw IP string (no wildcard for IPs)
func GetEffectiveTarget(host, dstIP string) string {
	if host == "" {
		return dstIP
	}

	h := strings.ToLower(host)

	// Check LRU cache
	if targetCache != nil {
		if result, ok := targetCache.Get(h); ok {
			return result
		}
	}

	result := computeEffectiveTarget(h)

	if targetCache != nil {
		targetCache.Set(h, result)
		if strings.HasPrefix(result, "*.") {
			targetCache.Set(result, result)
		}
	}

	return result
}

func computeEffectiveTarget(h string) string {
	parts := strings.Split(h, ".")

	reg, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil || reg == "" || !(h == reg || strings.HasSuffix(h, "."+reg)) {
		if len(parts) >= 2 {
			reg = strings.Join(parts[len(parts)-2:], ".")
		} else {
			return h
		}
	}

	var sub string
	if h == reg {
		sub = ""
	} else {
		sub = strings.TrimSuffix(h, "."+reg)
	}

	if sub == "" {
		// bare eTLD+1 — wrap to wildcard
		return "*." + reg
	}

	labels := strings.Split(sub, ".")
	last := labels[len(labels)-1]

	// Wildcardize randomized labels
	if strings.Contains(last, "-") {
		last = "*"
	} else if hexRandom.MatchString(last) {
		last = "*"
	} else {
		letters, digits := 0, 0
		for _, r := range last {
			if r >= 'a' && r <= 'z' {
				letters++
			} else if r >= '0' && r <= '9' {
				digits++
			}
		}
		if letters > 0 && digits > 0 {
			if len(last) > 10 || (digits > 0 && float64(digits)/float64(len(last)) > 0.6) {
				last = "*"
			}
		}
	}

	if !validLabel.MatchString(last) || strings.HasPrefix(last, "-") || strings.HasSuffix(last, "-") {
		last = "*"
	}

	var normalizedSub string
	if len(labels) == 1 {
		normalizedSub = last
	} else {
		normalizedSub = "*." + last
	}

	if normalizedSub == "" || normalizedSub == "*" || normalizedSub == "*.*" {
		return "*." + reg
	}

	return normalizedSub + "." + reg
}
