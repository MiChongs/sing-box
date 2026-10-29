package smart

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

const (
	BroadRuleCount    = 10000 // entries a rule set or geosite needs to count as a collection
	BroadASNDiversity = 6

	ASNClaimMinKinds  = 2   // networks a service must span to claim without repeats
	ASNClaimMinHits   = 4   // successes a single network service needs before it claims
	ASNClaimAmbiguous = "-" // network two services were seen on, never used as key
)

// SharedASNs are networks that rent addresses to unrelated parties, so the ASN does
// not identify a single service and must not be used as a service key.
var SharedASNs = map[string]bool{
	"13335":  true, // Cloudflare
	"12222":  true, // Akamai
	"16625":  true, // Akamai
	"20940":  true, // Akamai
	"31110":  true, // Akamai
	"35994":  true, // Akamai
	"54113":  true, // Fastly
	"22822":  true, // Limelight Networks
	"15133":  true, // EdgeCast (Verizon)
	"19551":  true, // Incapsula (Imperva)
	"20446":  true, // StackPath
	"5065":   true, // BunnyCDN
	"60068":  true, // CDN77
	"16509":  true, // Amazon CloudFront
	"36408":  true, // CDNetworks
	"4809":   true, // ChinaCache
	"4847":   true, // ChinaNetCenter
	"199524": true, // Gcore
	"212238": true, // BelugaCDN
	"55933":  true, // QUANTIL
	"43260":  true, // Medianova
	"43317":  true, // CDNvideo
	"43996":  true, // CDNsun
	"33438":  true, // Edgio (Highwinds)
	"396982": true, // Google Cloud Platform
	"16276":  true, // OVH
	"30081":  true, // CacheFly
	"12389":  true, // Zenlayer
	"37888":  true, // Alibaba CDN
	"45090":  true, // Tencent CDN
	"207143": true, // KeyCDN
	"14061":  true, // DigitalOcean
	"24940":  true, // Hetzner
	"31898":  true, // Oracle Cloud
	"36351":  true, // IBM Cloud (SoftLayer)
	"14618":  true, // Amazon AES (AWS)
	"45102":  true, // Alibaba Cloud
	"132203": true, // Tencent Cloud
	"55990":  true, // Huawei Cloud
	"12876":  true, // Scaleway
	"51167":  true, // Contabo
	"197540": true, // Netcup
	"20473":  true, // Vultr (Choopa)
	"63949":  true, // Linode
	"9009":   true, // Leaseweb
	"60781":  true, // Leaseweb NL
	"36236":  true, // NetActuate (anycast hosting)
	"39572":  true, // DataWeb Global Group (hosting)
	"400618": true, // Prime Security (JP IDC)
	"4134":   true, // China Telecom
	"4808":   true, // China Unicom
	"4837":   true, // China Unicom (China169)
}

// broadSetNames are meta-rules-dat entries that collect unrelated services; an
// "@<scope>" suffix only marks the scope of the same entry.
var broadSetNames = map[string]bool{
	"cn":           true,
	"private":      true,
	"gfw":          true,
	"greatfire":    true,
	"ads-all":      true,
	"oc-cn-domain": true, // OpenClash generated CN domain collection
	"china-domain": true,
	"china-ip":     true,
	"tor":          true,
}

var broadNamePrefixes = []string{"category-", "geolocation-", "tld-"}

// sharedGeoIPPayloads are geoip entries of shared or non routable address space.
var sharedGeoIPPayloads = map[string]bool{
	"cloudflare": true,
	"cloudfront": true,
	"fastly":     true,
	"private":    true,
}

// TargetKind classifies a target string: a collection of unrelated services, a
// single service, or a rule entry name that only the counts can tell apart.
type TargetKind int

const (
	TargetKindNoRule   TargetKind = iota // no rule identity, the fallback target
	TargetKindRuleName                   // rule set / geosite / geoip name, which may be provider defined
	TargetKindService                    // the rule type itself is narrow
	TargetKindBroad                      // collection of unrelated services, e.g. a region
)

// ClassifyTargetName classifies a target by naming conventions. A name that matches
// no convention is a rule name, NeedsASNKey decides it from counts and diversity.
func ClassifyTargetName(target string) TargetKind {
	kind, payload, ok := splitTarget(target)
	if !ok {
		return TargetKindNoRule
	}

	name, _, _ := strings.Cut(strings.ToLower(payload), "@")
	// a negated list is a collection whenever the list it negates is one
	name = strings.TrimPrefix(name, "!")
	// sing-box rule sets carry the source database in their tag
	if kind == "RuleSet" {
		switch {
		case strings.HasPrefix(name, "geosite-"):
			kind, name = "GeoSite", strings.TrimPrefix(name, "geosite-")
		case strings.HasPrefix(name, "geoip-"):
			kind, name = "GeoIP", strings.TrimPrefix(name, "geoip-")
		}
		name = strings.TrimPrefix(name, "!")
	}

	switch kind {
	case "GeoIP", "SrcGeoIP":
		if isCountryCode(name) || sharedGeoIPPayloads[name] || broadSetNames[name] {
			return TargetKindBroad
		}
		return TargetKindRuleName
	case "RuleSet", "GeoSite":
		if broadSetNames[name] {
			return TargetKindBroad
		}
		for _, prefix := range broadNamePrefixes {
			if strings.HasPrefix(name, prefix) {
				return TargetKindBroad
			}
		}
		if asn, ok := asnRuleSetName(name); ok && SharedASNs[asn] {
			return TargetKindBroad
		}
		return TargetKindRuleName
	default:
		return TargetKindService
	}
}

// NeedsASNKey reports whether the ASN has to replace the target as key: always for a
// collection or a target without rule identity, and for a provider defined name only
// once its entry count or its number of unrelated networks proves it is a collection.
func NeedsASNKey(target string, ruleCount, asnDiversity int) bool {
	switch ClassifyTargetName(target) {
	case TargetKindBroad, TargetKindNoRule:
		return true
	case TargetKindService:
		return false
	}
	if ruleCount >= BroadRuleCount {
		return true
	}
	return asnDiversity >= BroadASNDiversity
}

// RulePayload returns the rule type and payload whose entry count is looked up.
func RulePayload(target string) (ruleType, payload string, ok bool) {
	ruleType, payload, ok = splitTarget(target)
	if !ok {
		return "", "", false
	}
	switch ruleType {
	case "RuleSet", "GeoSite":
		return ruleType, payload, true
	}
	return "", "", false
}

func splitTarget(target string) (kind, payload string, ok bool) {
	if target == "" {
		return "", "", false
	}
	open := strings.LastIndex(target, " [")
	if open <= 0 || !strings.HasSuffix(target, "]") {
		return "", "", false
	}
	payload = target[open+2 : len(target)-1]
	if payload == "" {
		return "", "", false
	}
	return target[:open], payload, true
}

// IsRuleTarget reports whether a target carries rule identity (rule name or rule set).
func IsRuleTarget(target string) bool {
	_, _, ok := splitTarget(target)
	return ok
}

func asnRuleSetName(name string) (string, bool) {
	if len(name) < 3 || name[0] != 'a' || name[1] != 's' {
		return "", false
	}
	digits := name[2:]
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return "", false
		}
	}
	return digits, true
}

// SmartTargetKey folds a target into a service key when the group runs with prefer-asn. A
// service rule keeps its rule string and a rule set covers every ASN it is served from,
// otherwise the key is the ASN, or the site for a shared or unknown network.
func SmartTargetKey(preferASN bool, asn, target, wildcardTarget, site string, needsASNKey bool) string {
	if target == "" {
		target = wildcardTarget
	}
	if target == "" {
		return ""
	}
	if !preferASN {
		return target
	}
	if !needsASNKey {
		return target
	}
	if site != "" {
		return site
	}
	if asn != "" && !SharedASNs[asn] {
		return asn
	}
	if wildcardTarget != "" {
		return wildcardTarget
	}
	return target
}

func isCountryCode(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// ClaimedASNRules maps every network to the service rule that owns it, from the
// evidence collected per target. A network that two services were seen on is
// reported as ambiguous, so it is never keyed to either of them.
func ClaimedASNRules(evidence map[string]map[string]int) map[string]string {
	type claim struct {
		rule string
		hits int
	}

	claims := make(map[string]claim)

	for target, asns := range evidence {
		if ClassifyTargetName(target) != TargetKindRuleName {
			continue
		}
		singleNetwork := len(asns) < ASNClaimMinKinds
		for asn, hits := range asns {
			if singleNetwork && hits < ASNClaimMinHits {
				continue
			}
			switch existing, ok := claims[asn]; {
			case !ok:
				claims[asn] = claim{rule: target, hits: hits}
			case existing.rule == ASNClaimAmbiguous:
			case existing.rule != target:
				claims[asn] = claim{rule: ASNClaimAmbiguous, hits: existing.hits}
			case hits > existing.hits:
				claims[asn] = claim{rule: target, hits: hits}
			}
		}
	}

	result := make(map[string]string, len(claims))
	for asn, c := range claims {
		result[asn] = c.rule
	}
	return result
}

func isHexRandom(s string) bool {
	if len(s) < 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isValidLabel(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

// GetEffectiveTarget folds a host into the wildcard key its records are kept
// under (www.example.com and cdn-12.example.com both become *.example.com);
// without a host it is the destination IP.
func GetEffectiveTarget(host string, dstIP string) string {
	if host == "" {
		return dstIP
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if cached, ok := wildcardCache.get(h); ok {
		return cached
	}
	result := computeWildcard(h)
	if result == h && strings.Count(h, ".") == 1 {
		result = "*." + h
	}
	if result != "" {
		wildcardCache.put(h, result)
	}
	return result
}

func computeWildcard(h string) string {
	reg := ""
	if !strings.HasPrefix(h, ".") && !strings.Contains(h, "..") {
		suffix, _ := publicsuffix.PublicSuffix(h)
		if len(h) > len(suffix) {
			if cut := len(h) - len(suffix) - 1; h[cut] == '.' {
				reg = h[1+strings.LastIndexByte(h[:cut], '.'):]
			}
		}
	}
	if reg == h {
		// A bare registrable domain, also under a multi-label public suffix
		// such as example.co.uk.
		return "*." + h
	}
	if reg == "" || !strings.HasSuffix(h, "."+reg) {
		lastDot := strings.LastIndexByte(h, '.')
		if lastDot < 0 {
			return h
		}
		reg = h[strings.LastIndexByte(h[:lastDot], '.')+1:]
	}
	var sub string
	if h != reg {
		sub = strings.TrimSuffix(h, "."+reg)
	}
	if sub == "" {
		return reg
	}
	last := sub
	if dot := strings.LastIndexByte(sub, '.'); dot >= 0 {
		last = sub[dot+1:]
	}
	if strings.Contains(last, "-") || isHexRandom(last) {
		last = "*"
	} else {
		letters, digits := 0, 0
		for i := 0; i < len(last); i++ {
			switch c := last[i]; {
			case c >= 'a' && c <= 'z':
				letters++
			case c >= '0' && c <= '9':
				digits++
			}
		}
		if letters > 0 && digits > 0 && (len(last) > 10 || float64(digits)/float64(len(last)) > 0.6) {
			last = "*"
		}
	}
	if !isValidLabel(last) {
		last = "*"
	}
	if strings.IndexByte(sub, '.') < 0 || last == "*" {
		return "*." + reg
	}
	return "*." + last + "." + reg
}

// SiteOf returns the registrable domain of a host (eTLD+1), or the host
// itself when it has none.
func SiteOf(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" {
		return ""
	}
	if site, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
		return site
	}
	return h
}

var wildcardCache = newStringCache(8192)
