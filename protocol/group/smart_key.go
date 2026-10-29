package group

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/geodb"
	"github.com/sagernet/sing-box/common/smart"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// smartDialMeta is what the group knows about one connection's target.
type smartDialMeta struct {
	// host is the destination domain (lowercase), "" for IP targets.
	host string
	// smartTarget is the service key: the matched rule ("RuleSet [x]"),
	// the claimed rule of the destination ASN, the ASN itself or the site,
	// else the wildcard target (mihomo SmartTarget).
	smartTarget string
	// wildcard is the host level key (*.example.com or the IP).
	wildcard string
	// target is the exact "host:port" (or "ip:port").
	target string
	// asnCode is the destination ASN number, asnInfo "number org".
	asnCode     string
	asnInfo     string
	destGeoIP   []string
	resolvedIPs []netip.Addr
	destIP      netip.Addr
	destPort    uint16
	family      smart.Family
	isUDP       bool
	source      netip.Addr
	ruleTarget  string
	balance     *balanceRequest

	scoreContext smart.Context
}

type smartMetaCtxKey struct{}

func (m *smartDialMeta) network() smart.Network {
	if m.isUDP {
		return smart.NetworkUDP
	}
	return smart.NetworkTCP
}

// buildMeta derives the target keys of one connection from its routing
// metadata.
func (s *Smart) buildMeta(metadata adapter.InboundContext, isUDP bool) *smartDialMeta {
	meta := &smartDialMeta{
		host:       strings.ToLower(strings.TrimSuffix(smartHostOf(metadata), ".")),
		isUDP:      isUDP,
		destPort:   metadata.Destination.Port,
		source:     metadata.Source.Addr,
		ruleTarget: metadata.SmartTarget,
	}
	meta.resolvedIPs = smartIPsOf(metadata)
	s.completeMeta(meta)
	return meta
}

// metaForDial returns the meta of a dial: the one a smart-region outbound
// attached, else one built from the routing metadata in ctx, else one built
// from the destination alone (a dial from another group or a detour).
func (s *Smart) metaForDial(ctx context.Context, destination M.Socksaddr, isUDP bool) *smartDialMeta {
	if meta, ok := ctx.Value(smartMetaCtxKey{}).(*smartDialMeta); ok && meta != nil {
		if meta.isUDP == isUDP {
			return meta
		}
		copied := *meta
		copied.isUDP = isUDP
		s.completeMeta(&copied)
		return &copied
	}
	if metadata := adapter.ContextFrom(ctx); metadata != nil {
		meta := s.buildMeta(*metadata, isUDP)
		if destination.IsValid() {
			if !meta.destIP.IsValid() && destination.IsIP() {
				meta.destIP = destination.Addr
			}
			if meta.destPort == 0 {
				meta.destPort = destination.Port
			}
		}
		if meta.host == "" && destination.IsFqdn() {
			meta.host = strings.ToLower(destination.Fqdn)
			s.completeMeta(meta)
		}
		return meta
	}
	meta := &smartDialMeta{isUDP: isUDP, destPort: destination.Port}
	if destination.IsFqdn() {
		meta.host = strings.ToLower(destination.Fqdn)
	} else if destination.IsIP() {
		meta.resolvedIPs = []netip.Addr{destination.Addr}
	}
	s.completeMeta(meta)
	return meta
}

func smartHostOf(m adapter.InboundContext) string {
	switch {
	case m.Destination.IsFqdn():
		return m.Destination.Fqdn
	case m.SniffHost != "":
		return m.SniffHost
	case m.Domain != "":
		return m.Domain
	case m.OriginDestination.IsFqdn():
		return m.OriginDestination.Fqdn
	case m.RouteOriginalDestination.IsFqdn():
		return m.RouteOriginalDestination.Fqdn
	}
	return ""
}

func smartIPsOf(m adapter.InboundContext) []netip.Addr {
	out := make([]netip.Addr, 0, len(m.DestinationAddresses)+1)
	add := func(a netip.Addr) {
		if a.IsValid() {
			for _, existing := range out {
				if existing == a {
					return
				}
			}
			out = append(out, a.Unmap())
		}
	}
	for _, a := range m.DestinationAddresses {
		add(a)
	}
	add(m.Destination.Addr)
	add(m.OriginDestination.Addr)
	return out
}

// completeMeta fills the derived keys: family, exact target, wildcard,
// ASN, country and the service key.
func (s *Smart) completeMeta(meta *smartDialMeta) {
	if len(meta.resolvedIPs) > 0 {
		meta.destIP = meta.resolvedIPs[0]
	}
	switch {
	case meta.destIP.Is4():
		meta.family = smart.FamilyIPv4
	case meta.destIP.Is6():
		meta.family = smart.FamilyIPv6
	default:
		meta.family = smart.FamilyNone
	}
	ipString := ""
	if meta.destIP.IsValid() {
		ipString = meta.destIP.String()
	}
	if meta.host != "" {
		if addr, err := netip.ParseAddr(meta.host); err == nil {
			meta.host = ""
			if !meta.destIP.IsValid() {
				meta.destIP = addr
				ipString = addr.String()
			}
		}
	}
	switch {
	case meta.host != "":
		meta.target = meta.host + ":" + strconv.Itoa(int(meta.destPort))
	case ipString != "":
		meta.target = M.SocksaddrFrom(meta.destIP, meta.destPort).String()
	}
	meta.wildcard = smart.GetEffectiveTarget(meta.host, ipString)
	if s.preferASN || s.useLightGBM || s.collectData {
		meta.asnCode, meta.asnInfo = s.keys.lookupASN(s, meta.resolvedIPs)
	}
	if s.useLightGBM || s.collectData || s.balance != nil {
		meta.destGeoIP = s.lookupCountry(meta.resolvedIPs)
	}
	meta.smartTarget = s.keys.serviceKey(s, meta)
	meta.scoreContext = smart.Context{
		Network: meta.network(),
		Family:  meta.family,
		Target:  meta.target,
		Site:    meta.smartTarget,
	}
}

// smartKeys derives mihomo's service keys: a rule identifying a service
// keeps its rule string; with prefer_asn a broad rule (or none) is keyed by
// the destination ASN, a shared or unknown network by the site, and an ASN
// that a service rule has claimed by that rule.
type smartKeys struct {
	asnAccess sync.RWMutex
	asnDBs    []*geodb.Database
	asnReady  atomic.Bool

	countryAccess sync.RWMutex
	countryDB     *geodb.Database
	countryReady  atomic.Bool

	// destination ASN diversity per rule target
	diversityAccess sync.Mutex
	diversity       map[string]map[string]struct{}
	// ASN evidence per rule target and the claims derived from it
	evidenceAccess sync.Mutex
	evidence       map[string]map[string]int
	claims         atomic.Pointer[map[string]string]
	// entry counts of rule sets
	ruleCounts sync.Map
	// sites first seen on a shared or unknown network
	siteKeys sync.Map
	siteKeyN atomic.Int32
}

const (
	smartDiversityLimit = 4096
	smartSiteKeyLimit   = 4096
)

func (k *smartKeys) init() {
	k.diversity = make(map[string]map[string]struct{})
	k.evidence = make(map[string]map[string]int)
}

func (k *smartKeys) openDatabases(s *Smart) {
	geoSvc := service.FromContext[adapter.GeoXService](s.ctx)
	if geoSvc == nil {
		return
	}
	if s.preferASN || s.useLightGBM || s.collectData {
		paths := geoSvc.ASNPaths()
		if len(paths) == 0 {
			paths = []string{geoSvc.RequireDefaultASN()}
		}
		var dbs []*geodb.Database
		for _, path := range paths {
			db, err := geodb.Open(path)
			switch {
			case err == nil:
				s.logger.Debug("ASN database loaded from ", path)
			case errors.Is(err, fs.ErrNotExist):
				s.logger.Debug("ASN database ", path, " is downloading")
			default:
				s.logger.Warn("open ASN database ", path, ": ", err)
			}
			if db != nil {
				dbs = append(dbs, db)
			}
		}
		k.asnAccess.Lock()
		k.asnDBs = dbs
		k.asnAccess.Unlock()
		k.asnReady.Store(len(dbs) > 0)
	}
	if s.useLightGBM || s.collectData || s.balance != nil {
		path := geoSvc.MMDBPath()
		if path == "" {
			path = geoSvc.RequireDefaultMMDB()
		}
		db, err := geodb.Open(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.logger.Warn("open country database ", path, ": ", err)
		}
		if db != nil {
			k.countryAccess.Lock()
			k.countryDB = db
			k.countryAccess.Unlock()
			k.countryReady.Store(true)
		}
	}
}

func (k *smartKeys) close() {
	k.asnAccess.Lock()
	for _, db := range k.asnDBs {
		_ = db.Close()
	}
	k.asnDBs = nil
	k.asnAccess.Unlock()
	k.countryAccess.Lock()
	if k.countryDB != nil {
		_ = k.countryDB.Close()
		k.countryDB = nil
	}
	k.countryAccess.Unlock()
}

func smartPublicIP(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

func (k *smartKeys) lookupASN(s *Smart, ips []netip.Addr) (code, info string) {
	if !k.asnReady.Load() {
		return "", ""
	}
	k.asnAccess.RLock()
	defer k.asnAccess.RUnlock()
	for _, ip := range ips {
		if !smartPublicIP(ip) {
			continue
		}
		for _, db := range k.asnDBs {
			var record struct {
				Number       uint   `maxminddb:"autonomous_system_number"`
				Organization string `maxminddb:"autonomous_system_organization"`
			}
			if db.Lookup(ip, &record) == nil && record.Number != 0 {
				code = strconv.FormatUint(uint64(record.Number), 10)
				if record.Organization != "" {
					return code, code + " " + record.Organization
				}
				return code, code
			}
		}
	}
	return "", ""
}

// lookupCountry returns the ISO country of the first public address.
func (s *Smart) lookupCountry(ips []netip.Addr) []string {
	k := &s.keys
	if !k.countryReady.Load() {
		return nil
	}
	k.countryAccess.RLock()
	defer k.countryAccess.RUnlock()
	if k.countryDB == nil {
		return nil
	}
	for _, ip := range ips {
		if !smartPublicIP(ip) {
			continue
		}
		var record struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if k.countryDB.Lookup(ip, &record) == nil && record.Country.ISOCode != "" {
			return []string{record.Country.ISOCode}
		}
	}
	return nil
}

// asnDiversity records asn for target and returns how many unrelated
// networks the target was seen on, capped at BroadASNDiversity.
func (k *smartKeys) asnDiversity(target, asn string) int {
	if asn == "" || smart.SharedASNs[asn] {
		return 0
	}
	k.diversityAccess.Lock()
	defer k.diversityAccess.Unlock()
	set := k.diversity[target]
	if set == nil {
		if len(k.diversity) >= smartDiversityLimit {
			return 0
		}
		set = make(map[string]struct{})
		k.diversity[target] = set
	}
	if len(set) < smart.BroadASNDiversity {
		set[asn] = struct{}{}
	}
	return len(set)
}

// ruleEntryCount returns how many entries a rule set target holds; a rule
// set of BroadRuleCount entries or more is a collection. Counts are cached
// once known.
func (s *Smart) ruleEntryCount(target string) int {
	ruleType, payload, ok := smart.RulePayload(target)
	if !ok || ruleType != "RuleSet" || s.router == nil {
		return 0
	}
	if count, cached := s.keys.ruleCounts.Load(payload); cached {
		return count.(int)
	}
	ruleSet, loaded := s.router.RuleSet(payload)
	if !loaded {
		return 0
	}
	count := int(min(ruleSet.RuleCount(), uint64(1<<31-1)))
	if count > 0 {
		s.keys.ruleCounts.Store(payload, count)
	}
	return count
}

func (k *smartKeys) serviceKey(s *Smart, meta *smartDialMeta) string {
	target := meta.ruleTarget
	if target == "" {
		target = meta.wildcard
	}
	if !s.preferASN {
		return target
	}
	needsASNKey := smart.NeedsASNKey(target, s.ruleEntryCount(target), k.asnDiversity(target, meta.asnCode))
	if needsASNKey && meta.asnCode != "" {
		if claims := k.claims.Load(); claims != nil {
			if rule, ok := (*claims)[meta.asnCode]; ok && rule != smart.ASNClaimAmbiguous {
				return rule
			}
		}
	}
	site := ""
	if needsASNKey && meta.host != "" {
		if meta.asnCode == "" || smart.SharedASNs[meta.asnCode] {
			k.recordSiteKey(s, meta.wildcard)
			site = meta.wildcard
		} else if _, ok := k.siteKeys.Load(meta.wildcard); ok {
			site = meta.wildcard
		}
	}
	return smart.SmartTargetKey(true, meta.asnCode, target, meta.wildcard, site, needsASNKey)
}

// recordSiteKey remembers a site seen on a shared or unknown network; its
// connections keyed by network until now are closed, so the site converges
// on one exit.
func (k *smartKeys) recordSiteKey(s *Smart, site string) {
	if site == "" || k.siteKeyN.Load() >= smartSiteKeyLimit {
		return
	}
	if _, loaded := k.siteKeys.LoadOrStore(site, struct{}{}); loaded {
		return
	}
	k.siteKeyN.Add(1)
	s.conns.closeMatching(func(c *smartConnInfo) bool {
		return c.wildcard == site && c.key != site && c.key != "" && !smart.IsRuleTarget(c.key)
	})
}

// recordEvidence counts a successful connection of a service target on an
// unshared network, for ASN claims.
func (k *smartKeys) recordEvidence(target, asn string) {
	if asn == "" || smart.SharedASNs[asn] {
		return
	}
	switch smart.ClassifyTargetName(target) {
	case smart.TargetKindRuleName, smart.TargetKindService:
	default:
		return
	}
	k.evidenceAccess.Lock()
	defer k.evidenceAccess.Unlock()
	m := k.evidence[target]
	if m == nil {
		if len(k.evidence) >= smartDiversityLimit {
			return
		}
		m = make(map[string]int)
		k.evidence[target] = m
	}
	m[asn]++
}

// claim recomputes which service rule owns each ASN.
func (k *smartKeys) claim() {
	k.evidenceAccess.Lock()
	claims := smart.ClaimedASNRules(k.evidence)
	k.evidenceAccess.Unlock()
	if len(claims) == 0 {
		return
	}
	k.claims.Store(&claims)
}

func (k *smartKeys) claimCount() int {
	if claims := k.claims.Load(); claims != nil {
		return len(*claims)
	}
	return 0
}

func smartNetworkOf(network string) bool {
	return N.NetworkName(network) == N.NetworkUDP
}
