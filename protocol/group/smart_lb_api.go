package group

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/smart"
	E "github.com/sagernet/sing/common/exceptions"
)

// Runtime control and introspection of smart-loadbalance groups, used by
// the Clash API, the daemon and the group's own Now / All / SelectOutbound.

// MemberTags returns the member node tags. Unlike All, it never lists the
// region outbounds a smart-loadbalance group may present as its members.
func (s *Smart) MemberTags() []string {
	snap := s.state.Load()
	if snap == nil {
		return nil
	}
	return append([]string(nil), snap.tags...)
}

// FixedSelection is the Clash API `fixed` value: the pinned member, else
// the locked region (its region outbound when the group lists them).
func (s *Smart) FixedSelection() string {
	if pinned := s.PinnedTag(); pinned != "" {
		return pinned
	}
	if s.balance != nil {
		return s.balance.lockDisplay()
	}
	return ""
}

// IsLoadBalance reports whether the group is a smart-loadbalance group.
func (s *Smart) IsLoadBalance() bool { return s.balance != nil }

// RegionLock returns the locked region code, "" when none.
func (s *Smart) RegionLock() string {
	if s.balance == nil {
		return ""
	}
	return s.balance.currentLock()
}

// RegionOf returns the region a member belongs to.
func (s *Smart) RegionOf(tag string) string {
	if s.balance == nil {
		return ""
	}
	return s.balance.snapshot().regionOf[tag]
}

// SetRegionLock locks the group to a region (code, built-in name or region
// outbound tag); "" unlocks. Returns the applied region code.
func (s *Smart) SetRegionLock(raw string) (string, error) {
	if s.balance == nil {
		return "", E.New("not a smart-loadbalance group")
	}
	b := s.balance
	code := ""
	if strings.TrimSpace(raw) != "" {
		var ok bool
		code, ok = b.resolveRegion(raw)
		if !ok {
			return "", E.New("unknown region: ", raw)
		}
	}
	previous := b.currentLock()
	b.setLock(code)
	b.persistRegionState()
	if previous != code {
		if code == "" {
			s.logger.Info("smart-loadbalance[", s.Tag(), "] region lock released (was ", previous, ")")
		} else {
			s.logger.Info("smart-loadbalance[", s.Tag(), "] locked to region ", code)
		}
		if s.interruptExternalConnections && s.interruptGroup != nil {
			s.interruptGroup.Interrupt(true)
		}
	}
	return code, nil
}

// SetRegionMode switches the region mode at runtime; "" restores the
// configured mode. Returns the applied mode.
func (s *Smart) SetRegionMode(raw string) (string, error) {
	if s.balance == nil {
		return "", E.New("not a smart-loadbalance group")
	}
	b := s.balance
	mode := b.configMode
	if strings.TrimSpace(raw) != "" {
		var ok bool
		if mode, ok = normaliseRegionMode(raw); !ok {
			return "", E.New("unknown region mode: ", raw)
		}
	}
	if mode == regionModePriority && len(b.priority) == 0 {
		return "", E.New("region mode priority requires region.priority in the configuration")
	}
	if mode == regionModeDestination {
		// Start fetching the country database now rather than on the first
		// connection.
		go b.countryDatabase()
	}
	b.setMode(mode)
	b.regionMemo.Clear()
	b.persistRegionState()
	s.logger.Info("smart-loadbalance[", s.Tag(), "] region mode: ", mode)
	return mode, nil
}

// SetBalance switches the balance strategy and / or affinity at runtime;
// empty arguments keep the current value, "default" restores the
// configured one. Returns the applied values.
func (s *Smart) SetBalance(strategy, affinity string) (string, string, error) {
	if s.balance == nil {
		return "", "", E.New("not a smart-loadbalance group")
	}
	b := s.balance
	newStrategy, newAffinity := b.currentStrategy(), b.currentAffinity()
	switch strings.TrimSpace(strategy) {
	case "":
	case "default":
		newStrategy = b.configStrategy
	default:
		var ok bool
		if newStrategy, ok = normaliseBalanceStrategy(strategy); !ok {
			return "", "", E.New("unknown balance strategy: ", strategy)
		}
	}
	switch strings.TrimSpace(affinity) {
	case "":
	case "default":
		newAffinity = b.configAffinity
	default:
		var ok bool
		if newAffinity, ok = normaliseBalanceAffinity(affinity); !ok {
			return "", "", E.New("unknown balance affinity: ", affinity)
		}
	}
	if newAffinity != b.currentAffinity() {
		b.affinityMemo.Clear()
	}
	b.setStrategy(newStrategy)
	b.setAffinity(newAffinity)
	b.persistRegionState()
	s.logger.Info("smart-loadbalance[", s.Tag(), "] balance: strategy=", newStrategy, " affinity=", newAffinity)
	return newStrategy, newAffinity, nil
}

// RedetectRegions re-runs member classification and starts exit probes:
// for every member with force, else for the members that need one.
// Returns how many exit probes were started.
func (s *Smart) RedetectRegions(force bool) int {
	if s.balance == nil {
		return 0
	}
	snap := s.balance.rebuild()
	started := s.balance.scheduleExitDetection(snap, force)
	go s.balance.syncSubgroups()
	return started
}

// resolveRegion maps a region code, a built-in region name or the tag of a
// region outbound of this group to a region code present in the group.
func (b *smartBalance) resolveRegion(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	for code, child := range b.subgroupList() {
		if child.Tag() == raw {
			return code, true
		}
	}
	code := normaliseRegionCode(raw)
	if _, ok := b.snapshot().regions[code]; ok {
		return code, true
	}
	return "", false
}

// selectionRegion reports whether a Clash API / daemon selection names a
// region (a region outbound tag or a region code) rather than a member.
func (b *smartBalance) selectionRegion(tag string) (string, bool) {
	if state := b.s.state.Load(); state != nil {
		for _, member := range state.tags {
			if member == tag {
				return "", false
			}
		}
	}
	return b.resolveRegion(tag)
}

// listsRegions reports whether the group lists its region outbounds as its
// members (region.outbounds.members = regions).
func (b *smartBalance) listsRegions() bool {
	return b.sub.enabled && b.sub.members == subgroupMembersRegions && len(b.subgroupList()) > 0
}

// allMembers is All() for groups listing region outbounds: the region
// outbounds in region order, then the members of regions without one.
func (b *smartBalance) allMembers() []string {
	if !b.listsRegions() {
		return nil
	}
	snap := b.snapshot()
	children := b.subgroupList()
	out := make([]string, 0, len(snap.codes))
	listed := make(map[string]bool)
	for _, code := range snap.codes {
		if child := children[code]; child != nil {
			out = append(out, child.Tag())
			listed[code] = true
		}
	}
	// Declared region outbounds whose region has no members yet.
	var empty []string
	for code, child := range children {
		if !listed[code] {
			empty = append(empty, child.Tag())
		}
	}
	sort.Strings(empty)
	out = append(out, empty...)
	for _, code := range snap.codes {
		if listed[code] {
			continue
		}
		for _, ob := range snap.regions[code].members {
			out = append(out, ob.Tag())
		}
	}
	return out
}

// now is Now() for groups listing region outbounds: the locked region's
// outbound, else the outbound of the region that carried the last
// connection. "" lets Now() fall back to the last node.
func (b *smartBalance) now() string {
	if !b.listsRegions() {
		return ""
	}
	code := b.currentLock()
	if code == "" {
		if last := b.lastRegion.Load(); last != nil {
			code = *last
		}
	}
	if code != "" {
		if child := b.subgroupFor(code); child != nil {
			return child.Tag()
		}
		return ""
	}
	snap := b.snapshot()
	for _, c := range snap.codes {
		if child := b.subgroupFor(c); child != nil {
			return child.Tag()
		}
	}
	return ""
}

// lockDisplay is the Clash API `fixed` value of a locked group: the region
// outbound when there is one, else the region code.
func (b *smartBalance) lockDisplay() string {
	code := b.currentLock()
	if code == "" {
		return ""
	}
	if child := b.subgroupFor(code); child != nil && b.listsRegions() {
		return child.Tag()
	}
	return code
}

// BalanceInfo is the compact smart-loadbalance block of GET /proxies.
func (s *Smart) BalanceInfo() map[string]any {
	if s.balance == nil {
		return nil
	}
	b := s.balance
	snap := b.snapshot()
	counts := b.healthyCounts(snap, false)
	regions := make([]map[string]any, 0, len(snap.codes))
	for _, code := range snap.codes {
		name, nameEn, icon := b.regionName(code)
		entry := map[string]any{
			"code":    code,
			"name":    name,
			"nameEn":  nameEn,
			"flag":    regionFlag(code),
			"count":   len(snap.regions[code].members),
			"healthy": counts[code],
		}
		if icon != "" {
			entry["icon"] = icon
		}
		if child := b.subgroupFor(code); child != nil {
			entry["outbound"] = child.Tag()
		}
		regions = append(regions, entry)
	}
	return map[string]any{
		"strategy": b.currentStrategy(),
		"affinity": b.currentAffinity(),
		"mode":     b.currentMode(),
		"lock":     b.currentLock(),
		"fallback": b.fallback,
		"regions":  regions,
	}
}

// RegionTable is the detailed region view of GET /smart/groups/{name}/regions.
func (s *Smart) RegionTable() map[string]any {
	if s.balance == nil {
		return nil
	}
	b := s.balance
	snap := b.snapshot()
	blocked := b.blockedNodes()
	sc := b.newScorer(nil, false)
	counts := b.healthyCounts(snap, false)
	regions := make([]map[string]any, 0, len(snap.codes))
	for _, code := range snap.codes {
		info := snap.regions[code]
		name, nameEn, icon := b.regionName(code)
		members := make([]map[string]any, 0, len(info.members))
		var load int64
		for _, ob := range info.members {
			tag := ob.Tag()
			q, _ := sc.quality(tag)
			nodeLoad := b.nodeLoad(tag)
			load += nodeLoad
			member := map[string]any{
				"name":    tag,
				"source":  snap.sourceOf[tag],
				"healthy": b.nodeHealthy(ob, false, blocked),
				"load":    nodeLoad,
				"quality": math.Round(q*1000) / 1000,
			}
			if exit, ok := b.exitGeo.Load(tag); ok && !exit.failed {
				member["exit"] = exit.country
				if exit.ip != "" {
					member["exitIp"] = exit.ip
				}
			}
			members = append(members, member)
		}
		entry := map[string]any{
			"code":    code,
			"name":    name,
			"nameEn":  nameEn,
			"flag":    regionFlag(code),
			"count":   len(info.members),
			"healthy": counts[code],
			"load":    load,
			"score":   math.Round(b.regionScore(code, snap, sc, false, blocked, nil)*1000) / 1000,
			"allowed": b.allowed(code),
			"members": members,
		}
		if icon != "" {
			entry["icon"] = icon
		}
		if weight, ok := b.weights[code]; ok {
			entry["weight"] = weight
		}
		if child := b.subgroupFor(code); child != nil {
			entry["outbound"] = child.Tag()
		}
		if last, ok := b.regionLast.Load(code); ok {
			entry["last"] = last
		}
		regions = append(regions, entry)
	}
	priority := b.priority
	if priority == nil {
		priority = []string{}
	}
	return map[string]any{
		"group":          s.Tag(),
		"mode":           b.currentMode(),
		"configMode":     b.configMode,
		"lock":           b.currentLock(),
		"strategy":       b.currentStrategy(),
		"configStrategy": b.configStrategy,
		"affinity":       b.currentAffinity(),
		"configAffinity": b.configAffinity,
		"affinityTtl":    b.affinityTTL.String(),
		"fallback":       b.fallback,
		"priority":       priority,
		"minNodes":       b.minNodes,
		"minQuality":     b.minQuality,
		"maxNodes":       b.maxNodes,
		"maxConnections": b.maxConnsPerNode,
		"sticky":         b.sticky.String(),
		"switchMargin":   b.switchMargin,
		"unknown":        b.unknown,
		"detect": map[string]any{
			"name":    b.detectName,
			"exit":    b.exit.mode,
			"exitUrl": b.exit.url,
			"exitTtl": b.exit.ttl.String(),
		},
		"probe": map[string]any{
			"enabled":  b.probe.enabled,
			"interval": b.probe.interval.String(),
			"targets":  b.probe.targets,
			"regions":  b.probe.regions,
			"tracked":  b.probeTargets.Size(),
			"results":  b.probes.Size(),
		},
		"outbounds": map[string]any{
			"enabled": b.sub.enabled,
			"auto":    b.sub.auto,
			"members": b.sub.members,
			"tag":     b.sub.tagTemplate,
		},
		"regions":  regions,
		"excluded": nonNilStrings(snap.excluded),
		"memory": map[string]any{
			"regionTargets": b.regionMemo.Size(),
			"affinity":      b.affinityMemo.Size(),
		},
	}
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// reset drops the runtime state along with a flush of the group's stored
// data: the lock and the runtime mode / strategy / affinity return to the
// configuration, exit results, memories and probe results are forgotten,
// and the members are re-sorted (and their exits re-probed).
func (b *smartBalance) reset() {
	b.setLock("")
	b.setMode(b.configMode)
	b.setStrategy(b.configStrategy)
	b.setAffinity(b.configAffinity)
	b.exitGeo.Clear()
	b.regionMemo.Clear()
	b.affinityMemo.Clear()
	b.probes.Clear()
	b.probeTargets.Clear()
	b.destCache.Clear()
	b.regionLast.Clear()
	b.lastRegion.Store(nil)
	b.wrrMu.Lock()
	clear(b.wrrState)
	b.wrrMu.Unlock()
	b.rebuild()
	b.scheduleRefresh()
}

// persistRegionState stores the runtime overrides (lock, and mode /
// strategy / affinity when they differ from the configuration).
func (b *smartBalance) persistRegionState() {
	store := b.s.store
	if store == nil {
		return
	}
	record := smart.RegionStateRecord{Lock: b.currentLock(), UpdatedAt: time.Now().Unix()}
	if mode := b.currentMode(); mode != b.configMode {
		record.Mode = mode
	}
	if strategy := b.currentStrategy(); strategy != b.configStrategy {
		record.Strategy = strategy
	}
	if affinity := b.currentAffinity(); affinity != b.configAffinity {
		record.Affinity = affinity
	}
	if record.Lock == "" && record.Mode == "" && record.Strategy == "" && record.Affinity == "" {
		store.AppendToGlobalQueue(smart.StoreOperation{
			Type:   smart.OpDeleteRegionState,
			Group:  b.s.Tag(),
			Config: smartConfigName,
		})
		return
	}
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	store.AppendToGlobalQueue(smart.StoreOperation{
		Type:   smart.OpSaveRegionState,
		Group:  b.s.Tag(),
		Config: smartConfigName,
		Data:   data,
	})
}

// hydrate restores the persisted runtime overrides and exit results.
func (b *smartBalance) hydrate() {
	b.hydrateExitGeo()
	store := b.s.store
	if store == nil {
		return
	}
	rows, err := store.GetSubBytesByPath(smart.FormatDBKey(smart.KeyTypeRegionState, smartConfigName, b.s.Tag()))
	if err != nil {
		return
	}
	for _, data := range rows {
		var record smart.RegionStateRecord
		if json.Unmarshal(data, &record) != nil {
			continue
		}
		if record.Lock != "" {
			b.setLock(normaliseRegionCode(record.Lock))
		}
		if mode, ok := normaliseRegionMode(record.Mode); ok && record.Mode != "" && (mode != regionModePriority || len(b.priority) > 0) {
			b.setMode(mode)
		}
		if strategy, ok := normaliseBalanceStrategy(record.Strategy); ok && record.Strategy != "" {
			b.setStrategy(strategy)
		}
		if affinity, ok := normaliseBalanceAffinity(record.Affinity); ok && record.Affinity != "" {
			b.setAffinity(affinity)
		}
		b.s.logger.Info("smart-loadbalance[", b.s.Tag(), "] restored runtime state: lock=", b.currentLock(),
			" mode=", b.currentMode(), " strategy=", b.currentStrategy(), " affinity=", b.currentAffinity())
		break
	}
}

// summary is the one-line region overview logged at start.
func (b *smartBalance) summary() string {
	snap := b.snapshot()
	parts := make([]string, 0, len(snap.codes))
	for _, code := range snap.codes {
		parts = append(parts, code+"("+strconv.Itoa(len(snap.regions[code].members))+")")
	}
	if len(parts) == 0 {
		parts = append(parts, "none")
	}
	return strings.Join(parts, " ")
}
