package group

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

// Region probes: the auto mode learns a target's best region from real
// traffic, but traffic only ever flows through the region it already
// picked. For the most visited TLS sites the group therefore also measures
// a TLS handshake to the site through the best node of each candidate
// region every probe interval, and scales the region scores by how the
// regions compare for that site. Probes reuse the shared probe workers and
// stop while the group is idle or the network is down.

const (
	// regionProbeTargetLimit caps how many targets are tracked as probe
	// candidates.
	regionProbeTargetLimit = 1024
	// regionProbeFreshFor is how many probe intervals a result stays usable.
	regionProbeFreshFor = 3
	// regionProbeUnprobedFactor scales regions without a result for a
	// target when others have one, so a measured region is not beaten by an
	// unmeasured one on prior alone.
	regionProbeUnprobedFactor = 0.85
	regionProbeFailedFactor   = 0.25
	regionProbeMinFactor      = 0.35
)

type regionProbeConfig struct {
	enabled  bool
	interval time.Duration
	targets  int
	regions  int
}

func newRegionProbeConfig(options option.SmartRegionProbeOptions) regionProbeConfig {
	config := regionProbeConfig{
		enabled:  !options.Disabled,
		interval: time.Duration(options.Interval),
		targets:  options.Targets,
		regions:  options.Regions,
	}
	if config.interval <= 0 {
		config.interval = defaultRegionProbeEvery
	}
	if config.targets <= 0 {
		config.targets = defaultRegionProbeTargets
	}
	if config.regions <= 0 {
		config.regions = defaultRegionProbeRegions
	}
	return config
}

type regionProbeStat struct {
	access sync.Mutex
	rttMS  float64
	ok     bool
	at     int64
	fails  int
}

type regionProbeTarget struct {
	host     atomic.Pointer[string]
	hits     atomic.Int64
	lastSeen atomic.Int64
}

func regionProbeKey(target, code string) string { return target + "\x00" + code }

// recordProbeTarget remembers a TLS target worth probing: TCP to port 443
// of a domain.
func (b *smartBalance) recordProbeTarget(meta *smartDialMeta) {
	if !b.probe.enabled || meta.isUDP || meta.destPort != 443 || meta.host == "" || meta.smartTarget == "" {
		return
	}
	if _, err := netip.ParseAddr(meta.host); err == nil {
		return
	}
	entry, loaded := b.probeTargets.Load(meta.smartTarget)
	if !loaded {
		if b.probeTargets.Size() >= regionProbeTargetLimit {
			return
		}
		entry, _ = b.probeTargets.LoadOrCompute(meta.smartTarget, func() *regionProbeTarget { return new(regionProbeTarget) })
	}
	host := meta.host
	entry.host.Store(&host)
	entry.hits.Add(1)
	entry.lastSeen.Store(time.Now().UnixNano())
}

func (b *smartBalance) recordRegionProbe(target, code string, ok bool, rttMS float64) {
	stat, _ := b.probes.LoadOrCompute(regionProbeKey(target, code), func() *regionProbeStat { return new(regionProbeStat) })
	stat.access.Lock()
	defer stat.access.Unlock()
	stat.at = time.Now().UnixNano()
	if !ok {
		stat.ok = false
		stat.fails++
		return
	}
	if stat.ok && stat.rttMS > 0 {
		stat.rttMS = 0.5*stat.rttMS + 0.5*rttMS
	} else {
		stat.rttMS = rttMS
	}
	stat.ok = true
	stat.fails = 0
}

// probeFactors returns the per-region score factor for a target, or nil
// when no region has a fresh probe result for it.
func (b *smartBalance) probeFactors(target string) map[string]float64 {
	if !b.probe.enabled || target == "" {
		return nil
	}
	snap := b.regions.Load()
	if snap == nil {
		return nil
	}
	now := time.Now().UnixNano()
	fresh := int64(b.probe.interval) * regionProbeFreshFor
	type result struct {
		ok  bool
		rtt float64
	}
	results := make(map[string]result)
	bestRTT := math.Inf(1)
	for _, code := range snap.codes {
		stat, ok := b.probes.Load(regionProbeKey(target, code))
		if !ok {
			continue
		}
		stat.access.Lock()
		at, statOK, rtt := stat.at, stat.ok, stat.rttMS
		stat.access.Unlock()
		if now-at > fresh {
			continue
		}
		results[code] = result{ok: statOK, rtt: rtt}
		if statOK && rtt > 0 && rtt < bestRTT {
			bestRTT = rtt
		}
	}
	if len(results) == 0 {
		return nil
	}
	factors := make(map[string]float64, len(snap.codes))
	for _, code := range snap.codes {
		r, probed := results[code]
		switch {
		case !probed:
			factors[code] = regionProbeUnprobedFactor
		case !r.ok:
			factors[code] = regionProbeFailedFactor
		case math.IsInf(bestRTT, 1) || r.rtt <= 0:
			factors[code] = 1
		default:
			factors[code] = math.Max(regionProbeMinFactor, math.Min(1, bestRTT/r.rtt))
		}
	}
	return factors
}

// runRegionProbes is the periodic probe task.
func (b *smartBalance) runRegionProbes() {
	if !b.probe.enabled || !b.s.started.Load() || b.s.isGroupIdle() || b.s.inNetworkStorm() {
		return
	}
	if b.currentLock() != "" {
		return
	}
	switch b.currentMode() {
	case regionModeAuto, regionModeDestination:
	default:
		return
	}
	snap := b.snapshot()
	if len(snap.codes) < 2 {
		return
	}
	type candidate struct {
		target string
		host   string
		hits   int64
	}
	now := time.Now().UnixNano()
	var candidates []candidate
	b.probeTargets.Range(func(target string, entry *regionProbeTarget) bool {
		hits := entry.hits.Load()
		// Halve the counts every round so the ranking follows what the user
		// visits now.
		entry.hits.Store(hits / 2)
		if hits == 0 || now-entry.lastSeen.Load() > int64(2*b.probe.interval) {
			return true
		}
		if host := entry.host.Load(); host != nil {
			candidates = append(candidates, candidate{target: target, host: *host, hits: hits})
		}
		return true
	})
	if len(candidates) == 0 {
		return
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].hits > candidates[j].hits })
	if len(candidates) > b.probe.targets {
		candidates = candidates[:b.probe.targets]
	}
	blocked := b.blockedNodes()
	counts := b.healthyCounts(snap, false)
	worker := getSmartWorker()
	startBy := time.Now().Add(sniProbeStartWindow)
	queued := 0
	for _, c := range candidates {
		sc := b.newScorer(&smartDialMeta{smartTarget: c.target}, false)
		type regionPick struct {
			code  string
			score float64
			node  adapter.Outbound
		}
		var picks []regionPick
		for _, code := range snap.codes {
			if !b.allowed(code) || counts[code] < b.minNodes {
				continue
			}
			var (
				bestNode    adapter.Outbound
				bestQuality = -1.0
			)
			for _, ob := range snap.members(code) {
				if !b.nodeHealthy(ob, false, blocked) || b.s.isTargetDebargoed(c.target, ob.Tag()) {
					continue
				}
				if q, _ := sc.quality(ob.Tag()); q > bestQuality {
					bestNode, bestQuality = ob, q
				}
			}
			if bestNode != nil {
				picks = append(picks, regionPick{code: code, score: b.regionScore(code, snap, sc, false, blocked, nil), node: bestNode})
			}
		}
		if len(picks) < 2 {
			continue
		}
		sort.Slice(picks, func(i, j int) bool { return picks[i].score > picks[j].score })
		if len(picks) > b.probe.regions {
			picks = picks[:b.probe.regions]
		}
		for _, p := range picks {
			target, host, code, ob := c.target, c.host, p.code, p.node
			worker.enqueueProbe("lbregion|"+host+"|"+ob.Tag(), sniProbeBudget, startBy, func(ctx context.Context) (uint16, error) {
				rtt, err := b.s.probeSNIOnce(ctx, net.JoinHostPort(host, "443"), ob)
				return uint16(min(max(rtt, 0), math.MaxUint16)), err
			}, func(rtt uint16, err error) {
				if errors.Is(err, errProbeSkipped) || !b.s.started.Load() {
					return
				}
				b.recordRegionProbe(target, code, err == nil, float64(rtt))
			})
			queued++
		}
	}
	if queued > 0 {
		b.s.logger.Debug("smart-loadbalance[", b.s.Tag(), "] queued ", queued, " region probe(s) for ", len(candidates), " target(s)")
	}
}

// pruneProbes drops stale probe results and targets not visited lately.
func (b *smartBalance) pruneProbes() {
	now := time.Now().UnixNano()
	fresh := int64(b.probe.interval) * regionProbeFreshFor
	b.probes.Range(func(key string, stat *regionProbeStat) bool {
		stat.access.Lock()
		at := stat.at
		stat.access.Unlock()
		if now-at > fresh {
			b.probes.Delete(key)
		}
		return true
	})
	b.probeTargets.Range(func(target string, entry *regionProbeTarget) bool {
		if now-entry.lastSeen.Load() > int64(time.Hour) {
			b.probeTargets.Delete(target)
		}
		return true
	})
}
