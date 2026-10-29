package group

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// checkHealth probes every member with the health check URL. Results feed
// the member liveness, the dashboard delay history, the engine's probe
// baseline and the stability (MAD) records. force ignores fresh shared
// results.
func (s *Smart) checkHealth(force bool) {
	st := s.state.Load()
	if st == nil {
		return
	}
	ctx := s.taskContext()
	now := time.Now()
	since := now.Add(-s.interval / 2)
	if force {
		since = now
	}
	storage, _ := s.history.(*urltest.HistoryStorage)
	sem := make(chan struct{}, smartProbeParallel)
	var wg sync.WaitGroup
	for i, member := range st.outbounds {
		if smartSkipType(member.Type()) || member.Tag() == "Compatible" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(member adapter.Outbound, node uint32) {
			defer wg.Done()
			defer func() { <-sem }()
			realTag := RealTag(member, N.NetworkTCP)
			var result urltest.ProbeResult
			if storage != nil {
				result = storage.Prober().Probe(ctx, urltest.ProbeRequest{
					Tag:     realTag,
					Link:    s.testURL,
					Status:  s.expectedStatus,
					Dialer:  member,
					Timeout: C.TCPTimeout,
					Since:   since,
				})
			} else {
				probeCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
				result.Delay, result.Err = urltest.URLTestWithStatus(probeCtx, s.testURL, member, s.expectedStatus)
				cancel()
				result.Time = time.Now()
			}
			if ctx.Err() != nil {
				return
			}
			ok := result.Err == nil
			s.health.record(member.Tag(), result.Delay, ok, result.Time)
			s.group.Probe(node, smart.NetworkTCP, time.Duration(result.Delay)*time.Millisecond, ok, s.interval)
			if s.history != nil {
				if ok {
					storeURLTestHistory(s.history, realTag, result)
				} else {
					deleteURLTestHistory(s.history, realTag, result.Time)
				}
			}
			if !ok {
				s.logger.Debug("outbound ", member.Tag(), " unavailable: ", result.Err)
			}
		}(member, st.nodes[i])
	}
	wg.Wait()
}

// checkStability blocks members whose recent probe delays are anomalous,
// unstable or worsened in grade, for one check interval plus two minutes
// (mihomo checkNodesStable).
func (s *Smart) checkStability() {
	if s.flood.suppressed.Load() {
		return
	}
	st := s.state.Load()
	if st == nil {
		return
	}
	until := time.Now().Add(smartStableInterval + 2*time.Minute)
	for i, tag := range st.tags {
		h, ok := s.health.snapshot(tag)
		if !ok || !h.alive || len(h.delays) == 0 {
			continue
		}
		anomaly, unstable, grade := madMetrics(h.delays)
		previous := h.grade
		worsened := (previous > 0 && grade > previous) || (previous <= 2 && grade > 2)
		s.health.setGrade(tag, grade)
		if anomaly || unstable || worsened {
			s.blocks.BlockGroupNode(s.group.ID(), st.nodes[i], until, "unstable")
			s.logger.Debug("outbound ", tag, " unstable (anomaly=", anomaly, " unstable=", unstable, " grade=", previous, "->", grade, ")")
		}
	}
}

func (h *smartHealth) setGrade(tag string, grade int) {
	if grade <= 0 {
		return
	}
	h.access.Lock()
	if n := h.nodes[tag]; n != nil {
		n.grade = grade
	}
	h.access.Unlock()
}

// applyHostFailLimit sets how many blocked members make a host itself
// broken: a third of the members, at least two.
func (s *Smart) applyHostFailLimit() {
	st := s.state.Load()
	if st == nil {
		return
	}
	s.hostFailLimit.Store(int32(max(2, len(st.outbounds)/3)))
}

// recheckHosts reprobes members blocked for a host by a refused answer,
// so a lifted refusal unblocks them early (mihomo checkHostStatus).
func (s *Smart) recheckHosts() {
	now := time.Now()
	st := s.state.Load()
	type check struct {
		meta   *smartDialMeta
		member adapter.Outbound
		node   uint32
	}
	var checks []check
	for _, host := range s.blocks.Hosts(s.group.ID(), int(s.hostFailLimit.Load()), now) {
		if host.UDP {
			continue
		}
		for node, block := range host.Nodes {
			if block.Code != smart.BlockAnswer || block.Host == "" || block.Until == 0 || block.Until-now.Unix() > int64(20*time.Hour/time.Second) {
				continue
			}
			if smart.HostBackedOff("", s.Tag(), block.Host) || rand.IntN(2) == 0 {
				continue
			}
			member := st.find(s.engine.NodeName(node))
			if member == nil {
				continue
			}
			meta := &smartDialMeta{host: block.Host, wildcard: host.Key, smartTarget: host.Key, destPort: 443}
			checks = append(checks, check{meta, member, node})
		}
	}
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	for _, c := range checks {
		wg.Add(1)
		sem <- struct{}{}
		go func(c check) {
			defer wg.Done()
			defer func() { <-sem }()
			verdict := s.probeVerdict(c.member, c.meta.host)
			if verdict.Action != smart.VerdictIgnore {
				s.applyAnswer(c.meta, c.member, c.node, verdict)
			}
		}(c)
	}
	wg.Wait()
}

// startTasks runs the group's maintenance in the background until close.
func (s *Smart) startTasks() {
	s.tasks.Add(1)
	go func() {
		defer s.tasks.Done()
		s.keys.openDatabases(s)
	}()
	idleSkip := func(fn func()) func() {
		return func() {
			if s.isGroupActive() {
				fn()
			}
		}
	}
	s.runTask(10*time.Second, s.interval, idleSkip(func() { s.checkHealth(false) }))
	s.runTask(5*time.Minute, smartStableInterval, s.checkStability)
	s.runTask(time.Minute, smartHostLimitInterval, s.applyHostFailLimit)
	s.runTask(time.Minute, smartClaimInterval, s.keys.claim)
	s.runTask(smartPersistInterval, smartPersistInterval, s.persist)
	s.runTask(15*time.Minute, smartHostCheckInterval, idleSkip(s.recheckHosts))
	s.runTask(smartCleanupInterval, smartCleanupInterval, func() { s.blocks.Cleanup(time.Now()) })
	if s.balance != nil {
		probe := s.balance.probe
		if probe.enabled {
			s.runTask(90*time.Second, probe.interval, idleSkip(s.balance.runRegionProbes))
		}
		s.runTask(time.Hour, time.Hour, func() { s.balance.scheduleExitDetection(s.balance.snapshot(), false) })
		s.runTask(3*time.Minute, 5*time.Minute, s.balance.pruneMemory)
	}
}

func (s *Smart) runTask(initial, period time.Duration, fn func()) {
	ctx := s.taskContext()
	s.tasks.Add(1)
	go func() {
		defer s.tasks.Done()
		timer := time.NewTimer(initial)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			if s.pause == nil || (!s.pause.IsDevicePaused() && !s.pause.IsNetworkPaused()) {
				fn()
			}
			timer.Reset(period)
		}
	}()
}

// RecordDelays applies the results of a member test run from the API: a
// zero delay is a failed probe.
func (s *Smart) RecordDelays(result map[string]uint16) {
	st := s.state.Load()
	now := time.Now()
	for tag, delay := range result {
		i, ok := st.byTag[tag]
		if !ok {
			continue
		}
		s.health.record(tag, delay, delay > 0, now)
		s.group.Probe(st.nodes[i], smart.NetworkTCP, time.Duration(delay)*time.Millisecond, delay > 0, s.interval)
	}
	s.refreshRanking()
}
