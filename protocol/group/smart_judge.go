package group

import (
	"math/rand/v2"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/common/smart/lightgbm"
	"github.com/sagernet/sing-box/common/tcpinfo"
)

// Loss strike gates of a judged TCP window (mihomo checkNodeQuality).
const (
	smartLossStrikeRate = 0.10
	smartLossSoftRate   = 0.05
)

// captureTCP reads the member socket's retransmission counters before the
// connection closes, judged in windows by the group's loss sampler.
func (f *smartFeedback) captureTCP() {
	if f.meta.isUDP || f.conn == nil {
		return
	}
	info, source, ok := tcpinfo.ReadWithSource(f.conn)
	if !ok {
		return
	}
	if window, judged := f.s.loss.Consume(source, info); judged {
		f.lossWindow = window
		f.lossJudged = true
	}
}

// smartVerdict is the judgement of one finished connection.
type smartVerdict struct {
	outcome  smart.Outcome
	scope    smart.FailureScope
	upstream bool // the node or path returned an error
	stalled  bool
}

func (f *smartFeedback) verdict(duration time.Duration) smartVerdict {
	tx, rx := f.tx.Load(), f.rx.Load()
	upstream := f.readErr.Load() != nil || f.writeErr.Load() != nil
	switch {
	case f.degraded.Load():
		// The group closed it to converge a key on one exit.
		return smartVerdict{outcome: smart.OutcomeCancelled}
	case upstream:
		// Setup succeeded, so the node reached the target path: the failure
		// belongs to the target unless it repeats across targets.
		return smartVerdict{outcome: smart.OutcomeFailure, scope: smart.ScopeTarget, upstream: true}
	case tx == 0 && rx == 0:
		return smartVerdict{outcome: smart.OutcomeCancelled}
	case rx == 0:
		if !f.meta.isUDP && duration > smartStalledGrace && (f.meta.destPort == 443 || f.meta.host == "") {
			return smartVerdict{outcome: smart.OutcomeFailure, scope: smart.ScopeTarget, stalled: true}
		}
		// The client gave up before an answer: nothing is known.
		return smartVerdict{outcome: smart.OutcomeCancelled}
	}
	return smartVerdict{outcome: smart.OutcomeSuccess}
}

// judge settles a finished connection (mihomo recordConnectionStats with
// honk's outcome scoping): the engine learns the outcome, timings, goodput
// and quality weight; the block records learn stalls, low quality and
// loss; short answers are probed; the exit of the member is learned; a
// training sample may be written.
func (s *Smart) judge(f *smartFeedback) {
	member, meta := f.member, f.meta
	duration := time.Since(f.start)
	skip := smartSkipType(member.Type()) || (meta.host != "" && meta.host == s.testHost)
	if !skip && s.balance == nil {
		s.exitWatch.MaybeProbe(s.taskContext(), member.Tag(), smartProber{s, member})
	}
	if skip {
		f.attempt.Finish(&smart.Finish{Outcome: smart.OutcomeCancelled})
		return
	}
	v := f.verdict(duration)
	if v.outcome == smart.OutcomeFailure {
		if suppressed, started := s.flood.failure(time.Now()); suppressed {
			if started {
				s.logger.Warn("failures are flooding in, learning paused until a connection succeeds")
			}
			f.attempt.Finish(&smart.Finish{Outcome: smart.OutcomeCancelled})
			return
		}
	} else if v.outcome == smart.OutcomeSuccess {
		s.flood.success()
	}
	tx, rx := f.tx.Load(), f.rx.Load()
	if rx > 0 && tx == 0 {
		// The server spoke first; the exchange still worked.
		tx = 1
	}
	finish := &smart.Finish{
		Outcome:         v.outcome,
		Scope:           v.scope,
		SetupOK:         true,
		TX:              tx,
		RX:              rx,
		SetupLatency:    f.setupLatency,
		ResponseLatency: time.Duration(f.responseLatency.Load()),
		Duration:        duration,
		MaxUpRate:       f.upRate.max() / 1024,
		MaxDownRate:     f.downRate.max() / 1024,
	}
	if last := f.lastRXPublish.Load(); last != 0 {
		finish.RXAt = smart.MonoAt(time.Unix(0, last))
	}
	if f.lossJudged {
		finish.Sent = f.lossWindow.Sent()
		finish.Retrans = f.lossWindow.TotalRetrans()
		finish.LossRate = f.lossWindow.LossRate()
	}
	if v.outcome == smart.OutcomeCancelled {
		f.attempt.Finish(finish)
		return
	}
	history := s.group.History(&meta.scoreContext, f.node)
	input := s.modelInput(f, finish, history)
	weight, predicted := s.qualityWeight(input)
	finish.Quality = weight
	f.attempt.Finish(finish)
	if v.outcome == smart.OutcomeSuccess && meta.asnCode != "" {
		s.keys.recordEvidence(meta.smartTarget, meta.asnCode)
	}
	degraded, failed := false, false
	if s.balance == nil {
		degraded, failed = s.judgeBlocks(f, v, finish, weight)
	}
	if s.collector != nil && (s.sampleRate >= 1 || rand.Float64() <= s.sampleRate) {
		label := weight
		if degraded || failed {
			switch {
			case label >= smart.AllowedWeight:
				label *= 0.1
			case label == 0:
				label = smart.AllowedWeight * rand.Float64()
			}
		}
		source := "Traditional"
		if predicted {
			source = "LightGBM"
		}
		s.collector.AddSample(input, lightgbm.SampleMeta{
			ASN:   meta.asnInfo,
			Host:  meta.host,
			IP:    smartAddrString(meta),
			Port:  meta.destPort,
			GeoIP: meta.destGeoIP,
		}, label, source)
	}
}

func smartAddrString(meta *smartDialMeta) string {
	if meta.destIP.IsValid() {
		return meta.destIP.String()
	}
	return ""
}

// modelInput assembles the mihomo ModelInput of a finished connection from
// the service record plus this connection.
func (s *Smart) modelInput(f *smartFeedback, finish *smart.Finish, h smart.CellHistory) *smart.ModelInput {
	meta := f.meta
	ema := func(old, sample float64) int64 {
		if sample <= 0 {
			return int64(old)
		}
		if old <= 0 {
			return int64(sample)
		}
		return int64((old*2 + sample*4) / 6)
	}
	upMB := float64(finish.TX) / (1 << 20)
	downMB := float64(finish.RX) / (1 << 20)
	minutes := finish.Duration.Minutes()
	durationAvg := minutes
	if h.DurationAvg > 0 {
		durationAvg = (h.DurationAvg + minutes) / 2
	}
	sent := h.CumulSent + finish.Sent
	cumulLoss := 0.0
	if sent > 0 {
		cumulLoss = min(float64(h.CumulRetrans+finish.Retrans)/float64(sent), 1)
	}
	input := &smart.ModelInput{
		Success:                   h.Success,
		Failure:                   h.Failure,
		ConnectTime:               ema(h.ConnectAvg, float64(finish.SetupLatency.Milliseconds())),
		Latency:                   ema(h.LatencyAvg, float64(finish.ResponseLatency.Milliseconds())),
		UploadTotal:               upMB,
		HistoryUploadTotal:        h.UploadTotal + upMB,
		MaxuploadRate:             finish.MaxUpRate,
		HistoryMaxUploadRate:      max(h.MaxUpRate, finish.MaxUpRate),
		DownloadTotal:             downMB,
		HistoryDownloadTotal:      h.DownloadTotal + downMB,
		MaxdownloadRate:           finish.MaxDownRate,
		HistoryMaxDownloadRate:    max(h.MaxDownRate, finish.MaxDownRate),
		ConnectionDuration:        minutes,
		HistoryConnectionDuration: durationAvg,
		LastUsed:                  h.LastUsed,
		IsUDP:                     meta.isUDP,
		IsTCP:                     !meta.isUDP,
		ConnectionFailed:          finish.Outcome == smart.OutcomeFailure,
		LossRate:                  finish.LossRate,
		CumulLossRate:             cumulLoss,
		EmaLossRate:               h.LossEMA,
		DestIPASN:                 meta.asnInfo,
		Host:                      meta.wildcard,
		DestIP:                    smartAddrString(meta),
		DestPort:                  meta.destPort,
		DestGeoIP:                 meta.destGeoIP,
		GroupName:                 s.Tag(),
		NodeName:                  f.member.Tag(),
	}
	if finish.Outcome == smart.OutcomeSuccess {
		input.Success++
	} else {
		input.Failure++
	}
	region, asn := s.exitWatch.Label(meta.wildcard, f.member.Tag())
	input.ExitRegion = region
	if s.preferASN {
		input.ExitASN = asn
	}
	return input
}

// qualityWeight scores the connection with the LightGBM model when one is
// loaded, else with the scene formula. The policy priority is applied by
// the engine, not baked into the weight.
func (s *Smart) qualityWeight(input *smart.ModelInput) (float64, bool) {
	if s.model.IsLoaded() {
		return s.model.PredictWeight(input, 1)
	}
	return smart.CalculateWeight(input, 1)
}

// judgeBlocks applies mihomo's checkNodeQuality and markNodeFailure: the
// first matching rule judges the connection and the host records learn
// it. It returns whether the connection degraded the node and whether
// that newly blocked it.
func (s *Smart) judgeBlocks(f *smartFeedback, v smartVerdict, finish *smart.Finish, weight float64) (degraded, failed bool) {
	meta, member := f.meta, f.member
	tag := member.Tag()
	if s.PinnedTag() != "" {
		return false, false
	}
	if f.manualBlock.Load() {
		failed = s.markNodeFailure(meta, f.node, true, smart.BlockManual, 0)
		s.afterBlock(meta, f.node, failed, true, smart.BlockManual)
		return true, failed
	}
	now := time.Now()
	codes, hostBroken := s.blocks.Lookup(s.group.ID(), meta.wildcard, meta.isUDP, int(s.hostFailLimit.Load()), []string{meta.smartTarget}, now)
	if hostBroken {
		return false, false
	}
	adjusted := weight * s.priority.Factor(tag)
	var code smart.BlockCode
	switch {
	case adjusted > 0 && adjusted < smart.AllowedWeight:
		code, degraded = smart.BlockLowWeight, true
	case v.upstream:
		code = smart.BlockError
	case codes[f.node] != smart.BlockNone:
		return false, false
	case v.stalled:
		code, degraded = smart.BlockStalled, true
	default:
		suspected := s.exitWatch.Suspected(meta.wildcard, tag)
		eligible := smart.ResponseProbeEligible(meta.host, meta.destPort, false, float64(finish.RX)/(1<<20), meta.isUDP)
		if suspected || eligible {
			s.probeAfterClose(f, eligible)
			return false, false
		}
		if f.lossJudged {
			rate := f.lossWindow.LossRate()
			ema := s.group.History(&meta.scoreContext, f.node).LossEMA
			if rate >= smartLossStrikeRate || (rate >= smartLossSoftRate && ema >= smartLossSoftRate) {
				code, degraded = smart.BlockLoss, true
			}
		}
		if code == smart.BlockNone {
			return false, false
		}
	}
	ttl := time.Duration(0)
	if code == smart.BlockStalled {
		ttl = smartStalledProbeTTL
	}
	failed = s.markNodeFailure(meta, f.node, degraded || code == smart.BlockError, code, ttl)
	s.afterBlock(meta, f.node, failed, degraded, code)
	return degraded, failed
}

// markNodeFailure records a judgement on the host key and, unless it is
// only evidence about the host (answer, stalled), on the service key too,
// so every host of a rule avoids the node together.
func (s *Smart) markNodeFailure(meta *smartDialMeta, node uint32, failure bool, code smart.BlockCode, ttl time.Duration) bool {
	update := smart.BlockUpdate{
		Group:          s.group.ID(),
		Key:            meta.wildcard,
		UDP:            meta.isUDP,
		Node:           node,
		Failure:        failure && code != smart.BlockError,
		Checked:        true,
		Code:           code,
		TTL:            ttl,
		Host:           meta.host,
		MaxFailedTimes: s.maxFailedTimes,
		HostLimit:      int(s.hostFailLimit.Load()),
	}
	now := time.Now()
	failed := s.blocks.Update(update, now)
	hostEvidence := code == smart.BlockAnswer || code == smart.BlockStalled
	if (failed || (failure && !hostEvidence && code != smart.BlockError)) && meta.smartTarget != "" && meta.smartTarget != meta.wildcard {
		update.Key = meta.smartTarget
		if s.blocks.Update(update, now) {
			failed = true
		}
	}
	return failed
}

// afterBlock closes the key's connections and drops its incumbent once a
// node is blocked for it; loss and stalls wait for confirmation.
func (s *Smart) afterBlock(meta *smartDialMeta, node uint32, failed, degraded bool, code smart.BlockCode) {
	needsConfirm := code == smart.BlockLoss || code == smart.BlockStalled
	if !failed && !(degraded && !needsConfirm) {
		return
	}
	if !meta.isUDP && meta.smartTarget != "" {
		s.conns.closeKey(meta.smartTarget, 0, false)
	}
	s.dropPin(meta.smartTarget)
	s.logger.Debug("node ", s.engine.NodeName(node), " ", code, " for [", meta.smartTarget, "]")
}

// dropPin forgets the incumbent of a key so the next connection ranks the
// members again.
func (s *Smart) dropPin(key string) {
	if key != "" {
		s.group.ForgetKey(key)
	}
}

// judgeDialFailure counts a failed dial toward the error block of the
// target (mihomo records dial errors through recordConnectionStats).
func (s *Smart) judgeDialFailure(meta *smartDialMeta, member adapter.Outbound, _ time.Duration) {
	if s.balance != nil || s.PinnedTag() != "" {
		return
	}
	node := s.engine.NodeID(member.Tag())
	_, hostBroken := s.blocks.Lookup(s.group.ID(), meta.wildcard, meta.isUDP, int(s.hostFailLimit.Load()), nil, time.Now())
	if hostBroken {
		return
	}
	failed := s.markNodeFailure(meta, node, true, smart.BlockError, 0)
	s.afterBlock(meta, node, failed, false, smart.BlockError)
}

// probeAfterClose checks a short answer (or a node under exit suspicion)
// with a response probe through the same member (mihomo probeAfterClose).
func (s *Smart) probeAfterClose(f *smartFeedback, eligible bool) {
	meta, member := f.meta, f.member
	tag := member.Tag()
	now := time.Now()
	if smart.HostBackedOff("", s.Tag(), meta.host) {
		return
	}
	if !s.throttle.AllowNode(meta.wildcard, tag, now) {
		if eligible {
			pending := s.throttle.PendingFor(meta.wildcard, tag, now)
			if pending > smartStalledProbeGrace || s.throttle.Unproven(meta.wildcard, tag) {
				s.throttle.ClearUnproven(meta.wildcard, tag)
				failed := s.markNodeFailure(meta, f.node, true, smart.BlockStalled, smartStalledProbeTTL)
				s.afterBlock(meta, f.node, failed, true, smart.BlockStalled)
			}
		}
		return
	}
	if !smart.AllowGlobalProbe(now) {
		return
	}
	done, ok := smart.TryStartProbe()
	if !ok {
		return
	}
	s.throttle.MarkPending(meta.wildcard, tag, now)
	s.tasks.Add(1)
	go func() {
		defer s.tasks.Done()
		defer done()
		defer s.throttle.ClearPending(meta.wildcard, tag)
		verdict := s.probeVerdict(member, meta.host)
		if verdict.Action == smart.VerdictIgnore {
			if verdict.Unproven {
				s.throttle.MarkUnproven(meta.wildcard, tag, time.Now())
				s.throttle.NoteFailure(meta.wildcard, tag, time.Now())
			}
			return
		}
		s.throttle.ClearUnproven(meta.wildcard, tag)
		if s.PinnedTag() != "" || s.state.Load().find(tag) == nil {
			return
		}
		if _, broken := s.blocks.Lookup(s.group.ID(), meta.wildcard, meta.isUDP, int(s.hostFailLimit.Load()), []string{meta.smartTarget}, time.Now()); broken {
			return
		}
		if verdict.Action != smart.VerdictReachable {
			s.throttle.NoteFailure(meta.wildcard, tag, time.Now())
		}
		s.applyAnswer(meta, member, f.node, verdict)
	}()
}

// applyAnswer applies a probe verdict: a reachable answer clears the node's
// records for the host, a refusal blocks it (or backs the host off when
// several nodes are refused) and feeds the exit suspicion.
func (s *Smart) applyAnswer(meta *smartDialMeta, member adapter.Outbound, node uint32, verdict smart.Verdict) {
	tag := member.Tag()
	if verdict.Action == smart.VerdictReachable {
		smart.NoteHostAnswer("", s.Tag(), meta.host)
		s.markNodeFailure(meta, node, false, smart.BlockNone, 0)
		if verdict.ControlSuccess {
			s.exitWatch.NoteSuccess(meta.wildcard, tag)
			s.exitWatch.MaybeProbeTarget(s.taskContext(), smartProber{s, member}, meta.wildcard, tag, meta.host)
		}
		s.exitWatch.Clear(meta.wildcard, tag)
		return
	}
	if smart.NoteHostRefusal("", s.Tag(), meta.host, tag, verdict.Reason) {
		return
	}
	failed := s.markNodeFailure(meta, node, true, smart.BlockAnswer, verdict.TTL)
	if smart.RegionEvidence(verdict.Reason) {
		s.exitWatch.Note(meta.wildcard, tag)
		s.exitWatch.MaybeProbeTarget(s.taskContext(), smartProber{s, member}, meta.wildcard, tag, meta.host)
	}
	s.logger.Debug("node ", tag, " refused for ", meta.host, ": ", verdict.Reason)
	if failed && !meta.isUDP {
		s.conns.closeKey(meta.smartTarget, 0, false)
		s.dropPin(meta.smartTarget)
	}
}
