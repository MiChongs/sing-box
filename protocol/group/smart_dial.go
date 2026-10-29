package group

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/dns"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// smartPlan is the dial plan of one connection.
type smartPlan struct {
	outbounds []adapter.Outbound
	nodes     []uint32
	decision  smart.Decision
	pinned    bool // manual pin or region pin: dial one by one, keep the pin
	scored    bool // the engine planned it: trials and incumbents apply
}

// plan picks the members one connection may dial, in order.
func (s *Smart) plan(meta *smartDialMeta, network string) smartPlan {
	st := s.state.Load()
	if st == nil || len(st.outbounds) == 0 {
		return smartPlan{}
	}
	isUDP := network == N.NetworkUDP
	if meta.balance == nil {
		if pin := s.PinnedTag(); pin != "" {
			if i, ok := st.byTag[pin]; ok && (!isUDP || s.supportsUDP(st.outbounds[i])) {
				return smartPlan{outbounds: st.outbounds[i : i+1], nodes: st.nodes[i : i+1], pinned: true}
			}
		}
	}
	if s.balance != nil {
		outbounds, source := s.balance.selectCandidates(meta, isUDP, false)
		plan := smartPlan{outbounds: outbounds, pinned: source == "region-pin"}
		plan.nodes = make([]uint32, len(outbounds))
		for i, ob := range outbounds {
			plan.nodes[i] = s.engine.NodeID(ob.Tag())
		}
		return plan
	}
	indexes := s.filterCandidates(st, meta, isUDP)
	if len(indexes) == 0 {
		return smartPlan{}
	}
	candidates := st.candidates
	if len(indexes) != len(st.outbounds) {
		candidates = make([]smart.Candidate, len(indexes))
		for i, idx := range indexes {
			candidates[i] = st.candidates[idx]
		}
	}
	decision := s.group.Select(&meta.scoreContext, candidates, true, smart.Now())
	order := s.orderFallbacks(st, meta, indexes, decision)
	n := min(len(order), smartMaxCandidates)
	plan := smartPlan{decision: decision, scored: true, outbounds: make([]adapter.Outbound, n), nodes: make([]uint32, n)}
	for k, i := range order[:n] {
		plan.outbounds[k] = st.outbounds[indexes[i]]
		plan.nodes[k] = st.nodes[indexes[i]]
	}
	return plan
}

// filterCandidates applies mihomo's filterProxies stages: members that are
// alive, support the network, are not blocked for the group or the target
// and are not deferred by an exit suspicion; failing that, ever looser sets.
// The result is shared and read-only when every member passes.
func (s *Smart) filterCandidates(st *smartGroupState, meta *smartDialMeta, isUDP bool) []int {
	now := time.Now()
	groupID := s.group.ID()
	codes, hostBroken := s.blocks.Lookup(groupID, meta.wildcard, isUDP, int(s.hostFailLimit.Load()), []string{meta.smartTarget}, now)
	soft := func(i int) bool {
		code, ok := codes[st.nodes[i]]
		return ok && (!hostBroken || code == smart.BlockManual)
	}
	manual := func(i int) bool { return len(codes) > 0 && codes[st.nodes[i]] == smart.BlockManual }
	groupBlocked := func(i int) bool {
		_, blocked := s.blocks.GroupBlocked(groupID, st.nodes[i], now)
		return blocked
	}
	deferred := func(i int) bool {
		return s.exitWatch.Defer(meta.wildcard, st.tags[i], now, smart.ExitHalfOpenLease)
	}
	udpOK := func(i int) bool { return !isUDP || s.supportsUDP(st.outbounds[i]) }
	stages := [...]func(i int) bool{
		func(i int) bool {
			return udpOK(i) && s.health.alive(st.tags[i]) && !groupBlocked(i) && !soft(i) && !deferred(i)
		},
		func(i int) bool { return udpOK(i) && !soft(i) && !deferred(i) },
		func(i int) bool { return udpOK(i) && s.health.alive(st.tags[i]) && !deferred(i) },
		func(i int) bool { return !manual(i) && !deferred(i) },
	}
	var indexes []int
	for stage, accept := range stages {
		indexes = indexes[:0]
		all := true
		for i := range st.outbounds {
			if accept(i) {
				if !all {
					indexes = append(indexes, i)
				}
				continue
			}
			if all {
				all = false
				indexes = append(make([]int, 0, len(st.outbounds)), st.all[:i]...)
			}
		}
		if all {
			return st.all
		}
		if len(indexes) == 0 {
			continue
		}
		s.group.CountFiltered(len(st.outbounds) - len(indexes))
		if stage == 0 {
			// One exit-deferred member may take the half-open lease and
			// probe the suspicion.
			for i := range st.outbounds {
				if udpOK(i) && s.health.alive(st.tags[i]) && deferred(i) &&
					s.exitWatch.AllowFallback(meta.wildcard, st.tags[i], now, smart.ExitHalfOpenLease) {
					indexes = append(indexes, i)
					break
				}
			}
		}
		return indexes
	}
	return nil
}

// orderFallbacks keeps the engine's pool order and fills the remaining dial
// slots from the members outside the pool like mihomo's fallback sort: not
// suspected first, then higher policy priority, then probe delay (within
// tolerance by declaration order). Only the slots that can be dialed are
// ordered.
func (s *Smart) orderFallbacks(st *smartGroupState, meta *smartDialMeta, indexes []int, decision smart.Decision) []int {
	order := decision.Order
	pool := min(decision.PoolSize, len(order))
	need := smartMaxCandidates - pool
	if need <= 0 || pool >= len(order) {
		return order
	}
	type key struct {
		position  int
		suspected bool
		factor    float64
		delay     uint16
		index     int
	}
	tail := order[pool:]
	keys := make([]key, len(tail))
	for i, position := range tail {
		member := indexes[position]
		tag := st.tags[member]
		delay := s.health.delay(tag)
		if delay == 0 {
			delay = 0xFFFF
		}
		keys[i] = key{position, s.exitWatch.Suspected(meta.wildcard, tag), st.candidates[member].Priority, delay, member}
	}
	tolerance := int(s.tolerance)
	hasPriority := !s.priority.Empty()
	less := func(a, b key) bool {
		if a.suspected != b.suspected {
			return !a.suspected
		}
		if hasPriority && a.factor != b.factor {
			return a.factor > b.factor
		}
		if tolerance > 0 {
			diff := int(a.delay) - int(b.delay)
			if diff < 0 {
				diff = -diff
			}
			if diff <= tolerance {
				return a.index < b.index
			}
		}
		if a.delay != b.delay {
			return a.delay < b.delay
		}
		return a.index < b.index
	}
	// Partial selection: the first need keys in order.
	for i := 0; i < len(keys) && i < need; i++ {
		best := i
		for j := i + 1; j < len(keys); j++ {
			if less(keys[j], keys[best]) {
				best = j
			}
		}
		keys[i], keys[best] = keys[best], keys[i]
	}
	result := make([]int, pool, pool+min(need, len(keys)))
	copy(result, order[:pool])
	for i := 0; i < len(keys) && i < need; i++ {
		result = append(result, keys[i].position)
	}
	return result
}

// peekBest is the member a new connection would most likely use, without
// recording a selection.
func (s *Smart) peekBest(network string) adapter.Outbound {
	st := s.state.Load()
	if st == nil || len(st.outbounds) == 0 {
		return nil
	}
	isUDP := network == N.NetworkUDP
	candidates := make([]smart.Candidate, 0, len(st.outbounds))
	indexes := make([]int, 0, len(st.outbounds))
	for i, ob := range st.outbounds {
		if isUDP && !s.supportsUDP(ob) {
			continue
		}
		candidates = append(candidates, smart.Candidate{Node: st.nodes[i], Priority: s.priority.Factor(st.tags[i])})
		indexes = append(indexes, i)
	}
	if len(candidates) == 0 {
		return nil
	}
	ctx := smart.Context{Network: smart.NetworkTCP}
	if isUDP {
		ctx.Network = smart.NetworkUDP
	}
	decision := s.group.Select(&ctx, candidates, false, smart.Now())
	if len(decision.Order) == 0 {
		return nil
	}
	return st.outbounds[indexes[decision.Order[0]]]
}

// smartDialBatch returns the members of dial round i: one each for the
// first rounds, then parallel batches; pinned plans dial one by one.
func smartDialBatch(total, round int, pinned bool) (begin, end int) {
	switch {
	case total <= 0:
		return 0, 0
	case pinned || round < smartDeterministicPrefix:
		if round < total {
			return round, round + 1
		}
		return 0, 0
	}
	begin = smartDeterministicPrefix + (round-smartDeterministicPrefix)*smartParallelDials
	if begin >= total {
		return 0, 0
	}
	return begin, min(begin+smartParallelDials, total)
}

// dialTimeout is the member's connect time EMA times smartConnectThreshold,
// capped by the group timeout.
func (s *Smart) dialTimeout(node uint32, network smart.Network) time.Duration {
	connect := s.group.ConnectAverage(node, network)
	if connect <= 0 {
		return s.timeout
	}
	return min(max(time.Duration(connect*smartConnectThreshold*float64(time.Millisecond)), time.Second), s.timeout)
}

type smartDialResult struct {
	index   int
	conn    net.Conn
	packet  net.PacketConn
	attempt *smart.Attempt
	latency time.Duration
	err     error
}

type smartDialFunc func(ctx context.Context, member adapter.Outbound) (net.Conn, net.PacketConn, error)

// dialPlan dials the plan in mihomo's rounds: the first members one at a
// time, then racing batches; the first success wins and the losers are
// closed. Every attempt reports to the engine.
func (s *Smart) dialPlan(ctx context.Context, plan *smartPlan, meta *smartDialMeta, dial smartDialFunc) (smartDialResult, error) {
	var finalErr error
	defer func() {
		if len(plan.nodes) > 0 {
			s.group.Release(&plan.decision, plan.nodes[0])
		}
	}()
	rounds := smartMaxRetries
	if plan.pinned {
		// One member per round: every planned member gets its round.
		rounds = len(plan.outbounds)
	}
	for round := 0; round < rounds; round++ {
		begin, end := smartDialBatch(len(plan.outbounds), round, plan.pinned)
		if begin == end {
			break
		}
		if ctx.Err() != nil {
			break
		}
		timeout := time.Duration(0)
		for i := begin; i < end; i++ {
			timeout = max(timeout, s.dialTimeout(plan.nodes[i], meta.network()))
		}
		result, err := s.dialBatch(ctx, plan, meta, begin, end, timeout, timeout < s.timeout, dial)
		if err == nil {
			return result, nil
		}
		finalErr = err
		if smartStopRetry(err) {
			break
		}
	}
	if finalErr == nil {
		finalErr = ctx.Err()
	}
	if finalErr == nil {
		finalErr = E.New("no member dialed")
	}
	return smartDialResult{}, E.Cause(finalErr, "all members failed for ", smartDestinationString(meta, M.Socksaddr{}))
}

func (s *Smart) dialBatch(ctx context.Context, plan *smartPlan, meta *smartDialMeta, begin, end int, timeout time.Duration, adaptive bool, dial smartDialFunc) (smartDialResult, error) {
	batchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	n := end - begin
	results := make(chan smartDialResult, n)
	var won atomic.Bool
	for i := begin; i < end; i++ {
		var decision *smart.Decision
		if i == 0 && plan.scored {
			decision = &plan.decision
		}
		attempt := s.group.Begin(&meta.scoreContext, decision, plan.nodes[i], smart.Now())
		go func(i int, attempt *smart.Attempt) {
			start := time.Now()
			conn, packet, err := dial(batchCtx, plan.outbounds[i])
			results <- smartDialResult{index: i, conn: conn, packet: packet, attempt: attempt, latency: time.Since(start), err: err}
		}(i, attempt)
	}
	var errs []error
	for received := 0; received < n; received++ {
		result := <-results
		if result.err == nil {
			if won.CompareAndSwap(false, true) {
				cancel()
				result.attempt.Setup(result.latency)
				if remaining := n - received - 1; remaining > 0 {
					go drainDials(results, remaining)
				}
				return result, nil
			}
		}
		errs = append(errs, result.err)
		s.settleDialFailure(ctx, adaptive, meta, plan.outbounds[result.index], result)
	}
	return smartDialResult{}, errors.Join(errs...)
}

// drainDials closes the connections of dials that lost the race; their
// attempts settle neutrally.
func drainDials(results chan smartDialResult, remaining int) {
	for range remaining {
		result := <-results
		if result.conn != nil {
			_ = result.conn.Close()
		}
		if result.packet != nil {
			_ = result.packet.Close()
		}
		result.attempt.Finish(&smart.Finish{Outcome: smart.OutcomeCancelled})
	}
}

// settleDialFailure reports a failed dial: a cancelled caller, a lost race,
// an address resolution failure or the expiry of a timeout adapted to the
// member's own connect time says nothing certain about the member; anything
// else is a node-scoped setup failure.
func (s *Smart) settleDialFailure(ctx context.Context, adaptive bool, meta *smartDialMeta, member adapter.Outbound, result smartDialResult) {
	cancelled := ctx.Err() != nil || errors.Is(result.err, context.Canceled) || smartStopRetry(result.err) ||
		(adaptive && errors.Is(result.err, context.DeadlineExceeded))
	if cancelled || smartSkipType(member.Type()) || meta.host == s.testHost && meta.host != "" {
		result.attempt.Finish(&smart.Finish{Outcome: smart.OutcomeCancelled})
		return
	}
	if suppressed, started := s.flood.failure(time.Now()); suppressed {
		if started {
			s.logger.Warn("failures are flooding in, learning paused until a connection succeeds")
		}
		result.attempt.Finish(&smart.Finish{Outcome: smart.OutcomeCancelled})
		return
	}
	result.attempt.Finish(&smart.Finish{
		Outcome:      smart.OutcomeFailure,
		Scope:        smart.ScopeNode,
		SetupLatency: result.latency,
	})
	s.logger.Debug("dial ", member.Tag(), " for ", smartDestinationString(meta, M.Socksaddr{}), " failed: ", result.err)
	if !meta.isUDP {
		s.judgeDialFailure(meta, member, result.latency)
	}
}

// smartStopRetry reports errors no other member can fix: the destination
// does not resolve (mihomo ShouldStopRetry).
func smartStopRetry(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return true
	}
	var rcode dns.RcodeError
	return errors.As(err, &rcode) && rcode == dns.RcodeNameError
}

func (s *Smart) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.markActive()
	switch N.NetworkName(network) {
	case N.NetworkTCP, N.NetworkUDP:
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	isUDP := N.NetworkName(network) == N.NetworkUDP
	meta := s.metaForDial(ctx, destination, isUDP)
	if s.balance != nil {
		meta = s.balance.prepareMeta(ctx, meta, destination)
	}
	plan := s.plan(meta, N.NetworkName(network))
	if len(plan.outbounds) == 0 {
		return nil, E.New("no available member for ", smartDestinationString(meta, destination))
	}
	if s.balance != nil {
		s.balance.pendingAdd(plan.outbounds[0].Tag(), 1)
		defer s.balance.pendingAdd(plan.outbounds[0].Tag(), -1)
	}
	result, err := s.dialPlan(ctx, &plan, meta, func(ctx context.Context, member adapter.Outbound) (net.Conn, net.PacketConn, error) {
		conn, err := member.DialContext(ctx, network, destination)
		return conn, nil, err
	})
	if err != nil {
		return nil, err
	}
	member := plan.outbounds[result.index]
	fb := s.newFeedback(member, plan.nodes[result.index], meta, result.attempt, time.Now().Add(-result.latency), result.latency)
	wrapped := s.wrapConn(result.conn, fb)
	conn := s.interruptGroup.NewConn(wrapped, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx))
	s.conns.setCloser(fb.info, conn)
	s.dialed(ctx, meta, plan, result.index)
	return conn, nil
}

func (s *Smart) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.markActive()
	if s.disableUDP {
		return nil, E.New("UDP is disabled for ", s.Tag())
	}
	meta := s.metaForDial(ctx, destination, true)
	if s.balance != nil {
		meta = s.balance.prepareMeta(ctx, meta, destination)
	}
	plan := s.plan(meta, N.NetworkUDP)
	if len(plan.outbounds) == 0 {
		return nil, E.New("no available member for UDP to ", smartDestinationString(meta, destination))
	}
	// UDP dials one member at a time; a lone member is retried.
	plan.pinned = true
	if len(plan.outbounds) == 1 {
		plan.outbounds = []adapter.Outbound{plan.outbounds[0], plan.outbounds[0], plan.outbounds[0]}
		plan.nodes = []uint32{plan.nodes[0], plan.nodes[0], plan.nodes[0]}
	}
	if s.balance != nil {
		s.balance.pendingAdd(plan.outbounds[0].Tag(), 1)
		defer s.balance.pendingAdd(plan.outbounds[0].Tag(), -1)
	}
	result, err := s.dialPlan(ctx, &plan, meta, func(ctx context.Context, member adapter.Outbound) (net.Conn, net.PacketConn, error) {
		conn, err := member.ListenPacket(ctx, destination)
		return nil, conn, err
	})
	if err != nil {
		return nil, err
	}
	member := plan.outbounds[result.index]
	fb := s.newFeedback(member, plan.nodes[result.index], meta, result.attempt, time.Now().Add(-result.latency), result.latency)
	wrapped := &smartPacketConn{PacketConn: result.packet, feedback: fb}
	conn := s.interruptGroup.NewPacketConn(wrapped, interrupt.IsExternalConnectionFromContext(ctx), interrupt.IsResourceDownloadFromContext(ctx))
	s.conns.setCloser(fb.info, conn)
	s.dialed(ctx, meta, plan, result.index)
	return conn, nil
}

// dialed records the member that carried a connection.
func (s *Smart) dialed(ctx context.Context, meta *smartDialMeta, plan smartPlan, index int) {
	member := plan.outbounds[index]
	tag := member.Tag()
	s.lastSelected.Store(&tag)
	adapter.RecordGroupDial(ctx, s.Tag(), member)
	if meta.balance != nil && meta.balance.via != "" {
		adapter.RecordGroupDial(ctx, meta.balance.via, member)
	}
	s.flood.success()
	if s.balance != nil {
		s.balance.onDialSuccess(meta, tag)
		return
	}
	if !plan.scored || plan.pinned || index == 0 {
		return
	}
	// The planned member failed and a fallback carried the connection: it
	// becomes the key's incumbent, and the key's connections through other
	// members converge on it (mihomo adoptUnwrapWinner).
	s.group.Adopt(&meta.scoreContext, plan.nodes[index], smart.Now())
	if !meta.isUDP && meta.smartTarget != "" {
		if closed := s.conns.closeKey(meta.smartTarget, plan.nodes[index], true); closed > 0 {
			s.logger.DebugContext(ctx, "converged ", closed, " connections of [", meta.smartTarget, "] on ", tag)
		}
	}
}
