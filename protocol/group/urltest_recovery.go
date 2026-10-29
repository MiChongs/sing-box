package group

import (
	"context"
	"math/rand/v2"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// randomUnmeasured picks a random member supporting network, so a cold group
// does not send every first connection to the first member.
func (g *URLTestGroup) randomUnmeasured(st *groupState, network string, exclude adapter.Outbound) adapter.Outbound {
	var candidates []adapter.Outbound
	for _, detour := range st.outbounds {
		if detour == exclude || !supportsNetwork(g.history, detour, network) {
			continue
		}
		candidates = append(candidates, detour)
	}
	if len(candidates) == 0 {
		return nil
	}
	return candidates[rand.IntN(len(candidates))]
}

func (g *URLTestGroup) memberAlive(detour adapter.Outbound, network string) bool {
	history := g.history.LoadURLTestHistory(RealTag(detour, network))
	return history != nil && history.Delay > 0
}

func (g *URLTestGroup) hasAliveOutbound() bool {
	st := g.state.Load()
	if st == nil {
		return false
	}
	for _, detour := range st.outbounds {
		if g.memberAlive(detour, N.NetworkTCP) || g.memberAlive(detour, N.NetworkUDP) {
			return true
		}
	}
	return false
}

func (g *URLTestGroup) isIdle() bool {
	return g.idleFor() > g.idleTimeout
}

func (g *URLTestGroup) startupCheckWithBackoff() {
	runStartupProbeBackoff(g.lifetime(), g.close, g.interval, g.isIdle, g.hasAliveOutbound, func() bool {
		result, _ := g.urlTest(g.lifetime(), true)
		if len(result) > 0 {
			g.logger.Debug("startup probe succeeded")
			return true
		}
		g.logger.Debug("startup probe found no available outbound, retrying")
		return false
	})
}

// replaceSelection switches the selection of network to outbound.
func (g *URLTestGroup) replaceSelection(network string, outbound adapter.Outbound) {
	g.updateAccess.Lock()
	var previous adapter.Outbound
	if network == N.NetworkUDP {
		previous = g.selectedOutboundUDP.Swap(outbound)
	} else {
		previous = g.selectedOutboundTCP.Swap(outbound)
	}
	g.updateAccess.Unlock()
	if previous == outbound {
		return
	}
	g.history.NotifyUpdated()
	if previous != nil {
		g.logger.Info("selected outbound updated, ", network, ": ", outbound.Tag())
		if g.interruptExternalConnections {
			g.interruptGroup.Interrupt(true)
		}
	}
}

// onUnmeasuredDialFailed handles a failed connection through a member while
// no other member has a measured delay to fail over to (cold start, or every
// probe failing). See group_probe_recovery.go.
func (g *URLTestGroup) onUnmeasuredDialFailed(failed adapter.Outbound, network string) {
	if g.pinnedOutbound(network) != nil {
		return
	}
	st := g.state.Load()
	if st == nil || len(st.outbounds) <= 1 {
		return
	}
	now := time.Now()
	if now.UnixNano() < g.emergencyCheckAt.Load() || now.UnixNano() < g.failureTrustUntil.Load() {
		return
	}
	if !g.failureProbePending.CompareAndSwap(false, true) {
		return
	}
	time.AfterFunc(groupFailureProbeDelay, func() {
		defer g.failureProbePending.Store(false)
		if g.lifetime().Err() != nil {
			return
		}
		round := g.requestRound(g.lifetime(), probePlan{focus: map[string]struct{}{failed.Tag(): {}}}, true)
		if round != nil {
			timer := time.NewTimer(C.TCPTimeout)
			select {
			case <-round.done:
			case <-timer.C:
			case <-g.lifetime().Done():
			}
			timer.Stop()
		}
		if g.memberAlive(failed, network) {
			g.failureTrustUntil.Store(time.Now().Add(groupFailureTrustDuration).UnixNano())
			return
		}
		if g.selectedOutbound(network) == failed {
			if st := g.state.Load(); st != nil {
				if next, measured := g.Select(network); next != nil && measured && next != failed {
					g.replaceSelection(network, next)
				} else if next = g.randomUnmeasured(st, network, failed); next != nil {
					g.replaceSelection(network, next)
				}
			}
		}
		if g.hasAliveOutbound() {
			return
		}
		g.emergencyCheckAt.Store(time.Now().Add(groupEmergencyCheckCooldown).UnixNano())
		if !g.isIdle() {
			go g.CheckOutbounds(false)
		}
	})
}

// probeManualSelection checks a member the user selects by hand; an
// unavailable member is rejected.
func (g *URLTestGroup) probeManualSelection(detour adapter.Outbound) error {
	ctx, cancel := context.WithTimeout(g.lifetime(), groupFailureProbeTimeout)
	defer cancel()
	delay, err := urltest.URLTestWithStatus(ctx, g.link, detour, g.expectedStatus)
	if err != nil {
		return err
	}
	g.recordProbe(detour.Tag(), time.Now(), true)
	history := &adapter.URLTestHistory{Time: time.Now(), Delay: delay}
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		g.history.StoreURLTestHistory(RealTag(detour, network), history)
	}
	return nil
}

// storeInitialSelection records the selection made before any health check,
// unless one was stored meanwhile.
func (g *URLTestGroup) storeInitialSelection(network string, outbound adapter.Outbound) {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()
	if network == N.NetworkUDP {
		if g.selectedOutboundUDP.Load() == nil {
			g.selectedOutboundUDP.Store(outbound)
		}
		return
	}
	if g.selectedOutboundTCP.Load() == nil {
		g.selectedOutboundTCP.Store(outbound)
	}
}
