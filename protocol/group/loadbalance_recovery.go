package group

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	N "github.com/sagernet/sing/common/network"
)

// memberInterrupt returns the interrupt group of the connections dialed through
// member tag, so a member found dead can have its connections closed alone.
func (g *LoadBalanceGroup) memberInterrupt(tag string) *interrupt.Group {
	g.memberInterruptAccess.Lock()
	defer g.memberInterruptAccess.Unlock()
	if g.memberInterrupts == nil {
		g.memberInterrupts = make(map[string]*interrupt.Group)
	}
	group := g.memberInterrupts[tag]
	if group == nil {
		group = interrupt.NewGroup()
		g.memberInterrupts[tag] = group
	}
	return group
}

func (g *LoadBalanceGroup) newConn(tag string, conn net.Conn, isExternal bool, isResourceDownload bool) net.Conn {
	return g.memberInterrupt(tag).NewConn(g.interruptGroup.NewConn(conn, isExternal, isResourceDownload), isExternal, isResourceDownload)
}

func (g *LoadBalanceGroup) newPacketConn(tag string, conn net.PacketConn, isExternal bool, isResourceDownload bool) net.PacketConn {
	return g.memberInterrupt(tag).NewPacketConn(g.interruptGroup.NewPacketConn(conn, isExternal, isResourceDownload), isExternal, isResourceDownload)
}

// interruptMember closes the connections through tag, except resource downloads.
func (g *LoadBalanceGroup) interruptMember(tag string) {
	g.memberInterruptAccess.Lock()
	group := g.memberInterrupts[tag]
	g.memberInterruptAccess.Unlock()
	if group != nil {
		group.Interrupt(true)
	}
}

// pruneMemberInterrupts drops the interrupt groups of removed members.
func (g *LoadBalanceGroup) pruneMemberInterrupts(outbounds []adapter.Outbound) {
	members := make(map[string]struct{}, len(outbounds))
	for _, detour := range outbounds {
		members[detour.Tag()] = struct{}{}
	}
	g.memberInterruptAccess.Lock()
	for tag := range g.memberInterrupts {
		if _, loaded := members[tag]; !loaded {
			delete(g.memberInterrupts, tag)
		}
	}
	g.memberInterruptAccess.Unlock()
}

func (g *LoadBalanceGroup) isIdle() bool {
	return time.Since(g.lastActive.Load()) > g.idleTimeout
}

func (g *LoadBalanceGroup) hasAliveOutbound() bool {
	for _, detour := range g.loadOutbounds() {
		if g.aliveForTestURL(detour, N.NetworkTCP, make(map[string]bool)) || g.aliveForTestURL(detour, N.NetworkUDP, make(map[string]bool)) {
			return true
		}
	}
	return false
}

func (g *LoadBalanceGroup) startupCheckWithBackoff() {
	runStartupProbeBackoff(g.ctx, g.close, g.interval, g.isIdle, g.hasAliveOutbound, func() bool {
		result, _ := g.urlTestWait(g.ctx, true)
		if len(result) > 0 {
			g.logger.Debug("startup probe succeeded")
			return true
		}
		g.logger.Debug("startup probe found no available outbound, retrying")
		return false
	})
}

// onOutboundFailed re-probes a member that failed a connection, see
// group_probe_recovery.go.
func (g *LoadBalanceGroup) onOutboundFailed(failed adapter.Outbound) {
	if failed == nil || len(g.loadOutbounds()) <= 1 {
		return
	}
	tag := failed.Tag()
	now := time.Now()
	if now.UnixNano() < g.emergencyCheckAt.Load() {
		return
	}
	g.failureAccess.Lock()
	if g.failureProbePending == nil {
		g.failureProbePending = make(map[string]bool)
		g.failureTrustUntil = make(map[string]time.Time)
	}
	if now.Before(g.failureTrustUntil[tag]) || g.failureProbePending[tag] {
		g.failureAccess.Unlock()
		return
	}
	g.failureProbePending[tag] = true
	g.failureAccess.Unlock()
	time.AfterFunc(groupFailureProbeDelay, func() {
		defer func() {
			g.failureAccess.Lock()
			delete(g.failureProbePending, tag)
			g.failureAccess.Unlock()
		}()
		if g.ctx.Err() != nil {
			return
		}
		g.probeFailedMember(failed)
	})
}

func (g *LoadBalanceGroup) probeFailedMember(failed adapter.Outbound) {
	tag := failed.Tag()
	ctx, cancel := context.WithTimeout(g.ctx, groupFailureProbeTimeout)
	delay, err := urltest.URLTest(ctx, g.link, failed)
	cancel()
	if err == nil {
		history := &adapter.URLTestHistory{Time: time.Now(), Delay: delay}
		if previous := g.history.LoadURLTestHistory(tag); previous != nil && previous.Delay > 0 {
			// The probe only confirms availability; keep the measured delay.
			history.Delay = previous.Delay
		}
		g.history.StoreURLTestHistory(tag, history)
		g.failureAccess.Lock()
		g.failureTrustUntil[tag] = time.Now().Add(groupFailureTrustDuration)
		g.failureAccess.Unlock()
		if g.tag != "" {
			updateLoadBalanceURLTestHistory(g.outbound, g.history, g.tag, g.loadOutbounds())
		}
		return
	}
	g.logger.Debug("outbound ", tag, " failed availability probe: ", err)
	g.history.DeleteURLTestHistory(tag)
	g.interruptMember(tag)
	if g.tag != "" {
		updateLoadBalanceURLTestHistory(g.outbound, g.history, g.tag, g.loadOutbounds())
	}
	if g.hasAliveOutbound() {
		return
	}
	g.emergencyCheckAt.Store(time.Now().Add(groupEmergencyCheckCooldown).UnixNano())
	if !g.isIdle() {
		go g.CheckOutbounds(false)
	}
}
