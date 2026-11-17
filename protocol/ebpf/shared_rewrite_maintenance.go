//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"time"

	ECommon "github.com/MiChongs/sing-ebpf"
)

func (s *sharedRewrite) startFlowJanitor() {
	s.janitorAccess.Lock()
	defer s.janitorAccess.Unlock()
	if s.janitorCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(s.inbound.ctx)
	done := make(chan struct{})
	s.janitorCancel = cancel
	s.janitorDone = done
	go s.runFlowJanitor(ctx, done)
}

func (s *sharedRewrite) stopFlowJanitor() {
	s.janitorAccess.Lock()
	if s.janitorCancel == nil {
		s.janitorAccess.Unlock()
		return
	}
	cancel := s.janitorCancel
	done := s.janitorDone
	s.janitorCancel = nil
	s.janitorDone = nil
	s.janitorAccess.Unlock()
	cancel()
	<-done
}

func (s *sharedRewrite) runFlowJanitor(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	tcTicker := time.NewTicker(tcAssignmentMaintenanceSchedule.watchdog)
	defer tcTicker.Stop()
	// Independent jobs share scheduling semantics, never one another's state.
	tcJob := newMaintenanceJob(tcAssignmentMaintenanceSchedule)
	flowJob := newMaintenanceJob(sharedFlowMaintenanceSchedule)
	defer func() {
		tcJob.stop()
		flowJob.stop()
	}()
	tcMaintenancePending := false
	var releaseTimer *time.Timer
	var releaseTimerChannel <-chan time.Time
	var lastReleaseFlush time.Time
	releaseBacklog := false
	resetReleaseTimer := func(backend *ECommon.SharedPacketRewriteBackend, flushed bool) {
		now := time.Now()
		delay, available := backend.NextTCPFlowReleaseDelay(now)
		if !available {
			releaseBacklog = false
			if releaseTimer != nil {
				releaseTimer.Stop()
			}
			releaseTimerChannel = nil
			return
		}
		if flushed {
			// A flush leaves an already expired deadline only when it ran out
			// of budget; finish that backlog without waiting.
			releaseBacklog = delay == 0
		}
		if !releaseBacklog {
			delay = max(delay, sharedFlowReleaseFlushInterval-now.Sub(lastReleaseFlush))
		}
		if releaseTimer == nil {
			releaseTimer = time.NewTimer(delay)
		} else {
			if !releaseTimer.Stop() {
				select {
				case <-releaseTimer.C:
				default:
				}
			}
			releaseTimer.Reset(delay)
		}
		releaseTimerChannel = releaseTimer.C
	}
	defer func() {
		if releaseTimer != nil {
			releaseTimer.Stop()
		}
	}()
	pressure := false
	knownPressure := false
	var belowExitRounds uint32
	var lastReservationFailures uint64
	scanInProgress := false
	for {
		backend := s.sharedBackendInstance()
		var flowWake <-chan struct{}
		if backend != nil {
			flowWake = backend.TCPFlowWake()
		}
		var tcWake <-chan struct{}
		if tcJob.continuation == nil {
			tcWake = s.inbound.tcAssignmentWake
		}
		sweepRequested := false
		select {
		case <-ctx.Done():
			return
		case <-flowWake:
			resetReleaseTimer(backend, false)
			knownPressure, sweepRequested = updateSharedFlowWakeState(
				pressure,
				knownPressure,
				scanInProgress,
				backend.KnownFlowUsage(),
			)
			if !sweepRequested {
				continue
			}
		case <-tcWake:
			tcMaintenancePending = true
		case <-tcTicker.C:
			tcMaintenancePending = true
			// Kernel-only allocations do not appear in KnownFlowUsage and may
			// never produce a userspace wake. Keep a bounded orphan watchdog.
			sweepRequested = flowJob.continuation == nil
		case <-tcJob.continuation:
			tcJob.continuation = nil
			tcMaintenancePending = true
		case <-releaseTimerChannel:
		case <-flowJob.continuation:
			flowJob.continuation = nil
			sweepRequested = true
		}
		if tcMaintenancePending {
			s.inbound.maintainTCAssignments(&tcJob)
			tcMaintenancePending = false
		}
		if backend == nil {
			continue
		}
		now := time.Now()
		if sweepRequested {
			if delay := flowJob.schedule.delay(now); delay > 0 {
				if flowJob.continuation == nil {
					flowJob.reset(delay)
				}
				sweepRequested = false
			}
		}
		if !sweepRequested {
			if !releaseBacklog && now.Sub(lastReleaseFlush) < sharedFlowReleaseFlushInterval {
				// Every path that is not sweeping lands here, including flow
				// wakes during a sweep cooldown; keep them all on one cadence.
				resetReleaseTimer(backend, false)
				continue
			}
			lastReleaseFlush = now
			_, flushErr := backend.FlushReleasedTCPFlows(now, sharedFlowReleaseFlushBudget)
			if flushErr != nil {
				s.janitorWarnings.warn(s.inbound.logger, "flush released shared-network TCP flows: ", flushErr)
			}
			resetReleaseTimer(backend, true)
			continue
		}
		dataPlane := s.dataPlaneInstance()
		if dataPlane == nil || !dataPlane.IsEnabled() {
			pressure = false
			knownPressure = false
			belowExitRounds = 0
			scanInProgress = false
			continue
		}
		reservationPressure := false
		reservationFailures, failureErr := backend.TokenReservationFailures()
		if failureErr != nil {
			s.janitorWarnings.warn(s.inbound.logger, "read shared-network token reservation failures: ", failureErr)
		} else {
			reservationPressure = reservationFailures > lastReservationFailures
			lastReservationFailures = reservationFailures
		}
		maxIdle := sharedFlowMaxIdle
		if pressure || reservationPressure {
			maxIdle = sharedFlowPressureMaxIdle
		}
		result, err := backend.SweepOrphanedFlows(maxIdle, sharedFlowFallbackScanBudget)
		if err != nil {
			if reservationPressure {
				pressure = true
			}
			s.janitorWarnings.warn(s.inbound.logger, "sweep orphaned shared-network flows: ", err)
		} else {
			scanInProgress = !result.Complete
			if !result.Complete {
				flowJob.finish(time.Now(), false, pressure, nil)
				continue
			}
			entered, exited := false, false
			pressure, belowExitRounds, entered, exited = updateSharedFlowPressure(
				pressure,
				belowExitRounds,
				result.Usage,
			)
			if reservationPressure {
				pressure = true
				belowExitRounds = 0
			}
			if entered {
				s.inbound.logger.Warn("eBPF ", ebpfStructuredEvent("shared_map_pressure", map[string]any{
					"entries":  result.Usage.Entries,
					"capacity": result.Usage.Capacity,
					"max_idle": sharedFlowPressureMaxIdle.String(),
				}))
			} else if exited {
				s.inbound.logger.Info("eBPF ", ebpfStructuredEvent("shared_map_pressure_cleared", map[string]any{
					"entries":  result.Usage.Entries,
					"capacity": result.Usage.Capacity,
				}))
			}
		}
		flowJob.finish(time.Now(), result.Complete, pressure, err)
	}
}

func updateSharedFlowWakeState(pressure, knownPressure, scanInProgress bool, usage ECommon.MapUsage) (bool, bool) {
	if !knownPressure {
		knownPressure = flowUsagePressure(false, usage)
	} else if !flowUsagePressure(true, usage) {
		knownPressure = false
	}
	return knownPressure, pressure || knownPressure || scanInProgress
}

func flowUsagePressure(active bool, usage ECommon.MapUsage) bool {
	if active {
		return mapUsageAbovePercent(usage, sharedFlowPressureExitPercent)
	}
	return mapUsageAtLeastPercent(usage, sharedFlowPressureEnterPercent)
}

func updateSharedFlowPressure(active bool, belowExitRounds uint32, usage ECommon.MapUsage) (bool, uint32, bool, bool) {
	return updateMapPressure(active, belowExitRounds, usage, mapPressureHysteresis{
		enterPercent: sharedFlowPressureEnterPercent,
		exitPercent:  sharedFlowPressureExitPercent,
		exitRounds:   sharedFlowPressureExitRounds,
	})
}
