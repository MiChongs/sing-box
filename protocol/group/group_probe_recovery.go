package group

import (
	"context"
	"time"
)

// Recovery behavior shared by URLTest and LoadBalance groups (mihomo style):
//
//   - After startup the members are probed once; when none is alive (the
//     network was not ready yet) the probe is retried 15s, 35s and 60s after
//     startup, never later than the interval, until a member answers.
//   - When the selected member fails a connection, it is re-probed alone after
//     groupFailureProbeDelay. A member that passes is trusted for
//     groupFailureTrustDuration; one that fails is dropped from the history.
//     When no member is left alive, every member is probed again, at most once
//     per groupEmergencyCheckCooldown.
var groupFailureProbeDelay = 3 * time.Second

const (
	groupFailureProbeTimeout    = 2500 * time.Millisecond
	groupFailureTrustDuration   = time.Minute
	groupEmergencyCheckCooldown = 90 * time.Second
)

var groupStartupProbeBackoff = []time.Duration{15 * time.Second, 20 * time.Second, 25 * time.Second}

// runStartupProbeBackoff retries the startup probe while no member is alive.
// It stops when the group closes, goes idle or probe reports success.
func runStartupProbeBackoff(ctx context.Context, closeChan <-chan struct{}, interval time.Duration, idle func() bool, alive func() bool, probe func() bool) {
	if alive() {
		return
	}
	for _, delay := range groupStartupProbeBackoff {
		lastAttempt := delay >= interval
		if lastAttempt {
			delay = interval
		}
		timer := time.NewTimer(delay)
		select {
		case <-closeChan:
			timer.Stop()
			return
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if idle() || alive() {
			return
		}
		if probe() || lastAttempt {
			return
		}
	}
}
