package bundle

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

type routePrepareResult struct {
	lanes *preparedLanes
	err   error
}

// prepareWithFallback acquires physical lanes for the primary mix route within
// timeout, then tries the other allowed route once with a new flow ID. READY,
// target-dial, and payload failures must not use this helper: starting a
// FlowHeader or Target write commits the flow.
func prepareWithFallback(
	ctx context.Context,
	timeout time.Duration,
	initialID wire.FlowID,
	plan routePlan,
	allocFallback func() (wire.FlowID, error),
	prepare func(context.Context, wire.FlowID, resolvedRoute) (*preparedLanes, error),
) (*preparedLanes, wire.FlowID, resolvedRoute, error) {
	if !plan.hasFallback {
		lanes, err := prepare(ctx, initialID, plan.primary)
		if err == nil {
			return lanes, initialID, plan.primary, nil
		}
		if lanes != nil {
			_ = lanes.Close()
		}
		return nil, initialID, plan.primary, err
	}

	if timeout <= 0 {
		timeout = DefaultMixFallbackTimeout
	}
	primaryDeadline := time.Now().Add(timeout)
	primaryCtx, cancelPrimary := context.WithTimeout(ctx, timeout)
	primaryResult := make(chan routePrepareResult)
	abandoned := make(chan struct{})
	go func() {
		lanes, err := prepare(primaryCtx, initialID, plan.primary)
		select {
		case primaryResult <- routePrepareResult{lanes: lanes, err: err}:
		case <-abandoned:
			if lanes != nil {
				_ = lanes.Close()
			}
		}
	}()

	var (
		lanes *preparedLanes
		err   error
	)
	select {
	case result := <-primaryResult:
		lanes, err = result.lanes, result.err
		// A result that races with expiry is not allowed to revive the primary
		// route after its preparation budget has elapsed.
		primaryErr := primaryCtx.Err()
		if primaryErr != nil || !time.Now().Before(primaryDeadline) {
			if lanes != nil {
				_ = lanes.Close()
				lanes = nil
			}
			if parentErr := ctx.Err(); parentErr != nil {
				cancelPrimary()
				return nil, initialID, plan.primary, parentErr
			}
			if primaryErr == nil || errors.Is(primaryErr, context.DeadlineExceeded) {
				err = fmt.Errorf("nowhere: route %s preparation timed out after %s", plan.primary.label(), timeout)
			}
		}
	case <-primaryCtx.Done():
		close(abandoned)
		if parentErr := ctx.Err(); parentErr != nil {
			cancelPrimary()
			return nil, initialID, plan.primary, parentErr
		}
		err = fmt.Errorf("nowhere: route %s preparation timed out after %s", plan.primary.label(), timeout)
	}
	cancelPrimary()
	if parentErr := ctx.Err(); parentErr != nil {
		if lanes != nil {
			_ = lanes.Close()
		}
		return nil, initialID, plan.primary, parentErr
	}
	if err == nil {
		return lanes, initialID, plan.primary, nil
	}
	if lanes != nil {
		_ = lanes.Close()
	}

	fallbackID, allocErr := allocFallback()
	if allocErr != nil {
		return nil, initialID, plan.primary, fmt.Errorf(
			"nowhere: route %s failed before commit: %w; failed to allocate fallback flow ID: %v",
			plan.primary.label(), err, allocErr,
		)
	}
	fallbackResult := make(chan routePrepareResult)
	fallbackAbandoned := make(chan struct{})
	go func() {
		lanes, err := prepare(ctx, fallbackID, plan.fallback)
		select {
		case fallbackResult <- routePrepareResult{lanes: lanes, err: err}:
		case <-fallbackAbandoned:
			if lanes != nil {
				_ = lanes.Close()
			}
		}
	}()
	var fallbackLanes *preparedLanes
	var fallbackErr error
	select {
	case result := <-fallbackResult:
		fallbackLanes, fallbackErr = result.lanes, result.err
		if parentErr := ctx.Err(); parentErr != nil {
			if fallbackLanes != nil {
				_ = fallbackLanes.Close()
			}
			return nil, fallbackID, plan.fallback, parentErr
		}
	case <-ctx.Done():
		close(fallbackAbandoned)
		return nil, fallbackID, plan.fallback, ctx.Err()
	}
	if fallbackErr != nil {
		if fallbackLanes != nil {
			_ = fallbackLanes.Close()
		}
		return nil, fallbackID, plan.fallback, fmt.Errorf(
			"nowhere: route %s failed before commit: %v; fallback route %s failed before commit: %w",
			plan.primary.label(), err, plan.fallback.label(), fallbackErr,
		)
	}
	return fallbackLanes, fallbackID, plan.fallback, nil
}
