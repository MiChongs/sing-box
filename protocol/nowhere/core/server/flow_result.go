package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/protocol/nowhere/core/wire"
)

const setupResultWriteTimeout = time.Second

// FlowReadiness is resolved by Upstream only after the real target is ready or rejected.
type FlowReadiness interface {
	Ready() error
	Reject(cause error) error
}

type flowReadiness struct {
	once          sync.Once
	mu            sync.Mutex
	ready         func() error
	reject        func(wire.SetupResult) error
	gate          *readyGate
	onReady       func()
	resolved      bool
	readyResolved bool
	done          chan struct{}
	err           error
}

func newFlowReadiness(ready func() error, reject func(wire.SetupResult) error) *flowReadiness {
	return &flowReadiness{ready: ready, reject: reject, done: make(chan struct{})}
}

func (r *flowReadiness) Ready() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		r.mu.Lock()
		gate := r.gate
		r.mu.Unlock()
		if gate != nil && !gate.tryEnter() {
			if r.reject != nil {
				r.err = errors.Join(ErrDraining, r.reject(wire.SetupResultFlowLimit))
			} else {
				r.err = ErrDraining
			}
		} else if r.ready != nil {
			// Arm local consumers (e.g. paired UDP datagram delivery via
			// setOnReady) before committing the peer-visible READY byte: a
			// client may answer the byte within one RTT, faster than this
			// goroutine resumes after the write returns.
			r.mu.Lock()
			onReady := r.onReady
			r.mu.Unlock()
			if onReady != nil {
				onReady()
			}
			r.err = r.ready()
		}
		r.mu.Lock()
		r.resolved = true
		r.readyResolved = r.err == nil
		r.mu.Unlock()
		close(r.done)
	})
	<-r.done
	return r.err
}

func (r *flowReadiness) setReadyGate(gate *readyGate) {
	if r == nil || gate == nil {
		return
	}
	r.mu.Lock()
	if !r.resolved {
		r.gate = gate
	}
	r.mu.Unlock()
}

func (r *flowReadiness) Reject(cause error) error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		if r.reject != nil {
			r.err = r.reject(setupFailureCode(cause))
		}
		r.mu.Lock()
		r.resolved = true
		r.mu.Unlock()
		close(r.done)
	})
	<-r.done
	return r.err
}

func (r *flowReadiness) setOnReady(callback func()) {
	if r == nil || callback == nil {
		return
	}
	r.mu.Lock()
	if r.readyResolved {
		r.mu.Unlock()
		callback()
		return
	}
	if r.resolved {
		r.mu.Unlock()
		return
	}
	previous := r.onReady
	r.onReady = func() {
		if previous != nil {
			previous()
		}
		callback()
	}
	r.mu.Unlock()
}

func (r *flowReadiness) Wait(ctx context.Context) error {
	if r == nil {
		return nil
	}
	select {
	case <-r.done:
		return r.err
	case <-ctx.Done():
		cause := context.Cause(ctx)
		if cause == nil {
			cause = ctx.Err()
		}
		return r.Reject(cause)
	}
}

// setupResult commits the single 1.5 setup-result byte exactly once. UDP over
// TLS carries ordinary UoT packets only after READY; it has no separate control
// envelope.
type setupResult struct {
	mu        sync.Mutex
	writer    net.Conn
	committed bool
}

type setupResultError struct{ code wire.SetupResult }

func (e *setupResultError) Error() string { return "nowhere: setup rejected: " + e.code.String() }

func (e *setupResultError) SetupResultCode() wire.SetupResult { return e.code }

func newSetupResult(writer net.Conn, _ wire.FlowKind, _ wire.Carrier) *setupResult {
	return &setupResult{writer: writer}
}

func (r *setupResult) ready() error { return r.commit(wire.SetupResultReady) }

func (r *setupResult) reject(code wire.SetupResult) error { return r.commit(code) }

func (r *setupResult) rejectContext(ctx context.Context, code wire.SetupResult) error {
	return r.commitContext(ctx, code)
}

func (r *setupResult) commit(result wire.SetupResult) error {
	return r.commitContext(context.Background(), result)
}

func (r *setupResult) commitContext(ctx context.Context, result wire.SetupResult) error {
	if r == nil || r.writer == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.committed {
		return nil
	}
	r.committed = true
	deadline := time.Now().Add(setupResultWriteTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	_ = r.writer.SetWriteDeadline(deadline)
	defer r.writer.SetWriteDeadline(time.Time{})
	if ctx.Err() != nil {
		_ = r.writer.Close()
	} else if ctx.Done() != nil {
		stop := afterContextFunc(ctx, func() { _ = r.writer.Close() })
		defer stop()
	}
	return wire.WriteSetupResult(r.writer, result)
}

func setupFailureCode(err error) wire.SetupResult {
	var setupErr interface {
		SetupResultCode() wire.SetupResult
	}
	if errors.As(err, &setupErr) {
		return setupErr.SetupResultCode()
	}
	switch {
	case errors.Is(err, ErrCarrierMismatch), errors.Is(err, wire.ErrInvalidFlowHeader), errors.Is(err, wire.ErrInvalidFrame):
		return wire.SetupResultInvalidRequest
	case errors.Is(err, ErrMetadataConflict), errors.Is(err, ErrDuplicateHalf):
		return wire.SetupResultMetadataConflict
	case errors.Is(err, ErrPairTimeout):
		return wire.SetupResultPairTimeout
	case errors.Is(err, ErrPairLimit), errors.Is(err, ErrSessionLimit), errors.Is(err, ErrDraining), errors.Is(err, ErrPortalHopLimit):
		return wire.SetupResultFlowLimit
	case errors.Is(err, ErrClosed), errors.Is(err, net.ErrClosed), errors.Is(err, context.Canceled):
		return wire.SetupResultSessionReplaced
	case errors.Is(err, ErrInvalidHandler), errors.Is(err, ErrUpstreamNotConfigured):
		return wire.SetupResultInternalError
	default:
		return wire.SetupResultDialFailed
	}
}

type readyGate struct {
	mu     sync.Mutex
	closed bool
}

func (g *readyGate) tryEnter() bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	open := !g.closed
	g.mu.Unlock()
	return open
}

func (g *readyGate) close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
}
