package server

import (
	"context"
	"sync/atomic"
)

// afterContextFunc is the Go 1.20-compatible subset of context.AfterFunc used
// by the server lifecycle. The returned function reports whether it prevented f.
func afterContextFunc(ctx context.Context, f func()) func() bool {
	if ctx == nil || ctx.Done() == nil {
		return func() bool { return true }
	}
	var claimed atomic.Bool
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if claimed.CompareAndSwap(false, true) {
				f()
			}
		case <-stopped:
		}
	}()
	return func() bool {
		if !claimed.CompareAndSwap(false, true) {
			return false
		}
		close(stopped)
		return true
	}
}
