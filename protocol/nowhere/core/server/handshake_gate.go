package server

import (
	"context"
	"sync"
)

// DefaultMaxConcurrentHandshakes bounds in-flight TLS handshakes after admission.
// Default is half of the per-source pre-auth cap so handshake CPU cannot amplify
// beyond admission under burst.
const DefaultMaxConcurrentHandshakes = DefaultMaxUnauthenticatedPerSource / 2

// handshakeGate is a second overload guard between admission and TLS.
// Waiters do not start the TLS deadline until a slot is acquired.
type handshakeGate struct {
	slots chan struct{}
}

func newHandshakeGate(limit int) *handshakeGate {
	if limit <= 0 {
		limit = DefaultMaxConcurrentHandshakes
	}
	return &handshakeGate{slots: make(chan struct{}, limit)}
}

func (g *handshakeGate) acquire(ctx context.Context) (func(), error) {
	if g == nil || g.slots == nil {
		return func() {}, nil
	}
	select {
	case g.slots <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-g.slots })
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
