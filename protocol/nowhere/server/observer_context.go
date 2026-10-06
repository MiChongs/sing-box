package server

import (
	"context"

	"github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"
)

type observerContextKey struct{}

// ContextWithObserver supplies a structured Nowhere observer to an inbound.
func ContextWithObserver(ctx context.Context, observer diagnostic.Observer) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, observerContextKey{}, observer)
}

// ObserverFromContext returns the observer supplied by ContextWithObserver.
func ObserverFromContext(ctx context.Context) diagnostic.Observer {
	if ctx == nil {
		return nil
	}
	observer, _ := ctx.Value(observerContextKey{}).(diagnostic.Observer)
	return observer
}
