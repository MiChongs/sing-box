package nowhere

import (
	"context"
	"errors"
	"sync"
)

type inboundShutdownCoordinator struct {
	mu sync.Mutex

	started       bool
	resultDone    chan struct{}
	cleanupDone   chan struct{}
	phaseObserved chan struct{}
	result        error
	cleanupErr    error
}

func (c *inboundShutdownCoordinator) start(
	contextFactory func() (context.Context, context.CancelFunc),
	phaseFactory func(context.Context) []func() error,
) {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return
	}
	ctx, cancel := contextFactory()
	if ctx == nil {
		ctx = context.Background()
	}
	c.started = true
	c.resultDone = make(chan struct{})
	c.cleanupDone = make(chan struct{})
	phases := phaseFactory(ctx)
	c.phaseObserved = make(chan struct{}, len(phases))
	c.mu.Unlock()

	go c.run(ctx, cancel, phases)
}

func (c *inboundShutdownCoordinator) run(ctx context.Context, cancel context.CancelFunc, phases []func() error) {
	if cancel != nil {
		defer cancel()
	}
	if ctx.Err() != nil {
		c.publishResult(ctx.Err())
		c.finishCleanup(ctx.Err())
		return
	}
	if len(phases) == 0 {
		c.publishResult(nil)
		c.finishCleanup(nil)
		return
	}

	results := make(chan struct{}, len(phases))
	for _, phase := range phases {
		phase := phase
		go func() {
			c.recordPhaseResult(phase())
			results <- struct{}{}
		}()
	}

	var (
		completed int
		published bool
		ctxDone   = ctx.Done()
	)
	for completed < len(phases) {
		select {
		case <-results:
			completed++
		case <-ctxDone:
			c.publishResult(errors.Join(ctx.Err(), c.aggregateError()))
			published = true
			ctxDone = nil
		}
	}
	cleanupErr := c.aggregateError()
	if ctx.Err() != nil {
		cleanupErr = errors.Join(ctx.Err(), cleanupErr)
	}
	if !published {
		c.publishResult(cleanupErr)
	}
	c.finishCleanup(cleanupErr)
}

func (c *inboundShutdownCoordinator) recordPhaseResult(err error) {
	c.mu.Lock()
	c.cleanupErr = errors.Join(c.cleanupErr, err)
	observed := c.phaseObserved
	c.mu.Unlock()
	if observed != nil {
		observed <- struct{}{}
	}
}

func (c *inboundShutdownCoordinator) aggregateError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cleanupErr
}

func (c *inboundShutdownCoordinator) publishResult(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.resultDone:
		return
	default:
	}
	c.result = err
	close(c.resultDone)
}

func (c *inboundShutdownCoordinator) finishCleanup(err error) {
	c.mu.Lock()
	c.cleanupErr = err
	close(c.cleanupDone)
	c.mu.Unlock()
}

func (c *inboundShutdownCoordinator) wait(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	resultDone := c.resultDone
	c.mu.Unlock()
	if resultDone == nil {
		return nil
	}
	select {
	case <-resultDone:
		c.mu.Lock()
		result := c.result
		c.mu.Unlock()
		if ctx.Err() != nil {
			return errors.Join(ctx.Err(), result)
		}
		return result
	case <-ctx.Done():
		var result error
		select {
		case <-resultDone:
			c.mu.Lock()
			result = c.result
			c.mu.Unlock()
		default:
		}
		if result != nil {
			return errors.Join(ctx.Err(), result)
		}
		return errors.Join(ctx.Err(), c.aggregateError())
	}
}

func (c *inboundShutdownCoordinator) phaseObservedForTest() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phaseObserved == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return c.phaseObserved
}

func (c *inboundShutdownCoordinator) cleanupDoneForTest() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cleanupDone == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return c.cleanupDone
}
