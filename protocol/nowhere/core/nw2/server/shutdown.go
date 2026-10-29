package server

import (
	"context"
	"sync"
)

type cleanupCoordinator struct {
	mu   sync.Mutex
	done chan struct{}
	err  error
}

func (c *cleanupCoordinator) start(ctx context.Context, prepare func(), cleanup func(context.Context) error) (<-chan struct{}, bool) {
	c.mu.Lock()
	started := false
	if c.done == nil {
		started = true
		if prepare != nil {
			prepare()
		}
		c.done = make(chan struct{})
		done := c.done
		go func() {
			err := cleanup(ctx)
			c.mu.Lock()
			c.err = err
			close(done)
			c.mu.Unlock()
		}()
	}
	done := c.done
	c.mu.Unlock()
	return done, started
}

func (c *cleanupCoordinator) wait(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return c.result()
	case <-ctx.Done():
		cause := context.Cause(ctx)
		if cause == nil {
			cause = ctx.Err()
		}
		return cause
	}
}

func (c *cleanupCoordinator) waitDone(done <-chan struct{}) error {
	<-done
	return c.result()
}

func (c *cleanupCoordinator) result() error {
	c.mu.Lock()
	err := c.err
	c.mu.Unlock()
	return err
}

func (c *cleanupCoordinator) Done() <-chan struct{} {
	c.mu.Lock()
	done := c.done
	c.mu.Unlock()
	return done
}
