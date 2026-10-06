//go:build with_quic

package quic

import (
	"context"
	"errors"
	"sync"

	"github.com/sagernet/sing-box/protocol/nowhere/core/carrier/dialgate"
	nwquic "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic"
)

// Client caches one handshaked Session per proxy behind the shared dial gate.
type Client struct {
	cfg        *QUICConfig
	gate       *dialgate.Gate
	newSession func(*QUICConfig) *Session

	mu      sync.Mutex
	session *Session
}

func NewClient(cfg *QUICConfig) *Client {
	initial, max := dialgate.DefaultInitial, dialgate.DefaultMax
	if cfg != nil {
		if cfg.DialBackoffInitial > 0 {
			initial = cfg.DialBackoffInitial
		}
		if cfg.DialBackoffMax > 0 {
			max = cfg.DialBackoffMax
		}
	}
	return &Client{
		cfg:        cfg,
		newSession: NewSession,
		gate: dialgate.New(dialgate.Options{
			Initial:        initial,
			Max:            max,
			AlwaysCoalesce: true,
		}),
	}
}

func (c *Client) AcquireSession(ctx context.Context) (nwquic.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out *Session
	err := c.gate.Run(ctx, func(ctx context.Context) error {
		for {
			c.mu.Lock()
			candidate := c.session
			if candidate != nil && candidate.IsClosed() {
				c.session = nil
				candidate = nil
			}
			if candidate != nil {
				c.mu.Unlock()
				if err := candidate.EnsureReady(ctx); err != nil {
					if isCallerContextError(ctx, err) {
						return err
					}
					c.invalidateSession(candidate)
					return err
				}
				if candidate.IsClosed() {
					c.invalidateSession(candidate)
					continue
				}
				out = candidate
				return nil
			}
			newSession := c.newSession
			if newSession == nil {
				newSession = NewSession
			}
			session := newSession(c.cfg)
			c.session = session
			c.mu.Unlock()

			if err := session.EnsureReady(ctx); err != nil {
				if isCallerContextError(ctx, err) {
					return err
				}
				c.invalidateSession(session)
				return err
			}
			out = session
			return nil
		}
	})
	if err != nil {
		if isCallerContextError(ctx, err) {
			return nil, err
		}
		// Older dialgate versions propagate a leader-local error to live
		// followers. The physical Session keeps dialing on its base context, so
		// reuse and wait for that cached Session instead of starting another one.
		cached, waitErr := c.awaitCachedSession(ctx)
		if waitErr != nil {
			return nil, waitErr
		}
		if cached == nil {
			return nil, err
		}
		out = cached
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		c.mu.Lock()
		out = c.session
		c.mu.Unlock()
	}
	if out == nil || out.IsClosed() {
		return nil, errors.New("nowhere: quic session unavailable")
	}
	return out, nil
}

func (c *Client) awaitCachedSession(ctx context.Context) (*Session, error) {
	for {
		c.mu.Lock()
		candidate := c.session
		if candidate != nil && candidate.IsClosed() {
			c.session = nil
			candidate = nil
		}
		c.mu.Unlock()
		if candidate == nil {
			return nil, nil
		}
		if err := candidate.EnsureReady(ctx); err != nil {
			if isCallerContextError(ctx, err) {
				return nil, err
			}
			c.invalidateSession(candidate)
			return nil, err
		}
		if candidate.IsClosed() {
			c.invalidateSession(candidate)
			continue
		}
		return candidate, nil
	}
}

func isCallerContextError(ctx context.Context, err error) bool {
	if ctx == nil || err == nil {
		return false
	}
	ctxErr := ctx.Err()
	return ctxErr != nil && errors.Is(err, ctxErr)
}

func (c *Client) InvalidateSession(stale nwquic.Session) {
	session, ok := stale.(*Session)
	if !ok {
		return
	}
	c.invalidateSession(session)
}

func (c *Client) invalidateSession(stale *Session) {
	c.mu.Lock()
	if c.session == stale {
		c.session = nil
	}
	c.mu.Unlock()
	stale.Close()
}

func (c *Client) Close() error {
	c.mu.Lock()
	session := c.session
	c.session = nil
	c.mu.Unlock()
	if session != nil {
		session.Close()
	}
	return nil
}

var _ nwquic.Backend = (*Client)(nil)
