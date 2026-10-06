//go:build with_quic

package quic

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	nwquic "github.com/sagernet/sing-box/protocol/nowhere/core/carrier/quic"
)

// preparedStream owns an opened QUIC stream until setup bytes are committed.
type preparedStream struct {
	session *Session
	stream  stream
	once    sync.Once
}

func (s *Session) PrepareStream(ctx context.Context) (nwquic.PreparedStream, error) {
	if err := s.EnsureReady(ctx); err != nil {
		return nil, err
	}
	if s.IsClosed() {
		return nil, errSessionClosed
	}
	opened, err := s.openQUICStream(ctx)
	if err != nil {
		s.maybeFailSession(err)
		return nil, err
	}
	s.mu.Lock()
	s.activeConns++
	s.disarmIdleTimerLocked()
	s.mu.Unlock()
	return &preparedStream{session: s, stream: opened}, nil
}

func (p *preparedStream) Commit(ctx context.Context, setup []byte, finishWrite bool) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var (
		conn net.Conn
		err  error
	)
	p.once.Do(func() {
		if p.stream == nil || p.session == nil {
			err = errSessionClosed
			return
		}
		if p.session.IsClosed() {
			_ = p.abort()
			err = errSessionClosed
			return
		}
		select {
		case <-ctx.Done():
			_ = p.abort()
			err = ctx.Err()
			return
		default:
		}
		if writeErr, reset := writeAllContext(ctx, p.stream, setup); writeErr != nil {
			if reset {
				err = errors.Join(writeErr, p.closeAfterReset())
			} else {
				_ = p.abort()
				if ctxErr := ctx.Err(); ctxErr != nil {
					err = ctxErr
				} else {
					p.session.maybeFailSession(writeErr)
					err = writeErr
				}
			}
			return
		}
		select {
		case <-ctx.Done():
			_ = p.abort()
			err = ctx.Err()
			return
		default:
		}
		if finishWrite {
			if closeErr := p.stream.Close(); closeErr != nil {
				_ = p.abort()
				p.session.maybeFailSession(closeErr)
				err = closeErr
				return
			}
		}
		conn = wrapStream(p.session, p.stream)
		p.stream = nil
	})
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (p *preparedStream) Close() error {
	var err error
	p.once.Do(func() {
		err = p.abort()
	})
	return err
}

func (p *preparedStream) abort() error {
	if p.stream == nil {
		return nil
	}
	err := abortStream(p.stream)
	if p.session != nil {
		p.session.releaseStream()
	}
	p.stream = nil
	return err
}

func (p *preparedStream) closeAfterReset() error {
	if p.stream == nil {
		return nil
	}
	err := p.stream.Close()
	if p.session != nil {
		p.session.releaseStream()
	}
	p.stream = nil
	return err
}

func writeAllContext(ctx context.Context, stream stream, payload []byte) (error, bool) {
	if ctx.Done() == nil {
		return writeAll(stream, payload), false
	}
	resetDone := make(chan struct{})
	var resetDoneOnce sync.Once
	var resetPerformed atomic.Bool
	finishReset := func() { resetDoneOnce.Do(func() { close(resetDone) }) }
	stopReset := context.AfterFunc(ctx, func() {
		resetPerformed.Store(true)
		resetStream(stream)
		finishReset()
	})
	writeErr := writeAll(stream, payload)
	if stopReset() {
		finishReset()
	}
	<-resetDone
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr, resetPerformed.Load()
	}
	return writeErr, false
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		payload = payload[n:]
	}
	return nil
}

var (
	_ nwquic.PreparedStream = (*preparedStream)(nil)
	_ nwquic.Session        = (*Session)(nil)
)
