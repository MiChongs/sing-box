//go:build with_quic

package quic

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

func TestPreparedStreamCancelBeforeCommitResetsWrite(t *testing.T) {
	stream := newTask9ResetStream()
	_, prepared := prepareFakeStream(t, stream)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	conn, err := prepared.Commit(ctx, []byte("setup"), false)
	if !errors.Is(err, context.Canceled) || conn != nil {
		t.Fatalf("Commit = (%v, %v), want nil/context.Canceled", conn, err)
	}
	stream.assertCalls(t, "SetWriteDeadline", "CancelWrite(0)", "CancelRead(0)", "Close")
}

func TestPreparedStreamCancelDuringSetupWriteResetsWrite(t *testing.T) {
	stream := newTask9ResetStream()
	stream.blockWrite = true
	_, prepared := prepareFakeStream(t, stream)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := prepared.Commit(ctx, []byte("opaque-setup"), false)
		result <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: err}
	}()
	stream.waitWriteStarted(t)
	cancel()

	select {
	case got := <-result:
		if !errors.Is(got.err, context.Canceled) || got.conn != nil {
			t.Fatalf("Commit = (%v, %v), want nil/context.Canceled", got.conn, got.err)
		}
	case <-time.After(250 * time.Millisecond):
		stream.releaseBlockedWrite()
		<-result
		t.Fatal("Commit remained blocked after context cancellation")
	}
	stream.assertResetBeforeClose(t)
}

func TestPreparedStreamCommitCancellationAfterStoppedResetAbortsStream(t *testing.T) {
	stream := newTask9ResetStream()
	session, prepared := prepareFakeStream(t, stream)
	session.mu.Lock()
	session.activeConns++
	session.mu.Unlock()

	ctx := newTask9PostStopCancellationContext()
	t.Cleanup(ctx.cancelAndRelease)
	result := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := prepared.Commit(ctx, []byte("opaque-setup"), true)
		result <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: err}
	}()
	select {
	case <-ctx.errObserved:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for post-stop context error check")
	}
	ctx.cancelAndRelease()

	select {
	case got := <-result:
		if !errors.Is(got.err, context.Canceled) || got.conn != nil {
			t.Fatalf("Commit = (%v, %v), want nil/context.Canceled", got.conn, got.err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Commit remained blocked after post-stop cancellation")
	}
	stream.assertCalls(t, "Write", "SetWriteDeadline", "CancelWrite(0)", "CancelRead(0)", "Close")
	if active := activeStreamCount(session); active != 1 {
		t.Fatalf("active streams = %d, want sentinel-only 1", active)
	}
}

func TestPreparedStreamPartialSetupWriteResetsWrite(t *testing.T) {
	wantErr := errors.New("test: partial setup write")
	stream := newTask9ResetStream()
	stream.writeN = 2
	stream.writeErr = wantErr
	_, prepared := prepareFakeStream(t, stream)

	conn, err := prepared.Commit(context.Background(), []byte("opaque-setup"), true)
	if !errors.Is(err, wantErr) || conn != nil {
		t.Fatalf("Commit = (%v, %v), want nil/%v", conn, err, wantErr)
	}
	stream.assertCalls(t, "Write", "SetWriteDeadline", "CancelWrite(0)", "CancelRead(0)", "Close")
}

func TestPreparedStreamExplicitCloseResetsWrite(t *testing.T) {
	stream := newTask9ResetStream()
	_, prepared := prepareFakeStream(t, stream)

	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	stream.assertCalls(t, "SetWriteDeadline", "CancelWrite(0)", "CancelRead(0)", "Close")
}

func TestPreparedStreamFinishWriteSendsFINOnlyAfterCompleteSetup(t *testing.T) {
	stream := newTask9ResetStream()
	_, prepared := prepareFakeStream(t, stream)

	conn, err := prepared.Commit(context.Background(), []byte("opaque-setup"), true)
	if err != nil {
		t.Fatal(err)
	}
	stream.assertCalls(t, "Write", "Close")
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

type task9PostStopCancellationContext struct {
	mu          sync.Mutex
	err         error
	done        chan struct{}
	errObserved chan struct{}
	allowErr    chan struct{}
	errOnce     sync.Once
	cancelOnce  sync.Once
	releaseOnce sync.Once
}

func newTask9PostStopCancellationContext() *task9PostStopCancellationContext {
	return &task9PostStopCancellationContext{
		done:        make(chan struct{}),
		errObserved: make(chan struct{}),
		allowErr:    make(chan struct{}),
	}
}

func (*task9PostStopCancellationContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *task9PostStopCancellationContext) Done() <-chan struct{}     { return c.done }
func (c *task9PostStopCancellationContext) Err() error {
	c.errOnce.Do(func() {
		close(c.errObserved)
		<-c.allowErr
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}
func (*task9PostStopCancellationContext) Value(any) any { return nil }
func (c *task9PostStopCancellationContext) cancelAndRelease() {
	c.cancelOnce.Do(func() {
		c.mu.Lock()
		c.err = context.Canceled
		c.mu.Unlock()
		close(c.done)
	})
	c.releaseOnce.Do(func() { close(c.allowErr) })
}

type task9ResetStream struct {
	mu            sync.Mutex
	calls         []string
	written       []byte
	writeN        int
	writeErr      error
	blockWrite    bool
	writeCanceled bool
	writeStarted  chan struct{}
	writeRelease  chan struct{}
	startedOnce   sync.Once
	releaseOnce   sync.Once
}

func newTask9ResetStream() *task9ResetStream {
	return &task9ResetStream{writeStarted: make(chan struct{}), writeRelease: make(chan struct{})}
}

func (*task9ResetStream) Read([]byte) (int, error) { return 0, io.EOF }
func (s *task9ResetStream) Write(payload []byte) (int, error) {
	s.record("Write")
	if s.blockWrite {
		s.startedOnce.Do(func() { close(s.writeStarted) })
		<-s.writeRelease
		s.mu.Lock()
		canceled := s.writeCanceled
		s.mu.Unlock()
		if canceled {
			return 0, net.ErrClosed
		}
	}
	n := len(payload)
	if s.writeN > 0 && s.writeN < n {
		n = s.writeN
	}
	s.mu.Lock()
	s.written = append(s.written, payload[:n]...)
	s.mu.Unlock()
	return n, s.writeErr
}

func (s *task9ResetStream) Close() error {
	s.record("Close")
	return nil
}

func (s *task9ResetStream) CancelRead(code quic.StreamErrorCode) {
	s.record("CancelRead(0)")
}

func (s *task9ResetStream) CancelWrite(code quic.StreamErrorCode) {
	s.record("CancelWrite(0)")
	s.mu.Lock()
	s.writeCanceled = true
	s.mu.Unlock()
	s.releaseBlockedWrite()
}
func (s *task9ResetStream) SetDeadline(time.Time) error     { return nil }
func (s *task9ResetStream) SetReadDeadline(time.Time) error { return nil }
func (s *task9ResetStream) SetWriteDeadline(time.Time) error {
	s.record("SetWriteDeadline")
	return nil
}

func (s *task9ResetStream) record(call string) {
	s.mu.Lock()
	s.calls = append(s.calls, call)
	s.mu.Unlock()
}

func (s *task9ResetStream) waitWriteStarted(t *testing.T) {
	t.Helper()
	select {
	case <-s.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("setup write did not start")
	}
}

func (s *task9ResetStream) releaseBlockedWrite() {
	s.releaseOnce.Do(func() { close(s.writeRelease) })
}

func (s *task9ResetStream) assertResetBeforeClose(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	calls := append([]string(nil), s.calls...)
	s.mu.Unlock()
	cancelWrite := -1
	closeCall := -1
	for index, call := range calls {
		if call == "CancelWrite(0)" && cancelWrite == -1 {
			cancelWrite = index
		}
		if call == "Close" && closeCall == -1 {
			closeCall = index
		}
	}
	if cancelWrite == -1 || closeCall == -1 || cancelWrite > closeCall {
		t.Fatalf("calls = %v, want CancelWrite before Close", calls)
	}
}

func (s *task9ResetStream) assertCalls(t *testing.T, want ...string) {
	t.Helper()
	s.mu.Lock()
	got := append([]string(nil), s.calls...)
	s.mu.Unlock()
	if len(got) != len(want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("calls = %v, want %v", got, want)
		}
	}
}

var (
	_ stream   = (*task9ResetStream)(nil)
	_ net.Conn = (*streamConn)(nil)
)
