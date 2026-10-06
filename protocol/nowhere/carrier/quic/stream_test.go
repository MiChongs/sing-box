//go:build with_quic

package quic

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

func TestStreamConnCloseOrder(t *testing.T) {
	stream := newFakeStream()
	conn := &streamConn{
		stream: stream,
		onClose: func() {
			stream.record("ReleaseTCP")
		},
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	stream.assertCalls(t, "SetWriteDeadline", "CancelRead(0)", "Close", "ReleaseTCP")
	stream.assertExpiredWriteDeadline(t)
}

func TestStreamConnHalfCloseKeepsOppositeDirectionUsable(t *testing.T) {
	t.Run("close write preserves read", func(t *testing.T) {
		stream := newFakeStream()
		releases := 0
		conn := &streamConn{stream: stream, onClose: func() { releases++ }}
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("Read = %v, want EOF", err)
		}
		stream.assertCalls(t, "Close")
		if releases != 0 {
			t.Fatalf("stream released by half-close: %d", releases)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if releases != 1 {
			t.Fatalf("stream releases = %d, want 1", releases)
		}
	})

	t.Run("close read preserves write", func(t *testing.T) {
		stream := newFakeStream()
		conn := &streamConn{stream: stream}
		if err := conn.CloseRead(); err != nil {
			t.Fatal(err)
		}
		if err := conn.CloseRead(); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("after-close-read")); err != nil {
			t.Fatal(err)
		}
		stream.assertCalls(t, "CancelRead(0)", "Write:start", "Write:end")
	})
}

func TestStreamConnCloseUnblocksWriteBeforeAbort(t *testing.T) {
	stream := newFakeStream()
	stream.blockWrite = true
	conn := &streamConn{
		stream: stream,
		onClose: func() {
			stream.record("ReleaseTCP")
		},
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("payload"))
		writeDone <- err
	}()
	waitForSignal(t, stream.writeStarted, "Write to start")

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- conn.Close()
	}()

	select {
	case err := <-writeDone:
		if !errors.Is(err, errFakeWriteDeadline) {
			t.Fatalf("Write error = %v, want %v", err, errFakeWriteDeadline)
		}
	case <-time.After(time.Second):
		t.Fatal("Write did not exit after Close set its write deadline")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not acquire the write mutex after Write exited")
	}

	stream.assertCalls(t,
		"Write:start",
		"SetWriteDeadline",
		"Write:end",
		"CancelRead(0)",
		"Close",
		"ReleaseTCP",
	)
	stream.assertExpiredWriteDeadline(t)
}

func TestStreamConnCloseFallsBackToCancelWrite(t *testing.T) {
	stream := newFakeStream()
	stream.blockWrite = true
	stream.deadlineErr = errors.New("test deadline unsupported")
	conn := &streamConn{
		stream: stream,
		onClose: func() {
			stream.record("ReleaseTCP")
		},
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("payload"))
		writeDone <- err
	}()
	waitForSignal(t, stream.writeStarted, "Write to start")

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- conn.Close()
	}()

	select {
	case err := <-writeDone:
		if !errors.Is(err, errFakeWriteCanceled) {
			t.Fatalf("Write error = %v, want %v", err, errFakeWriteCanceled)
		}
	case <-time.After(time.Second):
		t.Fatal("Write remained blocked after write deadline failed")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close deadlocked waiting for the write mutex")
	}

	stream.assertCalls(t,
		"Write:start",
		"SetWriteDeadline",
		"CancelWrite(0)",
		"Write:end",
		"CancelRead(0)",
		"Close",
		"ReleaseTCP",
	)
	stream.assertExpiredWriteDeadline(t)
}

func TestStreamConnCloseIsIdempotentAndReleasesOnError(t *testing.T) {
	closeErr := errors.New("test close error")
	stream := newFakeStream()
	stream.closeErr = closeErr
	conn := &streamConn{
		stream: stream,
		onClose: func() {
			stream.record("ReleaseTCP")
		},
	}

	if err := conn.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("first Close error = %v, want %v", err, closeErr)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close error = %v, want nil", err)
	}
	stream.assertCalls(t, "SetWriteDeadline", "CancelRead(0)", "Close", "ReleaseTCP")
	stream.assertExpiredWriteDeadline(t)
}

func TestStreamConnConcurrentCloseIsIdempotent(t *testing.T) {
	stream := newFakeStream()
	conn := &streamConn{
		stream: stream,
		onClose: func() {
			stream.record("ReleaseTCP")
		},
	}

	const callers = 32
	start := make(chan struct{})
	errCh := make(chan error, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for range callers {
		go func() {
			defer wait.Done()
			<-start
			errCh <- conn.Close()
		}()
	}
	close(start)
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	waitForSignal(t, done, "concurrent Close calls")
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent Close: %v", err)
		}
	}

	stream.assertCalls(t, "SetWriteDeadline", "CancelRead(0)", "Close", "ReleaseTCP")
	stream.assertExpiredWriteDeadline(t)
}

func TestPreparedStreamFailureAndOwnershipPaths(t *testing.T) {
	setup := []byte{0xf1, 0x01, 0x03, 0xaa, 0xbb}

	t.Run("session closed", func(t *testing.T) {
		stream := newFakeStream()
		session, prepared := prepareFakeStream(t, stream)
		session.mu.Lock()
		session.closed = true
		session.mu.Unlock()

		conn, err := prepared.Commit(context.Background(), setup, false)
		if !errors.Is(err, errSessionClosed) || conn != nil {
			t.Fatalf("Commit = (%v, %v), want (nil, errSessionClosed)", conn, err)
		}
		assertPreparedReleased(t, session, prepared)
		stream.assertCalls(t, "SetWriteDeadline", "CancelWrite(0)", "CancelRead(0)", "Close")
		stream.assertExpiredWriteDeadline(t)
	})

	t.Run("context canceled", func(t *testing.T) {
		stream := newFakeStream()
		session, prepared := prepareFakeStream(t, stream)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		conn, err := prepared.Commit(ctx, setup, false)
		if !errors.Is(err, context.Canceled) || conn != nil {
			t.Fatalf("Commit = (%v, %v), want (nil, context.Canceled)", conn, err)
		}
		assertPreparedReleased(t, session, prepared)
		stream.assertCalls(t, "SetWriteDeadline", "CancelWrite(0)", "CancelRead(0)", "Close")
	})

	t.Run("write failure", func(t *testing.T) {
		writeErr := errors.New("test prepared write failure")
		stream := newFakeStream()
		stream.writeErr = writeErr
		session, prepared := prepareFakeStream(t, stream)

		conn, err := prepared.Commit(context.Background(), setup, false)
		if !errors.Is(err, writeErr) || conn != nil {
			t.Fatalf("Commit = (%v, %v), want (nil, write error)", conn, err)
		}
		if session.IsClosed() {
			t.Fatal("stream-scoped write failure closed the session")
		}
		assertPreparedReleased(t, session, prepared)
		stream.assertCalls(t, "Write:start", "Write:end", "SetWriteDeadline", "CancelWrite(0)", "CancelRead(0)", "Close")
		stream.assertExpiredWriteDeadline(t)
	})

	t.Run("fatal write failure invalidates session", func(t *testing.T) {
		stream := newFakeStream()
		stream.writeErr = net.ErrClosed
		session, prepared := prepareFakeStream(t, stream)

		conn, err := prepared.Commit(context.Background(), setup, false)
		if !errors.Is(err, net.ErrClosed) || conn != nil {
			t.Fatalf("Commit = (%v, %v), want (nil, net.ErrClosed)", conn, err)
		}
		if !session.IsClosed() {
			t.Fatal("fatal write failure did not close the session")
		}
		assertPreparedReleased(t, session, prepared)
	})

	t.Run("explicit close", func(t *testing.T) {
		closeErr := errors.New("test prepared close failure")
		stream := newFakeStream()
		stream.closeErr = closeErr
		session, prepared := prepareFakeStream(t, stream)

		if err := prepared.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("Close error = %v, want %v", err, closeErr)
		}
		if err := prepared.Close(); err != nil {
			t.Fatalf("second Close error = %v, want nil", err)
		}
		assertPreparedReleased(t, session, prepared)
		stream.assertCalls(t, "SetWriteDeadline", "CancelWrite(0)", "CancelRead(0)", "Close")
		stream.assertExpiredWriteDeadline(t)
	})

	t.Run("successful commit transfers opaque setup", func(t *testing.T) {
		stream := newFakeStream()
		session, prepared := prepareFakeStream(t, stream)

		conn, err := prepared.Commit(context.Background(), setup, false)
		if err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if conn == nil {
			t.Fatal("Commit returned nil connection")
		}
		if prepared.stream != nil {
			t.Fatal("prepared stream retained ownership after Commit")
		}
		if active := activeStreamCount(session); active != 1 {
			t.Fatalf("active stream count after Commit = %d, want 1", active)
		}
		stream.assertWritten(t, setup)
		stream.assertCalls(t, "Write:start", "Write:end")
		if err := prepared.Close(); err != nil {
			t.Fatalf("prepared Close after Commit: %v", err)
		}

		if err := conn.Close(); err != nil {
			t.Fatalf("committed connection Close: %v", err)
		}
		if active := activeStreamCount(session); active != 0 {
			t.Fatalf("active stream count after connection Close = %d, want 0", active)
		}
		stream.assertCalls(t, "Write:start", "Write:end", "SetWriteDeadline", "CancelRead(0)", "Close")
		stream.assertExpiredWriteDeadline(t)
	})

	t.Run("finish write closes send direction", func(t *testing.T) {
		stream := newFakeStream()
		_, prepared := prepareFakeStream(t, stream)

		conn, err := prepared.Commit(context.Background(), setup, true)
		if err != nil {
			t.Fatalf("Commit: %v", err)
		}
		stream.assertWritten(t, setup)
		stream.assertCalls(t, "Write:start", "Write:end", "Close")
		if err := conn.Close(); err != nil {
			t.Fatalf("committed connection Close: %v", err)
		}
		stream.assertCalls(t, "Write:start", "Write:end", "Close", "SetWriteDeadline", "CancelRead(0)", "Close")
	})
}

func TestAbortStream(t *testing.T) {
	closeErr := errors.New("test abort close error")
	stream := newFakeStream()
	stream.closeErr = closeErr

	if err := abortStream(stream); !errors.Is(err, closeErr) {
		t.Fatalf("abortStream error = %v, want %v", err, closeErr)
	}
	stream.assertCalls(t, "SetWriteDeadline", "CancelWrite(0)", "CancelRead(0)", "Close")
	stream.assertExpiredWriteDeadline(t)
}

func newReadyTestSession(t *testing.T, opened stream) *Session {
	t.Helper()
	session := NewSession(&QUICConfig{
		Addr: "127.0.0.1:1",
	})
	close(session.ready)
	session.openStream = func(context.Context) (stream, error) {
		return opened, nil
	}
	t.Cleanup(session.Close)
	return session
}

func prepareFakeStream(t *testing.T, opened stream) (*Session, *preparedStream) {
	t.Helper()
	session := newReadyTestSession(t, opened)
	preparedValue, err := session.PrepareStream(context.Background())
	if err != nil {
		t.Fatalf("PrepareStream: %v", err)
	}
	prepared, ok := preparedValue.(*preparedStream)
	if !ok {
		t.Fatalf("PrepareStream returned %T, want *preparedStream", preparedValue)
	}
	if active := activeStreamCount(session); active != 1 {
		t.Fatalf("active stream count after prepare = %d, want 1", active)
	}
	return session, prepared
}

func assertPreparedReleased(t *testing.T, session *Session, prepared *preparedStream) {
	t.Helper()
	if prepared.stream != nil {
		t.Fatal("prepared stream retained ownership after failure")
	}
	if active := activeStreamCount(session); active != 0 {
		t.Fatalf("active stream count after cleanup = %d, want 0", active)
	}
}

func activeStreamCount(session *Session) int {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.activeConns
}

var (
	errFakeWriteDeadline = errors.New("test write deadline")
	errFakeWriteCanceled = errors.New("test write canceled")
)

type fakeStream struct {
	mu sync.Mutex

	calls           []string
	written         []byte
	blockWrite      bool
	writeErr        error
	closeErr        error
	deadlineErr     error
	writeDeadlineAt time.Time

	writeStarted     chan struct{}
	writeUnblock     chan error
	writeStartOnce   sync.Once
	writeUnblockOnce sync.Once
}

func newFakeStream() *fakeStream {
	return &fakeStream{
		writeStarted: make(chan struct{}),
		writeUnblock: make(chan error, 1),
	}
}

func (s *fakeStream) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (s *fakeStream) Write(payload []byte) (int, error) {
	s.record("Write:start")
	s.writeStartOnce.Do(func() { close(s.writeStarted) })
	if s.blockWrite {
		err := <-s.writeUnblock
		s.record("Write:end")
		return 0, err
	}
	s.record("Write:end")
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	s.mu.Lock()
	s.written = append(s.written, payload...)
	s.mu.Unlock()
	return len(payload), nil
}

func (s *fakeStream) Close() error {
	s.record("Close")
	return s.closeErr
}

func (s *fakeStream) CancelRead(code quic.StreamErrorCode) {
	s.record("CancelRead(" + strconv.FormatUint(uint64(code), 10) + ")")
}

func (s *fakeStream) CancelWrite(code quic.StreamErrorCode) {
	s.record("CancelWrite(" + strconv.FormatUint(uint64(code), 10) + ")")
	s.unblockWrite(errFakeWriteCanceled)
}

func (s *fakeStream) SetDeadline(time.Time) error {
	return nil
}

func (s *fakeStream) SetReadDeadline(time.Time) error {
	return nil
}

func (s *fakeStream) SetWriteDeadline(deadline time.Time) error {
	s.mu.Lock()
	s.calls = append(s.calls, "SetWriteDeadline")
	s.writeDeadlineAt = deadline
	err := s.deadlineErr
	s.mu.Unlock()
	if err == nil {
		s.unblockWrite(errFakeWriteDeadline)
	}
	return err
}

func (s *fakeStream) unblockWrite(err error) {
	s.writeUnblockOnce.Do(func() {
		s.writeUnblock <- err
	})
}

func (s *fakeStream) record(call string) {
	s.mu.Lock()
	s.calls = append(s.calls, call)
	s.mu.Unlock()
}

func (s *fakeStream) assertCalls(t *testing.T, expected ...string) {
	t.Helper()
	s.mu.Lock()
	actual := append([]string(nil), s.calls...)
	s.mu.Unlock()
	if len(actual) != len(expected) {
		t.Fatalf("calls = %v, want %v", actual, expected)
	}
	for index := range expected {
		if actual[index] != expected[index] {
			t.Fatalf("calls = %v, want %v", actual, expected)
		}
	}
}

func (s *fakeStream) assertWritten(t *testing.T, expected []byte) {
	t.Helper()
	s.mu.Lock()
	actual := append([]byte(nil), s.written...)
	s.mu.Unlock()
	if string(actual) != string(expected) {
		t.Fatalf("written setup = %x, want %x", actual, expected)
	}
}

func (s *fakeStream) assertExpiredWriteDeadline(t *testing.T) {
	t.Helper()
	observedAt := time.Now()
	s.mu.Lock()
	deadline := s.writeDeadlineAt
	s.mu.Unlock()
	if deadline.IsZero() {
		t.Fatal("write deadline was zero")
	}
	if deadline.After(observedAt) {
		t.Fatalf("write deadline %v is after observation time %v", deadline, observedAt)
	}
}

func waitForSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}
