package v2rayxhttp

import (
	"errors"
	"io"
	"net"
	"testing"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/http2"
)

// requireClosed 验证 err 被归为隧道正常结束: 匹配 net.ErrClosed，消息与原始错误不变。
func requireClosed(t *testing.T, err error) {
	t.Helper()
	wrapped := wrapError(err)
	if !E.IsClosedOrCanceled(wrapped) {
		t.Fatalf("%q should be a normal close", err)
	}
	if wrapped.Error() != err.Error() {
		t.Fatalf("message changed: %q → %q", err, wrapped)
	}
	if !errors.Is(wrapped, err) {
		t.Fatalf("%q lost the original error", err)
	}
}

func requireNotClosed(t *testing.T, err error) {
	t.Helper()
	wrapped := wrapError(err)
	if E.IsClosedOrCanceled(wrapped) {
		t.Fatalf("%q should stay an error", err)
	}
	if wrapped.Error() != err.Error() {
		t.Fatalf("message changed: %q → %q", err, wrapped)
	}
}

func TestWrapErrorHTTP2(t *testing.T) {
	for _, err := range []error{
		http2.StreamError{StreamID: 3, Code: http2.ErrCodeNo},
		http2.StreamError{StreamID: 3, Code: http2.ErrCodeNo, Cause: errors.New("received from peer")},
		http2.StreamError{StreamID: 5, Code: http2.ErrCodeCancel},
		http2.GoAwayError{LastStreamID: 7, ErrCode: http2.ErrCodeNo},
		errors.New("client disconnected"),
		errors.New("body closed by handler"),
		errors.New("http2: response body closed"),
		errors.New("http2: client connection lost"),
		errors.New("http2: client connection force closed via ClientConn.Close"),
	} {
		requireClosed(t, err)
	}
	for _, err := range []error{
		http2.StreamError{StreamID: 3, Code: http2.ErrCodeProtocol},
		http2.StreamError{StreamID: 3, Code: http2.ErrCodeFlowControl},
		http2.GoAwayError{LastStreamID: 7, ErrCode: http2.ErrCodeProtocol},
		http2.ConnectionError(http2.ErrCodeInternal),
	} {
		requireNotClosed(t, err)
	}
}

// HTTP/2 的流错误不能原样从隧道里漏出去: x/net http2 对 Read 返回的错误做
// err.(StreamError) 断言，命中后会继续读，内层是 HTTP/2 时外层读循环会空转。
func TestWrapErrorHidesHTTP2StreamError(t *testing.T) {
	for _, err := range []error{
		http2.StreamError{StreamID: 3, Code: http2.ErrCodeNo},
		http2.StreamError{StreamID: 3, Code: http2.ErrCodeProtocol},
	} {
		if _, isStreamError := wrapError(err).(http2.StreamError); isStreamError {
			t.Fatalf("%q leaked as http2.StreamError", err)
		}
	}
}

func TestWrapErrorPassthrough(t *testing.T) {
	if wrapError(nil) != nil {
		t.Fatal("nil changed")
	}
	for _, err := range []error{io.EOF, net.ErrClosed, io.ErrClosedPipe, xhttpDeadlineError{}} {
		if wrapError(err) != err {
			t.Fatalf("%q changed", err)
		}
	}
	err := errors.New("xhttp: packet queue is too large")
	if wrapError(err) != err {
		t.Fatalf("%q changed", err)
	}
}

func TestWrapErrorUnexpectedEOF(t *testing.T) {
	requireClosed(t, io.ErrUnexpectedEOF)
	requireClosed(t, E.Cause(io.ErrUnexpectedEOF, "read chunked body"))
}

// packet-up 上行失败时错误被 E.Cause 包了一层再从 Write 返回。
func TestWrapErrorCause(t *testing.T) {
	requireClosed(t, E.Cause(http2.StreamError{StreamID: 3, Code: http2.ErrCodeCancel}, "xhttp: failed to send upload"))
	requireNotClosed(t, E.Cause(errors.New("xhttp: bad status code: 404 Not Found"), "xhttp: failed to send upload"))
}
