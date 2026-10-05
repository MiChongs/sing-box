package v2rayxhttp

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

var errTestBodyClosed = errors.New("http2: response body closed")

// closedBodyReader 模拟 http2 response.Body：Close 后 pending Read 返回
// "http2: response body closed"，而不是 net.ErrClosed。
type closedBodyReader struct {
	closed chan struct{}
}

func (r *closedBodyReader) Read([]byte) (int, error) {
	<-r.closed
	return 0, errTestBodyClosed
}

func (r *closedBodyReader) Close() error {
	close(r.closed)
	return nil
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriteCloser) Close() error                { return nil }

// TestReadAfterLocalCloseReturnsErrClosed 验证本端 Close 解开 pending Read 时
// 返回 net.ErrClosed：上行结束后路由层关闭 conn，下行 Read 不应被记成
// "connection download closed: http2: response body closed" 错误。
func TestReadAfterLocalCloseReturnsErrClosed(t *testing.T) {
	c := newXHTTPConn(&closedBodyReader{closed: make(chan struct{})}, nopWriteCloser{}, nil, nil, nil)
	errCh := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		errCh <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_ = c.Close()
	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("want net.ErrClosed, got %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Read did not unblock after Close")
	}
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }
func (eofReader) Close() error             { return nil }

// TestReadEOFPreservedAfterClose 验证正常 EOF 不被改写成 net.ErrClosed。
func TestReadEOFPreservedAfterClose(t *testing.T) {
	c := newXHTTPConn(eofReader{}, nopWriteCloser{}, nil, nil, nil)
	_ = c.Close()
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("want io.EOF, got %v", err)
	}
}

// TestReadErrorBeforeCloseUnchanged 验证未 Close 时底层错误原样透传。
func TestReadErrorBeforeCloseUnchanged(t *testing.T) {
	reader := &closedBodyReader{closed: make(chan struct{})}
	close(reader.closed)
	c := newXHTTPConn(reader, nopWriteCloser{}, nil, nil, nil)
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, errTestBodyClosed) {
		t.Fatalf("want underlying error, got %v", err)
	}
}
