package v2rayxhttp

import (
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// httpServerConn 包住一对 request.Body (读) + http.ResponseWriter (写)。
// 移植自 Xray-core hub.go httpServerConn。
type httpServerConn struct {
	access    sync.Mutex
	done      chan struct{}
	closeOnce sync.Once
	reader    io.Reader // request.Body，由 http.Server 负责关闭
	writer    http.ResponseWriter
}

func newHTTPServerConn(reader io.Reader, writer http.ResponseWriter) *httpServerConn {
	return &httpServerConn{
		done:   make(chan struct{}),
		reader: reader,
		writer: writer,
	}
}

func (c *httpServerConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *httpServerConn) Write(b []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.isDone() {
		return 0, io.ErrClosedPipe
	}
	n, err := c.writer.Write(b)
	if err == nil {
		if flusher, loaded := c.writer.(http.Flusher); loaded {
			flusher.Flush()
		}
	}
	return n, err
}

func (c *httpServerConn) isDone() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// Close 只标记结束: "A ResponseWriter may not be used after Handler.ServeHTTP
// has returned"，因此持锁关闭，保证 Write 不会与 ServeHTTP 返回并发。
func (c *httpServerConn) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	c.closeOnce.Do(func() { close(c.done) })
	return nil
}

func (c *httpServerConn) Wait() <-chan struct{} { return c.done }

// splitConn 把读写两端拼成交给上层协议 (vless / vmess / trojan ...) 的 net.Conn。
//   - stream-one: reader = writer = 同一个 httpServerConn
//   - stream-up / packet-up: reader = uploadQueue，writer = GET 下行的 httpServerConn
//
// 底层是 HTTP body，没有原生 deadline 语义，与 Xray 一样不实现 deadline；
// NeedAdditionalReadDeadline 让 sing 在需要时包一层读超时。
type splitConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	closeOnce  sync.Once
}

func (c *splitConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *splitConn) Write(b []byte) (int, error) { return c.writer.Write(b) }

func (c *splitConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.writer.Close()
		if readerErr := c.reader.Close(); err == nil {
			err = readerErr
		}
	})
	return err
}

func (c *splitConn) LocalAddr() net.Addr              { return c.localAddr }
func (c *splitConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *splitConn) SetDeadline(time.Time) error      { return nil }
func (c *splitConn) SetReadDeadline(time.Time) error  { return nil }
func (c *splitConn) SetWriteDeadline(time.Time) error { return nil }
func (c *splitConn) NeedAdditionalReadDeadline() bool { return true }
