package v2rayxhttp

import (
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// httpServerConn 包住一对 request.Body (上行) + http.ResponseWriter (下行)，
// 给 stream-one / stream-up / packet-up 的下行长流共用。
//
// done 通道：服务端 ServeHTTP 处理完毕（连接被上层 Close 或 request.Context 取消）
// 后 Close()，让外层 select { <-request.Context().Done(): <-httpSC.Wait() } 解阻塞。
//
// 移植自 Xray-core hub.go 的 httpServerConn。
type httpServerConn struct {
	mu       sync.Mutex
	done     chan struct{}
	doneOnce sync.Once

	reader io.Reader      // request.Body — caller 不需要 Close 它（http.Server 管）
	writer http.ResponseWriter
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
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return 0, io.ErrClosedPipe
	default:
	}
	n, err := c.writer.Write(b)
	// 立即 flush 让 SSE / chunked 帧及时下发
	if err == nil {
		if flusher, ok := c.writer.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	return n, err
}

func (c *httpServerConn) Close() error {
	c.doneOnce.Do(func() { close(c.done) })
	return nil
}

func (c *httpServerConn) Wait() <-chan struct{} { return c.done }

// ────────────────────────────────────────────────────────────────────────
// splitConn — net.Conn 包装，server 端给上层（vless / trojan / 等）的实体
// ────────────────────────────────────────────────────────────────────────

// splitConn 把 reader + writer 拼成 net.Conn。reader 端可能是:
//   - stream-one: 同一个 httpServerConn (reader/writer 都是它)
//   - stream-up / packet-up: uploadQueue (按 seq 重排或继承 reader)
//
// deadline 在 v2ray transport 体系下不容易精确实现（底层是 HTTP body 而非
// socket），与上游 Xray 一样 stub 掉，只满足 net.Conn 接口要求。
type splitConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	onClose    func()

	closeOnce sync.Once
}

func newSplitConn(writer io.WriteCloser, reader io.ReadCloser, localAddr, remoteAddr net.Addr) *splitConn {
	return &splitConn{
		writer:     writer,
		reader:     reader,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

func (c *splitConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *splitConn) Write(b []byte) (int, error) { return c.writer.Write(b) }

func (c *splitConn) Close() error {
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
		_ = c.writer.Close()
		_ = c.reader.Close()
	})
	return nil
}

func (c *splitConn) LocalAddr() net.Addr            { return c.localAddr }
func (c *splitConn) RemoteAddr() net.Addr           { return c.remoteAddr }
func (c *splitConn) SetDeadline(time.Time) error    { return nil }
func (c *splitConn) SetReadDeadline(time.Time) error  { return nil }
func (c *splitConn) SetWriteDeadline(time.Time) error { return nil }
