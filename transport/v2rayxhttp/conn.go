package v2rayxhttp

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// xhttpDeadlineError 是 deadline 触发后 pending Read/Write 返回的错误，
// Timeout() 为 true，与真实 TCP 行为一致 (urltest / TLS 握手据此区分超时与对端关闭)。
type xhttpDeadlineError struct{}

func (xhttpDeadlineError) Error() string   { return "xhttp: deadline exceeded" }
func (xhttpDeadlineError) Timeout() bool   { return true }
func (xhttpDeadlineError) Temporary() bool { return true }
func (xhttpDeadlineError) Unwrap() error   { return errDeadline }

var errDeadline = errors.New("i/o timeout")

// xhttpConn 是客户端交给上层协议的 net.Conn (Xray splitConn):
//   - stream-one: reader = response.Body，writer = io.PipeWriter (→ request.Body)
//   - stream-up:  reader = GET 下行 response.Body，writer = POST 上行的 io.PipeWriter
//   - packet-up:  reader = GET 下行 response.Body，writer = uploadPipe (→ 每批一个 POST)
//
// 上下行分离时 reader 来自 download_settings 指定的服务器。
type xhttpConn struct {
	reader     io.ReadCloser
	writer     io.WriteCloser
	remoteAddr net.Addr
	localAddr  net.Addr

	closeOnce sync.Once
	closeErr  error
	// closed 在本端 Close 后置位：pending Read 拿到的 "http2: response body closed"
	// 等底层错误统一改报 net.ErrClosed，上层据此按正常关闭处理而非报错。
	closed atomic.Bool
	// onClose 在 Close 时调用一次，用于归还 XMUX 计数、取消请求 context。
	onClose func()

	// HTTP body 没有原生 deadline，这里用 timer 到期时关闭整条连接来模拟，
	// pending Read/Write 随之返回超时错误；满足 urltest / TLS 握手等调用方。
	deadlineAccess     sync.Mutex
	readDeadlineTimer  *time.Timer
	writeDeadlineTimer *time.Timer
	deadlineFired      atomic.Bool
}

func newXHTTPConn(reader io.ReadCloser, writer io.WriteCloser, remoteAddr, localAddr net.Addr, onClose func()) *xhttpConn {
	return &xhttpConn{
		reader:     reader,
		writer:     writer,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
		onClose:    onClose,
	}
}

func (c *xhttpConn) Read(p []byte) (int, error) {
	if c.deadlineFired.Load() {
		return 0, xhttpDeadlineError{}
	}
	n, err := c.reader.Read(p)
	if err != nil && c.deadlineFired.Load() {
		return n, xhttpDeadlineError{}
	}
	if err != nil && err != io.EOF && c.closed.Load() {
		return n, net.ErrClosed
	}
	return n, err
}

func (c *xhttpConn) Write(p []byte) (int, error) {
	if c.deadlineFired.Load() {
		return 0, xhttpDeadlineError{}
	}
	n, err := c.writer.Write(p)
	if err != nil && c.deadlineFired.Load() {
		return n, xhttpDeadlineError{}
	}
	return n, err
}

func (c *xhttpConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.deadlineAccess.Lock()
		if c.readDeadlineTimer != nil {
			c.readDeadlineTimer.Stop()
			c.readDeadlineTimer = nil
		}
		if c.writeDeadlineTimer != nil {
			c.writeDeadlineTimer.Stop()
			c.writeDeadlineTimer = nil
		}
		c.deadlineAccess.Unlock()
		// 先关写端 (对端收到 EOF / 发出剩余上行数据)，再关读端。
		c.closeErr = c.writer.Close()
		if err := c.reader.Close(); err != nil && c.closeErr == nil {
			c.closeErr = err
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.closeErr
}

func (c *xhttpConn) LocalAddr() net.Addr {
	if c.localAddr == nil {
		return M.Socksaddr{}
	}
	return c.localAddr
}

func (c *xhttpConn) RemoteAddr() net.Addr {
	if c.remoteAddr == nil {
		return M.Socksaddr{}
	}
	return c.remoteAddr
}

// SetDeadline / SetReadDeadline / SetWriteDeadline: 到期后关闭整条连接。
// 零值表示取消 deadline。
func (c *xhttpConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *xhttpConn) SetReadDeadline(t time.Time) error {
	c.armDeadline(&c.readDeadlineTimer, t)
	return nil
}

func (c *xhttpConn) SetWriteDeadline(t time.Time) error {
	c.armDeadline(&c.writeDeadlineTimer, t)
	return nil
}

func (c *xhttpConn) armDeadline(slot **time.Timer, t time.Time) {
	c.deadlineAccess.Lock()
	defer c.deadlineAccess.Unlock()
	if *slot != nil {
		(*slot).Stop()
		*slot = nil
	}
	if t.IsZero() {
		c.deadlineFired.Store(false)
		return
	}
	d := time.Until(t)
	if d <= 0 {
		c.deadlineFired.Store(true)
		go c.Close()
		return
	}
	*slot = time.AfterFunc(d, func() {
		c.deadlineFired.Store(true)
		_ = c.Close()
	})
}

// NeedAdditionalReadDeadline: 让 sing 在需要精确读超时的场景额外包一层。
func (c *xhttpConn) NeedAdditionalReadDeadline() bool { return true }
