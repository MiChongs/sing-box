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

// xhttpDeadlineExceeded 是 SetDeadline timer 超时后 Close conn 时写给
// pending Read/Write 的错误。包装 os.ErrDeadlineExceeded 让 net.Error
// Timeout() 正确上报 true，与真 TCP 行为对齐（urltest / TLS handshake
// 依赖这个语义判断超时 vs 对端主动关闭）。
type xhttpDeadlineError struct{}

func (xhttpDeadlineError) Error() string   { return "xhttp: deadline exceeded" }
func (xhttpDeadlineError) Timeout() bool   { return true }
func (xhttpDeadlineError) Temporary() bool { return true }
func (xhttpDeadlineError) Unwrap() error   { return errDeadline }

var errDeadline = errors.New("i/o timeout")

// xhttpConn 是所有 XHTTP 模式下对外暴露的 net.Conn 基类包装。
// 它把一个只读 reader + 一个只写 writer 组合成 net.Conn 接口，
// 底层在不同模式下对应不同实体:
//   - stream-one: reader = response.Body, writer = io.PipeWriter (→ request.Body)
//   - stream-up:  同 stream-one 但 reader/writer 来自两条独立 HTTP 请求
//   - packet-up:  reader = SSE response.Body, writer = packetUpWriter (每 Write 发独立 POST)
//
// 所有 Close() 调用都会串联关闭 reader 和 writer，确保 goroutine 不泄露。
// Reader/Writer 本身负责从 HTTP body 里自动处理 chunked/SSE 包装。
type xhttpConn struct {
	reader     io.Reader
	writer     io.WriteCloser
	remoteAddr net.Addr

	closeOnce sync.Once
	closeErr  error

	// setupDone 在客户端使用，server 端不关心。客户端侧 reader 是
	// HTTP response.Body，异步拿到；Read 前需要阻塞等 setupDone。
	setupDone chan struct{}
	setupErr  error

	// Deadline enforcement. v2ray transports don't have native per-op
	// deadline semantics (the underlying carrier is HTTP body, not a
	// socket), so we emulate by scheduling a Close when the deadline
	// hits. pending Read/Write then observes the Close and returns a
	// timeout-typed error. Matches what urltest / tls.Handshake /
	// net/http expect from a net.Conn.
	deadlineMu        sync.Mutex
	readDeadlineTimer *time.Timer
	writeDeadlineTim  *time.Timer
	deadlineFired     atomic.Bool

	// onClose 在 Close 被成功调用一次后触发；供 dial 侧挂清理回调（例如
	// cancel 绑定的 reqCtx，让 upload/download goroutine 尽快收尾）。
	onClose func()
}

func newXHTTPConn(reader io.Reader, writer io.WriteCloser, remoteAddr net.Addr) *xhttpConn {
	return &xhttpConn{
		reader:     reader,
		writer:     writer,
		remoteAddr: remoteAddr,
	}
}

// newLateXHTTPConn 当 reader 需要异步 setup (客户端发起 HTTP 请求等
// response 到达后才能拿到 body) 时使用。第一次 Read 前阻塞在 setupDone。
func newLateXHTTPConn(writer io.WriteCloser, remoteAddr net.Addr) *xhttpConn {
	return &xhttpConn{
		writer:     writer,
		remoteAddr: remoteAddr,
		setupDone:  make(chan struct{}),
	}
}

// setupReader 由 dial 侧的 RoundTrip goroutine 在拿到 response 之后调用。
// 失败时同时关闭 writer pipe，使任何 pending Write（例如 TLS ClientHello
// 或 VLESS handshake 已开始写入但 tunnel 还没建起）立即返回，而不是
// 永久阻塞在 pipeW.Write 等待 pipeR 被消费。
func (c *xhttpConn) setupReader(reader io.Reader, err error) {
	c.reader = reader
	c.setupErr = err
	if err != nil && c.writer != nil {
		_ = c.writer.Close()
	}
	if c.setupDone != nil {
		close(c.setupDone)
	}
}

func (c *xhttpConn) Read(p []byte) (int, error) {
	if c.setupDone != nil {
		<-c.setupDone
		if c.setupErr != nil {
			return 0, c.setupErr
		}
	}
	if c.deadlineFired.Load() {
		return 0, xhttpDeadlineError{}
	}
	if c.reader == nil {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := c.reader.Read(p)
	// If a deadline fired mid-Read and Close() returned EOF/ErrClosed,
	// surface it as timeout so callers (TLS handshake, urltest Peek)
	// can distinguish "server shut us down" from "we gave up waiting".
	if err != nil && c.deadlineFired.Load() {
		return n, xhttpDeadlineError{}
	}
	return n, err
}

func (c *xhttpConn) Write(p []byte) (int, error) {
	if c.writer == nil {
		return 0, io.ErrClosedPipe
	}
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
		// 先关 deadline timer，避免 timer 再回调已关闭的 conn。
		c.deadlineMu.Lock()
		if c.readDeadlineTimer != nil {
			c.readDeadlineTimer.Stop()
			c.readDeadlineTimer = nil
		}
		if c.writeDeadlineTim != nil {
			c.writeDeadlineTim.Stop()
			c.writeDeadlineTim = nil
		}
		c.deadlineMu.Unlock()

		// 先关写端（能触发对端 EOF），再关读端。读端可能是 response.Body，
		// Close 会释放 HTTP 客户端连接回池。
		if c.writer != nil {
			if err := c.writer.Close(); err != nil {
				c.closeErr = err
			}
		}
		if closer, ok := c.reader.(io.Closer); ok {
			if err := closer.Close(); err != nil && c.closeErr == nil {
				c.closeErr = err
			}
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.closeErr
}


func (c *xhttpConn) LocalAddr() net.Addr  { return M.Socksaddr{} }
func (c *xhttpConn) RemoteAddr() net.Addr { return c.remoteAddr }

// SetDeadline / SetReadDeadline / SetWriteDeadline 用 timer + Close
// 实现。HTTP body 层面无法原生做"只读超时"或"只写超时"，粒度退化为
// "任意一端超时就整条 conn 立刻错误"——这对 urltest / TLS handshake /
// 上层 HTTP 客户端读请求都够用，避免节点失联时 probe 无限挂起。
//
// zero time.Time 语义 = 取消 deadline（标准 net.Conn 约定），会停掉
// 现有 timer 并清 deadlineFired 标志。
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
	c.armDeadline(&c.writeDeadlineTim, t)
	return nil
}

func (c *xhttpConn) armDeadline(slot **time.Timer, t time.Time) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
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
		_ = c.closeInternal()
		return
	}
	*slot = time.AfterFunc(d, func() {
		c.deadlineFired.Store(true)
		_ = c.closeInternal()
	})
}

// closeInternal 是 Close 的非幂等版本；SetDeadline 的 timer 用它主动
// 拆 conn。和 Close 一样被 closeOnce 保护，所以多次调用安全。
func (c *xhttpConn) closeInternal() error {
	return c.Close()
}

// NeedAdditionalReadDeadline 保留 true：sing/bufio 层仍会额外包一层
// 超时 wrapper（对上层协议栈更友好），我们的 SetDeadline 只是额外
// 保险，不和 wrapper 冲突。
func (c *xhttpConn) NeedAdditionalReadDeadline() bool { return true }
