package v2rayxhttp

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

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
func (c *xhttpConn) setupReader(reader io.Reader, err error) {
	c.reader = reader
	c.setupErr = err
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
	if c.reader == nil {
		return 0, io.ErrUnexpectedEOF
	}
	return c.reader.Read(p)
}

func (c *xhttpConn) Write(p []byte) (int, error) {
	if c.writer == nil {
		return 0, io.ErrClosedPipe
	}
	return c.writer.Write(p)
}

func (c *xhttpConn) Close() error {
	c.closeOnce.Do(func() {
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
	})
	return c.closeErr
}

func (c *xhttpConn) LocalAddr() net.Addr  { return M.Socksaddr{} }
func (c *xhttpConn) RemoteAddr() net.Addr { return c.remoteAddr }

// HTTP body 上的 deadline 不受支持；v2ray 层对 deadline 的依赖已经
// 被 bufio.deadline wrapper 吃掉（NeedAdditionalReadDeadline 返回 true 即可）。
func (c *xhttpConn) SetDeadline(t time.Time) error      { return os.ErrInvalid }
func (c *xhttpConn) SetReadDeadline(t time.Time) error  { return os.ErrInvalid }
func (c *xhttpConn) SetWriteDeadline(t time.Time) error { return os.ErrInvalid }

// NeedAdditionalReadDeadline 通知 sing 的 bufio 层：本 conn 不原生支持
// read deadline，需要外层额外加一层 deadline wrapper。
func (c *xhttpConn) NeedAdditionalReadDeadline() bool { return true }
