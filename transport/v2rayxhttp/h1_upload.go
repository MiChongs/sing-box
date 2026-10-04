package v2rayxhttp

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
)

// h1Conn 是 packet-up 上行用的一条 HTTP/1.1 连接 (Xray H1Conn)。
type h1Conn struct {
	net.Conn
	reader *bufio.Reader
}

// h1UploadPool: HTTP/1.1 一条连接同一时刻只能处理一个请求，packet-up 的每个
// POST 从池里取一条空闲连接，手写序列化后写出，读完响应再放回。
//
// 对齐 Xray DefaultDialerClient.PostPacket 的 H1 分支: 请求先完整序列化进缓冲，
// 复用连接写失败时可以换一条连接重试。与 Xray 不同的是这里会读取每个响应 (Xray
// 从不读响应，连接上的响应会一直堆积)；复用连接在读响应时失败也会重试 —— 服务端
// upload queue 会丢弃重复的 seq，重发是安全的。
type h1UploadPool struct {
	access sync.Mutex
	conns  []*h1Conn
	closed bool
	dial   func(ctx context.Context) (net.Conn, error)
}

func newH1UploadPool(dial func(ctx context.Context) (net.Conn, error)) *h1UploadPool {
	return &h1UploadPool{dial: dial}
}

func (p *h1UploadPool) get() *h1Conn {
	p.access.Lock()
	defer p.access.Unlock()
	if len(p.conns) == 0 {
		return nil
	}
	conn := p.conns[len(p.conns)-1]
	p.conns = p.conns[:len(p.conns)-1]
	return conn
}

func (p *h1UploadPool) put(conn *h1Conn) {
	p.access.Lock()
	if !p.closed {
		p.conns = append(p.conns, conn)
		p.access.Unlock()
		return
	}
	p.access.Unlock()
	_ = conn.Close()
}

func (p *h1UploadPool) close() {
	p.access.Lock()
	conns := p.conns
	p.conns = nil
	p.closed = true
	p.access.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (p *h1UploadPool) postPacket(ctx context.Context, request *http.Request, onWrote func()) error {
	// stringify the entire HTTP/1.1 request so it can be safely retried.
	// if instead request.Write is called multiple times, the body is already
	// drained after the first request
	requestBuffer := new(bytes.Buffer)
	requestBuffer.Grow(512 + int(request.ContentLength))
	if err := request.Write(requestBuffer); err != nil {
		return E.Cause(err, "xhttp: serialize request")
	}
	requestBytes := requestBuffer.Bytes()
	for {
		conn := p.get()
		newConnection := conn == nil
		if newConnection {
			rawConn, err := p.dial(context.WithoutCancel(ctx))
			if err != nil {
				return E.Cause(err, "xhttp: dial upload connection")
			}
			conn = &h1Conn{Conn: rawConn, reader: bufio.NewReader(rawConn)}
		}
		_, err := conn.Write(requestBytes)
		if err == nil {
			onWrote()
			var response *http.Response
			response, err = http.ReadResponse(conn.reader, request)
			if err == nil {
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != http.StatusOK {
					_ = conn.Close()
					return E.New("xhttp: bad status code: ", response.Status)
				}
				if response.Close {
					_ = conn.Close()
				} else {
					p.put(conn)
				}
				return nil
			}
		}
		_ = conn.Close()
		// failed writes/reads on a pooled connection are normal when the
		// connection has been closed in the meantime; retry until a new
		// connection fails.
		if newConnection {
			return err
		}
	}
}
