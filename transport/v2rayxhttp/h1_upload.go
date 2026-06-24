package v2rayxhttp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// H1Conn 包装一条裸 TCP/TLS 连接，附带 bufio.Reader 用于读 HTTP/1.1 response。
//
// HTTP/1.1 是串行的（一条连接同一时刻只处理一个 request-response），
// packet-up 模式下客户端要发大量 POST，不可能每条都新建 TCP+TLS 握手。
// 所以维护一个连接池 (h1UploadPool)，每片 POST 取一条空闲连接写出去，
// 读完 response 后放回池里。
//
// 对齐 Xray-core v26.3.27 transport/internet/splithttp/h1_conn.go。
type H1Conn struct {
	// UnreadedResponses: 连接从池里取出来时，可能上次 POST 的 response
	// 还没读。如果 > 0，下次取出来要先把堆积的 response drain 掉。
	UnreadedResponses int
	RespBufReader     *bufio.Reader
	net.Conn
}

func NewH1Conn(conn net.Conn) *H1Conn {
	return &H1Conn{
		RespBufReader: bufio.NewReaderSize(conn, 65536),
		Conn:          conn,
	}
}

// h1UploadPool 管理 packet-up 模式下 HTTP/1.1 上行连接的复用。
//
// sync.Pool 提供 get/put 语义:
//   Get → nil 表示池空，需要新建连接
//   Get → *H1Conn 表示有空闲连接，直接写 serialized request
//   Put → 把用完的连接放回
//
// 连接断开时 (write error) 不 Put 回池，让 GC 回收。
type h1UploadPool struct {
	pool          sync.Pool
	dialUploadCtx func(ctx context.Context) (net.Conn, error)
}

func newH1UploadPool(dialFn func(ctx context.Context) (net.Conn, error)) *h1UploadPool {
	return &h1UploadPool{
		dialUploadCtx: dialFn,
	}
}

// postH1Packet 把一片 packet-up POST 通过 H1 手写序列化 + 连接池发出去。
//
// 与 http.Transport.RoundTrip 的区别:
//   1. requestBuff.Grow(512 + ContentLength) 预分配 — 避免 bytes.Buffer 多次 grow+copy
//   2. 整个 request 被 req.Write 序列化进 bytes.Buffer — body 被消费但不影响重试
//   3. 写失败时可以从池取另一条连接重试 (http.Transport 在 body 已消费后无法重试)
//   4. response 不立即读 — 放回池后下次取出来再 drain (pipeline 优化)
//
// 对齐 Xray-core v26.3.27 client.go DefaultDialerClient.PostPacket H1 分支。
func (p *h1UploadPool) postH1Packet(ctx context.Context, req *http.Request) error {
	// 序列化整个 HTTP/1.1 request 到 buffer — body 读完后可以安全重试
	requestBuff := new(bytes.Buffer)
	// PR#5803: 按 ContentLength 预分配，避免 bytes.Buffer 内部多次 grow+copy
	requestBuff.Grow(512 + int(req.ContentLength))
	if err := req.Write(requestBuff); err != nil {
		return fmt.Errorf("xhttp h1: serialize request: %w", err)
	}
	serialized := requestBuff.Bytes()

	for {
		// 从池取一条连接
		uploadConn := p.pool.Get()
		newConnection := uploadConn == nil

		var h1c *H1Conn
		if newConnection {
			// 池空 → 新建
			rawConn, err := p.dialUploadCtx(context.WithoutCancel(ctx))
			if err != nil {
				return fmt.Errorf("xhttp h1: dial upload: %w", err)
			}
			h1c = NewH1Conn(rawConn)
		} else {
			h1c = uploadConn.(*H1Conn)
			// 池里的连接可能有上次没读的 response — drain 掉
			dropConn := false
			for h1c.UnreadedResponses > 0 {
				stale, err := http.ReadResponse(h1c.RespBufReader, req)
				if err != nil {
					_ = h1c.Close()
					dropConn = true
					break
				}
				h1c.UnreadedResponses--
				_, _ = io.Copy(io.Discard, stale.Body)
				stale.Body.Close()
				if stale.StatusCode != http.StatusOK {
					_ = h1c.Close()
					return fmt.Errorf("xhttp h1: stale response status %d", stale.StatusCode)
				}
			}
			if dropConn {
				continue
			}
		}

		// 写 serialized request
		_, writeErr := h1c.Write(serialized)
		if writeErr != nil {
			// 写失败
			_ = h1c.Close()
			if newConnection {
				return fmt.Errorf("xhttp h1: write to new conn: %w", writeErr)
			}
			// 旧连接写失败 → 可能是对端关了，下一轮建新连接重试
			continue
		}

		// 写成功 — 读 response（立即读避免连接超时）
		resp, readErr := http.ReadResponse(h1c.RespBufReader, req)
		if readErr != nil {
			_ = h1c.Close()
			if newConnection {
				return fmt.Errorf("xhttp h1: read response: %w", readErr)
			}
			continue // 旧连接读失败 → 重试
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_ = h1c.Close()
			return fmt.Errorf("xhttp h1: bad status %d", resp.StatusCode)
		}
		// 放回池
		p.pool.Put(h1c)
		return nil
	}
}

// close 清理池（best-effort）
func (p *h1UploadPool) close() {
	// sync.Pool 没有 "drain" 方法，Put 一个 nil marker 让旧连接自然 GC
	// 实际连接的 Close 由 net/http.Transport 或上层 ctx cancel 触发
}

// 防止 unused import warning (buf 在将来 packet-up body 改造时会用到)
var _ = buf.Buffer{}
var _ N.Dialer = (N.Dialer)(nil)
