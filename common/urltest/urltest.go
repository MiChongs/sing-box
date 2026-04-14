package urltest

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/observable"
)

// ════════════════ HistoryStorage ════════════════

var _ adapter.URLTestHistoryStorage = (*HistoryStorage)(nil)

type HistoryStorage struct {
	delayHistory sync.Map
	updateHook   *observable.Subscriber[struct{}]
	hookAccess   sync.Mutex
}

func NewHistoryStorage() *HistoryStorage { return &HistoryStorage{} }

func (s *HistoryStorage) SetHook(h *observable.Subscriber[struct{}]) {
	s.hookAccess.Lock()
	s.updateHook = h
	s.hookAccess.Unlock()
}

func (s *HistoryStorage) LoadURLTestHistory(tag string) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	v, ok := s.delayHistory.Load(tag)
	if !ok {
		return nil
	}
	return v.(*adapter.URLTestHistory)
}

func (s *HistoryStorage) DeleteURLTestHistory(tag string) {
	s.delayHistory.Delete(tag)
	s.notifyUpdated()
}

func (s *HistoryStorage) StoreURLTestHistory(tag string, h *adapter.URLTestHistory) {
	s.delayHistory.Store(tag, h)
	s.notifyUpdated()
}

func (s *HistoryStorage) notifyUpdated() {
	s.hookAccess.Lock()
	h := s.updateHook
	s.hookAccess.Unlock()
	if h != nil {
		h.Emit(struct{}{})
	}
}

func (s *HistoryStorage) Close() error {
	s.hookAccess.Lock()
	s.updateHook = nil
	s.hookAccess.Unlock()
	return nil
}

// ════════════════ Pool & Cache ════════════════

// bufioSize 单次响应头缓冲上限。generate_204 典型响应头 ≈ 400B；
// 2KB 留足富余同时控制池驻留内存（并发 100 节点约 200KB，远低于 4KB 版本）。
const bufioSize = 2048

// maxResidualBody 对违反规范的 HEAD+body 响应主动消费的上限，防御性内存屏障。
const maxResidualBody = 64 * 1024

// bufio.Reader 池 — 解析 HTTP 响应时复用。
var readerPool = sync.Pool{
	New: func() any { return bufio.NewReaderSize(nil, bufioSize) },
}

// 每个 URL 预构建一次 HEAD 请求字节，永久复用。绝大多数场景 URL 固定（generate_204），命中率 100%。
var requestCache sync.Map // map[string]*cachedRequest

type cachedRequest struct {
	headKeepAlive []byte // HEAD ... Connection: keep-alive
	headClose     []byte // HEAD ... Connection: close
	headReq       *http.Request
}

var errBodyTooLarge = errors.New("urltest: response body exceeds safety limit")

func getOrBuildRequest(linkURL *url.URL, hostname string) *cachedRequest {
	key := linkURL.String()
	if v, ok := requestCache.Load(key); ok {
		return v.(*cachedRequest)
	}
	uri := linkURL.RequestURI()
	head := "HEAD " + uri + " HTTP/1.1\r\nHost: " + hostname + "\r\nUser-Agent: sing-box\r\nAccept: */*\r\n"
	// http.ReadResponse 需要 Request 参考来正确解释 body 语义
	// （HEAD 方法下 body 永远为空，避免误读下一条响应）
	req, _ := http.NewRequest(http.MethodHead, key, nil)
	cr := &cachedRequest{
		headKeepAlive: []byte(head + "Connection: keep-alive\r\n\r\n"),
		headClose:     []byte(head + "Connection: close\r\n\r\n"),
		headReq:       req,
	}
	requestCache.Store(key, cr)
	return cr
}

// ════════════════ URLTest ════════════════

// URLTest 通过指定 dialer 执行多维度延迟测量。
//
// 测量流程：
//  1. TCP Connect (DialContext) — 包含代理隧道建立
//  2. TLS Handshake (如为 HTTPS)
//  3. HTTP HEAD 请求 + first-byte RTT 测量
//
// 计时策略（First-Byte RTT）：
//   - 用 bufio.Reader.Peek(1) 阻塞到服务器第一字节到达
//   - delay = first_byte_time - write_start_time
//   - 语义：纯 HTTP 往返延迟，排除 TCP/TLS 握手噪声
//   - 对 BBR/QUIC 等非线性 CC 协议更稳定（不受窗口抖动影响）
//
// UnifiedDelay 模式（对齐 Clash Meta 语义）：
//   - 请求 1：HEAD keep-alive 暖身（也测 RTT，作为 fallback）
//   - 请求 2：HEAD close 计时（keep-alive 稳态 RTT，更准）
//   - 若请求 2 失败（QUIC stream 异常、keep-alive 被服务器拒绝等），
//     自动降级返回请求 1 的 RTT，避免测试失败
//
// 为何用 HEAD：
//   - 避免 body 传输，降低测量方差
//   - net/http.ReadResponse 在 HEAD 语义下不尝试读 body，规避 body 编码歧义
//
// 高可用增强：
//   - 无 tls.CloseWrite — 避免对 QUIC stream 的额外交互
//   - UnifiedDelay 双请求降级机制 — hy2/tuic QUIC 单流场景下至少保底一次测量
//   - first-byte 计时 — 对 BBR 慢启动、QUIC Write→wire 延迟不敏感
//
// 兼容性：
//   - hy2 / tuic / anytls：QUIC 单流路径受益于降级机制，hy2 stream 异常不再报错
//   - vless / trojan / vmess / ss：标准 TCP keep-alive 路径，双请求均成功
//   - shadowtls / naive：HTTP/2 代理层透明
//   - chunked / gzip / 无 Content-Length 响应：交由 http.ReadResponse 处理
//   - 2xx/3xx 均视可达（仅 4xx/5xx 判失败）
func URLTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	// ── Phase 1: TCP Connect + Proxy Handshake ──
	instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return
	}
	defer instance.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = instance.SetDeadline(deadline)
		defer instance.SetDeadline(time.Time{})
	}

	// ── Phase 2: TLS Handshake ──
	// 注意：不使用 defer tlsConn.CloseWrite() —— 对 QUIC 单流协议（hy2/tuic），
	// 在测速结尾发 close_notify 可能触发 server 端 stream 异常处理，干扰下次测速。
	// TLS 连接随 instance.Close 一起释放即可。
	var conn net.Conn = instance
	if linkURL.Scheme == "https" {
		tlsConn := tls.Client(instance, &tls.Config{
			ServerName: hostname,
			Time:       ntp.TimeFuncFromContext(ctx),
			RootCAs:    adapter.RootPoolFromContext(ctx),
		})
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			return
		}
		conn = tlsConn
	}

	// ── Phase 3: HTTP HEAD + First-Byte RTT ──
	req := getOrBuildRequest(linkURL, hostname)
	reader := readerPool.Get().(*bufio.Reader)
	reader.Reset(conn)
	defer func() {
		reader.Reset(nil)
		readerPool.Put(reader)
	}()

	var rtt time.Duration
	if C.URLTestUnifiedDelay {
		// 请求 1：暖身 + 首次 RTT 测量
		rtt1, err1 := measureRequest(conn, reader, req.headReq, req.headKeepAlive)
		if err1 != nil {
			err = err1
			return
		}
		// 请求 2：稳态 RTT 测量（首选）
		rtt2, err2 := measureRequest(conn, reader, req.headReq, req.headClose)
		if err2 != nil {
			// 降级：hy2/tuic 等 QUIC 协议或服务器拒绝 keep-alive 时，
			// 用暖身 RTT 兜底，保证测试不作废
			rtt = rtt1
		} else {
			rtt = rtt2
		}
	} else {
		rtt, err = measureRequest(conn, reader, req.headReq, req.headClose)
		if err != nil {
			return
		}
	}

	t = uint16(rtt.Milliseconds())
	// 亚毫秒级响应提升到 1ms，避免 0 被上层判为失败
	if t == 0 && rtt > 0 {
		t = 1
	}
	return
}

// measureRequest 发起单次 HTTP HEAD 请求并测量 first-byte RTT。
//
// 计时窗口：write_start → 响应首字节可读时刻。
//
//   - bufio.Reader.Peek(1) 阻塞至少 1 字节，不消费 buffer（后续 ReadResponse 正常解析）
//   - 排除 TCP/TLS 握手，排除 QUIC 连接建立，排除 BBR 窗口扩张
//   - 即使读到首字节后 drainResponse 失败（如 4xx 状态），仍返回已测 RTT + 错误，
//     调用方可决定是否采用
func measureRequest(conn net.Conn, reader *bufio.Reader, req *http.Request, reqBytes []byte) (time.Duration, error) {
	writeStart := time.Now()
	if _, err := conn.Write(reqBytes); err != nil {
		return 0, err
	}
	// Peek(1) 阻塞到响应首字节到达 —— 纯 HTTP RTT 边界
	if _, err := reader.Peek(1); err != nil {
		return 0, err
	}
	rtt := time.Since(writeStart)
	// 完整消费响应头与 body，保持 stream 干净（下次请求可复用）
	if err := drainResponse(reader, req); err != nil {
		return rtt, err
	}
	return rtt, nil
}

// drainResponse 通过 net/http.ReadResponse 解析完整响应并消费 body。
//
// 为何不手写解析：
//   - HTTP/1.1 body 结束条件有三种（Content-Length、chunked、connection-close），
//     每一种都有非平凡的边界（chunked 的 trailer，100-continue，transfer-encoding 栈）；
//   - 手写解析一旦漏处理，keep-alive 的下一次请求会读到残留字节流，对 QUIC 单流
//     协议（hy2/tuic）尤其致命 —— 它们无法通过 EOF 自愈；
//   - 标准库经过十余年生产验证，稳定性远胜重造轮子。
//
// 内存行为：
//   - HEAD 方法下 resp.Body == http.NoBody；io.Copy 走 WriteTo 快速路径零分配；
//   - bufio.Reader 从 Pool 取用，稳态零分配；
//   - resp 结构体本身一次性堆分配 ~1KB，随返回即可被 GC 回收；
//   - 违规服务器对 HEAD 返回 body 时，标准库将 Body 置为 NoBody —— 字节仍在 reader，
//     主动按 Content-Length drain，避免污染下次 keep-alive 请求。
func drainResponse(reader *bufio.Reader, req *http.Request) error {
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return err
	}
	// 防御性 drain：违规 HEAD+body 的字节还在 bufio 中
	if cl := resp.ContentLength; cl > 0 {
		if cl > maxResidualBody {
			return errBodyTooLarge
		}
		if _, err = io.CopyN(io.Discard, reader, cl); err != nil {
			return err
		}
	}
	// Body 为 NoBody 时 Copy/Close 均为 no-op；非 HEAD 场景完整 drain
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		return &httpStatusError{resp.StatusCode}
	}
	return nil
}

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string {
	return "HTTP " + string([]byte{
		byte(e.code/100) + '0',
		byte((e.code/10)%10) + '0',
		byte(e.code%10) + '0',
	})
}
