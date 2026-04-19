package urltest

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart/tcpinfo"
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

// requestPayloads contains the raw byte sequences for HEAD tests
type requestPayloads struct {
	headKeepAlive []byte
	headClose     []byte
	headReq       *http.Request
}

var errBodyTooLarge = errors.New("urltest: response body exceeds safety limit")

func buildDynamicRequest(linkURL *url.URL, hostname string) *requestPayloads {
	// Anti-Spoofing: Inject a high-entropy nonce to defeat aggressive ISP/Airport caches
	b := make([]byte, 4)
	rand.Read(b)
	nonce := hex.EncodeToString(b)
	
	q := linkURL.Query()
	q.Set("rnd", nonce)
	linkURL.RawQuery = q.Encode()

	key := linkURL.String()
	uri := linkURL.RequestURI()
	head := "HEAD " + uri + " HTTP/1.1\r\nHost: " + hostname + "\r\nUser-Agent: sing-box\r\nAccept: */*\r\n"
	
	req, _ := http.NewRequest(http.MethodHead, key, nil)
	return &requestPayloads{
		headKeepAlive: []byte(head + "Connection: keep-alive\r\n\r\n"),
		headClose:     []byte(head + "Connection: close\r\n\r\n"),
		headReq:       req,
	}
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
// URLTestDetail is the optional per-probe phase-timing detail structure.
// Passed by pointer to URLTestWithDetail; any phase that is not applicable
// (e.g. TLSHandshakeMS for a plain HTTP link) remains 0.
//
// Field semantics:
//
//	TCPConnectMS   — time to establish the transport instance via detour.DialContext.
//	                 Includes proxy-handshake cost when the detour is a proxy chain.
//	                 Does NOT include DNS resolution when the proxy resolves the
//	                 remote name internally (which is the common case); set by the
//	                 dialer stack, not by URLTest.
//	TLSHandshakeMS — wall clock from tls.Client to HandshakeContext-return.
//	                 Excludes TCP/proxy connect; 0 for HTTP and for failed dials.
//	FirstByteMS    — the headline delay number returned as the uint16 result.
//	DidResume      — true when the TLS handshake reused a cached session
//	                 (tls.ConnectionState.DidResume). Meaningful only for HTTPS
//	                 probes that actually completed the handshake.
//	DNSResolveMS   — reserved: 0 in v2 because URLTest does not own the DNS
//	                 resolver (proxy chains resolve internally). Populated by a
//	                 future sing-dialer hook without an API break.
type URLTestDetail struct {
	TCPConnectMS   int64
	TLSHandshakeMS int64
	FirstByteMS    int64
	DidResume      bool
	DNSResolveMS   int64

	// xiaobaf14g v3 — kernel TCP metrics read from the probe socket
	// before the conn is closed. Zero on non-Linux platforms or when the
	// outer conn is a proxy wrapper that hides its fd (common for
	// protocol-stack conns: anytls / vmess / trojan / shadowtls / etc.).
	// See common/smart/tcpinfo for the exact read-path semantics.
	TCPRetransmissions uint32
	TCPLosses          uint32
	PathMTU            uint32
}

// URLTest probes a link through the given dialer and returns the headline
// first-byte RTT in milliseconds. This wrapper preserves the legacy two-value
// return signature used by every callsite that does NOT need phase timings.
func URLTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	return URLTestWithDetail(ctx, link, detour, nil)
}

// URLTestWithDetail is the full-fidelity probe. When detail is non-nil, the
// caller receives per-phase timings alongside the RTT — used by Smart groups
// to split TCP vs TLS latency and detect session-resumption signals for
// sticky-session / least-loaded routing strategies. Pass nil detail to get
// the same behaviour as URLTest (no measurement overhead besides the existing
// wall-clock reads).
func URLTestWithDetail(ctx context.Context, link string, detour N.Dialer, detail *URLTestDetail) (t uint16, err error) {
	dialStart := time.Now()
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
	if detail != nil {
		detail.TCPConnectMS = time.Since(dialStart).Milliseconds()
	}

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
		tlsStart := time.Now()
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			return
		}
		if detail != nil {
			detail.TLSHandshakeMS = time.Since(tlsStart).Milliseconds()
			detail.DidResume = tlsConn.ConnectionState().DidResume
		}
		conn = tlsConn
	}

	// ── Phase 3: HTTP HEAD + First-Byte RTT ──
	req := buildDynamicRequest(linkURL, hostname)
	reader := readerPool.Get().(*bufio.Reader)
	reader.Reset(conn)
	defer func() {
		reader.Reset(nil)
		readerPool.Put(reader)
	}()

	dialDuration := time.Since(dialStart)
	
	// Assess if the target URL implies a strict 204 No Content assertion
	require204 := strings.Contains(linkURL.Path, "204") || strings.Contains(linkURL.Host, "204")

	var totalDelay time.Duration
	if C.URLTestUnifiedDelay {
		// UnifiedDelay mode semantics (Aligned with Clash Meta):
		// Unify protocol disparity by completely ignoring the preliminary dial, TCP, 
		// and explicit TLS handshake overheads (DialDuration).
		// We execute a warm-up strike first, then measure the pure un-adulterated steady-state RTT
		// of the naked conduit.
		rtt1, err1 := measureRequest(conn, reader, req.headReq, req.headKeepAlive, require204)
		if err1 != nil {
			return 0, err1
		}
		
		// Strike 2: Measure steady-state naked line RTT.
		rtt2, err2 := measureRequest(conn, reader, req.headReq, req.headClose, require204)
		if err2 != nil {
			// Degradation recovery: MUX protocols like HY2/TUIC may freak out over connection: close 
			// stream severing. If so, fall back to pure rtt1 (which already ignores dialDuration).
			totalDelay = rtt1
		} else {
			totalDelay = rtt2
		}
	} else {
		// Strict Truth Mode: Test using a clean single shot.
		rtt, err := measureRequest(conn, reader, req.headReq, req.headClose, require204)
		if err != nil {
			return 0, err
		}
		// The total user-perceived UX delay includes the painful tunnel/handshake creation penalty!
		totalDelay = dialDuration + rtt
	}

	t = uint16(totalDelay.Milliseconds())
	// 亚毫秒级响应提升到 1ms，避免 0 被上层判为失败
	if t == 0 && totalDelay > 0 {
		t = 1
	}
	if detail != nil {
		detail.FirstByteMS = int64(t)
		// Read kernel TCP metrics before the deferred instance.Close() fires
		// (tcp_info is invalidated the moment the socket closes). The
		// instance here is the detour.DialContext return value, which is
		// usually a proxy wrapper — tcpinfo.Read returns ok=false unless
		// the outer type exposes syscall.Conn (direct outbound, and a
		// handful of thin wrappers). Non-Linux builds always return
		// ok=false. We swallow ok because zero is the documented "unknown"
		// marker in ModelInput.
		if tinfo, ok := tcpinfo.Read(instance); ok {
			detail.TCPRetransmissions = tinfo.Retransmissions
			detail.TCPLosses = tinfo.Losses
			detail.PathMTU = tinfo.PathMTU
		}
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
//     调用方可决定是否采用
func measureRequest(conn net.Conn, reader *bufio.Reader, req *http.Request, reqBytes []byte, require204 bool) (time.Duration, error) {
	// Deep-Penetration kill limit: Prevent proxy stream deadlocks or fake-connected hangs!
	// Ensures Peek(1) never hangs infinitely if the wall/node silently drops the packet.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

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
	if err := drainResponse(reader, req, require204); err != nil {
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
func drainResponse(reader *bufio.Reader, req *http.Request, require204 bool) error {
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
	
	// Anti-Poisoning Validation: 
	// If target expects a clean 204 (generate_204), reject 200/302 redirects often fed by captive portals, 
	// ISPs, or airport-proxy mock hijacks.
	if require204 && resp.StatusCode != 204 {
		return errors.New("urltest: proxy hijack or poison detected (expected 204, got " + strconv.Itoa(resp.StatusCode) + ")")
	}
	
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
