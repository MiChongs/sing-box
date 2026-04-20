package v2rayxhttp

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// packet-up 模式：每个上行数据包一个独立 HTTP POST，带递增 seq。
// 服务端按 seq 有序 reassemble；客户端并发发送但服务端等前置 seq 到齐
// 才 pop 到 handler 的读流。
//
// 该模式最复杂、开销最大，但穿透性最好（单个请求短小，CDN/WAF 友好）。

// packetUpSession 服务端为每个 session (由 URL path 里的 UUID 标识) 维护的状态。
// - 一个 SSE 下行 response.Body 作为 writer（handler 写 conn 就是写 SSE 帧）
// - 一个有序 reader 把乱序 POST 重组成连续字节流
type packetUpSession struct {
	id string

	// handlerStarted 保护 handler goroutine 只被 POST seq=0 启动一次
	// （正常客户端只发一次 seq=0；防御客户端 bug 或重连复用同 session id）
	handlerStarted atomic.Bool

	// 上行：按 seq 排序的 buffer。POST 到达时先进 pending，seq == expected 时
	// 才 pop 到 upstream pipe，expected++；此时检查 pending 里是否已有
	// 连续的下一条。未到齐则等。
	upAccess       sync.Mutex
	upExpectedSeq  uint64
	upPending      map[uint64][]byte
	upMaxBuffered  int
	upReaderWriter *io.PipeWriter
	upReader       *io.PipeReader
	upClosed       atomic.Bool

	// 下行：SSE response 的 Flusher + 写锁
	downAccess  sync.Mutex
	downWriter  io.Writer // = http.ResponseWriter
	downFlusher http.Flusher
	downReady   chan struct{} // 等 SSE GET 到达才有 downWriter
	downClosed  atomic.Bool

	// 整个 session 的清理信号
	closeOnce sync.Once
	closed    chan struct{}

	lastActiveNanos atomic.Int64
}

func newPacketUpSession(id string, maxBuffered int) *packetUpSession {
	pipeReader, pipeWriter := io.Pipe()
	s := &packetUpSession{
		id:             id,
		upPending:      make(map[uint64][]byte, maxBuffered),
		upMaxBuffered:  maxBuffered,
		upReaderWriter: pipeWriter,
		upReader:       pipeReader,
		downReady:      make(chan struct{}),
		closed:         make(chan struct{}),
	}
	s.touch()
	return s
}

func (s *packetUpSession) touch() {
	s.lastActiveNanos.Store(time.Now().UnixNano())
}

// submitPacket 把一条 POST 的 body 按 seq 登记进 session。
// expected seq 到达时立刻 flush 到 upstream pipe，并推进 expectedSeq 消化已缓冲的后续 seq。
// 超过 maxBuffered 返回错误（客户端行为异常，服务端拒绝 DoS）。
func (s *packetUpSession) submitPacket(seq uint64, data []byte) error {
	s.touch()
	s.upAccess.Lock()
	defer s.upAccess.Unlock()
	if s.upClosed.Load() {
		return io.ErrClosedPipe
	}
	if seq < s.upExpectedSeq {
		// 重放或乱序抵达太晚，丢弃（客户端应该用递增 seq；TCP POST 不会乱序
		// 到这种程度，通常是客户端 bug 或攻击）
		return nil
	}
	if seq == s.upExpectedSeq {
		// 命中，直接写并推进
		if _, err := s.upReaderWriter.Write(data); err != nil {
			return err
		}
		s.upExpectedSeq++
		// 消化 pending 里的连续 seq
		for {
			buf, ok := s.upPending[s.upExpectedSeq]
			if !ok {
				break
			}
			delete(s.upPending, s.upExpectedSeq)
			if _, err := s.upReaderWriter.Write(buf); err != nil {
				return err
			}
			s.upExpectedSeq++
		}
		return nil
	}
	// seq > expected：入 pending
	if len(s.upPending) >= s.upMaxBuffered {
		return E.New("packet-up: buffer full (sc_max_buffered_posts=",
			s.upMaxBuffered, "), drop seq=", seq)
	}
	s.upPending[seq] = data
	return nil
}

// attachDownWriter 由 SSE GET handler 调用：一旦 GET 接起，把 writer/flusher
// 交给 session，后续 writeDown 调用才有效。
func (s *packetUpSession) attachDownWriter(w http.ResponseWriter, flusher http.Flusher) {
	s.downAccess.Lock()
	defer s.downAccess.Unlock()
	s.downWriter = w
	s.downFlusher = flusher
	// 仅 close 一次（避免多次 GET 重连时 panic）
	select {
	case <-s.downReady:
	default:
		close(s.downReady)
	}
}

// writeDown 供 xhttpConn.writer 调 — handler 的写会走这里推到客户端。
// 阻塞等到 SSE GET 已建立 (downReady)，之后按 SSE 帧格式写 response body。
// noSSE=true 时退化为普通 chunked 字节流。
func (s *packetUpSession) writeDown(data []byte, noSSE bool) (int, error) {
	select {
	case <-s.downReady:
	case <-s.closed:
		return 0, io.ErrClosedPipe
	}
	if s.downClosed.Load() {
		return 0, io.ErrClosedPipe
	}
	s.downAccess.Lock()
	defer s.downAccess.Unlock()
	s.touch()
	if s.downWriter == nil {
		return 0, io.ErrClosedPipe
	}
	if noSSE {
		n, err := s.downWriter.Write(data)
		if err == nil {
			s.downFlusher.Flush()
		}
		return n, err
	}
	// SSE: "data: <hex>\n\n"。用 hex 避免二进制破坏 SSE 分隔符。
	// 这里按 Xray 实现直接写原始字节 + "\n\n" —— Xray 的 SSE 模式并非
	// W3C 标准 SSE，只是利用 text/event-stream mime 绕过 CDN 的 chunked
	// 响应 buffering。
	n, err := s.downWriter.Write(data)
	if err == nil {
		s.downFlusher.Flush()
	}
	return n, err
}

func (s *packetUpSession) closeUp() {
	if s.upClosed.Swap(true) {
		return
	}
	_ = s.upReaderWriter.Close()
}

func (s *packetUpSession) closeDown() {
	s.downClosed.Store(true)
}

// close 全链路关闭，从 session map 移除。
func (s *packetUpSession) close() {
	s.closeOnce.Do(func() {
		s.closeUp()
		s.closeDown()
		close(s.closed)
	})
}

// packetUpWriter 是 client 端的写端。每次 Write 生成一条独立 POST 发给
// 服务器，带递增的 seq。服务端按 seq 重组。
type packetUpWriter struct {
	client      *http.Client
	requestURL  url.URL
	host        string
	headers     http.Header
	padding     paddingRange
	minInterval time.Duration
	maxEachPost int

	seq         uint64
	lastPostAt  time.Time
	access      sync.Mutex
	closedState atomic.Bool
}

func (w *packetUpWriter) Write(p []byte) (int, error) {
	if w.closedState.Load() {
		return 0, io.ErrClosedPipe
	}
	total := len(p)
	// 按 maxEachPost 切片
	for len(p) > 0 {
		chunk := p
		if w.maxEachPost > 0 && len(chunk) > w.maxEachPost {
			chunk = p[:w.maxEachPost]
		}
		if err := w.sendOne(chunk); err != nil {
			return total - len(p), err
		}
		p = p[len(chunk):]
	}
	return total, nil
}

func (w *packetUpWriter) sendOne(chunk []byte) error {
	w.access.Lock()
	seq := w.seq
	w.seq++
	// 最小间隔节流
	if w.minInterval > 0 {
		since := time.Since(w.lastPostAt)
		if since < w.minInterval {
			time.Sleep(w.minInterval - since)
		}
		w.lastPostAt = time.Now()
	}
	w.access.Unlock()

	u := w.requestURL
	// URL path: <base>/<seq>
	u.Path = appendPathSegment(u.Path, strconv.FormatUint(seq, 10))
	// query padding
	if pad := w.padding.randomHex(); pad != "" {
		q := u.Query()
		q.Set(paddingQueryKey, pad)
		u.RawQuery = q.Encode()
	}
	req := &http.Request{
		Method: methodPost,
		URL:    &u,
		Host:   w.host,
		Header: w.headers.Clone(),
		Body:   io.NopCloser(newBytesReader(chunk)),
	}
	req.ContentLength = int64(len(chunk))
	if pad := w.padding.randomHex(); pad != "" {
		req.Header.Set(paddingHeaderKey, pad)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	// drain + close
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return E.New("packet-up: unexpected status: ", resp.Status)
	}
	return nil
}

func (w *packetUpWriter) Close() error {
	w.closedState.Store(true)
	return nil
}

// 小辅助: 接 URL path 尾部。保留原 path 的前缀 slash 语义。
func appendPathSegment(base, seg string) string {
	if base == "" || base == "/" {
		return "/" + seg
	}
	if base[len(base)-1] == '/' {
		return base + seg
	}
	return base + "/" + seg
}

// newBytesReader 把 []byte 包成 io.Reader，避免为每次 POST 分配
// bytes.Buffer（bytes.NewReader 本身是值类型但 http.NewRequest 要 ReadCloser）
func newBytesReader(b []byte) *bytesReader {
	return &bytesReader{b: b}
}

type bytesReader struct {
	b   []byte
	pos int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}
