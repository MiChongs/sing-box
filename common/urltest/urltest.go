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

// bufioSize — HTTP HEAD response headers fit comfortably.
// generate_204 ≈ 400B; 2KB is headroom without bloating the pool
// (100 concurrent probes ≈ 200KB resident).
const bufioSize = 2048

// maxResidualBody is a defensive cap on how many bytes we will
// drain from a spec-violating HEAD+body response before giving up.
const maxResidualBody = 64 * 1024

// peekHardLimit upper-bounds the per-request Peek(1) wait so a
// silently-dropped packet can't hang a probe indefinitely. The
// function uses min(ctxDeadline-remaining, peekHardLimit) so
// callers that pass a shorter ctx still win; callers without a
// deadline at all still get this safety net.
const peekHardLimit = 10 * time.Second

// readerPool — bufio.Reader recycled across probes. Reset(nil) in
// defer so we don't retain a dead conn reference in the pool.
var readerPool = sync.Pool{
	New: func() any { return bufio.NewReaderSize(nil, bufioSize) },
}

var errBodyTooLarge = errors.New("urltest: response body exceeds safety limit")

// sessionCacheOnce builds ClientSessionCache lazily; one cache per
// hostname (see sessionCacheFor). TLS session resumption across
// back-to-back probes is the single biggest "did I measure the
// node or the handshake" confounder — a second probe with resume
// gives a much more representative steady-state number.
var (
	sessionCacheMu    sync.Mutex
	sessionCacheByHost = make(map[string]tls.ClientSessionCache)
)

// sessionCacheFor returns a ClientSessionCache scoped to hostname
// so probes of different SNIs don't cross-contaminate cached
// tickets. Reused across probes of the same SNI for the lifetime of
// the process. Size=8 is plenty — we only care about the LATEST
// ticket for resumption, older ones are there for back-to-back
// probe bursts.
func sessionCacheFor(hostname string) tls.ClientSessionCache {
	sessionCacheMu.Lock()
	defer sessionCacheMu.Unlock()
	if c, ok := sessionCacheByHost[hostname]; ok {
		return c
	}
	c := tls.NewLRUClientSessionCache(8)
	sessionCacheByHost[hostname] = c
	return c
}

// ════════════════ URLTest ════════════════

// URLTestDetail captures the per-phase timings for callers that
// need them (Smart group's recordStats, LightGBM feature extractor,
// session-resumption signal for sticky-session).
//
// Field semantics (ALL fields measure pure phase duration, never
// cumulative):
//
//	TCPConnectMS   — time inside detour.DialContext. For proxy
//	                 chains this is "TCP to edge + proxy handshake"
//	                 since the inner proxy handshake blocks DialContext
//	                 until the tunnel is up. TLS is NOT included.
//	TLSHandshakeMS — tls.HandshakeContext wall time. 0 for http://
//	                 links, 0 for failed dials (phase never ran).
//	FirstByteMS    — write_start to first-response-byte. Pure HTTP
//	                 round-trip; independent of TCP/TLS cost. Used
//	                 by BBR/QUIC-aware strategies that want RTT
//	                 without handshake artefacts.
//	DidResume      — true when the TLS handshake reused a cached
//	                 session. Back-to-back probes of the same SNI
//	                 benefit from ClientSessionCache (see
//	                 sessionCacheFor) and will normally resume on
//	                 the second probe onwards.
//	DNSResolveMS   — reserved: always 0 here. Proxy chains resolve
//	                 internally; if we ever own DNS we'll fill this.
//	TCPRetransmissions / TCPLosses / PathMTU — kernel counters read
//	                 via tcpinfo. Linux + direct-fd only; 0 on other
//	                 platforms or wrapped conns (proxy stacks hide fd).
type URLTestDetail struct {
	TCPConnectMS   int64
	TLSHandshakeMS int64
	FirstByteMS    int64
	DidResume      bool
	DNSResolveMS   int64

	TCPRetransmissions uint32
	TCPLosses          uint32
	PathMTU            uint32
}

// URLTest probes a link through the given dialer and returns the
// headline delay in milliseconds. The value respects
// C.URLTestUnifiedDelay:
//
//   - unified_delay = true  → pure first-byte RTT (dial + TLS
//                             excluded). Comparable across
//                             protocols; what Clash Meta returns.
//   - unified_delay = false → dial + TLS + first-byte RTT. The
//                             user-perceived TTFB for opening a new
//                             connection through this node.
//
// This is the behaviour every caller has relied on; the signature
// is preserved for API compatibility.
func URLTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	return URLTestWithDetail(ctx, link, detour, nil)
}

// URLTestWithDetail is the full-fidelity probe. When detail is non-
// nil, the caller receives per-phase timings plus TLS-resume signal
// plus kernel TCP metrics alongside the headline delay. Pass nil
// detail for the plain wrapper.
//
// Design rationale — why single-request:
//
// The previous implementation issued TWO HTTP HEAD requests when
// unified_delay was enabled: one with keep-alive, one with close.
// The idea was "warm up with request 1, measure steady-state with
// request 2". It didn't work:
//
//   - Both measurements are pure HTTP round-trips (write → first
//     byte), so they're semantically EQUIVALENT — the second
//     request carries no extra information.
//   - For QUIC-single-stream outbounds (hysteria2 / tuic), the
//     keep-alive → close transition in the same stream triggers
//     server-side stream-reset handling; request 2 usually fails
//     and the code silently degraded to request 1, so the "warm
//     up" round was thrown away too.
//   - The double request wasted bandwidth, halved the number of
//     probes the shared ants pool could run in a given second, and
//     polluted per-(target, node) telemetry because the two
//     requests were recorded against the same dial outcome.
//
// The clean design is ONE request per probe, with the boundary of
// the measurement controlled by unified_delay:
//
//	dialStart ──[detour.DialContext]── dialDone
//	           │
//	           │             ┌──[tls.HandshakeContext]── tlsDone
//	           │             │
//	           │             │                     writeStart ──[HEAD + first byte]── peekOK
//	           │             │                     │                 │
//	           │             │                     │   pure HTTP RTT  │
//	           ├─ TCPConnectMS ──┤                 │  (FirstByteMS)   │
//	                             ├─ TLSHandshakeMS ┤                  │
//	           └───────────── total dial-to-first-byte ────────────── ┘
//
//	unified_delay=true  → headline = FirstByteMS
//	unified_delay=false → headline = dial-to-first-byte (includes TLS)
//
// Single-request also removes all the QUIC-single-stream work-
// arounds — the entire error branch that used to silently degrade
// to rtt1 is gone. What we lose is nothing (rtt1/rtt2 were always
// the same number); what we gain is correct semantics, half the
// bandwidth, and protocol-agnostic behaviour.
func URLTestWithDetail(ctx context.Context, link string, detour N.Dialer, detail *URLTestDetail) (t uint16, err error) {
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
	dialStart := time.Now()
	instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return
	}
	defer instance.Close()
	dialDone := time.Now()
	if detail != nil {
		detail.TCPConnectMS = dialDone.Sub(dialStart).Milliseconds()
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = instance.SetDeadline(deadline)
		defer instance.SetDeadline(time.Time{})
	}

	// ── Phase 2: TLS Handshake ──
	// NO tls.CloseWrite before defer instance.Close — for QUIC single-
	// stream protocols (hysteria2 / tuic) sending close_notify during
	// probe teardown causes server-side stream-error handling and
	// corrupts the next probe's dial. The plain Close on the outer
	// instance is enough — it tears the whole stream down cleanly.
	var conn net.Conn = instance
	tlsDone := dialDone
	if linkURL.Scheme == "https" {
		tlsConn := tls.Client(instance, &tls.Config{
			ServerName:         hostname,
			Time:               ntp.TimeFuncFromContext(ctx),
			RootCAs:            adapter.RootPoolFromContext(ctx),
			ClientSessionCache: sessionCacheFor(hostname),
			// MinVersion stays default (1.2) — matches what net/http
			// would negotiate, keeps the probe representative of
			// real browser traffic through the same node.
		})
		tlsStart := time.Now()
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			return
		}
		tlsDone = time.Now()
		if detail != nil {
			detail.TLSHandshakeMS = tlsDone.Sub(tlsStart).Milliseconds()
			detail.DidResume = tlsConn.ConnectionState().DidResume
		}
		conn = tlsConn
	}

	// ── Phase 3: HTTP HEAD (with GET fallback) + First-Byte RTT ──
	reader := readerPool.Get().(*bufio.Reader)
	reader.Reset(conn)
	defer func() {
		reader.Reset(nil)
		readerPool.Put(reader)
	}()

	// Apply Peek(1) read deadline: prefer ctx.Deadline, fall back to
	// peekHardLimit. Without this a silently-dropped packet on a
	// "fake open" tunnel hangs the probe until the caller's outer
	// context fires (sometimes tens of seconds).
	peekDeadline := time.Now().Add(peekHardLimit)
	if d, ok := ctx.Deadline(); ok && d.Before(peekDeadline) {
		peekDeadline = d
	}

	req204 := isGenerate204(linkURL)
	rtt, reqErr := probeHTTP(conn, reader, linkURL, hostname, peekDeadline, req204)
	if reqErr != nil {
		return 0, reqErr
	}

	// ── Assemble the headline number per unified_delay policy ──
	var totalDelay time.Duration
	if C.URLTestUnifiedDelay {
		// Pure HTTP round-trip. Comparable across protocols — two
		// nodes with identical peering but different protocol
		// overhead (hy2 vs SS, say) get the same number if their
		// HTTP path is the same.
		totalDelay = rtt
	} else {
		// User-perceived TTFB through THIS node: cold dial + TLS +
		// first request. What a browser tab experiences on first
		// HTTPS click. dial/TLS overhead matters here — it's the
		// ping that eats real user time.
		totalDelay = tlsDone.Sub(dialStart) + rtt
	}

	t = uint16(totalDelay.Milliseconds())
	// Clamp sub-millisecond measurements to 1 so upstream code that
	// treats 0 as "failed probe" doesn't misread a very-fast result.
	if t == 0 && totalDelay > 0 {
		t = 1
	}
	if detail != nil {
		// FirstByteMS is ALWAYS the pure HTTP round-trip. This is
		// independent of what the headline `t` returned — callers
		// that want the raw protocol-comparable number read this
		// field directly.
		detail.FirstByteMS = rtt.Milliseconds()
		// Kernel TCP counters before the deferred Close invalidates
		// the fd. tcpinfo.Read returns ok=false for proxy wrappers
		// that hide the underlying fd (most of them) and on non-Linux.
		if tinfo, ok := tcpinfo.Read(instance); ok {
			detail.TCPRetransmissions = tinfo.Retransmissions
			detail.TCPLosses = tinfo.Losses
			detail.PathMTU = tinfo.PathMTU
		}
	}
	return
}

// ════════════════ Probe implementation ════════════════

// isGenerate204 reports whether linkURL is a strict generate_204
// endpoint — one that is REQUIRED to return HTTP 204 No Content.
// Used to detect captive-portal / ISP / proxy hijacks that return
// 200/302 with a login page.
//
// The previous check accepted anything containing "204" in host or
// path, which false-positives on hosts like 204.1.2.3 or paths like
// /docs/204-error. The correct criterion is a path that looks like
// Google / Chromium's /generate_204 conventions.
func isGenerate204(u *url.URL) bool {
	if u == nil {
		return false
	}
	p := u.Path
	return p == "/generate_204" || p == "/gen_204" ||
		strings.HasSuffix(p, "/generate_204") ||
		strings.HasSuffix(p, "/gen_204")
}

// probeHTTP performs one HEAD request over conn and returns the
// first-byte RTT. If the server rejects HEAD (405 Method Not
// Allowed, or the response parse indicates a method-specific
// failure), we retry with GET on the SAME connection — most
// servers that reject HEAD accept GET cleanly, so a second round
// trip gives us a valid measurement where otherwise the whole
// probe would fail.
//
// The conn+reader pair is reused across HEAD→GET to measure
// comparable RTT and to avoid re-paying dial/TLS costs on the
// fallback.
func probeHTTP(conn net.Conn, reader *bufio.Reader, linkURL *url.URL, hostname string, peekDeadline time.Time, req204 bool) (time.Duration, error) {
	// Anti-spoofing nonce in the query string defeats aggressive
	// ISP / airport caches that might short-circuit generate_204.
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	nonce := hex.EncodeToString(b)
	q := linkURL.Query()
	q.Set("rnd", nonce)
	linkURL.RawQuery = q.Encode()

	uri := linkURL.RequestURI()
	commonHeaders := "Host: " + hostname + "\r\n" +
		"User-Agent: sing-box\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"

	// Build proper http.Request for ReadResponse's method-awareness
	// (it suppresses body reading on HEAD). We mutate it per retry.
	req, _ := http.NewRequest(http.MethodHead, linkURL.String(), nil)

	// Round 1: HEAD
	rtt, err := measureRequest(conn, reader,
		[]byte("HEAD "+uri+" HTTP/1.1\r\n"+commonHeaders),
		req, peekDeadline, req204)
	if err == nil {
		return rtt, nil
	}

	// HEAD → GET fallback: only retry when the failure looks like a
	// method-restricted endpoint. Transport failures (write error,
	// EOF, timeout) propagate immediately — the conn is already
	// unusable for a second attempt.
	if !isHEADRejected(err) {
		return rtt, err
	}

	// Switch to GET. The conn was killed by Connection: close in
	// round 1, so in practice HEAD→GET can only succeed when the
	// server accepted HEAD but returned 405 — the conn may still be
	// alive. If write/peek fails here we just surface the error.
	req.Method = http.MethodGet
	rtt2, err2 := measureRequest(conn, reader,
		[]byte("GET "+uri+" HTTP/1.1\r\n"+commonHeaders),
		req, peekDeadline, req204)
	if err2 == nil {
		return rtt2, nil
	}
	// Prefer the HEAD-round error for reporting — it's usually more
	// informative (e.g. the actual 405 status).
	return rtt, err
}

// isHEADRejected reports whether err suggests the server refused
// HEAD specifically and a GET retry is worth trying. True for
// explicit 405 responses; false for network / TLS / write errors.
func isHEADRejected(err error) bool {
	if err == nil {
		return false
	}
	if hs, ok := err.(*httpStatusError); ok {
		return hs.code == http.StatusMethodNotAllowed
	}
	return false
}

// measureRequest issues one request and measures the time from
// write-start to the first response byte. Does NOT return until
// the response body has been fully drained (so the conn is reusable
// for a potential retry), but reports the first-byte RTT regardless
// of body outcome.
//
// peekDeadline upper-bounds how long Peek(1) will wait. Callers
// derive it from ctx.Deadline or peekHardLimit.
func measureRequest(conn net.Conn, reader *bufio.Reader, reqBytes []byte, req *http.Request, peekDeadline time.Time, req204 bool) (time.Duration, error) {
	_ = conn.SetReadDeadline(peekDeadline)
	defer conn.SetReadDeadline(time.Time{})

	writeStart := time.Now()
	if _, err := conn.Write(reqBytes); err != nil {
		return 0, err
	}
	// Peek(1) blocks on the first response byte — the measurement
	// boundary for pure HTTP RTT.
	if _, err := reader.Peek(1); err != nil {
		return 0, err
	}
	rtt := time.Since(writeStart)

	// Drain the rest of the response so the connection is in a
	// clean state for any follow-up request (e.g. GET fallback).
	// Even when drainResponse returns an error we've already
	// captured the valid rtt value.
	if err := drainResponse(reader, req, req204); err != nil {
		return rtt, err
	}
	return rtt, nil
}

// drainResponse parses the HTTP response via net/http.ReadResponse
// (handles chunked / close-delimited / content-length all correctly)
// and consumes the body. The bufio stream is left at a clean
// boundary so the caller may issue another request on the same
// connection (keep-alive path).
//
// Why defer to net/http instead of hand-rolling:
//
//   - HTTP/1.1 body termination has three distinct regimes
//     (Content-Length / chunked / connection-close) each with
//     non-trivial edge cases (chunked trailers, 100-continue,
//     transfer-encoding stacks). Hand-rolling drops one and the
//     next keep-alive request reads garbage — particularly lethal
//     for QUIC-single-stream outbounds where the stream can't
//     auto-recover from desync.
//
//   - net/http has had a decade of production scrutiny; the hit
//     on our probe budget is negligible (tens of µs) compared to
//     network RTT.
//
// Memory: on HEAD resp.Body is http.NoBody so io.Copy is a no-op
// that hits WriteTo's zero-alloc fast path. A spec-violating server
// may return actual body bytes on HEAD anyway — we drain up to
// Content-Length from the bufio.Reader so the next request sees a
// clean byte stream, capped at maxResidualBody to avoid
// unbounded-read attacks.
func drainResponse(reader *bufio.Reader, req *http.Request, require204 bool) error {
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return err
	}
	// HEAD responses must not have a body per RFC 7230 §3.3.3, but
	// some proxies send one anyway. Drain Content-Length bytes from
	// the raw reader so keep-alive doesn't desync.
	if cl := resp.ContentLength; cl > 0 {
		if cl > maxResidualBody {
			return errBodyTooLarge
		}
		if _, err = io.CopyN(io.Discard, reader, cl); err != nil {
			return err
		}
	}
	// For GET path (and non-conformant HEAD): Copy returns instantly
	// when Body is http.NoBody; otherwise drains to EOF.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// Captive-portal / hijack detection. /generate_204 that returns
	// anything other than 204 is almost certainly a MITM login page
	// or an ISP's block intercept — callers want this probe to fail
	// so the node gets a dead signal.
	if require204 && resp.StatusCode != 204 {
		return errors.New("urltest: captive-portal or hijack detected (expected 204, got " + strconv.Itoa(resp.StatusCode) + ")")
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
