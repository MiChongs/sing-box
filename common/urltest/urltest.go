package urltest

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart/tcpinfo"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
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

// ════════════════ TLS session cache ════════════════

// sessionCacheFor returns a per-hostname tls.ClientSessionCache so probes
// of the same SNI can resume across invocations. Different SNIs get distinct
// caches so tickets don't cross-contaminate. Size 8 is enough — only the
// most recent ticket matters for resumption.
var (
	sessionCacheMu     sync.Mutex
	sessionCacheByHost = make(map[string]tls.ClientSessionCache)
)

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

// ════════════════ URLTestDetail ════════════════

// URLTestDetail captures per-phase timings for callers that need them
// (Smart group's recordStats, LightGBM feature extractor, sticky-session
// signal). All fields measure pure phase duration, never cumulative:
//
//	TCPConnectMS   — time inside detour.DialContext. For proxy chains
//	                 this is "TCP to edge + proxy handshake" since the
//	                 inner proxy handshake blocks DialContext until the
//	                 tunnel is up. TLS is NOT included.
//	TLSHandshakeMS — TLS handshake wall time (read from httptrace).
//	                 0 for http://, 0 for failed handshakes, 0 when the
//	                 second (warm) request is the headline since that
//	                 request reuses the conn.
//	FirstByteMS    — write_request_done → first response byte. Pure
//	                 HTTP RTT, no handshake artefacts.
//	DidResume      — TLS resumption flag from the handshake. Probes of
//	                 the same SNI benefit from sessionCacheFor and will
//	                 normally resume on the second probe onwards.
//	DNSResolveMS   — reserved (always 0 here): proxy chains resolve
//	                 internally; if we ever own DNS we'll fill this.
//	TCPRetransmissions / TCPLosses / PathMTU — kernel counters via
//	                 tcpinfo. Linux + direct-fd only; 0 on other
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

// ════════════════ Public API ════════════════

// URLTest probes link through detour and returns the headline delay in
// milliseconds. The number respects C.URLTestUnifiedDelay:
//
//   - unified_delay = false → cold-conn TTFB (dial + TLS + first byte).
//     What a browser tab feels on the very first click through this node.
//   - unified_delay = true  → warm-conn HTTP RTT measured via a second
//     request on the keep-alive pool, mirroring mihomo's behaviour. This
//     drops handshake overhead, giving a cross-protocol-comparable number.
//
// API kept stable for compatibility — every previous caller still works.
func URLTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	return URLTestWithDetailAndStatus(ctx, link, detour, nil, nil)
}

// URLTestWithStatus accepts an explicit StatusMatcher (mihomo
// expected-status). matcher == nil reverts to the legacy heuristic:
// strict 204 for /generate_204 endpoints, < 400 elsewhere.
func URLTestWithStatus(ctx context.Context, link string, detour N.Dialer, matcher *StatusMatcher) (t uint16, err error) {
	return URLTestWithDetailAndStatus(ctx, link, detour, nil, matcher)
}

// URLTestWithDetail captures per-phase timings into detail (when non-nil).
// matcher stays at the legacy heuristic.
func URLTestWithDetail(ctx context.Context, link string, detour N.Dialer, detail *URLTestDetail) (t uint16, err error) {
	return URLTestWithDetailAndStatus(ctx, link, detour, detail, nil)
}

// URLTestWithDetailAndStatus is the canonical probe — every other entry
// point delegates here.
//
// Implementation notes (and the reason this looks like mihomo):
//
// The previous probe wrote raw HTTP/1.1 over a hand-rolled bufio reader
// stacked on top of `tls.Client(instance, ...)`. That worked for plain
// TCP-style outbounds but fell over for QUIC-stream proxies (hysteria2,
// tuic): a fresh stream per probe can't be cleanly torn down without
// triggering server-side stream-error handling, and the raw `Connection:
// close` request frame couldn't survive the QUIC half-close semantics on
// real-world deployments.
//
// The fix mirrors mihomo: dial the proxy once, hand the resulting net.Conn
// back to a stdlib `net/http.Transport`. The Transport speaks HTTP/1.1
// over the proxy stream, manages keep-alive idempotently, and does not
// care that the underlying conn is a QUIC stream. As a side effect, we
// also get the canonical mihomo `unified_delay` semantics (warm-conn
// second request) for free.
func URLTestWithDetailAndStatus(ctx context.Context, link string, detour N.Dialer, detail *URLTestDetail, matcher *StatusMatcher) (t uint16, err error) {
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
		default:
			return 0, E.New("unsupported scheme: ", linkURL.Scheme)
		}
	}

	// ── Phase 1: dial through proxy ──
	dialStart := time.Now()
	instance, dialErr := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if dialErr != nil {
		return 0, dialErr
	}
	defer instance.Close()
	if detail != nil {
		detail.TCPConnectMS = time.Since(dialStart).Milliseconds()
	}

	// ── Phase 2: build a single-shot http.Transport over the proxy conn ──
	// Transport.DialContext returns `instance` on the first call only.
	// Subsequent calls (which only happen if the conn dies and Transport
	// tries to reopen) get an error to break a redial loop — we already
	// committed the per-probe instance and a fresh dial would burn another
	// proxy handshake without the caller knowing.
	var dialed atomic.Bool
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			if !dialed.CompareAndSwap(false, true) {
				return nil, errors.New("urltest: only one dial allowed per probe")
			}
			return instance, nil
		},
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// http/1.1 only — h2 can multiplex streams which doesn't compose
		// with a per-probe single net.Conn handed back from DialContext.
		ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{
			ServerName:         hostname,
			Time:               ntp.TimeFuncFromContext(ctx),
			RootCAs:            adapter.RootPoolFromContext(ctx),
			ClientSessionCache: sessionCacheFor(hostname),
			NextProtos:         []string{"http/1.1"},
		},
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	baseReq, err := http.NewRequest(http.MethodHead, link, nil)
	if err != nil {
		return 0, err
	}

	// ── Phase 3: first request (cold conn) ──
	probe1 := newProbeTrace()
	resp, err := client.Do(baseReq.WithContext(httptrace.WithClientTrace(ctx, probe1.hooks())))
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if statusErr := validateStatus(resp.StatusCode, linkURL, matcher); statusErr != nil {
		return 0, statusErr
	}

	// `start` is what the headline delay is measured from. unified_delay
	// = false keeps it at dialStart, so the headline includes the full
	// cold-conn TTFB. unified_delay = true reassigns it to "just before
	// the warm second request" if that request succeeds, mirroring
	// mihomo's measurement boundary.
	start := dialStart
	firstByteMS := probe1.firstByteMS()

	// ── Phase 4 (optional): warm-conn second request for unified_delay ──
	if C.URLTestUnifiedDelay {
		probe2 := newProbeTrace()
		second := time.Now()
		secondResp, ignoredErr := client.Do(baseReq.WithContext(httptrace.WithClientTrace(ctx, probe2.hooks())))
		if ignoredErr == nil {
			_, _ = io.Copy(io.Discard, secondResp.Body)
			_ = secondResp.Body.Close()
			if validateStatus(secondResp.StatusCode, linkURL, matcher) == nil {
				start = second
				firstByteMS = probe2.firstByteMS()
			}
		}
	}

	totalDelay := time.Since(start)
	t = uint16(totalDelay.Milliseconds())
	// Sub-ms RTTs collapse to 1; upstream code treats 0 as "failed probe".
	if t == 0 && totalDelay > 0 {
		t = 1
	}

	if detail != nil {
		// TLS metrics always come from the cold probe — the warm request
		// reuses the conn so it has no handshake of its own.
		detail.TLSHandshakeMS = probe1.tlsMS()
		detail.DidResume = probe1.didResume()
		detail.FirstByteMS = firstByteMS
		if tinfo, ok := tcpinfo.Read(instance); ok {
			detail.TCPRetransmissions = tinfo.Retransmissions
			detail.TCPLosses = tinfo.Losses
			detail.PathMTU = tinfo.PathMTU
		}
	}
	return
}

// validateStatus mirrors drainResponse's status-decision logic for the
// http.Client probe path:
//
//   - matcher != nil  → matcher decides; bypasses the captive-portal
//                       and < 400 heuristic entirely.
//   - matcher == nil  → strict 204 on /generate_204 endpoints (so a
//                       captive-portal login page returning 200 fails),
//                       otherwise < 400 passes, ≥ 400 fails.
func validateStatus(code int, linkURL *url.URL, matcher *StatusMatcher) error {
	if matcher != nil {
		if matcher.Match(code) {
			return nil
		}
		return errors.New("urltest: status " + strconv.Itoa(code) +
			" not in expected-status=" + matcher.String())
	}
	if isGenerate204(linkURL) && code != 204 {
		return errors.New("urltest: captive-portal or hijack detected (expected 204, got " + strconv.Itoa(code) + ")")
	}
	if code >= 400 {
		return &httpStatusError{code: code}
	}
	return nil
}

// ════════════════ httptrace plumbing ════════════════

// probeTrace records per-request phase timestamps via httptrace. The
// callbacks may fire from different goroutines (httptrace docs), so
// timestamps are stored as atomic UnixNano values and the resume flag
// as atomic.Bool. After client.Do returns, every callback for THIS
// request has either fired or never will, so the read side is safe.
type probeTrace struct {
	tlsStartNS   atomic.Int64
	tlsDoneNS    atomic.Int64
	wroteAtNS    atomic.Int64
	firstByteNS  atomic.Int64
	resume       atomic.Bool
}

func newProbeTrace() *probeTrace { return &probeTrace{} }

func (p *probeTrace) hooks() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			p.tlsStartNS.Store(time.Now().UnixNano())
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err != nil {
				return
			}
			p.tlsDoneNS.Store(time.Now().UnixNano())
			if state.DidResume {
				p.resume.Store(true)
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				p.wroteAtNS.Store(time.Now().UnixNano())
			}
		},
		GotFirstResponseByte: func() {
			p.firstByteNS.Store(time.Now().UnixNano())
		},
	}
}

func (p *probeTrace) tlsMS() int64 {
	start, done := p.tlsStartNS.Load(), p.tlsDoneNS.Load()
	if start == 0 || done <= start {
		return 0
	}
	return (done - start) / int64(time.Millisecond)
}

func (p *probeTrace) firstByteMS() int64 {
	wrote, first := p.wroteAtNS.Load(), p.firstByteNS.Load()
	if wrote == 0 || first <= wrote {
		return 0
	}
	return (first - wrote) / int64(time.Millisecond)
}

func (p *probeTrace) didResume() bool { return p.resume.Load() }

// ════════════════ Legacy helpers (retained for tests + status logic) ════════════════
//
// drainResponse / measureRequest / probeHTTP / readerPool / etc. are kept
// for two reasons:
//
//   1. drainResponse encodes the matcher + require-204 + < 400 status
//      decision tree; the bench/integration tests pin its behaviour and
//      double as documentation for what "valid response" means.
//   2. The bufio.Reader pool, residual-body cap, and Peek-deadline guards
//      are cheap defensive utilities. Even though the http.Client probe
//      path doesn't use them, leaving the helpers in place means future
//      raw-conn callers (e.g. a fast-path probe gated to plain TCP
//      proxies) can reach for them without re-deriving the rules.

const (
	// bufioSize sized so HEAD response headers fit comfortably.
	// generate_204 ≈ 400B; 2KB is headroom without bloating the pool
	// (100 concurrent probes ≈ 200KB resident).
	bufioSize = 2048

	// maxResidualBody caps how many bytes drainResponse will pull from
	// a spec-violating HEAD+body response before giving up.
	maxResidualBody = 64 * 1024
)

var readerPool = sync.Pool{
	New: func() any { return bufio.NewReaderSize(nil, bufioSize) },
}

var errBodyTooLarge = errors.New("urltest: response body exceeds safety limit")

// isGenerate204 reports whether linkURL is a strict generate_204 endpoint
// (one that REQUIRES HTTP 204). Used to detect captive-portal / ISP /
// proxy hijacks that return 200/302 with a login page. The check pins the
// path to canonical Google / Chromium conventions — checking "204" as a
// substring false-positives on hosts like 204.1.2.3 or paths like
// /docs/204-error.
func isGenerate204(u *url.URL) bool {
	if u == nil {
		return false
	}
	p := u.Path
	return p == "/generate_204" || p == "/gen_204" ||
		strings.HasSuffix(p, "/generate_204") ||
		strings.HasSuffix(p, "/gen_204")
}

// measureRequest / drainResponse / isHEADRejected / httpStatusError remain
// for the test surface and for any future raw-conn caller. They are NOT
// exercised by URLTestWithDetailAndStatus.

func isHEADRejected(err error) bool {
	if err == nil {
		return false
	}
	if hs, ok := err.(*httpStatusError); ok {
		return hs.code == http.StatusMethodNotAllowed
	}
	return false
}

func measureRequest(conn net.Conn, reader *bufio.Reader, reqBytes []byte, req *http.Request, peekDeadline time.Time, req204 bool, matcher *StatusMatcher) (time.Duration, error) {
	_ = conn.SetReadDeadline(peekDeadline)
	defer conn.SetReadDeadline(time.Time{})

	writeStart := time.Now()
	if _, err := conn.Write(reqBytes); err != nil {
		return 0, err
	}
	if _, err := reader.Peek(1); err != nil {
		return 0, err
	}
	rtt := time.Since(writeStart)
	if err := drainResponse(reader, req, req204, matcher); err != nil {
		return rtt, err
	}
	return rtt, nil
}

func drainResponse(reader *bufio.Reader, req *http.Request, require204 bool, matcher *StatusMatcher) error {
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return err
	}
	if cl := resp.ContentLength; cl > 0 {
		if cl > maxResidualBody {
			return errBodyTooLarge
		}
		if _, err = io.CopyN(io.Discard, reader, cl); err != nil {
			return err
		}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if matcher != nil {
		if matcher.Match(resp.StatusCode) {
			return nil
		}
		return errors.New("urltest: status " + strconv.Itoa(resp.StatusCode) +
			" not in expected-status=" + matcher.String())
	}
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
