package urltest

import (
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
	updateHooks  []*observable.Subscriber[struct{}]
	hookAccess   sync.Mutex
}

func NewHistoryStorage() *HistoryStorage { return &HistoryStorage{} }

func (s *HistoryStorage) AddUpdateHook(hook *observable.Subscriber[struct{}]) {
	s.hookAccess.Lock()
	defer s.hookAccess.Unlock()
	s.updateHooks = append(s.updateHooks, hook)
}

func (s *HistoryStorage) NotifyUpdated() {
	s.hookAccess.Lock()
	hooks := s.updateHooks
	s.hookAccess.Unlock()
	for _, h := range hooks {
		h.Emit(struct{}{})
	}
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
	hooks := s.updateHooks
	s.hookAccess.Unlock()
	for _, h := range hooks {
		h.Emit(struct{}{})
	}
}

func (s *HistoryStorage) Close() error {
	s.hookAccess.Lock()
	s.updateHooks = nil
	s.hookAccess.Unlock()
	return nil
}

// ════════════════ TLS session cache ════════════════

// sessionCache wraps a tls.ClientSessionCache with a last-access timestamp
// for LRU eviction. The cache itself is goroutine-safe (stdlib guarantee).
type sessionCache struct {
	cache      tls.ClientSessionCache
	lastAccess atomic.Int64 // UnixNano
}

func (s *sessionCache) touch() {
	s.lastAccess.Store(time.Now().UnixNano())
}

const (
	sessionCacheMaxEntries = 256
	sessionCacheExpiry     = 30 * time.Minute
)

var sessionCaches sync.Map // hostname → *sessionCache

func sessionCacheFor(hostname string) tls.ClientSessionCache {
	if v, ok := sessionCaches.Load(hostname); ok {
		sc := v.(*sessionCache)
		sc.touch()
		return sc.cache
	}
	sc := &sessionCache{cache: tls.NewLRUClientSessionCache(8)}
	sc.touch()
	if actual, loaded := sessionCaches.LoadOrStore(hostname, sc); loaded {
		return actual.(*sessionCache).cache
	}
	return sc.cache
}

// PruneSessionCaches removes entries not accessed within sessionCacheExpiry
// and caps the total at sessionCacheMaxEntries. Called from group Close()
// or periodically by long-lived services.
func PruneSessionCaches() {
	now := time.Now().UnixNano()
	cutoff := now - int64(sessionCacheExpiry)
	var count int
	sessionCaches.Range(func(key, value any) bool {
		count++
		sc := value.(*sessionCache)
		if sc.lastAccess.Load() < cutoff {
			sessionCaches.Delete(key)
			count--
		}
		return true
	})
	if count > sessionCacheMaxEntries {
		oldest := now
		var oldestKey any
		sessionCaches.Range(func(key, value any) bool {
			sc := value.(*sessionCache)
			if t := sc.lastAccess.Load(); t < oldest {
				oldest = t
				oldestKey = key
			}
			return true
		})
		if oldestKey != nil {
			sessionCaches.Delete(oldestKey)
		}
	}
}

// ════════════════ URLTestDetail ════════════════

// URLTestDetail captures per-phase timings for callers that need them
// (Smart group's recordStats, LightGBM feature extractor, sticky-session
// signal). All fields measure pure phase duration, never cumulative.
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

func URLTest(ctx context.Context, link string, detour N.Dialer) (t uint16, err error) {
	return URLTestWithDetailAndStatus(ctx, link, detour, nil, nil)
}

func URLTestWithStatus(ctx context.Context, link string, detour N.Dialer, matcher *StatusMatcher) (t uint16, err error) {
	return URLTestWithDetailAndStatus(ctx, link, detour, nil, matcher)
}

func URLTestWithDetail(ctx context.Context, link string, detour N.Dialer, detail *URLTestDetail) (t uint16, err error) {
	return URLTestWithDetailAndStatus(ctx, link, detour, detail, nil)
}

// URLTestWithDetailAndStatus is the canonical probe entry point.
//
// Design: dial the proxy once, hand the conn to net/http.Transport for
// HTTP/1.1 request/response. This works across all protocols (TCP, QUIC
// streams, WireGuard/gVisor netstack, Tailscale, Shadowsocks+plugins)
// because they all return net.Conn-compatible objects.
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
	// Ensure conn is always closed. Transport.CloseIdleConnections releases
	// the Transport's reference first (defer is LIFO), then we close the
	// underlying conn.
	defer instance.Close()
	if detail != nil {
		detail.TCPConnectMS = time.Since(dialStart).Milliseconds()
	}

	// ── Phase 2: build single-shot http.Transport over the proxy conn ──
	var dialed atomic.Bool
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			if !dialed.CompareAndSwap(false, true) {
				return nil, errors.New("urltest: conn already consumed; no redial")
			}
			return instance, nil
		},
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   C.TCPTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
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
	if t == 0 && totalDelay > 0 {
		t = 1
	}

	if detail != nil {
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

// ════════════════ Status validation ════════════════

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

func isGenerate204(u *url.URL) bool {
	if u == nil {
		return false
	}
	p := u.Path
	return p == "/generate_204" || p == "/gen_204" ||
		strings.HasSuffix(p, "/generate_204") ||
		strings.HasSuffix(p, "/gen_204")
}

// ════════════════ httptrace plumbing ════════════════

// probeTrace records per-request phase timestamps via httptrace. The
// callbacks may fire from different goroutines (httptrace docs), so
// timestamps are stored as atomic values. After client.Do returns,
// all callbacks have completed — reads are safe without extra sync.
type probeTrace struct {
	tlsStartNS  atomic.Int64
	tlsDoneNS   atomic.Int64
	wroteAtNS   atomic.Int64
	firstByteNS atomic.Int64
	resume      atomic.Bool
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

// ════════════════ Error types ════════════════

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string {
	return "HTTP " + string([]byte{
		byte(e.code/100) + '0',
		byte((e.code/10)%10) + '0',
		byte(e.code%10) + '0',
	})
}

func IsHEADRejected(err error) bool {
	if err == nil {
		return false
	}
	if hs, ok := err.(*httpStatusError); ok {
		return hs.code == http.StatusMethodNotAllowed
	}
	return false
}
