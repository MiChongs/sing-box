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

	"github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart/tcpinfo"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-mux"
	"github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/observable"
)

// DefaultLink is probed when no URL is configured.
const DefaultLink = "https://www.gstatic.com/generate_204"

type unifiedDelayKey struct{}

// ContextWithUnifiedDelay binds the measurement policy to one instance or request.
func ContextWithUnifiedDelay(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, unifiedDelayKey{}, enabled)
}

func UnifiedDelayFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	enabled, _ := ctx.Value(unifiedDelayKey{}).(bool)
	return enabled
}

// ════════════════ HistoryStorage ════════════════

var _ adapter.URLTestHistoryStorage = (*HistoryStorage)(nil)

type HistoryStorage struct {
	delayHistory sync.Map
	updateHooks  []*observable.Subscriber[struct{}]
	hookAccess   sync.Mutex

	notifyAccess  sync.Mutex
	notifyPending bool
	lastNotify    time.Time

	prober Prober
}

// historyNotifyInterval coalesces store/delete notifications: a health
// check stores one result per member, and every notification makes the
// subscribers (reference tracking, dashboard pushes) walk all outbounds.
const historyNotifyInterval = 200 * time.Millisecond

func NewHistoryStorage() *HistoryStorage { return &HistoryStorage{} }

// Prober shares probes between everything measuring through this storage.
func (s *HistoryStorage) Prober() *Prober {
	return &s.prober
}

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

// notifyUpdated emits right away when the last emission is older than
// historyNotifyInterval, and otherwise schedules a single trailing emission.
func (s *HistoryStorage) notifyUpdated() {
	s.notifyAccess.Lock()
	if s.notifyPending {
		s.notifyAccess.Unlock()
		return
	}
	wait := historyNotifyInterval - time.Since(s.lastNotify)
	if wait <= 0 {
		s.lastNotify = time.Now()
		s.notifyAccess.Unlock()
		s.NotifyUpdated()
		return
	}
	s.notifyPending = true
	s.notifyAccess.Unlock()
	time.AfterFunc(wait, func() {
		s.notifyAccess.Lock()
		s.notifyPending = false
		s.lastNotify = time.Now()
		s.notifyAccess.Unlock()
		s.NotifyUpdated()
	})
}

func (s *HistoryStorage) Close() error {
	s.hookAccess.Lock()
	s.updateHooks = nil
	s.hookAccess.Unlock()
	return nil
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

// URLTestWithDetailAndStatus measures link through detour over a single
// proxy connection.
//
// Without unified delay the delay covers the whole cold path: dialing the
// proxy, its handshake, TLS to the test server and the request. With
// unified delay a second request is sent on the established connection
// and only that round trip counts, which is comparable across protocols.
//
// Multiplexed outbounds open their session with a warm-up request first,
// so the cold path measures a new stream on an established session like
// real connections see. Unified delay already excludes the session
// handshake and skips the warm-up.
func URLTestWithDetailAndStatus(ctx context.Context, link string, detour N.Dialer, detail *URLTestDetail, matcher *StatusMatcher) (uint16, error) {
	target, err := parseLink(link)
	if err != nil {
		return 0, err
	}
	unified := UnifiedDelayFromContext(ctx)
	if !unified {
		multiplexOutbound, isMultiplexOutbound := common.Cast[adapter.OutboundWithMultiplex](detour)
		if isMultiplexOutbound && multiplexOutbound.MultiplexEnabled() {
			_, err = urlTest(contextWithKeepSession(ctx), target, detour, nil, matcher, false)
			if err != nil {
				return 0, err
			}
		}
	}
	return urlTest(ctx, target, detour, detail, matcher, unified)
}

func contextWithKeepSession(ctx context.Context) context.Context {
	ctx = adapter.ContextWithKeepSession(ctx)
	ctx = mux.ContextWithKeepSession(ctx)
	ctx = anytls.ContextWithKeepSession(ctx)
	ctx = contextWithQUICKeepSession(ctx)
	return snell.ContextWithKeepSession(ctx)
}

// ════════════════ Probe ════════════════

type probeTarget struct {
	link        string
	url         *url.URL
	destination M.Socksaddr
}

func parseLink(link string) (*probeTarget, error) {
	if link == "" {
		link = DefaultLink
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	port := linkURL.Port()
	switch linkURL.Scheme {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
	default:
		return nil, E.New("unsupported scheme: ", linkURL.Scheme)
	}
	return &probeTarget{
		link:        link,
		url:         linkURL,
		destination: M.ParseSocksaddrHostPortStr(linkURL.Hostname(), port),
	}, nil
}

// probeSessionCache lets probes resume TLS sessions. A TLS 1.3 resumption
// takes the same round trips as a full handshake, so delays stay
// comparable, but the certificate chain is neither sent nor verified.
var probeSessionCache = tls.NewLRUClientSessionCache(64)

var errConnConsumed = errors.New("urltest: probe connection already used")

// urlTest dials the proxy once and runs the requests over that connection
// with net/http, which works on every protocol returning a net.Conn (TCP,
// QUIC streams, netstack, plugins).
func urlTest(ctx context.Context, target *probeTarget, detour N.Dialer, detail *URLTestDetail, matcher *StatusMatcher, unified bool) (uint16, error) {
	dialStart := time.Now()
	conn, err := detour.DialContext(ctx, N.NetworkTCP, target.destination)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if detail != nil {
		detail.TCPConnectMS = time.Since(dialStart).Milliseconds()
	}

	var dialed atomic.Bool
	transport := &http.Transport{
		// Never redial: a second connection would go through the proxy
		// handshake again and distort the measurement.
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if !dialed.CompareAndSwap(false, true) {
				return nil, errConnConsumed
			}
			return conn, nil
		},
		TLSClientConfig: &tls.Config{
			ServerName:         target.url.Hostname(),
			Time:               ntp.TimeFuncFromContext(ctx),
			RootCAs:            adapter.RootPoolFromContext(ctx),
			ClientSessionCache: probeSessionCache,
			NextProtos:         []string{"http/1.1"},
		},
		TLSHandshakeTimeout:    C.TCPTimeout,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, target.link, nil)
	if err != nil {
		return 0, err
	}

	first := new(probeTrace)
	end, err := roundTrip(client, request, first, target.url, matcher)
	if err != nil {
		return 0, err
	}
	start, headline := dialStart, first
	if unified {
		second := new(probeTrace)
		secondStart := time.Now()
		// A server closing the connection after the first response leaves
		// the cold measurement in place.
		if secondEnd, secondErr := roundTrip(client, request, second, target.url, matcher); secondErr == nil {
			start, end, headline = secondStart, secondEnd, second
		}
	}

	delay := end.Sub(start)
	t := uint16(min(delay.Milliseconds(), int64(^uint16(0))))
	if t == 0 && delay > 0 {
		t = 1
	}
	if detail != nil {
		detail.TLSHandshakeMS = first.tlsMS()
		detail.DidResume = first.didResume()
		detail.FirstByteMS = headline.firstByteMS()
		if info, loaded := tcpinfo.Read(conn); loaded {
			detail.TCPRetransmissions = info.Retransmissions
			detail.TCPLosses = info.Losses
			detail.PathMTU = info.PathMTU
		}
	}
	return t, nil
}

// roundTrip sends request and returns when the response headers arrived.
func roundTrip(client *http.Client, request *http.Request, trace *probeTrace, linkURL *url.URL, matcher *StatusMatcher) (time.Time, error) {
	response, err := client.Do(request.WithContext(httptrace.WithClientTrace(request.Context(), trace.hooks())))
	if err != nil {
		return time.Time{}, err
	}
	end := time.Now()
	// HEAD responses carry no body; drain defensively so the connection
	// can serve the unified delay request.
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
	return end, validateStatus(response.StatusCode, linkURL, matcher)
}

// ════════════════ Status validation ════════════════

// validateStatus applies matcher, or without one requires 204 from
// generate_204 endpoints (anything else is a captive portal or hijack)
// and a non-error status elsewhere.
func validateStatus(code int, linkURL *url.URL, matcher *StatusMatcher) error {
	if matcher != nil {
		if matcher.Match(code) {
			return nil
		}
		return errors.New("urltest: status " + strconv.Itoa(code) +
			" not in expected-status=" + matcher.String())
	}
	if isGenerate204(linkURL) && code != http.StatusNoContent {
		return errors.New("urltest: captive-portal or hijack detected (expected 204, got " + strconv.Itoa(code) + ")")
	}
	if code >= 400 {
		return E.New("urltest: HTTP ", code)
	}
	return nil
}

func isGenerate204(u *url.URL) bool {
	if u == nil {
		return false
	}
	return strings.HasSuffix(u.Path, "/generate_204") || strings.HasSuffix(u.Path, "/gen_204")
}

// ════════════════ httptrace plumbing ════════════════

// probeTrace records per-request phase timestamps via httptrace. The
// callbacks may fire from different goroutines, so timestamps are atomic;
// once client.Do returns every callback has completed.
type probeTrace struct {
	tlsStartNS  atomic.Int64
	tlsDoneNS   atomic.Int64
	wroteAtNS   atomic.Int64
	firstByteNS atomic.Int64
	resume      atomic.Bool
}

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
