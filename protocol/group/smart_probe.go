package group

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

const smartProbeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

// smartProber issues the group's HTTP probes through one member: the
// response probe of a target (robots.txt), and the exit traces that tell
// where the member's traffic lands.
type smartProber struct {
	s      *Smart
	member adapter.Outbound
}

var (
	_ smart.StatusProber     = smartProber{}
	_ smart.ExitProber       = smartProber{}
	_ smart.TargetExitProber = smartProber{}
)

func (p smartProber) request(ctx context.Context, rawURL string, checkRedirect func(*http.Request, []*http.Request) error) (*http.Response, *http.Transport, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return p.member.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(address))
		},
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			Time:       ntp.TimeFuncFromContext(p.s.ctx),
			RootCAs:    adapter.RootPoolFromContext(p.s.ctx),
			NextProtos: []string{"http/1.1"},
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return checkRedirect(req, via)
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("User-Agent", smartProbeUserAgent)
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	request.Header.Set("Accept-Language", "en-US,en;q=0.9")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, err
	}
	return response, transport, nil
}

// StatusProbe fetches rawURL through the member; a redirect to another
// host is left for the classifier.
func (p smartProber) StatusProbe(ctx context.Context, rawURL string) (*smart.ProbeResult, error) {
	response, transport, err := p.request(ctx, rawURL, func(req *http.Request, via []*http.Request) error {
		if !smartSameHostPort(req.URL, via[0].URL) {
			return http.ErrUseLastResponse
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	defer transport.CloseIdleConnections()
	defer response.Body.Close()
	return &smart.ProbeResult{
		StatusCode: response.StatusCode,
		Header:     response.Header,
		Body:       smartBodySnippet(response.Body, smart.ProbeBodyLimit, smart.ProbeBodyWait),
	}, nil
}

// smartBodySnippet never drains a streaming body; closing it releases the
// read.
func smartBodySnippet(body io.Reader, limit int, wait time.Duration) []byte {
	snippet := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(io.LimitReader(body, int64(limit)))
		snippet <- data
	}()
	select {
	case data := <-snippet:
		return data
	case <-time.After(wait):
		return nil
	}
}

// ExitProbe asks the trace endpoints through the member where its traffic
// lands; the address only serves the ASN lookup.
func (p smartProber) ExitProbe(ctx context.Context, wantASN bool) (*smart.ExitProbeResult, error) {
	var lastErr error
	for _, rawURL := range smart.ExitTraceURLs {
		if ctx.Err() != nil {
			break
		}
		result, err := p.exitProbe(ctx, rawURL, wantASN, false)
		if err == nil {
			return result, nil
		}
		lastErr = fmt.Errorf("%s: %w", rawURL, err)
	}
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return nil, lastErr
}

// TargetExitProbe asks the target site's own Cloudflare trace where the
// member lands for it.
func (p smartProber) TargetExitProbe(ctx context.Context, host string, wantASN bool) (*smart.ExitProbeResult, error) {
	if host == "" {
		return nil, errors.New("empty target host")
	}
	return p.exitProbe(ctx, "https://"+host+"/cdn-cgi/trace", wantASN, true)
}

func (p smartProber) exitProbe(ctx context.Context, rawURL string, wantASN, followOffHost bool) (*smart.ExitProbeResult, error) {
	response, transport, err := p.request(ctx, rawURL, func(req *http.Request, via []*http.Request) error {
		if smartSameHostPort(req.URL, via[len(via)-1].URL) || (followOffHost && len(via) == 1) {
			return nil
		}
		return http.ErrUseLastResponse
	})
	if err != nil {
		return nil, err
	}
	defer transport.CloseIdleConnections()
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &smart.TraceUnanswerableError{Reason: fmt.Sprintf("exit trace answered %d", response.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, smart.ExitProbeBodyLimit))
	if err != nil {
		return nil, err
	}
	region, ip := smart.ParseExitAnswer(body)
	if region == "" {
		return nil, &smart.TraceUnanswerableError{Reason: "exit trace has no region"}
	}
	result := &smart.ExitProbeResult{Region: region}
	if ip.IsValid() {
		result.Key = smart.ExitKey(ip)
		if wantASN {
			result.ASN, _ = p.s.keys.lookupASN(p.s, []netip.Addr{ip})
		}
	}
	return result, nil
}

// smartSameHostPort ignores an explicit default port.
func smartSameHostPort(a, b *url.URL) bool {
	normalize := func(u *url.URL) string {
		port := u.Port()
		if port == "" || (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
			return u.Hostname()
		}
		return net.JoinHostPort(u.Hostname(), port)
	}
	return strings.EqualFold(normalize(a), normalize(b))
}

// probeVerdict runs a response probe of host through the member.
func (s *Smart) probeVerdict(member adapter.Outbound, host string) smart.Verdict {
	ctx, cancel := context.WithTimeout(s.taskContext(), smart.ProbeTimeout)
	defer cancel()
	result, err := smartProber{s, member}.StatusProbe(ctx, smart.ProbeURL(host))
	if err != nil {
		return smart.ClassifyProbeError(err)
	}
	return smart.ClassifyResponse(result.StatusCode, result.Header, result.Body, time.Now())
}

func (s *Smart) taskContext() context.Context {
	if s.taskCtx != nil {
		return s.taskCtx
	}
	return s.ctx
}

// probeSNIOnce measures a TLS handshake with host through the member (the
// smart-loadbalance region probe).
func (s *Smart) probeSNIOnce(ctx context.Context, address string, member adapter.Outbound) (int32, error) {
	destination := M.ParseSocksaddr(address)
	start := time.Now()
	conn, err := member.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: destination.AddrString(),
		Time:       ntp.TimeFuncFromContext(s.ctx),
		RootCAs:    adapter.RootPoolFromContext(s.ctx),
	})
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		return 0, err
	}
	return int32(time.Since(start).Milliseconds()), nil
}
