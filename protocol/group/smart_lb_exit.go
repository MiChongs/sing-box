package group

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/smart"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

// Exit probes: find the country a member actually exits from by fetching an
// IP-echo page through it. Node names lie (relays, mislabelled nodes, names
// without any region), the server address is often a domestic relay, but
// the exit address is what websites see. Cloudflare's trace endpoint
// answers with "ip=…" and "loc=XX" lines; JSON services answering with a
// country field work too, and a bare IP is resolved with the GeoX country
// database.

// exitFailureRetry is how long a failed exit probe is not retried.
const exitFailureRetry = 30 * time.Minute

type exitDetectConfig struct {
	mode        string
	url         string
	ttl         time.Duration
	timeout     time.Duration
	concurrency int
}

type exitGeoEntry struct {
	country string
	ip      string
	at      int64 // unix nano
	failed  bool
}

func newExitDetectConfig(options option.SmartRegionDetectOptions) (exitDetectConfig, error) {
	config := exitDetectConfig{
		url:         options.ExitURL,
		ttl:         time.Duration(options.ExitTTL),
		timeout:     time.Duration(options.ExitTimeout),
		concurrency: options.ExitConcurrency,
	}
	switch strings.ToLower(strings.TrimSpace(options.Exit)) {
	case "", exitDetectFallback, "unknown":
		config.mode = exitDetectFallback
	case exitDetectPrefer, "all", "always":
		config.mode = exitDetectPrefer
	case exitDetectOff, "none", "disabled":
		config.mode = exitDetectOff
	default:
		return config, E.New("unknown region.detect.exit: ", options.Exit)
	}
	if config.url == "" {
		config.url = defaultExitURL
	}
	parsed, err := url.Parse(config.url)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return config, E.New("invalid region.detect.exit_url: ", config.url)
	}
	if config.ttl <= 0 {
		config.ttl = defaultExitTTL
	}
	if config.timeout <= 0 {
		config.timeout = defaultExitTimeout
	}
	if config.concurrency <= 0 {
		config.concurrency = defaultExitConcurrency
	}
	return config, nil
}

// freshExit returns the probed exit country of a member while the result
// is within its TTL.
func (b *smartBalance) freshExit(tag string) (string, bool) {
	if b.exit.mode == exitDetectOff {
		return "", false
	}
	entry, ok := b.exitGeo.Load(tag)
	if !ok || entry.failed || entry.country == "" {
		return "", false
	}
	if time.Now().UnixNano()-entry.at > int64(b.exit.ttl) {
		return "", false
	}
	return entry.country, true
}

// needsExitProbe reports whether a member should be (re-)probed: with
// exit=prefer every member keeps a fresh result, with exit=fallback only
// members their name and the rules could not place.
func (b *smartBalance) needsExitProbe(snap *regionSnapshot, ob adapter.Outbound, force bool) bool {
	if b.exit.mode == exitDetectOff || smartSkipType(ob.Type()) {
		return false
	}
	tag := ob.Tag()
	if force {
		return true
	}
	entry, ok := b.exitGeo.Load(tag)
	now := time.Now().UnixNano()
	if ok {
		if entry.failed && now-entry.at < int64(min(exitFailureRetry, b.exit.ttl)) {
			return false
		}
		if !entry.failed && now-entry.at < int64(b.exit.ttl) {
			return false
		}
	}
	switch b.exit.mode {
	case exitDetectPrefer:
		return snap.sourceOf[tag] != "rule"
	default:
		source := snap.sourceOf[tag]
		return source == "unknown" || source == "exit"
	}
}

// scheduleExitDetection probes, in the background, the members that need
// an exit result. Returns how many probes were started.
func (b *smartBalance) scheduleExitDetection(snap *regionSnapshot, force bool) int {
	if b.exit.mode == exitDetectOff || snap == nil || snap.state == nil || !b.s.started.Load() {
		return 0
	}
	started := 0
	for _, ob := range snap.state.outbounds {
		if ob == nil || !b.needsExitProbe(snap, ob, force) {
			continue
		}
		if _, running := b.exitInflight.LoadOrStore(ob.Tag(), struct{}{}); running {
			continue
		}
		started++
		go b.runExitProbe(ob)
	}
	if started > 0 {
		b.s.logger.Debug("smart-loadbalance[", b.s.Tag(), "] probing the exit of ", started, " member(s)")
	}
	return started
}

func (b *smartBalance) runExitProbe(ob adapter.Outbound) {
	tag := ob.Tag()
	defer b.exitInflight.Delete(tag)
	ctx := b.s.taskCtx
	if ctx == nil {
		ctx = b.s.ctx
	}
	select {
	case b.exitSem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-b.exitSem }()
	if !b.s.started.Load() {
		return
	}
	country, ip, err := b.detectExit(ctx, ob)
	if ctx.Err() != nil || !b.s.started.Load() {
		return
	}
	now := time.Now()
	if err != nil {
		b.exitGeo.Store(tag, exitGeoEntry{at: now.UnixNano(), failed: true})
		b.s.logger.Debug("smart-loadbalance[", b.s.Tag(), "] exit probe [", tag, "] failed: ", err)
		return
	}
	previous, hadPrevious := b.exitGeo.Load(tag)
	b.exitGeo.Store(tag, exitGeoEntry{country: country, ip: ip, at: now.UnixNano()})
	b.persistExitGeo(tag, country, ip, now)
	b.s.logger.Debug("smart-loadbalance[", b.s.Tag(), "] exit of [", tag, "] is ", country, " (", ip, ")")
	if !hadPrevious || previous.country != country {
		b.scheduleRefresh()
	}
}

// detectExit fetches the exit URL through the member and extracts the
// country (and address) of its exit.
func (b *smartBalance) detectExit(ctx context.Context, ob adapter.Outbound) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, b.exit.timeout)
	defer cancel()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return ob.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(address))
		},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: b.exit.timeout,
		TLSClientConfig: &tls.Config{
			Time:    ntp.TimeFuncFromContext(ctx),
			RootCAs: adapter.RootPoolFromContext(ctx),
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: b.exit.timeout}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, b.exit.url, nil)
	if err != nil {
		return "", "", err
	}
	request.Header.Set("User-Agent", "sing-box smart-loadbalance")
	request.Header.Set("Accept", "text/plain, application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", "", err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return "", "", E.New("exit url answered ", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return "", "", err
	}
	country, ip := parseExitResponse(body)
	if country == "" && ip != "" {
		if addr, parseErr := netip.ParseAddr(ip); parseErr == nil {
			country = b.lookupCountry([]netip.Addr{addr})
		}
	}
	if country == "" {
		return "", ip, E.New("no country in the exit url response")
	}
	return country, ip, nil
}

// parseExitResponse extracts the country and IP from a Cloudflare trace
// ("key=value" lines) or a JSON IP-echo answer.
func parseExitResponse(body []byte) (country, ip string) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var fields map[string]any
		if json.Unmarshal(trimmed, &fields) == nil {
			for _, key := range []string{"country_code", "countryCode", "country_iso", "cc", "loc", "country"} {
				if value, ok := fields[key].(string); ok && len(value) == 2 {
					country = strings.ToUpper(value)
					break
				}
			}
			for _, key := range []string{"ip", "query", "ip_addr", "address"} {
				if value, ok := fields[key].(string); ok {
					if _, err := netip.ParseAddr(value); err == nil {
						ip = value
						break
					}
				}
			}
			return
		}
	}
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	for scanner.Scan() {
		key, value, found := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if !found {
			continue
		}
		switch strings.ToLower(key) {
		case "loc":
			if len(value) == 2 && value != "XX" && value != "T1" {
				country = strings.ToUpper(value)
			}
		case "ip":
			ip = value
		}
	}
	if country == "" && ip == "" {
		// Plain-text echo services answer with the bare address.
		if _, err := netip.ParseAddr(string(trimmed)); err == nil {
			ip = string(trimmed)
		}
	}
	return
}

func (b *smartBalance) persistExitGeo(tag, country, ip string, at time.Time) {
	store := b.s.store
	if store == nil {
		return
	}
	data, err := json.Marshal(smart.ExitGeoRecord{Country: country, IP: ip, DetectedAt: at.Unix()})
	if err != nil {
		return
	}
	store.AppendToGlobalQueue(smart.StoreOperation{
		Type:   smart.OpSaveExitGeo,
		Group:  b.s.Tag(),
		Config: smartConfigName,
		Node:   tag,
		Data:   data,
	})
}

// hydrateExitGeo restores persisted exit results that are still fresh.
func (b *smartBalance) hydrateExitGeo() {
	store := b.s.store
	if store == nil {
		return
	}
	rows, err := store.GetSubBytesByPath(smart.FormatDBKey(smart.KeyTypeExitGeo, smartConfigName, b.s.Tag()))
	if err != nil {
		return
	}
	now := time.Now()
	restored := 0
	for key, data := range rows {
		parts := smart.SplitDBKey(key)
		if len(parts) == 0 {
			continue
		}
		tag := parts[len(parts)-1]
		var record smart.ExitGeoRecord
		if json.Unmarshal(data, &record) != nil || record.Country == "" {
			continue
		}
		detected := time.Unix(record.DetectedAt, 0)
		if now.Sub(detected) > b.exit.ttl {
			store.AppendToGlobalQueue(smart.StoreOperation{
				Type:   smart.OpDeleteExitGeo,
				Group:  b.s.Tag(),
				Config: smartConfigName,
				Node:   tag,
			})
			continue
		}
		b.exitGeo.Store(tag, exitGeoEntry{country: strings.ToUpper(record.Country), ip: record.IP, at: detected.UnixNano()})
		restored++
	}
	if restored > 0 {
		b.s.logger.Debug("smart-loadbalance[", b.s.Tag(), "] restored ", restored, " exit result(s)")
	}
}
