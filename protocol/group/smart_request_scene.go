package group

import (
	"sort"
	"strings"

	"github.com/sagernet/sing-box/adapter"
)

// Request-level scene inference.
//
// weight.go's identifyConnectionScene classifies by HISTORICAL traffic
// shape on a given (target, node) pair — "over the last few minutes,
// connections to this target looked like streaming". That's the right
// input for the Ranking weight that feeds prefetch / pre-computed
// selection orders: it reflects what a node HAS been good at.
//
// But when the user actually clicks YouTube, the dial path knows at
// ctx-time: the SNI is `www.youtube.com`, port is 443, TCP. That's
// enough to say "this specific request IS streaming" WITHOUT waiting
// for N bytes of history to accumulate. This file provides that
// request-level classifier. The returned scene name aligns with
// weight.go's buckets ("streaming" / "transfer" / "realtime" / "voip"
// / "interactive" / "api" / "web") so downstream code can reuse the
// same multiplier tables.
//
// Classification is purely heuristic — we don't reach into TLS or do
// DPI. The ingredients are:
//
//   - Host: sing-box's sniff layer populates metadata.Host when the
//     client sent SNI / HTTP Host / QUIC SNI, which is the common case
//     for 443/80 traffic. Domain-name keyword matching is cheap and
//     covers the vast majority of traffic by a small keyword set.
//
//   - Port: port alone is a weak signal (443 is everything on the
//     modern web), but certain ports are unambiguous — SSH/22, DNS/53,
//     SMTP/25 — and they bypass keyword matching.
//
//   - isUDP: narrows streaming-vs-realtime (UDP+443 is likely QUIC,
//     could be video or game; without other signals we bias to
//     "realtime" only when we see a known game port range).
//
// Unknown → "" (empty). Callers treat empty as "fall through to
// historical scene" which keeps behaviour identical to pre-feature
// when classification is uncertain.

// classifyRequestScene returns the most likely scene bucket for a
// just-received request. Returns "" when no reliable signal is
// available — the caller should NOT substitute "web" here; an empty
// result means "defer to historical classification", letting the
// pre-existing weight store decide.
func classifyRequestScene(host string, destPort uint16, isUDP bool) string {
	// Port-based unambiguous classifications come first — a known
	// protocol port is a stronger signal than a keyword match, and
	// lets us short-circuit keyword table lookups for infra traffic.
	switch destPort {
	case 22, 2222: // SSH
		return "interactive"
	case 23: // telnet — interactive even if nobody should be using it
		return "interactive"
	case 53, 853: // DNS, DoT
		return "api"
	case 3389: // RDP
		return "interactive"
	case 5900, 5901: // VNC
		return "interactive"
	case 25, 465, 587: // SMTP
		return "api"
	case 993, 995: // IMAP/POP3 over TLS
		return "api"
	case 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889: // BitTorrent
		return "transfer"
	}
	// Realtime / gaming port ranges. Port 19305 / 3478 / 3479 are STUN;
	// 27000-28000 is Steam/Source games; 3074 Xbox Live.
	if destPort == 3478 || destPort == 3479 || destPort == 19305 ||
		destPort == 3074 ||
		(destPort >= 27000 && destPort <= 28000) ||
		(destPort >= 7000 && destPort <= 7100 && isUDP) {
		return "realtime"
	}
	// VoIP ports.
	if destPort == 5060 || destPort == 5061 {
		return "voip"
	}

	// Host-keyword classification. Normalise host for suffix/contains
	// matching: lowercase, strip leading "www.". Empty host (direct
	// IP dial with no sniff success) falls through to port-only
	// heuristics below.
	h := strings.ToLower(host)
	h = strings.TrimPrefix(h, "www.")

	if h != "" {
		if scene := classifyByKeyword(h); scene != "" {
			return scene
		}
	}

	// Port-only fallback for unknown hosts. UDP/443 without a known
	// streaming host is most plausibly QUIC web browsing; leave blank
	// and defer to history.
	return ""
}

// classifyByKeyword does suffix / substring matching against a curated
// keyword table. Order matters — more specific suffixes should appear
// BEFORE generic ones (eg "discord.media" before "discord.com").
// Matching is suffix-first (domain components) with a substring
// fallback for CDN-style hosts like "v1.xyz.cdn.googlevideo.com".
func classifyByKeyword(host string) string {
	// Streaming: long-form video + live streaming. Includes major
	// region-specific services. Order:
	//   - Exact suffix first (eg "youtube.com")
	//   - CDN/edge suffixes second (eg "googlevideo.com",
	//     "nflxvideo.net")
	//   - Substring fallbacks where suffix is too restrictive
	for _, kw := range streamingHosts {
		if strings.HasSuffix(host, kw) || strings.Contains(host, kw) {
			return "streaming"
		}
	}
	// Realtime: games + WebRTC signalling + low-latency chat.
	for _, kw := range realtimeHosts {
		if strings.HasSuffix(host, kw) || strings.Contains(host, kw) {
			return "realtime"
		}
	}
	// VoIP: SIP / teleconferencing media servers.
	for _, kw := range voipHosts {
		if strings.HasSuffix(host, kw) || strings.Contains(host, kw) {
			return "voip"
		}
	}
	// Transfer: bulk download / cloud storage / package mirrors.
	for _, kw := range transferHosts {
		if strings.HasSuffix(host, kw) || strings.Contains(host, kw) {
			return "transfer"
		}
	}
	// API: REST-heavy, small-payload endpoints. Matched LAST because
	// "api.anything.com" would collide with streaming/realtime domains
	// that happen to host an api subdomain.
	for _, kw := range apiHosts {
		if strings.HasSuffix(host, kw) || strings.Contains(host, kw) {
			return "api"
		}
	}
	return ""
}

// Host keyword tables. Intentionally short and curated — we don't try
// to enumerate the entire internet. These cover the 80% of Android /
// desktop traffic that's bandwidth-sensitive or latency-sensitive,
// where per-request scene awareness actually changes selection.
//
// Each string is a suffix/substring fragment. Checked with
// strings.HasSuffix then strings.Contains — so "googlevideo.com" matches
// "r1---sn-xy.googlevideo.com" via contains even when the full host
// isn't the literal suffix.
var (
	streamingHosts = []string{
		// Global video
		"youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com",
		"netflix.com", "nflxvideo.net", "nflximg.com",
		"twitch.tv", "ttvnw.net", "jtvnw.net",
		"vimeo.com", "vimeocdn.com",
		"dailymotion.com", "dmcdn.net",
		"hulu.com", "hbomax.com", "max.com",
		"disneyplus.com", "bamgrid.com",
		"primevideo.com", "amazonvideo.com", "aiv-cdn.net",
		"peacocktv.com",
		// Music streaming (sustained audio, still bandwidth-sensitive)
		"spotify.com", "scdn.co",
		"apple.com/media", "itunes.apple.com",
		// Region-specific
		"bilibili.com", "hdslb.com", "bilivideo.com",
		"iqiyi.com", "iq.com", "qy.net",
		"youku.com", "youku.tudou.com",
		"tudou.com",
		"qq.com/v", "v.qq.com", "vqq.com", "qqvideo.tc.qq.com",
		"douyu.com", "huya.com",
		"douyin.com", "tiktok.com", "tiktokcdn.com", "byteoversea.com",
		"kuaishou.com", "kwaicdn.com",
		"niconico.jp", "nicovideo.jp", "dmc.nico",
	}
	realtimeHosts = []string{
		// WebRTC
		"discord.gg", "discord.com", "discord.media", "discordapp.com",
		"zoom.us", "zoomgov.com",
		"meet.google.com", "teams.microsoft.com",
		// Gaming infra
		"riotgames.com", "leagueoflegends.com",
		"valorant.com", "valorantnetwork.com",
		"steampowered.com", "steamcommunity.com", "steamstatic.com",
		"blizzard.com", "battle.net",
		"ea.com", "origin.com",
		"epicgames.com", "fortnite.com",
		"mojang.com", "minecraft.net",
		"xboxlive.com", "playstation.net", "nintendo.com",
		// Chinese gaming
		"tencent-cloud.com", "qq.com/games",
		"netease.com/games", "163.com/games",
	}
	voipHosts = []string{
		"whatsapp.net", "whatsapp.com",
		"skype.com", "lync.com",
		"wechat.com", "weixin.qq.com",
		"line.me", "naver.jp",
		"telegram.org", "t.me", // telegram voice, not bot API
	}
	transferHosts = []string{
		// OS / package mirrors
		"ubuntu.com", "debian.org", "archlinux.org", "fedoraproject.org",
		"softwareupdate.apple.com", "swscan.apple.com",
		"windowsupdate.com", "update.microsoft.com",
		// Cloud storage
		"dropbox.com", "dropboxusercontent.com",
		"googledrive.com", "drive.google.com",
		"onedrive.com", "1drv.ms",
		"mega.nz", "mega.io",
		"icloud-content.com",
		// Container / code registries
		"docker.io", "docker.com", "gcr.io", "quay.io",
		"ghcr.io",
		"github.com/releases", "githubusercontent.com",
		"npmjs.org", "npmjs.com",
		"pypi.org", "pythonhosted.org",
		"crates.io",
	}
	apiHosts = []string{
		"api.", // generic prefix — caught by contains
		".api.",
		"graph.facebook.com", "graph.microsoft.com",
		"slack.com", "slackb.com",
		"stripe.com", "checkout.stripe.com",
		"openai.com", "anthropic.com", "claude.ai",
		"googleapis.com", "google.com/apis",
		"amazonaws.com",
		"azure.com", "azureedge.net",
		"cloudflare.com/cdn-cgi",
	}
)

// reorderForRequestScene adjusts the order of a ranked candidate list
// based on the CURRENT request's inferred scene. Runs AFTER the normal
// selection/ranking pipeline, so it only tweaks the order of already-
// good candidates rather than introducing new ones.
//
// Intent by scene:
//
//   streaming / transfer → re-sort top K by node's historical peak
//      download rate (largest first). The request is bandwidth-
//      sensitive; a node with a demonstrated fat pipe should dial
//      first even if its latency is slightly worse.
//
//   realtime / voip      → re-sort top K by short-window latency
//      EWMA (lowest first). Gaming / voice care about 50-vs-100ms,
//      not bandwidth.
//
//   interactive          → lowest latency first, same as realtime.
//
//   api                  → default to historical order. api requests
//      are typically small + latency-sensitive but brief; aggressive
//      re-sorting could waste freshness of the ranking path.
//
//   "" (unknown) / web   → no reorder. Fall through to whatever the
//      ranking path decided — historical behaviour preserved.
//
// Only the TOP-K is shuffled (K=5). Deeper positions are fallbacks
// that the retry loop may touch if the lead candidates all fail, and
// we don't want scene-preference inverting an already-ranked tail.
func (s *Smart) reorderForRequestScene(candidates []adapter.Outbound, meta *smartDialMeta) []adapter.Outbound {
	if len(candidates) < 2 || meta == nil {
		return candidates
	}
	// Selection-style algorithms have already committed to position 0
	// as their chosen node (sticky / weighted-RR / p2c). Disturbing
	// that choice undoes the algorithm; request-scene hints only
	// apply to ranking-style algorithms.
	if s.algoRound0Width() == 1 {
		return candidates
	}
	scene := classifyRequestScene(meta.host, meta.destPort, meta.isUDP)
	if scene == "" || scene == "web" || scene == "api" {
		return candidates
	}

	const rerankTopK = 5
	k := rerankTopK
	if k > len(candidates) {
		k = len(candidates)
	}
	head := candidates[:k]

	switch scene {
	case "streaming", "transfer":
		sort.SliceStable(head, func(i, j int) bool {
			bi := s.nodePeakDownloadKBps(head[i].Tag())
			bj := s.nodePeakDownloadKBps(head[j].Tag())
			// Preserve original order when both unknown (bi==bj==0)
			// or equal, so we don't churn for no signal.
			return bi > bj
		})
	case "realtime", "voip", "interactive":
		sort.SliceStable(head, func(i, j int) bool {
			ri := s.shortRTTFor(head[i].Tag())
			rj := s.shortRTTFor(head[j].Tag())
			// Unknown (0) goes LAST — treat as worse than any known
			// measured latency. Without this, a fresh node with no
			// RTT data would always sort first and cause cold-start
			// misselection.
			switch {
			case ri == 0 && rj == 0:
				return false
			case ri == 0:
				return false
			case rj == 0:
				return true
			}
			return ri < rj
		})
	}
	return candidates
}

// nodePeakDownloadKBps returns the persisted max-download rate for a
// node tag, read from whatever AtomicStatsRecord is in the in-memory
// cache. Returns 0 when unknown (caller treats 0 as lowest priority).
func (s *Smart) nodePeakDownloadKBps(tag string) float64 {
	if s.store == nil || tag == "" {
		return 0
	}
	rec := s.lookupAnyAtomicRecord(tag)
	if rec == nil {
		return 0
	}
	// Historical peak download rate in KB/s — same field weight.go
	// consumes as input.MaxdownloadRate. Direct field read, no
	// allocation.
	return rec.GetFloat64("maxDownloadRate")
}

// shortSuccessRateFor reads the short-window EWMA success rate for a
// tag, analogous to shortRTTFor. Used by the adaptive parallel-dial
// logic to decide how aggressively to race candidates.
func (s *Smart) shortSuccessRateFor(tag string) float64 {
	if s.store == nil || tag == "" {
		return 0
	}
	rec := s.lookupAnyAtomicRecord(tag)
	if rec == nil {
		return 0
	}
	return rec.ShortSuccessRate()
}
