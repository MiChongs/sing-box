package lightgbm

import (
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/smart"
)

var (
	asnNumberRegex = regexp.MustCompile(`^(\d+)`)
	domainRegex    = regexp.MustCompile(`([a-zA-Z0-9-]+)(\.[a-zA-Z0-9-]+)+$`)
	ipv4Regex      = regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$`)

	// ASN provider name → integer category (verbatim mihomo parity)
	asnCategories = map[string]int{
		"google": 1, "amazon": 2, "microsoft": 3, "facebook": 4, "apple": 5,
		"cloudflare": 6, "akamai": 7, "fastly": 8, "netflix": 9, "alibaba": 10,
		"tencent": 11, "baidu": 12,
		"chinatelecom": 13, "chinaunicom": 14, "chinamobile": 15, "chinaedu": 16, "cstnet": 17,
		"cdn77": 20, "limelight": 21, "edgecast": 22, "stackpath": 23, "imperva": 24,
		"oracle": 25, "ibm": 26, "digitalocean": 27, "linode": 28, "ovh": 29,
		"hetzner": 30, "vultr": 31, "cogent": 32, "leaseweb": 33, "upyun": 34,
		"qingcloud": 35, "ucloud": 36,
		"verizon": 40, "comcast": 41, "att": 42, "sprint": 43, "tmobile": 44,
		"level3": 45, "ntt": 46, "kddi": 47, "softbank": 48, "telstra": 49,
		"singtel": 50, "starhub": 51, "m1": 52, "pccw": 53, "hkbn": 54,
		"smartone": 55, "hgc": 56, "cht": 57, "fetnet": 58, "twm": 59,
		"twitter": 70, "twitch": 71, "discord": 72, "spotify": 73, "github": 74,
		"steam": 75, "blizzard": 76, "riotgames": 77, "epicgames": 78, "ea": 79,
		"bytedance": 80, "bilibili": 81, "netactuate": 82,
		"hkix": 90, "linx": 91, "jpix": 92, "equinix": 93, "sgix": 94,
		"de-cix": 95, "ams-ix": 96,
		"cern": 100, "mit": 101, "stanford": 102, "tsinghua": 103, "pku": 104,
		"visa": 110, "mastercard": 111, "paypal": 112, "stripe": 113,
		"alipay": 114, "wechatpay": 115,
	}

	// Country/region code → category
	geoCategories = map[string]int{
		"CN": 1, "HK": 2, "TW": 3, "JP": 4, "KR": 5, "SG": 6, "US": 7, "CA": 8,
		"GB": 9, "DE": 10, "FR": 11, "RU": 12, "AU": 13, "IN": 14, "BR": 15,
		"IT": 16, "ES": 17, "NL": 18, "SE": 19, "CH": 20, "PL": 21, "TR": 22,
		"MX": 23, "ZA": 24, "AR": 25, "ID": 26, "TH": 27, "VN": 28, "PH": 29,
		"MY": 30, "MO": 31,
	}

	// Well-known port → service category
	wellKnownPorts = map[uint16]int{
		22: 1, 25: 2, 53: 3, 80: 4, 110: 5, 143: 6, 443: 7, 465: 8,
		784: 3, 853: 3, 993: 9, 995: 10, 1194: 11, 1812: 12, 3306: 13,
		5053: 3, 5353: 3, 5355: 3, 5432: 14, 6379: 15, 8853: 3, 9953: 3,
		27017: 16, 6660: 17, 6665: 17, 6666: 17, 6667: 17, 6668: 17, 6669: 17,
		8000: 18, 8008: 18, 8080: 18, 8443: 19, 8883: 20,
	}

	portRanges = []struct {
		min, max uint16
		category int
	}{
		{0, 1023, 20},
		{1024, 49151, 21},
		{49152, 65535, 22},
	}

	apiServicePorts = map[uint16]bool{
		8080: true, 8443: true, 9000: true, 9001: true, 9002: true,
		3000: true, 3001: true, 5000: true, 5001: true,
		8000: true, 8001: true, 8888: true, 4000: true, 4001: true,
		6000: true, 6001: true, 7000: true, 7001: true,
	}

	dnsServicePorts = map[uint16]bool{
		53: true, 853: true, 784: true, 5053: true, 5353: true,
		5355: true, 8853: true, 9953: true,
	}

	gameSpecificPorts = map[uint16]bool{
		25565: true,
		27015: true, 27016: true, 27017: true, 27018: true, 27019: true, 27020: true,
		27031: true, 27036: true,
		3074: true, 3478: true, 3479: true,
		3659: true, 6250: true,
		7000: true, 7001: true, 7002: true, 7003: true, 7004: true,
		8393: true, 8394: true,
		9000: true, 9001: true, 9330: true, 9331: true, 9339: true,
		14000: true, 14001: true, 14002: true, 14003: true, 14004: true, 14008: true,
		16000: true,
		18000: true, 18060: true, 18120: true, 18180: true, 18240: true, 18300: true,
		19000: true, 19132: true,
		20000: true, 20001: true, 20002: true,
		22100: true, 22101: true, 22102: true,
		30000: true, 30001: true, 30002: true, 30003: true, 30004: true,
		35000: true, 35001: true, 35002: true,
		40000: true, 40001: true, 40002: true,
		50000: true, 50001: true, 50002: true,
		50505: true, 65010: true, 65050: true,
		3724: true, 6112: true, 6881: true,
	}

	communicationPorts = map[uint16]bool{
		5060: true, 5061: true, 1720: true,
		1080: true, 1443: true,
		3478: true, 3479: true, 5349: true, 5350: true,
		5222: true, 5269: true, 5938: true,
		6881: true, 6882: true, 6883: true, 6884: true, 6885: true,
		6886: true, 6887: true, 6888: true, 6889: true,
		8801: true, 8802: true, 8443: true,
		10000: true, 10001: true,
		19302: true, 19303: true,
		50000: true, 50001: true, 50002: true,
		50003: true, 50004: true, 50005: true,
		55000: true, 55001: true,
		1863: true, 5228: true, 34784: true,
	}

	gameCommRanges = []struct {
		min, max uint16
		category int
	}{
		{3000, 3999, 3}, {5000, 5999, 2}, {6000, 7000, 3},
		{8000, 9000, 3}, {10000, 20000, 3}, {27000, 28000, 1},
		{30000, 32000, 1}, {49000, 50000, 2}, {50000, 55000, 3},
		{55000, 60000, 2},
	}

	streamingKeywords = []string{
		"youtube", "netflix", "hulu", "spotify", "tiktok", "douyin", "youku", "iqiyi",
		"bilibili", "twitch", "hbo", "disney", "vimeo", "vod", "stream", "video",
		"media", "movie", "tv", "music", "audio", "cdm", "cdn", "content",
		"live", "livestream", "replay", "shorts", "kuaishou", "huya", "douyu",
	}

	gameKeywords = []string{
		"game", "play", "steam", "xbox", "playstation", "nintendo", "ea.com", "riot",
		"blizzard", "ubisoft", "epic", "cod", "minecraft", "roblox", "pubg", "fortnite",
		"valorant", "riotgames", "leagueoflegends", "warzone",
		"apex", "apexlegends", "overwatch", "dota", "csgo",
		"counterstrike", "hearthstone", "battlenet", "battle.net",
		"genshin", "mihoyo", "hoyoverse", "lol", "arenaofvalor", "honorofkings",
	}

	communicationKeywords = []string{
		"meet", "zoom", "teams", "voip", "sip", "call", "chat", "conference", "webex",
		"discord", "slack", "telegram", "signal", "whatsapp", "skype", "wechat",
		"voicechat", "videocall", "rtc", "webrtc", "jitsi",
		"mumble", "ventrilo", "teamspeak", "discord.gg",
		"meeting", "huddle", "gather",
		"qq", "msn", "icq", "line", "kakao", "viber", "imo", "element",
	}

	apiServiceKeywords = []string{
		"api.cloudflare.com", "api.amazonaws.com", "api.azure.com", "googleapis.com",
		"api.fastly.com", "api.maxcdn.com", "api.keycdn.com", "api.bunnycdn.com",
		"api.digitalocean.com", "api.vultr.com", "api.linode.com", "api.hetzner.com",
		"api.vercel.com", "api.netlify.com", "api.heroku.com", "api.railway.app",
		"api.render.com", "api.fly.io", "registry.npmjs.org", "pypi.org",
		"hub.docker.com", "registry.docker.io", "rubygems.org", "crates.io",
		"api.datadog.com", "api.newrelic.com", "api.segment.com", "api.mixpanel.com",
		"api.amplitude.com", "api.hotjar.com", "api.sentry.io", "api.rollbar.com",
		"api.auth0.com", "api.okta.com", "api.twilio.com", "api.sendgrid.com",
		"api.mailgun.com", "api.stripe.com",
		"ecs.aliyuncs.com", "api.qcloud.com", "api.ucloud.cn", "api.huaweicloud.com",
		"api.baidubce.com", "api.volcengine.com",
		"gateway.", "api-gateway.", "apigateway.", "/api/", "/v1/", "/v2/", "/v3/", "/v4/",
		"/rest/", "/graphql/", "rest.", "graphql.", "webhook.", "rpc.",
	}

	dnsServiceKeywords = []string{
		"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
		"208.67.222.222", "208.67.220.220",
		"dns.google", "dns.google.com", "cloudflare-dns.com", "dns.cloudflare.com",
		"one.one.one.one", "family.cloudflare-dns.com", "security.cloudflare-dns.com",
		"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
		"doh.opendns.com", "doh.familyshield.opendns.com", "doh.sandbox.opendns.com",
		"mozilla.cloudflare-dns.com", "firefox.dns.nextdns.io",
		"dns.adguard.com", "dns-family.adguard.com", "dns-unfiltered.adguard.com",
		"doh.cleanbrowsing.org", "family-filter-dns.cleanbrowsing.org",
		"dot.cloudflare-dns.com", "dot.alidns.com", "dot.dns.sb", "dot.360.cn",
		"doh.pub", "dns.pub", "doh.360.cn", "dns.alidns.com", "doh.alidns.com",
		"doh.dns.sb", "rubyfish.cn", "dns.rubyfish.cn", "pdns.fkgfw.cf",
		"commons.host", "odvr.nic.cz", "doh.libredns.gr", "dns.digitale-gesellschaft.ch",
		"dns.switch.ch", "jp.tiar.app", "jp.tiarap.org", "kaitain.restena.lu",
		"dns.twnic.tw", "dns.hinet.net",
		"dns", "doh", "doq", "dot", "resolver", "nameserver", "recursive",
		"authoritative", "secure-dns", "private-dns",
	}

	privateIPNetworks = []struct {
		prefix   netip.Prefix
		category int
	}{
		{netip.MustParsePrefix("10.0.0.0/8"), 1},
		{netip.MustParsePrefix("172.16.0.0/12"), 1},
		{netip.MustParsePrefix("192.168.0.0/16"), 1},
		{netip.MustParsePrefix("127.0.0.0/8"), 2},
		{netip.MustParsePrefix("169.254.0.0/16"), 3},
		{netip.MustParsePrefix("::1/128"), 2},
		{netip.MustParsePrefix("fe80::/10"), 3},
		{netip.MustParsePrefix("fc00::/7"), 1},
		{netip.MustParsePrefix("2001:db8::/32"), 4},
	}
)

// PrepareFeatures extracts a 27-dimensional feature vector from a ModelInput.
// The order and semantics are byte-identical to mihomo for model compatibility.
func PrepareFeatures(input *smart.ModelInput) []float64 {
	features := make([]float64, 0, MaxFeatureSize)

	uploadMB := input.UploadTotal
	downloadMB := input.DownloadTotal
	maxUploadRateKB := input.MaxuploadRate
	maxDownloadRateKB := input.MaxdownloadRate
	durationMinutes := input.ConnectionDuration
	lastUsedSeconds := 0.0
	if input.LastUsed > 0 {
		lastUsedSeconds = float64(time.Now().Unix() - input.LastUsed)
	}

	// 0–15: core metrics
	features = append(features, float64(input.Success))
	features = append(features, float64(input.Failure))
	features = append(features, math.Log1p(float64(input.ConnectTime)))
	features = append(features, math.Log1p(float64(input.Latency)))
	features = append(features, math.Log1p(uploadMB))
	features = append(features, math.Log1p(input.HistoryUploadTotal))
	features = append(features, math.Log1p(maxUploadRateKB))
	features = append(features, math.Log1p(input.HistoryMaxUploadRate))
	features = append(features, math.Log1p(downloadMB))
	features = append(features, math.Log1p(input.HistoryDownloadTotal))
	features = append(features, math.Log1p(maxDownloadRateKB))
	features = append(features, math.Log1p(input.HistoryMaxDownloadRate))
	features = append(features, math.Log1p(durationMinutes))
	features = append(features, math.Log1p(lastUsedSeconds))
	features = append(features, boolToFloat(input.IsUDP))
	features = append(features, boolToFloat(input.IsTCP))

	// 16: ASN category
	features = append(features, float64(extractASNFeature(input.DestIPASN)))

	// 17: country/geo
	features = append(features, float64(extractGeoIPFeature(input.DestGeoIP)))

	// 18: address type
	var addressFeature int
	if input.Host != "" {
		addressFeature = extractDomainTypeFeature(input.Host)
	} else if input.DestIP != "" {
		addressFeature = extractIPFeature(input.DestIP)
	}
	features = append(features, float64(addressFeature))

	// 19: port category
	portFeature := extractPortFeature(input.DestPort)
	features = append(features, float64(portFeature))

	// 20: traffic ratio
	trafficRatio := 0.0
	if uploadMB > 0 && downloadMB > 0 {
		if uploadMB > downloadMB {
			trafficRatio = downloadMB / uploadMB
		} else {
			trafficRatio = -uploadMB / downloadMB
		}
	}
	features = append(features, trafficRatio)

	// 21: traffic density (log-transformed)
	trafficDensity := 0.0
	if durationMinutes > 0 {
		trafficDensity = math.Log1p((uploadMB + downloadMB) / durationMinutes)
	}
	features = append(features, trafficDensity)

	// 22: connection type derived
	features = append(features, float64(deriveConnectionType(input.DestPort, addressFeature, portFeature)))

	// 23-26: hash-bucket features
	features = append(features, hashStringToFloat(input.DestIPASN, 500))
	features = append(features, hashStringToFloat(input.Host, 1000))
	features = append(features, hashStringToFloat(input.DestIP, 10000))
	geoHash := 0.0
	if len(input.DestGeoIP) > 0 {
		geoHash = hashStringToFloat(input.DestGeoIP[0], 200)
	}
	features = append(features, geoHash)

	if len(features) > MaxFeatureSize {
		features = features[:MaxFeatureSize]
	}
	return features
}

// hashStringToFloat: FNV-1a hashing → float in range [1, buckets].
func hashStringToFloat(s string, buckets int) float64 {
	if s == "" || buckets <= 0 {
		return 0.0
	}
	const (
		fnvOffsetBasis uint32 = 2166136261
		fnvPrime       uint32 = 16777619
	)
	hash := fnvOffsetBasis
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= fnvPrime
	}
	return float64((hash % uint32(buckets)) + 1)
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func extractASNFeature(asnInfo string) int {
	if asnInfo == "" {
		return 0
	}
	asnInfo = strings.ToLower(asnInfo)
	for keyword, category := range asnCategories {
		if strings.Contains(asnInfo, keyword) {
			return category
		}
	}
	if matches := asnNumberRegex.FindStringSubmatch(asnInfo); len(matches) > 1 {
		if asnNum, err := strconv.Atoi(matches[1]); err == nil {
			switch {
			case asnNum < 1000:
				return 50
			case asnNum < 10000:
				return 51
			case asnNum < 50000:
				return 52
			case asnNum < 150000:
				return 53
			default:
				return 54
			}
		}
	}
	return 0
}

func extractGeoIPFeature(geoIPInfo []string) int {
	if len(geoIPInfo) == 0 {
		return 0
	}
	countryCode := geoIPInfo[0]
	if category, ok := geoCategories[countryCode]; ok {
		return category
	}
	if countryCode != "" {
		hashValue := 0
		for _, r := range countryCode {
			hashValue = hashValue*31 + int(r)
		}
		return 30 + (hashValue % 20)
	}
	return 0
}

func extractDomainTypeFeature(host string) int {
	if host == "" {
		return 0
	}
	host = strings.ToLower(host)
	if strings.Contains(host, "[") || (strings.Count(host, ".") == 3 && ipv4Regex.MatchString(host)) {
		return 1
	}
	for _, keyword := range dnsServiceKeywords {
		if strings.Contains(host, keyword) {
			return 6
		}
	}
	for _, keyword := range apiServiceKeywords {
		if strings.Contains(host, keyword) {
			return 5
		}
	}
	for _, keyword := range gameKeywords {
		if strings.Contains(host, keyword) {
			return 3
		}
	}
	for _, keyword := range communicationKeywords {
		if strings.Contains(host, keyword) {
			return 4
		}
	}
	for _, keyword := range streamingKeywords {
		if strings.Contains(host, keyword) {
			return 2
		}
	}
	if strings.HasSuffix(host, ".gov") {
		return 14
	} else if strings.HasSuffix(host, ".edu") {
		return 15
	} else if strings.HasSuffix(host, ".cn") {
		return 10
	} else if strings.HasSuffix(host, ".com") {
		return 11
	} else if strings.HasSuffix(host, ".net") {
		return 12
	} else if strings.HasSuffix(host, ".org") {
		return 13
	}
	if matches := domainRegex.FindStringSubmatch(host); len(matches) > 1 {
		domainParts := strings.Split(host, ".")
		if len(domainParts) >= 3 {
			return 30
		}
		return 31
	}
	return 0
}

func extractIPFeature(ipAddr string) int {
	if ipAddr == "" {
		return 0
	}
	addr, err := netip.ParseAddr(ipAddr)
	if err != nil {
		return 0
	}
	for _, network := range privateIPNetworks {
		if network.prefix.Contains(addr) {
			return network.category + 100
		}
	}
	if addr.Is4() {
		return 110
	}
	return 111
}

func extractPortFeature(port uint16) int {
	if _, ok := dnsServicePorts[port]; ok {
		return 36
	}
	if _, ok := apiServicePorts[port]; ok {
		return 35
	}
	if _, ok := gameSpecificPorts[port]; ok {
		return 30
	}
	if _, ok := communicationPorts[port]; ok {
		return 31
	}
	if category, ok := wellKnownPorts[port]; ok {
		return category
	}
	for _, r := range gameCommRanges {
		if port >= r.min && port <= r.max {
			switch r.category {
			case 1:
				return 32
			case 2:
				return 33
			case 3:
				return 34
			}
		}
	}
	for _, r := range portRanges {
		if port >= r.min && port <= r.max {
			return r.category
		}
	}
	return 0
}

func deriveConnectionType(port uint16, addressFeature, portFeature int) int {
	if addressFeature == 6 || portFeature == 36 {
		return 7
	}
	if _, ok := dnsServicePorts[port]; ok {
		return 7
	}
	if addressFeature == 5 || portFeature == 35 {
		return 6
	}
	if _, ok := apiServicePorts[port]; ok {
		return 6
	}
	if addressFeature == 3 || addressFeature == 4 {
		return 3
	}
	if _, ok := gameSpecificPorts[port]; ok {
		return 3
	}
	if _, ok := communicationPorts[port]; ok {
		return 3
	}
	if addressFeature == 2 {
		return 2
	}
	if port == 80 || port == 443 || portFeature == 4 || portFeature == 7 {
		return 1
	}
	if portFeature == 13 || portFeature == 14 || portFeature == 15 || portFeature == 16 {
		return 4
	}
	if port == 20 || port == 21 || port == 22 || port == 989 || port == 990 {
		return 5
	}
	for _, r := range gameCommRanges {
		if port >= r.min && port <= r.max {
			return 3
		}
	}
	if port > 10000 && port < 65000 {
		return 3
	}
	return 0
}
