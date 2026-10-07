package group

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Region detection from node names for smart-loadbalance.
//
// Airport subscriptions name nodes in a handful of conventions — flags
// ("🇭🇰 香港 01"), Chinese names ("日本 东京 IPLC"), English names
// ("Japan Tokyo 02"), ISO / IATA codes ("HK01", "JP-NRT-3"), and relay
// shorthands ("沪日 IPLC", "广港 01"). The classifier collects every match,
// drops matches nested inside longer ones ("印度尼西亚" is not also "印度"),
// scores them by how specific the evidence is, and picks the strongest
// region. Ties go to the match that appears last, because relay names put
// the exit after the entry ("香港中转美国", "HK → JP").

// regionUnknown is the pool unclassified members land in when
// region.unknown is "keep".
const regionUnknown = "OTHER"

const (
	regionWeightName = 3 // Chinese / English country or city name
	regionWeightFlag = 2 // flag emoji
	regionWeightCode = 1 // ISO / IATA code
)

type builtinRegion struct {
	code  string
	zh    []string // Chinese names, simplified and traditional; first is the display name
	en    []string // English names, matched case-insensitively on word boundaries; first is the display name
	alias []string // cities, provinces and relay shorthands (Chinese or English)
	codes []string // extra upper-case codes (ISO 3166 alpha-3, IATA), letter-bounded
	// lower lets the two-letter code match in lower case too ("hk-01");
	// only set for codes common in node names and rare as English words.
	lower bool
}

var builtinRegions = []builtinRegion{
	{code: "HK", zh: []string{"香港"}, en: []string{"Hong Kong", "HongKong"}, alias: []string{"沪港", "广港", "深港", "京港", "杭港", "苏港", "莞港", "佛港", "港"}, codes: []string{"HKG"}, lower: true},
	{code: "TW", zh: []string{"台湾", "台灣", "臺灣", "中华民国"}, en: []string{"Taiwan"}, alias: []string{"台北", "臺北", "台中", "臺中", "台南", "高雄", "新竹", "彰化", "桃园", "沪台", "广台", "Taipei", "Taichung", "Kaohsiung", "Hsinchu"}, codes: []string{"TWN", "TPE", "TSA", "KHH"}, lower: true},
	{code: "MO", zh: []string{"澳门", "澳門"}, en: []string{"Macau", "Macao"}, codes: []string{"MAC", "MFM"}, lower: true},
	{code: "JP", zh: []string{"日本"}, en: []string{"Japan"}, alias: []string{"东京", "東京", "大阪", "名古屋", "福冈", "福岡", "埼玉", "川崎", "横滨", "札幌", "京都", "沪日", "广日", "深日", "京日", "杭日", "苏日", "Tokyo", "Osaka", "Nagoya", "Fukuoka", "Saitama", "Yokohama", "Sapporo", "Kyoto"}, codes: []string{"JPN", "NRT", "HND", "KIX", "ITM", "TYO", "OSA", "NGO", "FUK", "CTS"}, lower: true},
	{code: "KR", zh: []string{"韩国", "韓國", "南韩", "南韓"}, en: []string{"Korea", "South Korea"}, alias: []string{"首尔", "首爾", "春川", "釜山", "仁川", "沪韩", "广韩", "Seoul", "Chuncheon", "Busan", "Incheon"}, codes: []string{"KOR", "ICN", "SEL", "GMP", "PUS"}, lower: true},
	{code: "SG", zh: []string{"新加坡"}, en: []string{"Singapore"}, alias: []string{"狮城", "獅城", "沪新", "广新", "深新"}, codes: []string{"SGP", "SIN"}, lower: true},
	{code: "MY", zh: []string{"马来西亚", "馬來西亞", "马来"}, en: []string{"Malaysia"}, alias: []string{"吉隆坡", "Kuala Lumpur"}, codes: []string{"MYS", "KUL"}, lower: true},
	{code: "TH", zh: []string{"泰国", "泰國"}, en: []string{"Thailand"}, alias: []string{"曼谷", "Bangkok"}, codes: []string{"THA", "BKK"}, lower: true},
	{code: "VN", zh: []string{"越南"}, en: []string{"Vietnam", "Viet Nam"}, alias: []string{"河内", "河內", "胡志明", "Hanoi", "Ho Chi Minh"}, codes: []string{"VNM", "SGN", "HAN"}, lower: true},
	{code: "PH", zh: []string{"菲律宾", "菲律賓"}, en: []string{"Philippines"}, alias: []string{"马尼拉", "馬尼拉", "Manila"}, codes: []string{"PHL", "MNL"}, lower: true},
	{code: "ID", zh: []string{"印度尼西亚", "印度尼西亞", "印尼"}, en: []string{"Indonesia"}, alias: []string{"雅加达", "雅加達", "Jakarta"}, codes: []string{"IDN", "CGK"}},
	{code: "KH", zh: []string{"柬埔寨"}, en: []string{"Cambodia"}, alias: []string{"金边", "金邊", "Phnom Penh"}, codes: []string{"KHM", "PNH"}},
	{code: "LA", zh: []string{"老挝", "寮國"}, en: []string{"Laos"}, alias: []string{"万象", "Vientiane"}, codes: []string{"LAO"}},
	{code: "MM", zh: []string{"缅甸", "緬甸"}, en: []string{"Myanmar", "Burma"}, alias: []string{"仰光", "Yangon"}, codes: []string{"MMR", "RGN"}},
	{code: "BN", zh: []string{"文莱", "汶萊"}, en: []string{"Brunei"}, codes: []string{"BRN"}},
	{code: "MN", zh: []string{"蒙古"}, en: []string{"Mongolia"}, alias: []string{"乌兰巴托", "Ulaanbaatar"}, codes: []string{"MNG", "ULN"}},
	{code: "IN", zh: []string{"印度"}, en: []string{"India"}, alias: []string{"孟买", "孟買", "新德里", "德里", "班加罗尔", "Mumbai", "New Delhi", "Delhi", "Bangalore", "Chennai"}, codes: []string{"IND", "BOM", "DEL", "MAA"}},
	{code: "PK", zh: []string{"巴基斯坦"}, en: []string{"Pakistan"}, alias: []string{"卡拉奇", "Karachi"}, codes: []string{"PAK", "KHI"}},
	{code: "BD", zh: []string{"孟加拉"}, en: []string{"Bangladesh"}, alias: []string{"达卡", "Dhaka"}, codes: []string{"BGD", "DAC"}},
	{code: "NP", zh: []string{"尼泊尔", "尼泊爾"}, en: []string{"Nepal"}, codes: []string{"NPL"}},
	{code: "LK", zh: []string{"斯里兰卡", "斯里蘭卡"}, en: []string{"Sri Lanka"}, codes: []string{"LKA"}},
	{code: "KZ", zh: []string{"哈萨克斯坦", "哈薩克"}, en: []string{"Kazakhstan"}, alias: []string{"阿拉木图", "Almaty"}, codes: []string{"KAZ", "ALA"}},
	{code: "UZ", zh: []string{"乌兹别克斯坦", "烏茲別克"}, en: []string{"Uzbekistan"}, codes: []string{"UZB"}},
	{code: "KG", zh: []string{"吉尔吉斯斯坦", "吉爾吉斯"}, en: []string{"Kyrgyzstan"}, codes: []string{"KGZ"}},
	{code: "AE", zh: []string{"阿联酋", "阿聯酋", "阿拉伯联合酋长国"}, en: []string{"United Arab Emirates", "UAE", "Emirates"}, alias: []string{"迪拜", "杜拜", "阿布扎比", "Dubai", "Abu Dhabi"}, codes: []string{"ARE", "DXB", "AUH"}},
	{code: "SA", zh: []string{"沙特", "沙特阿拉伯"}, en: []string{"Saudi Arabia", "Saudi"}, alias: []string{"利雅得", "吉达", "Riyadh", "Jeddah"}, codes: []string{"SAU", "RUH", "JED"}},
	{code: "QA", zh: []string{"卡塔尔", "卡達"}, en: []string{"Qatar"}, alias: []string{"多哈", "Doha"}, codes: []string{"QAT", "DOH"}},
	{code: "BH", zh: []string{"巴林"}, en: []string{"Bahrain"}, codes: []string{"BHR"}},
	{code: "OM", zh: []string{"阿曼"}, en: []string{"Oman"}, codes: []string{"OMN"}},
	{code: "KW", zh: []string{"科威特"}, en: []string{"Kuwait"}, codes: []string{"KWT"}},
	{code: "IL", zh: []string{"以色列"}, en: []string{"Israel"}, alias: []string{"特拉维夫", "Tel Aviv"}, codes: []string{"ISR", "TLV"}},
	{code: "TR", zh: []string{"土耳其"}, en: []string{"Turkey", "Türkiye", "Turkiye"}, alias: []string{"伊斯坦布尔", "伊斯坦堡", "安卡拉", "Istanbul", "Ankara"}, codes: []string{"TUR", "IST"}, lower: true},
	{code: "IR", zh: []string{"伊朗"}, en: []string{"Iran"}, codes: []string{"IRN"}},
	{code: "IQ", zh: []string{"伊拉克"}, en: []string{"Iraq"}, codes: []string{"IRQ"}},
	{code: "JO", zh: []string{"约旦", "約旦"}, en: []string{"Jordan"}, codes: []string{"JOR"}},
	{code: "LB", zh: []string{"黎巴嫩"}, en: []string{"Lebanon"}, codes: []string{"LBN"}},
	{code: "GE", zh: []string{"格鲁吉亚", "喬治亞"}, en: []string{"Georgia"}, alias: []string{"第比利斯", "Tbilisi"}, codes: []string{"GEO", "TBS"}},
	{code: "AM", zh: []string{"亚美尼亚", "亞美尼亞"}, en: []string{"Armenia"}, codes: []string{"ARM", "EVN"}},
	{code: "AZ", zh: []string{"阿塞拜疆", "亞塞拜然"}, en: []string{"Azerbaijan"}, codes: []string{"AZE"}},
	{code: "CY", zh: []string{"塞浦路斯", "賽普勒斯"}, en: []string{"Cyprus"}, codes: []string{"CYP"}},
	{code: "RU", zh: []string{"俄罗斯", "俄羅斯", "俄国"}, en: []string{"Russia", "Russian Federation"}, alias: []string{"莫斯科", "圣彼得堡", "聖彼得堡", "新西伯利亚", "伯力", "哈巴罗夫斯克", "海参崴", "符拉迪沃斯托克", "Moscow", "Saint Petersburg", "St Petersburg", "Novosibirsk", "Khabarovsk", "Vladivostok"}, codes: []string{"RUS", "MOW", "SVO", "DME", "LED", "OVB", "KHV", "VVO"}, lower: true},
	{code: "UA", zh: []string{"乌克兰", "烏克蘭"}, en: []string{"Ukraine"}, alias: []string{"基辅", "基輔", "Kyiv", "Kiev"}, codes: []string{"UKR", "KBP", "IEV"}},
	{code: "BY", zh: []string{"白俄罗斯", "白俄羅斯"}, en: []string{"Belarus"}, codes: []string{"BLR"}},
	{code: "MD", zh: []string{"摩尔多瓦", "摩爾多瓦"}, en: []string{"Moldova"}, codes: []string{"MDA"}},
	{code: "PL", zh: []string{"波兰", "波蘭"}, en: []string{"Poland"}, alias: []string{"华沙", "華沙", "Warsaw"}, codes: []string{"POL", "WAW"}},
	{code: "DE", zh: []string{"德国", "德國"}, en: []string{"Germany", "Deutschland"}, alias: []string{"法兰克福", "法蘭克福", "柏林", "慕尼黑", "杜塞尔多夫", "纽伦堡", "Frankfurt", "Berlin", "Munich", "Dusseldorf", "Düsseldorf", "Nuremberg", "Falkenstein"}, codes: []string{"DEU", "MUC", "BER", "DUS", "NUE"}, lower: true},
	{code: "FR", zh: []string{"法国", "法國"}, en: []string{"France"}, alias: []string{"巴黎", "马赛", "馬賽", "Paris", "Marseille", "Roubaix", "Gravelines"}, codes: []string{"CDG", "PAR", "MRS"}, lower: true},
	{code: "GB", zh: []string{"英国", "英國"}, en: []string{"United Kingdom", "Britain", "Great Britain", "England"}, alias: []string{"伦敦", "倫敦", "曼彻斯特", "曼徹斯特", "London", "Manchester"}, codes: []string{"GBR", "UK", "LHR", "LON", "LGW", "MAN"}, lower: true},
	{code: "IE", zh: []string{"爱尔兰", "愛爾蘭"}, en: []string{"Ireland"}, alias: []string{"都柏林", "Dublin"}, codes: []string{"IRL", "DUB"}},
	{code: "NL", zh: []string{"荷兰", "荷蘭"}, en: []string{"Netherlands", "Holland"}, alias: []string{"阿姆斯特丹", "Amsterdam"}, codes: []string{"NLD", "AMS"}, lower: true},
	{code: "BE", zh: []string{"比利时", "比利時"}, en: []string{"Belgium"}, alias: []string{"布鲁塞尔", "Brussels"}, codes: []string{"BEL", "BRU"}},
	{code: "LU", zh: []string{"卢森堡", "盧森堡"}, en: []string{"Luxembourg"}, codes: []string{"LUX"}},
	{code: "CH", zh: []string{"瑞士"}, en: []string{"Switzerland"}, alias: []string{"苏黎世", "蘇黎世", "日内瓦", "Zurich", "Zürich", "Geneva"}, codes: []string{"CHE", "ZRH", "GVA"}},
	{code: "AT", zh: []string{"奥地利", "奧地利"}, en: []string{"Austria"}, alias: []string{"维也纳", "維也納", "Vienna"}, codes: []string{"AUT", "VIE"}},
	{code: "IT", zh: []string{"意大利", "義大利"}, en: []string{"Italy"}, alias: []string{"米兰", "米蘭", "罗马", "羅馬", "Milan", "Rome"}, codes: []string{"ITA", "MXP", "LIN", "FCO"}},
	{code: "ES", zh: []string{"西班牙"}, en: []string{"Spain"}, alias: []string{"马德里", "馬德里", "巴塞罗那", "Madrid", "Barcelona"}, codes: []string{"ESP", "MAD", "BCN"}},
	{code: "PT", zh: []string{"葡萄牙"}, en: []string{"Portugal"}, alias: []string{"里斯本", "Lisbon"}, codes: []string{"PRT", "LIS"}},
	{code: "IS", zh: []string{"冰岛", "冰島"}, en: []string{"Iceland"}, alias: []string{"雷克雅未克", "Reykjavik"}, codes: []string{"ISL", "KEF"}},
	{code: "NO", zh: []string{"挪威"}, en: []string{"Norway"}, alias: []string{"奥斯陆", "奧斯陸", "Oslo"}, codes: []string{"NOR", "OSL"}},
	{code: "SE", zh: []string{"瑞典"}, en: []string{"Sweden"}, alias: []string{"斯德哥尔摩", "斯德哥爾摩", "Stockholm"}, codes: []string{"SWE", "ARN"}},
	{code: "FI", zh: []string{"芬兰", "芬蘭"}, en: []string{"Finland"}, alias: []string{"赫尔辛基", "赫爾辛基", "Helsinki"}, codes: []string{"FIN", "HEL"}},
	{code: "DK", zh: []string{"丹麦", "丹麥"}, en: []string{"Denmark"}, alias: []string{"哥本哈根", "Copenhagen"}, codes: []string{"DNK", "CPH"}},
	{code: "CZ", zh: []string{"捷克"}, en: []string{"Czech", "Czechia", "Czech Republic"}, alias: []string{"布拉格", "Prague"}, codes: []string{"CZE", "PRG"}},
	{code: "SK", zh: []string{"斯洛伐克"}, en: []string{"Slovakia"}, codes: []string{"SVK"}},
	{code: "SI", zh: []string{"斯洛文尼亚", "斯洛維尼亞"}, en: []string{"Slovenia"}, codes: []string{"SVN"}},
	{code: "HU", zh: []string{"匈牙利"}, en: []string{"Hungary"}, alias: []string{"布达佩斯", "Budapest"}, codes: []string{"HUN", "BUD"}},
	{code: "RO", zh: []string{"罗马尼亚", "羅馬尼亞"}, en: []string{"Romania"}, alias: []string{"布加勒斯特", "Bucharest"}, codes: []string{"ROU", "OTP"}},
	{code: "BG", zh: []string{"保加利亚", "保加利亞"}, en: []string{"Bulgaria"}, alias: []string{"索菲亚", "Sofia"}, codes: []string{"BGR", "SOF"}},
	{code: "GR", zh: []string{"希腊", "希臘"}, en: []string{"Greece"}, alias: []string{"雅典", "Athens"}, codes: []string{"GRC", "ATH"}},
	{code: "RS", zh: []string{"塞尔维亚", "塞爾維亞"}, en: []string{"Serbia"}, alias: []string{"贝尔格莱德", "Belgrade"}, codes: []string{"SRB", "BEG"}},
	{code: "HR", zh: []string{"克罗地亚", "克羅地亞"}, en: []string{"Croatia"}, codes: []string{"HRV", "ZAG"}},
	{code: "EE", zh: []string{"爱沙尼亚", "愛沙尼亞"}, en: []string{"Estonia"}, alias: []string{"塔林", "Tallinn"}, codes: []string{"EST", "TLL"}},
	{code: "LV", zh: []string{"拉脱维亚", "拉脫維亞"}, en: []string{"Latvia"}, alias: []string{"里加", "Riga"}, codes: []string{"LVA", "RIX"}},
	{code: "LT", zh: []string{"立陶宛"}, en: []string{"Lithuania"}, alias: []string{"维尔纽斯", "Vilnius"}, codes: []string{"LTU", "VNO"}},
	{code: "MT", zh: []string{"马耳他", "馬爾他"}, en: []string{"Malta"}, codes: []string{"MLT"}},
	{code: "US", zh: []string{"美国", "美國", "美利坚"}, en: []string{"United States", "America", "USA"}, alias: []string{"美西", "美东", "美東", "美南", "美北", "美中", "洛杉矶", "洛杉磯", "圣何塞", "聖何塞", "硅谷", "矽谷", "旧金山", "舊金山", "西雅图", "西雅圖", "芝加哥", "达拉斯", "達拉斯", "纽约", "紐約", "迈阿密", "邁阿密", "亚特兰大", "凤凰城", "鳳凰城", "拉斯维加斯", "弗里蒙特", "波特兰", "丹佛", "华盛顿", "弗吉尼亚", "维吉尼亚", "俄勒冈", "俄亥俄", "加州", "德州", "新泽西", "夏威夷", "阿什本", "沪美", "广美", "深美", "Los Angeles", "San Jose", "Silicon Valley", "San Francisco", "Seattle", "Chicago", "Dallas", "New York", "Miami", "Atlanta", "Phoenix", "Las Vegas", "Fremont", "Portland", "Denver", "Washington", "Virginia", "Oregon", "Ohio", "California", "Texas", "New Jersey", "Hawaii", "Ashburn", "Buffalo", "Kansas City"}, codes: []string{"LAX", "SJC", "SFO", "SEA", "ORD", "DFW", "JFK", "NYC", "EWR", "IAD", "ATL", "MIA", "PHX", "LAS", "DEN", "PDX", "HNL", "BOS"}, lower: true},
	{code: "CA", zh: []string{"加拿大"}, en: []string{"Canada"}, alias: []string{"多伦多", "多倫多", "温哥华", "溫哥華", "蒙特利尔", "蒙特利爾", "Toronto", "Vancouver", "Montreal"}, codes: []string{"CAN", "YYZ", "YVR", "YUL"}, lower: true},
	{code: "MX", zh: []string{"墨西哥"}, en: []string{"Mexico"}, alias: []string{"克雷塔罗", "Queretaro", "Querétaro"}, codes: []string{"MEX", "QRO"}},
	{code: "BR", zh: []string{"巴西"}, en: []string{"Brazil", "Brasil"}, alias: []string{"圣保罗", "聖保羅", "Sao Paulo", "São Paulo"}, codes: []string{"BRA", "GRU"}},
	{code: "AR", zh: []string{"阿根廷"}, en: []string{"Argentina"}, alias: []string{"布宜诺斯艾利斯", "Buenos Aires"}, codes: []string{"ARG", "EZE"}},
	{code: "CL", zh: []string{"智利"}, en: []string{"Chile"}, alias: []string{"Santiago"}, codes: []string{"CHL", "SCL"}},
	{code: "CO", zh: []string{"哥伦比亚", "哥倫比亞"}, en: []string{"Colombia"}, alias: []string{"波哥大", "Bogota", "Bogotá"}, codes: []string{"COL", "BOG"}},
	{code: "PE", zh: []string{"秘鲁", "秘魯"}, en: []string{"Peru"}, alias: []string{"利马", "Lima"}, codes: []string{"PER", "LIM"}},
	{code: "VE", zh: []string{"委内瑞拉", "委內瑞拉"}, en: []string{"Venezuela"}, codes: []string{"VEN"}},
	{code: "PA", zh: []string{"巴拿马", "巴拿馬"}, en: []string{"Panama"}, codes: []string{"PAN", "PTY"}},
	{code: "CR", zh: []string{"哥斯达黎加", "哥斯大黎加"}, en: []string{"Costa Rica"}, codes: []string{"CRI"}},
	{code: "AU", zh: []string{"澳大利亚", "澳大利亞", "澳洲"}, en: []string{"Australia"}, alias: []string{"悉尼", "雪梨", "墨尔本", "墨爾本", "布里斯班", "珀斯", "Sydney", "Melbourne", "Brisbane", "Perth"}, codes: []string{"AUS", "SYD", "MEL", "BNE"}, lower: true},
	{code: "NZ", zh: []string{"新西兰", "紐西蘭", "新西蘭"}, en: []string{"New Zealand"}, alias: []string{"奥克兰", "奧克蘭", "Auckland"}, codes: []string{"NZL", "AKL"}},
	{code: "ZA", zh: []string{"南非"}, en: []string{"South Africa"}, alias: []string{"约翰内斯堡", "約翰尼斯堡", "开普敦", "Johannesburg", "Cape Town"}, codes: []string{"ZAF", "JNB", "CPT"}},
	{code: "EG", zh: []string{"埃及"}, en: []string{"Egypt"}, alias: []string{"开罗", "開羅", "Cairo"}, codes: []string{"EGY", "CAI"}},
	{code: "NG", zh: []string{"尼日利亚", "奈及利亞"}, en: []string{"Nigeria"}, alias: []string{"拉各斯", "Lagos"}, codes: []string{"NGA"}},
	{code: "KE", zh: []string{"肯尼亚", "肯亞"}, en: []string{"Kenya"}, alias: []string{"内罗毕", "Nairobi"}, codes: []string{"KEN", "NBO"}},
	{code: "MA", zh: []string{"摩洛哥"}, en: []string{"Morocco"}, codes: []string{"MAR"}},
	{code: "CN", zh: []string{"中国", "中國", "大陆", "大陸", "回国", "回國"}, en: []string{"China", "Mainland"}, alias: []string{"上海", "北京", "广州", "廣州", "深圳", "杭州", "成都", "Shanghai", "Beijing", "Guangzhou", "Shenzhen"}, codes: []string{"CHN", "PEK", "PVG", "SHA"}},
}

// regionRelayMarkers follow an ENTRY region in relay names ("香港中转",
// "HK→"); a match immediately followed by one counts for little.
var regionRelayMarkers = []string{"中转", "中轉", "转", "轉", "入口", "relay", "transit", "→", "->", "=>", "⇒", "➡", "➜", "⟶", "至"}

// codeOverrides re-map codes whose meaning in node names differs from ISO:
// "UK" is Britain, "LA" / "NY" are US cities rather than Laos.
var codeOverrides = map[string]regionCodeKeyword{
	"UK": {region: "GB", code: "UK", lower: true},
	"LA": {region: "US", code: "LA"},
	"NY": {region: "US", code: "NY"},
}

// ambiguousAlpha2 are ISO codes that read as ordinary words or labels in
// node names ("NO.1", "ID", "IT", "CO", "AT", "AM"); their regions are
// still detected from flags and names.
var ambiguousAlpha2 = map[string]bool{
	"NO": true, "ID": true, "IT": true, "IS": true, "AM": true, "PE": true,
	"MA": true, "CO": true, "BE": true, "CH": true, "AT": true, "SA": true,
	"OM": true, "MD": true, "CR": true, "PA": true, "LT": true, "SI": true,
	"GE": true, "LB": true, "KE": true, "BN": true, "MT": true,
}

// flagOverrides re-map flags used as stand-ins (🇺🇲 for the US).
var flagOverrides = map[string]string{"UK": "GB", "UM": "US"}

type regionKeyword struct {
	region string
	text   string // lower-cased for Latin, as-is for CJK
	latin  bool   // needs letter boundaries and case folding
	weight int
}

type regionCodeKeyword struct {
	region string
	code   string // upper case
	lower  bool
}

type regionNameIndex struct {
	keywords []regionKeyword
	codes    map[string]regionCodeKeyword
	byCode   map[string]*builtinRegion
	lookup   map[string]string // normalised name / alias / code → region code
}

var builtinRegionIndex = buildRegionNameIndex()

func buildRegionNameIndex() *regionNameIndex {
	index := &regionNameIndex{
		codes:  make(map[string]regionCodeKeyword),
		byCode: make(map[string]*builtinRegion),
		lookup: make(map[string]string),
	}
	addKeyword := func(region, text string, weight int) {
		latin := isLatinText(text)
		normalised := text
		if latin {
			normalised = strings.ToLower(text)
		}
		index.keywords = append(index.keywords, regionKeyword{region: region, text: normalised, latin: latin, weight: weight})
		index.lookup[strings.ToLower(text)] = region
	}
	for i := range builtinRegions {
		region := &builtinRegions[i]
		index.byCode[region.code] = region
		index.lookup[strings.ToLower(region.code)] = region.code
		for _, name := range region.zh {
			addKeyword(region.code, name, regionWeightName)
		}
		for _, name := range region.en {
			addKeyword(region.code, name, regionWeightName)
		}
		for _, alias := range region.alias {
			weight := regionWeightName
			if utf8.RuneCountInString(alias) == 1 {
				// Single-character shorthands ("港") are weak evidence.
				weight = regionWeightCode
			}
			addKeyword(region.code, alias, weight)
		}
		if !ambiguousAlpha2[region.code] {
			index.codes[region.code] = regionCodeKeyword{region: region.code, code: region.code, lower: region.lower}
		}
		for _, code := range region.codes {
			index.codes[code] = regionCodeKeyword{region: region.code, code: code}
			index.lookup[strings.ToLower(code)] = region.code
		}
	}
	for code, keyword := range codeOverrides {
		index.codes[code] = keyword
		if code == "UK" {
			index.lookup[strings.ToLower(code)] = keyword.region
		}
	}
	// Longest keywords first, so a scan that stops at the first hit per
	// position still prefers "印度尼西亚" over "印度".
	sort.SliceStable(index.keywords, func(i, j int) bool {
		return len(index.keywords[i].text) > len(index.keywords[j].text)
	})
	return index
}

func isLatinText(text string) bool {
	for _, r := range text {
		if r > unicode.MaxLatin1 && !unicode.Is(unicode.Latin, r) {
			return false
		}
	}
	return true
}

// asciiLower lower-cases ASCII letters only, keeping byte offsets intact.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// codeIsNoise filters code matches that are something else in context:
// "CN2" is a carrier backbone and "100GB" / "1.5 GB" a traffic quota.
func codeIsNoise(text string, start, end int, upper string) bool {
	switch upper {
	case "CN":
		return end < len(text) && text[end] == '2'
	case "GB":
		before := strings.TrimRight(text[:start], " ")
		return before != "" && before[len(before)-1] >= '0' && before[len(before)-1] <= '9'
	}
	return false
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// latinBoundaryBefore / After report whether position i in s sits on a
// letter boundary. Digits count as boundaries so "HK01" still matches HK.
func latinBoundaryBefore(s string, i int) bool {
	if i <= 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return !unicode.IsLetter(r)
}

func latinBoundaryAfter(s string, i int) bool {
	if i >= len(s) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return !unicode.IsLetter(r)
}

type regionMatch struct {
	region string
	start  int
	end    int
	weight float64
}

// normaliseRegionCode upper-cases a user-supplied region code or name and
// resolves built-in names ("香港", "japan", "UK") to their codes. Unknown
// input is returned upper-cased, so custom regions ("IPLC") keep working.
func normaliseRegionCode(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if code, ok := builtinRegionIndex.lookup[strings.ToLower(trimmed)]; ok {
		return code
	}
	if code := flagRegion(trimmed); code != "" && utf8.RuneCountInString(trimmed) == 2 {
		return code
	}
	return strings.ToUpper(trimmed)
}

// flagRegion returns the region code of the first flag emoji in s, or "".
func flagRegion(s string) string {
	var prev rune
	for _, r := range s {
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			if prev != 0 {
				code := string([]rune{'A' + prev - 0x1F1E6, 'A' + r - 0x1F1E6})
				if override, ok := flagOverrides[code]; ok {
					code = override
				}
				return code
			}
			prev = r
			continue
		}
		prev = 0
	}
	return ""
}

// regionFlag renders the flag emoji for an ISO alpha-2 code, or "".
func regionFlag(code string) string {
	if len(code) != 2 || !isASCIILetter(code[0]) || !isASCIILetter(code[1]) {
		return ""
	}
	upper := strings.ToUpper(code)
	return string([]rune{0x1F1E6 + rune(upper[0]-'A'), 0x1F1E6 + rune(upper[1]-'A')})
}

// regionDisplayNames returns the built-in Chinese and English names of a
// region code, empty for custom regions.
func regionDisplayNames(code string) (zh, en string) {
	if region := builtinRegionIndex.byCode[code]; region != nil {
		if len(region.zh) > 0 {
			zh = region.zh[0]
		}
		if len(region.en) > 0 {
			en = region.en[0]
		}
	}
	if code == regionUnknown {
		return "其他", "Other"
	}
	return
}

// classifyRegionByName detects the exit region of a node from its name.
// Returns "" when the name carries no recognisable region.
func classifyRegionByName(name string) string {
	if name == "" {
		return ""
	}
	text := norm.NFKC.String(name)
	lower := asciiLower(text)
	var matches []regionMatch

	// Flags. NFKC leaves regional indicators alone.
	var prevStart int
	var prev rune
	for i, r := range text {
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			if prev != 0 {
				code := string([]rune{'A' + prev - 0x1F1E6, 'A' + r - 0x1F1E6})
				if override, ok := flagOverrides[code]; ok {
					code = override
				}
				matches = append(matches, regionMatch{region: code, start: prevStart, end: i + utf8.RuneLen(r), weight: regionWeightFlag})
				prev = 0
				continue
			}
			prev, prevStart = r, i
			continue
		}
		prev = 0
	}

	// Names and aliases. lower keeps the byte offsets of text.
	for _, keyword := range builtinRegionIndex.keywords {
		for offset := 0; offset < len(lower); {
			index := strings.Index(lower[offset:], keyword.text)
			if index < 0 {
				break
			}
			start := offset + index
			end := start + len(keyword.text)
			offset = end
			if keyword.latin && (!latinBoundaryBefore(lower, start) || !latinBoundaryAfter(lower, end)) {
				continue
			}
			matches = append(matches, regionMatch{region: keyword.region, start: start, end: end, weight: float64(keyword.weight)})
		}
	}

	// Codes: scan maximal ASCII letter runs and look each run up.
	for i := 0; i < len(text); {
		if !isASCIILetter(text[i]) {
			i++
			continue
		}
		j := i
		for j < len(text) && isASCIILetter(text[j]) {
			j++
		}
		word := text[i:j]
		if latinBoundaryBefore(text, i) && latinBoundaryAfter(text, j) && (len(word) == 2 || len(word) == 3) {
			upper := strings.ToUpper(word)
			if keyword, ok := builtinRegionIndex.codes[upper]; ok && (word == upper || keyword.lower) && !codeIsNoise(text, i, j, upper) {
				matches = append(matches, regionMatch{region: keyword.region, start: i, end: j, weight: regionWeightCode})
			}
		}
		i = j
	}
	if len(matches) == 0 {
		return ""
	}

	// Drop matches nested in longer ones (prefer "印度尼西亚" to "印度",
	// "Hong Kong" to "Kong" codes, "美西" to "美").
	sort.SliceStable(matches, func(i, j int) bool {
		li, lj := matches[i].end-matches[i].start, matches[j].end-matches[j].start
		if li != lj {
			return li > lj
		}
		return matches[i].start < matches[j].start
	})
	accepted := matches[:0:0]
	for _, match := range matches {
		overlapped := false
		for _, kept := range accepted {
			if match.start < kept.end && kept.start < match.end {
				overlapped = true
				break
			}
		}
		if !overlapped {
			accepted = append(accepted, match)
		}
	}

	// Discount entry regions of relay names.
	for i := range accepted {
		rest := strings.TrimLeft(lower[accepted[i].end:], " -_|·・")
		for _, marker := range regionRelayMarkers {
			if strings.HasPrefix(rest, marker) {
				accepted[i].weight *= 0.2
				break
			}
		}
	}

	type tally struct {
		weight float64
		last   int
	}
	scores := make(map[string]*tally)
	for _, match := range accepted {
		t := scores[match.region]
		if t == nil {
			t = &tally{}
			scores[match.region] = t
		}
		t.weight += match.weight
		if match.start > t.last {
			t.last = match.start
		}
	}
	// Mainland China in a node name is nearly always the entry of a relay
	// ("中国-香港 IPLC"); only pick it when nothing else matched.
	if len(scores) > 1 {
		delete(scores, "CN")
	}
	var (
		best      string
		bestScore float64
		bestLast  = -1
	)
	for region, t := range scores {
		switch {
		case t.weight > bestScore,
			t.weight == bestScore && t.last > bestLast,
			t.weight == bestScore && t.last == bestLast && region < best:
			best, bestScore, bestLast = region, t.weight, t.last
		}
	}
	return best
}
