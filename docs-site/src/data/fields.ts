// Config reference data. Mirrors option/smart.go (SmartOutboundOptions and
// friends) and option/group.go (GroupCommonOption); defaults come from
// newSmart (protocol/group/smart.go), newSmartBalance and friends
// (protocol/group/smart_lb*.go, smart_region.go), experimental/smart and
// experimental/geox. Keep in lockstep with the Go source when fields change.
//
// Descriptions use the inline syntax from src/lib/inline.ts:
// `code`, **bold**, [text](/zh/page/#anchor). Blank line = new paragraph.

export interface Field {
  name: string;
  type: string;
  default?: string;
  required?: boolean;
  zh: string;
  en: string;
}

// GroupCommonOption: shared by every group type of this fork.
export const membershipFields: Field[] = [
  {
    name: 'outbounds',
    type: 'string[]',
    zh: '本组的成员，写出站的标签（tag）。成员可以是普通节点，也可以是 `selector`、`urltest` 等其他策略组。\n\n`outbounds` 与 `providers` 至少写一个，否则启动报错 `missing outbound and provider tags`。这里列出的出站一定会加入本组，不受下面各项筛选的影响。同一标签写两次报错 `duplicate tag: <tag>`；写了不存在的标签，启动报错 `outbound <i> not found: <tag>`。',
    en: 'Members of the group, as outbound tags. A member can be a plain node or another group such as `selector` or `urltest`.\n\nSet at least one of `outbounds` and `providers`, otherwise startup fails with `missing outbound and provider tags`. Outbounds listed here always join the group; none of the filters below apply to them. Listing a tag twice fails with `duplicate tag: <tag>`; a tag that does not exist fails startup with `outbound <i> not found: <tag>`.',
  },
  {
    name: 'providers',
    type: 'string[]',
    zh: '要使用的订阅（Provider）的标签。订阅中的节点经下面各项筛选后成为本组成员。订阅加载或更新后，本组自动重建成员列表，不需要重启；离开本组的节点，其学习数据随之删除。\n\n订阅节点的标签形如 `<订阅标签>/<节点名>`。写了不存在的订阅，启动报错 `outbound provider <i> not found: <tag>`。',
    en: 'Tags of the subscriptions (providers) to use. Their nodes join the group after the filters below. When a subscription loads or updates, the group rebuilds its member list on its own, with no restart; the learned data of nodes that leave the group is dropped.\n\nSubscription members are tagged `<provider tag>/<node name>`. A provider that does not exist fails startup with `outbound provider <i> not found: <tag>`.',
  },
  {
    name: 'use_all_providers',
    type: 'bool',
    default: 'false',
    zh: '使用配置中的全部订阅，此时忽略 `providers`。',
    en: 'Uses every subscription in the configuration; `providers` is then ignored.',
  },
  {
    name: 'include',
    type: 'regex',
    zh: '只保留标签匹配这个正则（Go RE2 语法）的订阅节点，例如 `香港|HK`。匹配的是完整标签 `<订阅标签>/<节点名>`，所以一般写不锚定的模式。正则写错时读取配置就会报错。',
    en: 'Keeps only the subscription members whose tag matches this regex (Go RE2 syntax), for example `Hong Kong|HK`. The pattern is matched against the full tag `<provider tag>/<node name>`, so an unanchored pattern is usually what you want. An invalid regex is a config error.',
  },
  {
    name: 'exclude',
    type: 'regex',
    zh: '去掉标签匹配这个正则的订阅节点，常用来排除“剩余流量”“到期时间”之类的提示条目，例如 `(?i)剩余|到期|官网`。先按 `exclude` 排除，再按 `include` 筛选。\n\n筛选后一个成员都不剩时，本组改用内置的直连出站 `Compatible`，**流量会直接连出、不经过代理**，请确认筛选条件没有写错。',
    en: 'Drops the subscription members whose tag matches this regex, typically the "traffic left" or "expires on" entries some subscriptions include, for example `(?i)traffic|expire`. `exclude` is applied before `include`.\n\nIf no member is left, the group falls back to the built-in direct outbound `Compatible` and **traffic goes out directly, without a proxy**, so double-check your patterns.',
  },
  {
    name: 'include_type',
    type: 'string | string[]',
    zh: '只保留这些协议类型的订阅节点，如 `["vless", "hysteria2"]`。不区分大小写，接受 Clash 订阅中的写法与常见简称：`ss`、`socks5`、`hy`、`hy2`、`wg`、`naiveproxy`、`shadow-tls`、`openvpn`、`masque`。写了不认识的类型报错 `include_type: unknown outbound type: <type>`。',
    en: 'Keeps only subscription members of these protocol types, such as `["vless", "hysteria2"]`. Case-insensitive; Clash subscription names and common short forms are accepted: `ss`, `socks5`, `hy`, `hy2`, `wg`, `naiveproxy`, `shadow-tls`, `openvpn`, `masque`. An unknown type fails with `include_type: unknown outbound type: <type>`.',
  },
  {
    name: 'exclude_type',
    type: 'string | string[]',
    zh: '去掉这些协议类型的订阅节点，写法同 `include_type`，优先于它。',
    en: 'Drops subscription members of these protocol types; same syntax as `include_type`, and it takes precedence.',
  },
  {
    name: 'include_transport',
    type: 'string | string[]',
    zh: '只保留使用这些传输层的订阅节点：`tcp`（未配置传输层）、`ws`、`grpc`、`http`、`httpupgrade`、`quic`，以及插件提供的传输（如 `xhttp`）；也接受 `websocket`、`h2`、`gun`、`raw`、`splithttp` 等别名。只有 VMess、VLESS、Trojan、Shadowsocks（v2ray-plugin）节点有传输层，其他协议（如 hysteria2、wireguard）会被它去掉。写错报错 `include_transport: unknown transport: <name>`。',
    en: 'Keeps only subscription members using these transports: `tcp` (no transport configured), `ws`, `grpc`, `http`, `httpupgrade`, `quic`, and plugin transports such as `xhttp`; aliases such as `websocket`, `h2`, `gun`, `raw` and `splithttp` are accepted. Only VMess, VLESS, Trojan and Shadowsocks (v2ray-plugin) nodes have a transport, so other protocols (hysteria2, wireguard, …) are dropped by it. An unknown name fails with `include_transport: unknown transport: <name>`.',
  },
  {
    name: 'exclude_transport',
    type: 'string | string[]',
    zh: '去掉使用这些传输层的订阅节点，写法同 `include_transport`。没有传输层的协议不受影响。',
    en: 'Drops subscription members using these transports; same syntax as `include_transport`. Protocols without a transport are not affected.',
  },
  {
    name: 'network',
    type: 'string | string[]',
    zh: '只保留支持这些网络（`tcp`、`udp`）的订阅节点。要求 `udp` 时，最近一次 UDP 探测失败的节点也会被去掉。',
    en: 'Keeps only subscription members that support these networks (`tcp`, `udp`). With `udp`, members whose latest UDP probe failed are dropped as well.',
  },
];

export const probeFields: Field[] = [
  {
    name: 'url',
    type: 'string',
    default: 'https://www.gstatic.com/generate_204',
    zh: '健康检查访问的地址。Smart 经每个成员发出 HTTP HEAD 请求，单次最长 15 秒；结果写入面板显示的延迟记录，并作为探测延迟参与评分。多个组共用一个探测器，同一成员半个 `interval` 内的结果会直接复用。\n\n发往这个地址所在主机的连接不参与学习，避免健康检查本身影响评分。',
    en: 'The address health checks request. Smart sends an HTTP HEAD request through every member, up to 15 s each; the result goes into the delay history dashboards show and into the score as the probe delay. Groups share one prober, and a member result younger than half an `interval` is reused.\n\nConnections to this URL\'s host are never learned, so health checks cannot skew the score.',
  },
  {
    name: 'interval',
    type: 'duration',
    default: '5m',
    zh: '本组在使用中时的健康检查周期，第一轮在启动 10 秒后。必须不大于 `idle_timeout`，否则启动报错 `interval must be less or equal than idle_timeout`。`0` 或负数按 `5m` 处理。',
    en: 'Health-check period while the group is in use; the first round runs 10 s after start. It must not exceed `idle_timeout`, otherwise startup fails with `interval must be less or equal than idle_timeout`. `0` or negative values become `5m`.',
  },
  {
    name: 'idle_timeout',
    type: 'duration',
    default: '30m',
    zh: '本组超过这么久没有新连接后，暂停健康检查与封锁复查，手机待机时不耗电；有新连接后自动恢复。`0` 或负数按 `30m` 处理。',
    en: 'After the group has had no new connection for this long, health checks and block rechecks pause, so an idle phone does not spend battery on them; they resume with the next connection. `0` or negative values become `30m`.',
  },
  {
    name: 'timeout',
    type: 'duration',
    default: '5s',
    zh: '单次拨号的上限。成员积累了建连耗时后，它自己的超时是平均建连耗时 × 5（至少 1 秒，不超过本值），这样慢节点不会拖住整批拨号。因自适应超时到期而失败的拨号不计为节点失败。`0` 或负数按 `5s` 处理。',
    en: 'Upper bound of one dial. Once a member has connect-time history, its own timeout is its average connect time × 5 (at least 1 s, at most this value), so a slow node cannot hold a whole dial round. A dial that fails only because such an adaptive timeout expired does not count as a node failure. `0` or negative values become `5s`.',
  },
  {
    name: 'expected_status',
    type: 'string',
    default: '*',
    zh: '哪些 HTTP 状态码算健康检查成功。写法与 `urltest` 相同：单个状态码 `204`、范围 `200-299`，或用 `/` 连接多项，如 `204/300-399`。\n\n**留空或写 `*` 时任何 HTTP 响应都算成功**，包括强制门户（酒店、机场 Wi-Fi 的登录页）返回的重定向。要严格判断能否上网，写 `204` 并使用默认的 `url`。格式错误时启动报错，如 `urltest: invalid expected-status: <part>`。',
    en: 'Which HTTP status codes count as a successful health check. Same syntax as `urltest`: a single code `204`, a range `200-299`, or several joined by `/`, such as `204/300-399`.\n\n**Empty or `*` accepts any HTTP response**, including the redirects a captive portal (hotel or airport Wi-Fi login) returns. To check real internet access, set `204` with the default `url`. Bad syntax fails startup, for example `urltest: invalid expected-status: <part>`.',
  },
];

export const selectionFields: Field[] = [
  {
    name: 'policy_priority',
    type: 'string',
    zh: '按节点名称调整优先级，写法同 vernesong/mihomo：`模式:系数;模式:系数`，例如 `香港|HK:1.3;JP:1.1;(?i)x[2-9]:0.7`。系数必须是正数，大于 1 偏好、小于 1 回避。\n\n模式能编译为正则（RE2）时按正则匹配节点名称的任意位置，否则按子串匹配；区分大小写（正则可以加 `(?i)`）；模式中的 `:` 写成 `\\:`；**按顺序取第一条命中的规则**，不相乘。格式错误或系数不是正数时启动报错，如 `policy_priority: "HK" must be in \'pattern:factor\' format`。\n\n系数乘在综合分上，作用很强，但不会让可靠性明显落后的节点胜出，见 [节点偏好](/zh/scoring/#节点偏好)。',
    en: 'Adjusts priority by node name, in vernesong/mihomo syntax: `pattern:factor;pattern:factor`, for example `Hong Kong|HK:1.3;JP:1.1;(?i)x[2-9]:0.7`. Factors must be positive: above 1 prefers, below 1 avoids.\n\nA pattern that compiles as a regex (RE2) matches anywhere in the node name, otherwise it is a substring; matching is case-sensitive (add `(?i)` to a regex); write `:` inside a pattern as `\\:`. **The first matching rule wins**; factors do not multiply. Bad syntax or a non-positive factor fails startup, for example `policy_priority: "HK" must be in \'pattern:factor\' format`.\n\nThe factor multiplies the comprehensive score, which is a strong effect, yet it never lets a clearly less reliable node win; see [Node preferences](/en/scoring/#node-preferences).',
  },
  {
    name: 'prefer_asn',
    type: 'bool',
    default: 'false',
    zh: '按目标 IP 所属的网络（ASN）归并“服务”：没有路由规则、或规则是 `geosite-cn`、`geoip-xx` 这类大合集时，同一网络的网站共享学习结果与选中的节点，新网站也能沿用经验。Cloudflare、Akamai、AWS 等多方共用的网络不按 ASN 归并，而是按网站区分。需要 ASN 数据库，未配置时自动下载 GeoLite2-ASN。详见 [服务键](/zh/service-keys/#prefer_asn)。',
    en: 'Groups "services" by the network (ASN) of the destination IP: without a routing rule, or under a broad rule such as `geosite-cn` or `geoip-xx`, sites on the same network share what was learned and the chosen node, so a new site benefits right away. Networks shared by unrelated parties (Cloudflare, Akamai, AWS, …) are not grouped by ASN; their sites stay separate. Needs an ASN database; GeoLite2-ASN is downloaded when none is configured. See [Service keys](/en/service-keys/#prefer_asn).',
  },
  {
    name: 'tolerance',
    type: 'uint16 (ms)',
    default: '0',
    zh: '排序服务池之外的备用成员时，探测延迟相差不超过这么多毫秒的视为相同，保持配置中的先后顺序。`0` 表示严格按延迟排序。只影响备用顺序，不影响主选。',
    en: 'When ordering the fallback members outside the serving pool, probe delays within this many milliseconds count as equal and keep their configured order. `0` sorts strictly by delay. It only affects fallback order, never the primary choice.',
  },
  {
    name: 'max_failed_times',
    type: 'int',
    default: '5',
    zh: '同一网站上连续出现这么多次连接错误（拨号失败或传输中出错，每次距上次失败不超过 5 分钟），就把这个节点对该网站封锁 24 小时（封锁代码 `error`）。`0` 或负数按 `5` 处理。见 [封锁](/zh/blocks-and-probes/#封锁代码)。',
    en: 'After this many connection errors in a row for the same site (dial failures or errors mid-transfer, each within 5 minutes of the previous failure there), the node is blocked for that site for 24 hours (block code `error`). `0` or negative values become `5`. See [Blocks](/en/blocks-and-probes/#block-codes).',
  },
  {
    name: 'interrupt_exist_connections',
    type: 'bool',
    default: 'false',
    zh: '手动指定的节点变化时（指定、更换、取消，包括组测速自动解除指定），是否同时关闭本组已有的连接，让客户端重连到新选择。关闭时只影响新连接；sing-box 自身的内部连接总会被关闭。`smart-loadbalance` 锁定或解锁地区时同样适用。\n\n与此无关，Smart 自己也会在需要时关闭连接：服务收敛到新节点、节点对某服务被封锁时，见 [服务键](/zh/service-keys/#收敛)。',
    en: 'Whether a change of the manual pin (setting, changing or clearing it, including the automatic release by a group delay test) also closes the group\'s existing connections so clients reconnect to the new choice. When off, only new connections are affected; sing-box\'s own internal connections are always closed. The same applies to locking or unlocking a region of `smart-loadbalance`.\n\nIndependently of this flag, Smart closes connections itself when needed: when a service converges on a new node, or a node gets blocked for a service; see [Service keys](/en/service-keys/#convergence).',
  },
  {
    name: 'disable_udp',
    type: 'bool',
    default: 'false',
    zh: '本组只处理 TCP。经本组的 UDP 请求会失败，报错 `UDP is disabled for <tag>`，所以要用路由规则把 UDP（如 QUIC、游戏、语音）交给其他出站。',
    en: 'The group handles TCP only. UDP requests through it fail with `UDP is disabled for <tag>`, so route UDP traffic (QUIC, games, voice) to another outbound with rules.',
  },
];

export const learningFields: Field[] = [
  {
    name: 'use_lightgbm',
    type: 'bool',
    default: 'false',
    zh: '用 LightGBM 模型（`experimental.smart.lightgbm` 中所有组共用的那一个）计算连接质量，代替 mihomo 的场景公式。模型缺失时自动下载一次；下载完成前、或模型与当前特征布局不兼容时，仍用场景公式。见 [LightGBM 模型](/zh/lightgbm/)。',
    en: 'Computes connection quality with the LightGBM model shared by all groups (`experimental.smart.lightgbm`) instead of mihomo\'s scene formula. A missing model is downloaded once; until it arrives, or when the model does not fit the current feature layout, the scene formula is used. See [LightGBM model](/en/lightgbm/).',
  },
  {
    name: 'collect_data',
    type: 'bool',
    default: 'false',
    zh: '每条连接结束时把它的 32 个特征与质量写入 CSV，用来训练自己的模型。所有组写入同一个文件（`experimental.smart.collector`）。不打算训练模型时不要开启。',
    en: 'Writes the 32 features and the quality of every finished connection to a CSV, for training your own model. All groups write to one file (`experimental.smart.collector`). Leave it off unless you plan to train a model.',
  },
  {
    name: 'sample_rate',
    type: 'float',
    default: '1',
    zh: '`collect_data` 的采样比例，取值 (0, 1]，如 `0.3` 只记录 30% 的连接。`0`、负数或大于 1 按 `1` 处理。',
    en: 'Sampling ratio for `collect_data`, in (0, 1]; `0.3` records 30% of connections. `0`, negative values and values above 1 become `1`.',
  },
];

export const displayFields: Field[] = [
  {
    name: 'hidden',
    type: 'bool',
    default: 'false',
    zh: '在 Clash API 返回的组信息中带上 `hidden: true`，让面板隐藏本组。只影响显示，路由照常使用本组。',
    en: 'Adds `hidden: true` to the group in Clash API output so dashboards hide it. Display only; routing still uses the group.',
  },
  {
    name: 'icon',
    type: 'string',
    zh: '面板中显示的图标，原样通过 Clash API 返回，可以是图片 URL、data URI 或 emoji。',
    en: 'Icon shown in dashboards, returned verbatim by the Clash API: an image URL, a data URI or an emoji.',
  },
];

export const lightgbmFields: Field[] = [
  {
    name: 'model_path',
    type: 'string',
    default: 'Model.bin',
    zh: '模型文件的路径。相对路径基于 sing-box 的数据目录：命令行版本是 `-D` 指定的目录（未指定时为当前工作目录），图形客户端是应用自己的数据目录。',
    en: 'Path of the model file. A relative path resolves against the sing-box data directory: the directory given with `-D` for the command-line version (the working directory without it), or the app\'s own data directory in GUI clients.',
  },
  {
    name: 'url',
    type: 'string',
    default: 'vernesong/mihomo Model.bin',
    zh: '模型的下载地址，默认 `https://github.com/vernesong/mihomo/releases/download/LightGBM-Model/Model.bin`。换成自己训练的模型时改这里，或者直接替换本地文件并关闭 `auto_update`。',
    en: 'Model download URL; defaults to `https://github.com/vernesong/mihomo/releases/download/LightGBM-Model/Model.bin`. Point it at your own model, or replace the local file and keep `auto_update` off.',
  },
  {
    name: 'auto_update',
    type: 'bool',
    default: 'false',
    zh: '是否定期更新模型。开启后每隔 `update_interval` 检查一次，新模型下载完成后立即换用，无需重启。\n\n关闭时，模型文件缺失也会在后台下载一次；文件已存在就不再下载。',
    en: 'Whether to keep the model up to date. When on, it is checked every `update_interval`, and a new model takes over as soon as it is downloaded, with no restart.\n\nWhen off, a missing model file is still downloaded once in the background; an existing file is never downloaded again.',
  },
  {
    name: 'update_interval',
    type: 'duration',
    default: '72h',
    zh: '检查模型更新的间隔，只在 `auto_update` 开启时生效。`0` 或负数按 `72h` 处理。',
    en: 'How often to check for a new model; only used with `auto_update`. `0` or negative values become `72h`.',
  },
  {
    name: 'http_client',
    type: 'string | object',
    zh: '下载模型使用的 HTTP 客户端：顶层 `http_clients` 中的标签，或直接写一个对象。不写时使用 `download_detour`；两者都没有时使用默认 HTTP 客户端。',
    en: 'HTTP client for the model download: a tag from the top-level `http_clients`, or an inline object. Without it, `download_detour` is used; without either, the default HTTP client.',
  },
  {
    name: 'download_detour',
    type: 'string',
    zh: '旧字段：没有设置 `http_client` 时，经这个出站下载模型，例如 `direct`。不要让模型经过还没学好的 Smart 组本身下载。',
    en: 'Legacy field: without `http_client`, the model is downloaded through this outbound, for example `direct`. Do not download it through the Smart group that still has to learn.',
  },
];

export const collectorFields: Field[] = [
  {
    name: 'path',
    type: 'string',
    default: 'smart_weight_data.csv',
    zh: '训练数据 CSV 的路径，相对路径基于数据目录。已有文件的表头缺少 `cumul_loss_rate` 或 `exit_region` 列（旧格式）时，先改名为 `<path>.bak.<时间戳>` 备份，再新建文件。',
    en: 'Path of the training-data CSV, relative to the data directory. If an existing file\'s header lacks the `cumul_loss_rate` or `exit_region` column (an older format), the file is renamed to `<path>.bak.<timestamp>` and a new one is created.',
  },
  {
    name: 'size_limit_mb',
    type: 'float',
    default: '100',
    zh: 'CSV 文件的大小上限（MB），`0` 或负数按 `100` 处理。达到上限后停止写入并记录一条日志，不会轮转；删除文件后 5 秒内自动新建并恢复采集。',
    en: 'Size cap of the CSV in MB; `0` or negative values become `100`. At the cap, writing stops with one log line, with no rotation; after you delete the file, a new one is created and collection resumes within 5 s.',
  },
];

export const geoxFields: Field[] = [
  {
    name: 'enabled',
    type: 'bool',
    default: 'false',
    zh: '是否下载 `url` 中配置的文件。关闭时 Smart 也不会从这里取得数据库路径。\n\nSmart 需要的默认 ASN、国家数据库不受这个开关影响：需要时仍由 GeoX 在后台下载，并使用本节的下载设置。',
    en: 'Whether to download the files configured under `url`. When off, Smart gets no database paths from here either.\n\nThe default ASN and country databases Smart needs are not affected: when needed, GeoX still downloads them in the background with the download settings of this section.',
  },
  {
    name: 'url.asn',
    type: 'string | string[]',
    zh: 'ASN mmdb 的下载地址，可以写多个。第一个保存为 `GeoLite2-ASN.mmdb`，其余依次保存为 `GeoLite2-ASN-1.mmdb`、`GeoLite2-ASN-2.mmdb`……查询时按顺序，取第一个查到的结果。不写时，需要 ASN 的组（`prefer_asn`、`use_lightgbm`、`collect_data`）自动下载默认的 GeoLite2-ASN。',
    en: 'ASN mmdb download URL(s). The first is saved as `GeoLite2-ASN.mmdb`, the rest as `GeoLite2-ASN-1.mmdb`, `GeoLite2-ASN-2.mmdb` and so on; lookups go in order and the first hit wins. Without it, groups that need ASN data (`prefer_asn`, `use_lightgbm`, `collect_data`) download the default GeoLite2-ASN.',
  },
  {
    name: 'url.mmdb',
    type: 'string',
    zh: '国家 mmdb 的下载地址，保存为 `country.mmdb`。Smart 用它查目标所在国家，供 LightGBM、训练数据采集与 `smart-loadbalance` 使用。不写时，需要的组自动下载默认的 GeoLite2-Country。',
    en: 'Country mmdb download URL, saved as `country.mmdb`. Smart uses it to look up the destination country for LightGBM, training data and `smart-loadbalance`. Without it, groups that need one download the default GeoLite2-Country.',
  },
  {
    name: 'url.geoip',
    type: 'string',
    zh: 'geoip.dat 的下载地址。Smart 不读取这个文件。',
    en: 'geoip.dat download URL. Smart does not read this file.',
  },
  {
    name: 'url.geosite',
    type: 'string',
    zh: 'geosite.dat 的下载地址。Smart 不读取这个文件。',
    en: 'geosite.dat download URL. Smart does not read this file.',
  },
  {
    name: 'auto_update',
    type: 'bool',
    default: 'false',
    zh: '是否定期更新。开启后每隔 `update_interval` 更新一次每个文件；关闭时只在文件缺失时下载。mmdb 下载或更新后立即生效，无需重启。',
    en: 'Whether to keep the files up to date. When on, every file is refreshed every `update_interval`; when off, a file is downloaded only while it is missing. A downloaded or updated mmdb takes effect at once, with no restart.',
  },
  {
    name: 'update_interval',
    type: 'duration',
    default: '24h',
    zh: '自动更新的间隔，只在 `auto_update` 开启时生效。`0` 或负数按 `24h` 处理。',
    en: 'Auto-update interval; only used with `auto_update`. `0` or negative values become `24h`.',
  },
  {
    name: 'http_client / download_detour',
    type: 'string | object',
    zh: '下载使用的 HTTP 客户端，规则与 `experimental.smart.lightgbm` 相同。',
    en: 'HTTP client for downloads, with the same rules as `experimental.smart.lightgbm`.',
  },
];

// smart-loadbalance (option.SmartLoadBalanceOutboundOptions). Defaults
// come from newSmartBalance and friends in protocol/group/smart_lb*.go.

export const lbBalanceFields: Field[] = [
  {
    name: 'strategy',
    type: 'string',
    default: 'smart',
    zh: '在选中地区的节点池内分配连接的方式，见 [分配策略](/zh/smart-loadbalance/#分配策略)：\n\n`smart` 按质量加权分配，质量越好、当前连接越少的节点越容易被选中，适合大多数场景；`least-connections` 选当前连接最少的节点；`round-robin` 轮流使用；`weighted-round-robin` 按质量比例轮流；`weighted-random` 按质量加权随机；`random` 均匀随机；`consistent-hashing` 让同一网站（或同一亲和键）固定落到同一节点。\n\n不区分大小写，`_` 和空格等同于 `-`，接受别名（如 `lc`、`rr`、`wrr`、`chash`）。写错**会报错**：`unknown balance strategy: ...`。运行时可用 `PUT /smart/groups/{name}/balance` 切换，切换会保存到缓存文件，重启后保持。',
    en: 'How connections are spread across the node pool of the chosen region; see [Strategies](/en/smart-loadbalance/#strategies):\n\n`smart` weights by quality, so better nodes with fewer live connections are picked more often, and suits most setups; `least-connections` picks the node with the fewest live connections; `round-robin` takes turns; `weighted-round-robin` takes turns in proportion to quality; `weighted-random` draws at random weighted by quality; `random` draws uniformly; `consistent-hashing` keeps the same site (or the same affinity key) on the same node.\n\nCase-insensitive; `_` and spaces count as `-`, and aliases such as `lc`, `rr`, `wrr`, `chash` are accepted. An unknown value **is an error**: `unknown balance strategy: ...`. `PUT /smart/groups/{name}/balance` switches it at runtime; the change is saved to the cache file and survives a restart.',
  },
  {
    name: 'affinity',
    type: 'string',
    default: 'none',
    zh: '会话亲和：让哪些连接固定使用同一个节点，避免同一网站或同一设备在多个出口 IP 之间跳动。\n\n`none` 每条连接独立分配，分摊效果最好；`target` 同一目标（如 `*.example.com`）；`site` 同一可注册域名（如 `img.example.com` 与 `api.example.com`），适合登录状态与出口 IP 绑定的网站；`source` 同一客户端 IP；`source-site` 同一客户端访问同一网站。\n\n绑定按地区分别记录，节点不健康时自动重新分配。见 [会话亲和](/zh/smart-loadbalance/#会话亲和)。嵌套代理的前置组请保持 `none`。',
    en: 'Affinity: which connections stick to one node, so a site or a device does not hop between exit IPs.\n\n`none` places every connection independently and spreads the load best; `target` binds the same target (such as `*.example.com`); `site` binds the same registrable domain (such as `img.example.com` and `api.example.com`), for sites that tie logins to the exit IP; `source` binds the same client IP; `source-site` binds the same client visiting the same site.\n\nBindings are kept per region and re-placed when their node becomes unhealthy. See [Affinity](/en/smart-loadbalance/#affinity). Keep `none` on the front group of chained proxies.',
  },
  {
    name: 'affinity_ttl',
    type: 'duration',
    default: '10m',
    zh: '亲和绑定的有效期。每次经绑定节点成功连接都会重新计时，所以只要持续有流量，绑定就一直有效。`0` 或负数按 `10m` 处理。',
    en: 'Lifetime of an affinity binding. Every successful connection through the bound node restarts it, so a binding lasts as long as traffic keeps flowing. `0` or negative values become `10m`.',
  },
  {
    name: 'max_nodes',
    type: 'int',
    default: '0',
    zh: '节点池最多保留几个质量最好的节点，`0` 表示不限制。想把流量集中在少数最好的节点上时设置。负数报错。',
    en: 'Keeps at most this many of the best nodes in a pool; `0` means no limit. Set it to concentrate traffic on a few top nodes. Negative values are an error.',
  },
  {
    name: 'min_quality',
    type: 'float',
    default: '0.5',
    zh: '质量下限，取值 (0, 1]：质量低于池内最佳节点 × 该值的节点不分配连接。例如 `0.5` 表示只用质量不低于最佳节点一半的节点。调高更挑剔，调低能用上更多节点。`0` 或负数按默认值处理，大于 1 报错。',
    en: 'Quality floor in (0, 1]: nodes below the best node of the pool × this value get no connections. `0.5` means only nodes at least half as good as the best are used. Raise it to be pickier, lower it to use more nodes. `0` or negative values mean the default; values above 1 are an error.',
  },
  {
    name: 'max_connections_per_node',
    type: 'int',
    default: '0',
    zh: '单个节点的活跃连接（包括正在拨号的）达到这个数后，暂时不再分配新连接；池内所有节点都达到上限时仍照常分配。`0` 表示不限制，负数报错。适合限制每节点并发连接数的机场。',
    en: 'A node with this many live connections (dials in progress included) gets no new ones until some close; when every node of the pool is at the cap, they are used anyway. `0` means no limit; negative values are an error. Useful with providers that limit concurrent connections per node.',
  },
];

export const lbRegionFields: Field[] = [
  {
    name: 'mode',
    type: 'string',
    default: 'auto',
    zh: '为每条连接选择地区的方式，见 [地区模式](/zh/smart-loadbalance/#地区模式)：\n\n`auto` 按目标学习最优地区并记住它；`destination` 按目标所在国家选地区，适合游戏、本地流媒体和嵌套代理前置；`priority` 按 `priority` 的顺序取第一个可用地区；`off` 不分地区，所有节点组成一个池。\n\n写错报错。运行时可用 `PUT /smart/groups/{name}/regions` 切换，切换会保存到缓存文件。',
    en: 'How a region is chosen for each connection; see [Region modes](/en/smart-loadbalance/#region-modes):\n\n`auto` learns the best region per target and remembers it; `destination` picks the region by the target\'s country, for games, local streaming and the front of chained proxies; `priority` takes the first available region of `priority`; `off` ignores regions and puts every node in one pool.\n\nUnknown values are an error. `PUT /smart/groups/{name}/regions` switches it at runtime, and the change is saved to the cache file.',
  },
  {
    name: 'priority',
    type: 'string[]',
    zh: '地区的优先顺序，写地区代码或名称（`HK`、`香港`、`Japan`、`🇯🇵` 都可以）。\n\n`priority` 模式必填，否则报错 `region.mode priority requires region.priority`。其他模式下，它决定地区在面板中的显示顺序，以及 `fallback: priority` 时的回退顺序。',
    en: 'Region order, as codes or names (`HK`, `香港`, `Japan`, `🇯🇵` all work).\n\nRequired by the `priority` mode, otherwise startup fails with `region.mode priority requires region.priority`. In the other modes it sets the display order in dashboards and the order of `fallback: priority`.',
  },
  {
    name: 'allow',
    type: 'string[]',
    zh: '只允许这些地区承载连接，不写表示全部允许。例如只想用香港、日本、新加坡时写 `["HK", "JP", "SG"]`。不限制锁定的地区和地区出站。',
    en: 'Only these regions carry connections; empty allows all. To use only Hong Kong, Japan and Singapore, write `["HK", "JP", "SG"]`. Does not restrict a locked region or a region outbound.',
  },
  {
    name: 'deny',
    type: 'string[]',
    zh: '这些地区不承载连接，优先于 `allow`。常用来排除中国大陆（`CN`，订阅中的“回国”节点）。同样不限制锁定的地区和地区出站。',
    en: 'These regions carry no connections; takes precedence over `allow`. Often used to leave out mainland China (`CN`, the "back to China" nodes some subscriptions carry). Does not restrict a locked region or a region outbound either.',
  },
  {
    name: 'weights',
    type: 'object',
    zh: '地区评分的系数，如 `{"HK": 1.2, "US": 0.8}`：让 `auto` 模式（以及 `fallback: auto` 选备选地区时）更偏向或更避开某些地区。必须是正数，否则报错。',
    en: 'Factors on region scores, such as `{"HK": 1.2, "US": 0.8}`, so the `auto` mode (and `fallback: auto` when it picks a fallback region) favors or avoids some regions. Must be positive, otherwise it is an error.',
  },
  {
    name: 'fallback',
    type: 'string',
    default: 'auto',
    zh: '选中的地区无法服务时怎么办：`auto` 改用评分最高的其他地区，并在候选列表末尾附上其他地区的节点，拨号失败时可以切过去；`priority` 只按 `priority` 的顺序回退；`none` 不离开选中的地区。需要严格保证出口地区时用 `none`。\n\n所有能用的地区都没有健康节点时，组不会直接放弃，而是忽略健康状态尝试这些节点（锁定了地区且为 `none` 时，只尝试该地区的节点），因为健康数据可能已经过时，一次成功就能恢复。只有在别处明明有健康节点，却因为这里设为 `none`（或 `priority` 而列出的地区都没有健康节点）不能使用时，连接才会失败，报错 `no available member for ...`。',
    en: 'What happens when the chosen region cannot serve: `auto` switches to the best-scoring other region, and appends nodes of other regions to the candidate list so a failed dial can move there; `priority` falls back only along `priority`; `none` never leaves the chosen region. Use `none` when the exit region must not change.\n\nWhen no usable region has a healthy node at all, the group does not give up: it tries those nodes anyway, ignoring health (only the locked region\'s nodes when a region is locked with `none`), because health data may be stale and one success brings the group back. A connection only fails, with `no available member for ...`, when healthy nodes exist elsewhere but this setting keeps the connection away from them (`none`, or `priority` with no listed region healthy).',
  },
  {
    name: 'min_nodes',
    type: 'int',
    default: '1',
    zh: '一个地区至少要有这么多健康节点，才会被 `auto`、`priority`、`destination` 选中，避免把流量交给只剩一个节点的地区。锁定的地区和地区出站只要求 1 个。设得过高、所有地区都达不到时，改用有健康节点的最佳地区，不会因此失败。`0` 或负数按 `1` 处理。',
    en: 'A region needs at least this many healthy nodes to be chosen by `auto`, `priority` or `destination`, so traffic does not go to a region down to its last node. A locked region and region outbounds only need one. If it is set so high that no region qualifies, the best region with any healthy node is used instead; connections do not fail because of it. `0` or negative values become `1`.',
  },
  {
    name: 'sticky',
    type: 'duration',
    default: '30m',
    zh: '`auto` 模式下，每个目标记住所用地区的时长，每次使用都会重新计时。在此期间，只有当前地区不可用，或其他地区评分高出 `switch_margin` 时才换地区，所以同一网站的出口国家保持稳定。`0` 或负数按 `30m` 处理。',
    en: 'How long the `auto` mode remembers the region of each target; every use restarts it. Within it, the target only moves when its region becomes unavailable or another region scores `switch_margin` higher, so a site keeps its exit country. `0` or negative values become `30m`.',
  },
  {
    name: 'switch_margin',
    type: 'float',
    default: '0.25',
    zh: '换地区的门槛：其他地区的评分要高于当前地区 × (1 + 该值) 才会换。默认 `0.25` 即要高出 25%。调大更稳定，调小更灵敏。`0` 或负数按默认值处理。',
    en: 'Switching threshold: another region must score above the current one × (1 + this value) to take over. The default `0.25` means 25% higher. Raise it for stability, lower it for responsiveness. `0` or negative values mean the default.',
  },
  {
    name: 'unknown',
    type: 'string',
    default: 'keep',
    zh: '识别不出地区的节点怎么处理：`keep` 放入地区 `OTHER`（显示为“其他”）；`exclude` 不使用这些节点；写地区代码或名称则全部归入该地区。',
    en: 'What to do with members whose region cannot be detected: `keep` puts them in region `OTHER`; `exclude` leaves them out; a region code or name puts them all in that region.',
  },
  {
    name: 'rules',
    type: 'object[]',
    zh: '自定义地区规则，按顺序在名称识别之前生效，用来纠正识别错误或定义自己的地区（如专线），字段见下方 [region.rules](#rule-region)。',
    en: 'Custom region rules, applied in order before name detection, to correct misdetections or define your own regions (a private-line region, say); fields under [region.rules](#rule-region) below.',
  },
];

export const lbRuleFields: Field[] = [
  {
    name: 'region',
    type: 'string',
    required: true,
    zh: '地区代码。可以是内置地区（写名称也可以，如 `香港`），也可以是自定义地区，如 `IPLC`、`EU`。不写时报错 `region.rules[i]: missing region`。',
    en: 'Region code: a built-in region (names such as `香港` or `Hong Kong` work too) or a custom one such as `IPLC` or `EU`. Missing it fails with `region.rules[i]: missing region`.',
  },
  {
    name: 'match',
    type: 'regex',
    zh: 'Go RE2 正则，匹配节点名称（去掉订阅前缀 `<订阅标签>/` 之后）或完整标签，例如 `(?i)IPLC|IEPL`。',
    en: 'Go RE2 regex matched against the member name (without the `<provider tag>/` prefix) or its full tag, for example `(?i)IPLC|IEPL`.',
  },
  {
    name: 'outbounds',
    type: 'string[]',
    zh: '直接列出属于该地区的节点，写完整标签或去掉订阅前缀的名称都可以。',
    en: 'Members that belong to the region, by full tag or by name without the provider prefix.',
  },
  {
    name: 'name',
    type: 'string',
    zh: '地区的显示名称，用于 Clash API 和地区出站标签模板中的 `{name}`。只写 `region` 与 `name` / `icon` 的规则不匹配任何节点，只用来给地区改名或配图标。',
    en: 'Display name of the region, used by the Clash API and by `{name}` in region outbound tags. A rule with only `region` and `name` / `icon` matches no member; it only renames the region or gives it an icon.',
  },
  {
    name: 'icon',
    type: 'string',
    zh: '地区图标；生成的地区出站没有设置 `outbounds.icon` 时使用它。',
    en: 'Region icon; generated region outbounds use it when `outbounds.icon` is not set.',
  },
];

export const lbDestinationFields: Field[] = [
  {
    name: 'map',
    type: 'object',
    zh: '目标国家 → 地区列表，例如 `{"KR": ["JP", "HK"], "GB": ["DE", "NL"]}`：目标在韩国时依次尝试日本、香港，在英国时依次尝试德国、荷兰。没有写映射的国家，默认找同名地区。',
    en: 'Destination country → regions, such as `{"KR": ["JP", "HK"], "GB": ["DE", "NL"]}`: a destination in Korea tries Japan, then Hong Kong; one in the UK tries Germany, then the Netherlands. Countries without a mapping look for the region of the same code.',
  },
  {
    name: 'disable_tld',
    type: 'bool',
    default: 'false',
    zh: '不再根据域名的国家顶级域（`.jp`、`.co.uk`、`.de` 等）判断目标国家。`.io`、`.co`、`.tv`、`.me`、`.ai` 等常被当作通用域名使用的后缀本来就不参与判断。',
    en: 'Stops guessing the destination country from country-code TLDs (`.jp`, `.co.uk`, `.de`, …). Suffixes commonly used as generic domains, such as `.io`, `.co`, `.tv`, `.me`, `.ai`, are never used.',
  },
  {
    name: 'disable_resolve',
    type: 'bool',
    default: 'false',
    zh: '不再解析域名目标。默认情况下，没有 IP、顶级域也看不出国家的域名（例如以域名填写的落地服务器）会经 DNS 路由解析，再按 IP 查国家；最多等待 300 ms，结果按域名缓存 10 分钟（失败缓存 1 分钟）。使用 FakeIP 时解析结果查不到国家。',
    en: 'Stops resolving domain targets. By default a domain with no IP and no telling TLD (a landing server configured by name, for example) is resolved through the DNS router and its IP looked up; the lookup waits at most 300 ms and is cached per domain for 10 minutes (1 minute on failure). With FakeIP the answers carry no country.',
  },
];

export const lbDetectFields: Field[] = [
  {
    name: 'disable_name',
    type: 'bool',
    default: 'false',
    zh: '不根据节点名称识别地区，只用 `rules` 和出口探测。节点名称不规范、经常误判时使用。',
    en: 'Stops detecting regions from member names; only `rules` and exit probes are used. Useful when member names are unreliable.',
  },
  {
    name: 'exit',
    type: 'string',
    default: 'fallback',
    zh: '出口探测：经节点请求 `exit_url`，按节点真实出口 IP 所在国家归类。\n\n`fallback` 只探测规则和名称都识别不了的节点；`prefer` 探测除规则命中外的所有节点，探测结果优先于名称（适合名称不可信、入口是中转的订阅）；`off` 关闭。',
    en: 'Exit probing: fetches `exit_url` through the member and classifies it by the country of its real exit IP.\n\n`fallback` probes only members that neither the rules nor the name could place; `prefer` probes every member not placed by a rule and lets the result override the name (for subscriptions with unreliable names or relayed entries); `off` disables it.',
  },
  {
    name: 'exit_url',
    type: 'string',
    default: 'https://www.cloudflare.com/cdn-cgi/trace',
    zh: '出口探测的地址，必须是 http 或 https，否则报错 `invalid region.detect.exit_url`。支持三种响应：Cloudflare trace 的 `loc=`、`ip=` 行；带 `country` / `country_code` / `countryCode` 字段的 JSON；只返回 IP 的纯文本（此时用国家数据库查询）。',
    en: 'Exit probe address; must be http or https, otherwise startup fails with `invalid region.detect.exit_url`. Three kinds of answers work: the `loc=` / `ip=` lines of Cloudflare trace, JSON with a `country` / `country_code` / `countryCode` field, and plain text with just the IP (looked up in the country database).',
  },
  {
    name: 'exit_ttl',
    type: 'duration',
    default: '24h',
    zh: '探测结果的有效期。结果保存在缓存文件中，重启后继续使用。失败的探测在 30 分钟（`exit_ttl` 更短时以它为准）后重试。`0` 或负数按 `24h` 处理。',
    en: 'Lifetime of a probe result. Results are saved in the cache file and survive restarts. A failed probe is retried after 30 minutes (or `exit_ttl` if shorter). `0` or negative values become `24h`.',
  },
  {
    name: 'exit_timeout',
    type: 'duration',
    default: '8s',
    zh: '单次出口探测的超时。`0` 或负数按 `8s` 处理。',
    en: 'Timeout of one exit probe. `0` or negative values become `8s`.',
  },
  {
    name: 'exit_concurrency',
    type: 'int',
    default: '4',
    zh: '同时进行的出口探测数。`0` 或负数按 `4` 处理。',
    en: 'How many exit probes run at once. `0` or negative values become `4`.',
  },
];

export const lbProbeFields: Field[] = [
  {
    name: 'disabled',
    type: 'bool',
    default: 'false',
    zh: '关闭地区探测。地区探测会为最常访问的 HTTPS 网站，测量经各地区最佳节点的 TLS 握手耗时，用来比较哪个地区访问它更快，见 [地区探测](/zh/smart-loadbalance/#地区探测)。在意额外流量时可以关闭。',
    en: 'Turns region probes off. Region probes time a TLS handshake to the most visited HTTPS sites through the best node of each region, to compare which region reaches a site fastest; see [Region probes](/en/smart-loadbalance/#region-probes). Turn them off if the extra traffic matters to you.',
  },
  {
    name: 'interval',
    type: 'duration',
    default: '10m',
    zh: '探测周期，首次约在启动 90 秒后。结果在 3 个周期内有效。本组空闲（2 分钟内没有新连接）或失败风暴期间跳过。`0` 或负数按 `10m` 处理。',
    en: 'Probe period; the first run is about 90 s after start. Results stay valid for 3 periods. Skipped while the group is idle (no new connection for 2 minutes) or during a failure flood. `0` or negative values become `10m`.',
  },
  {
    name: 'targets',
    type: 'int',
    default: '6',
    zh: '每轮最多探测几个网站，按近期访问次数选取。`0` 或负数按 `6` 处理。',
    en: 'Sites probed per round at most, picked by recent visits. `0` or negative values become `6`.',
  },
  {
    name: 'regions',
    type: 'int',
    default: '5',
    zh: '每个网站最多比较几个地区，取当前评分最高的几个。`0` 或负数按 `5` 处理。',
    en: 'Regions compared per site at most, the best-scoring ones. `0` or negative values become `5`.',
  },
];

export const lbOutboundsFields: Field[] = [
  {
    name: 'enabled',
    type: 'bool',
    default: 'false',
    zh: '为地区生成 `smart-region` 出站。生成的出站可以作为路由规则的出站、落地节点的 `detour`，或 `selector` 的成员。',
    en: 'Generates `smart-region` outbounds for regions. They can be used as route outbounds, as the `detour` of landing nodes, or as `selector` members.',
  },
  {
    name: 'regions',
    type: 'string[]',
    zh: '启动时就创建的地区出站，只有它们能在配置的其他地方被引用。地区暂时没有节点时（例如订阅还没加载），经它的连接会失败，除非开启了 `fallback`。',
    en: 'Region outbounds created at startup; only these can be referenced elsewhere in the configuration. While such a region has no members (the subscription has not loaded yet, say), connections through it fail unless `fallback` is on.',
  },
  {
    name: 'auto',
    type: 'bool',
    default: 'false',
    zh: '运行中为新出现的地区自动创建出站（`OTHER` 除外），地区消失后删除这些自动创建的出站。`regions` 为空时自动开启。运行中创建的出站不能在配置文件中引用，但可以在面板中使用。',
    en: 'Creates outbounds for regions that appear at runtime (except `OTHER`) and removes them once their region disappears. Implied when `regions` is empty. Outbounds created at runtime cannot be referenced from the configuration, but dashboards can use them.',
  },
  {
    name: 'tag',
    type: 'string',
    default: '{group}-{region}',
    zh: '出站标签的模板，可用 `{group}`（组标签）、`{region}`（地区代码）、`{name}`（显示名称：`rules` 中设置的 `name`，否则为内置的中文名）、`{name_en}`（英文名）、`{flag}`（旗帜），必须包含后四个之一，否则报错。例如 `{flag} {name}负载` 生成 `🇭🇰 香港负载`。与已有出站重名时启动报错。',
    en: 'Tag template with `{group}` (group tag), `{region}` (region code), `{name}` (display name: the `name` set in `rules`, else the built-in Chinese name), `{name_en}` (English name) and `{flag}` (flag); it must contain one of the last four, otherwise it is an error. `{flag} {name_en} LB` gives `🇭🇰 Hong Kong LB`. A clash with an existing tag fails startup.',
  },
  {
    name: 'fallback',
    type: 'bool',
    default: 'false',
    zh: '生成的地区出站在本地区无法服务时，是否按组的 `region.fallback` 改用其他地区。默认关闭，保证经它的流量一定从该地区出去：本地区没有健康节点时，仍会忽略健康状态尝试本地区的节点，但不会改用其他地区。',
    en: 'Whether generated region outbounds may move to other regions (per the group\'s `region.fallback`) when their region cannot serve. Off by default, so traffic through them always leaves from that region: when the region has no healthy node, its nodes are still tried, ignoring health, but other regions never are.',
  },
  {
    name: 'members',
    type: 'string',
    default: 'regions',
    zh: '组在 Clash API 和面板中列出的成员：`regions` 列出地区出站，在面板中点选一个即锁定该地区；`nodes` 照常列出节点。',
    en: 'What the group lists as its members in the Clash API and dashboards: `regions` lists the region outbounds, and picking one in a dashboard locks that region; `nodes` lists the nodes as usual.',
  },
  {
    name: 'hidden',
    type: 'bool',
    default: 'false',
    zh: '生成的地区出站带上 `hidden: true`，让面板隐藏它们。',
    en: 'Marks generated region outbounds `hidden: true` so dashboards hide them.',
  },
  {
    name: 'icon',
    type: 'string',
    zh: '生成的地区出站的图标，不写时使用 `rules` 中为该地区设置的 `icon`。',
    en: 'Icon of generated region outbounds; defaults to the region\'s `icon` from `rules`.',
  },
];

export const smartRegionFields: Field[] = [
  {
    name: 'group',
    type: 'string',
    required: true,
    zh: '所属的 `smart-loadbalance` 组的标签。不写时报错 `smart-region: missing group`；不是该类型的组时，启动报错 `<group> is not a smart-loadbalance group`。',
    en: 'Tag of the `smart-loadbalance` group. Missing it fails with `smart-region: missing group`; a group of another type fails startup with `<group> is not a smart-loadbalance group`.',
  },
  {
    name: 'region',
    type: 'string',
    required: true,
    zh: '地区代码或名称，如 `JP`、`日本`。不写时报错 `smart-region: missing region`。',
    en: 'Region code or name, such as `JP` or `Japan`. Missing it fails with `smart-region: missing region`.',
  },
  {
    name: 'fallback',
    type: 'bool',
    default: 'false',
    zh: '本地区无法服务时，是否按组的 `region.fallback` 改用其他地区。默认关闭：只用本地区的节点，本地区没有健康节点时仍会尝试它们，但不会改用其他地区。',
    en: 'Whether to move to other regions (per the group\'s `region.fallback`) when the region cannot serve. Off by default: only the region\'s nodes are used, and they are still tried when none of them is healthy, but other regions never are.',
  },
  {
    name: 'hidden',
    type: 'bool',
    default: 'false',
    zh: '在 Clash API 中带上 `hidden: true`，让面板隐藏它。',
    en: 'Adds `hidden: true` in Clash API output so dashboards hide it.',
  },
  {
    name: 'icon',
    type: 'string',
    zh: '面板中显示的图标。',
    en: 'Icon shown in dashboards.',
  },
];

