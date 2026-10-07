// Config reference data. Mirrors option/smart.go and option/group.go
// (GroupCommonOption); defaults come from NewSmart (protocol/group/smart.go),
// experimental/smart/service.go and experimental/geox/service.go.
// Keep in lockstep with the Go source when fields change.
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

export const membershipFields: Field[] = [
  {
    name: 'outbounds',
    type: 'string[]',
    zh: '成员出站的标签列表，可以是普通节点，也可以是 `selector`、`urltest` 等其他策略组。`outbounds` 与 `providers` 至少填写一项，否则启动时报错 `missing outbound and provider tags`。\n\n`include` / `exclude` 不会过滤这里显式列出的出站。',
    en: 'Member outbound tags. Members can be plain nodes or other groups such as `selector` or `urltest`. Set at least one of `outbounds` and `providers`, otherwise startup fails with `missing outbound and provider tags`.\n\n`include` / `exclude` never filter outbounds listed here.',
  },
  {
    name: 'providers',
    type: 'string[]',
    zh: '引用的订阅 Provider 标签。Provider 的节点在其更新后通过回调加入本组，每次更新都会重建整个成员列表。引用不存在的 Provider 时启动报错 `outbound provider <i> not found: <tag>`。',
    en: 'Subscription provider tags. Provider nodes join the group through an update callback after the provider loads, and every update rebuilds the whole member list. A missing provider fails startup with `outbound provider <i> not found: <tag>`.',
  },
  {
    name: 'use_all_providers',
    type: 'bool',
    default: 'false',
    zh: '把所有已注册的 Provider 追加到 `providers`。开启后无需再在 `providers` 中重复列出同一个 Provider，否则其节点会被加入两次。',
    en: 'Appends every registered provider to `providers`. Do not also list the same provider in `providers`, or its nodes are added twice.',
  },
  {
    name: 'include',
    type: 'regex',
    zh: 'Go RE2 正则，只保留标签匹配的 Provider 节点。正则在解析配置时编译，写错会直接报配置错误。',
    en: 'Go RE2 regex; only provider nodes whose tag matches are kept. The pattern is compiled while decoding the config, so a bad pattern is a config error.',
  },
  {
    name: 'exclude',
    type: 'regex',
    zh: 'Go RE2 正则，排除标签匹配的 Provider 节点。先检查 `exclude` 再检查 `include`。过滤后没有任何成员时，本组退回内置的直连出站。',
    en: 'Go RE2 regex; provider nodes whose tag matches are dropped. `exclude` is checked before `include`. If filtering leaves no members, the group falls back to the built-in direct outbound.',
  },
];

export const probeFields: Field[] = [
  {
    name: 'url',
    type: 'string',
    default: 'https://www.gstatic.com/generate_204',
    zh: '健康检查的探测地址。每次探测是一个不跟随重定向的 HTTP GET，超时 5 秒。多个 Smart 组共用探测队列：同一节点 1 秒内的探测结果会被其他组直接复用。',
    en: 'Health-check probe URL. Each probe is an HTTP GET that does not follow redirects, with a 5 s timeout. Smart groups share one probe queue, and a node\'s probe result is reused by other groups for 1 s.',
  },
  {
    name: 'interval',
    type: 'duration',
    default: '3m',
    zh: '健康检查周期。`0` 或负数按 `3m` 处理，没有下限。\n\n节点只有在最近一次探测记录不超过 3 × `interval` 时才算存活，而探测会跳过 `max(interval, 5m)` 内已探测过的节点。所以 **`interval` 小于 100 秒时**，节点会在 3 × `interval` 到 5 分钟之间被视为不可用却不会重测，不建议这样设置。',
    en: 'Health-check period. `0` or negative values become `3m`; there is no lower bound.\n\nA node only counts as alive while its latest probe is younger than 3 × `interval`, but probing skips nodes probed within `max(interval, 5m)`. **With `interval` below 100 s**, nodes are treated as unavailable between 3 × `interval` and 5 minutes without being re-probed, so avoid such values.',
  },
  {
    name: 'expected_status',
    type: 'string',
    default: '""',
    zh: '视为探测成功的 HTTP 状态码，语法与 `urltest` 相同：单个状态码 `204`、范围 `200-299`，或用 `/` 连接多项，如 `204/300-399`，取值 100–599。\n\n**留空或 `*` 表示收到任何 HTTP 响应都算成功**，包括强制门户返回的 3xx。需要严格校验时请显式写 `204`。格式错误时启动报错，如 `urltest: invalid expected-status: <part>`。',
    en: 'HTTP status codes that count as a successful probe, with the same syntax as `urltest`: a single code `204`, a range `200-299`, or several joined by `/`, such as `204/300-399`. Codes must be 100–599.\n\n**Empty or `*` accepts any HTTP response**, including a captive portal\'s 3xx. Set `204` explicitly for a strict check. Bad syntax fails startup, for example `urltest: invalid expected-status: <part>`.',
  },
];

export const selectionFields: Field[] = [
  {
    name: 'algorithm',
    type: 'string',
    default: 'strict-best',
    zh: '选路算法，共 10 种，见 [选路算法](/zh/algorithms/)。不区分大小写，`_` 与空格视同 `-`，并接受若干别名（如 `rr`、`p2c`、`chash`）。\n\n无法识别的值**不会报错**，而是记录 WARN 后回退到 `strict-best`。运行时可用 `PUT /smart/groups/{name}/algorithm` 热切换，但不会写回配置，重启后恢复配置值。',
    en: 'Selection algorithm, one of 10; see [Algorithms](/en/algorithms/). Case-insensitive; `_` and spaces are treated as `-`, and several aliases are accepted (such as `rr`, `p2c`, `chash`).\n\nUnknown values **do not fail**: a WARN is logged and `strict-best` is used. `PUT /smart/groups/{name}/algorithm` switches it at runtime, but the change is not persisted and the config value returns after a restart.',
  },
  {
    name: 'hysteresis',
    type: 'duration',
    default: '0',
    zh: '防抖窗口。大于 0 时，同一目标在窗口内优先沿用上一次成功使用的节点（TCP 与 UDP 分别记录），只要它仍在候选列表中。每次成功拨号都会刷新时间戳，所以窗口是滑动的。`0` 表示关闭。',
    en: 'Anti-flap window. When above 0, a target keeps the node it last used successfully (tracked separately for TCP and UDP) as long as that node is still a candidate. Each successful dial refreshes the timestamp, so the window slides. `0` disables it.',
  },
  {
    name: 'policy_priority',
    type: 'string',
    zh: '按节点名称调整优先级，如 `HK:1.5;JP:1.2;US:0.7`。支持子串、`=` 精确、`~` 正则、`*`/`?` 通配与 `!` 取反，区分大小写，多条命中时系数相乘。无效规则只会被忽略并记录 WARN。完整语法见 [节点偏好与手动指定](/zh/priority-and-pinning/)。',
    en: 'Adjusts priority by node name, for example `HK:1.5;JP:1.2;US:0.7`. Supports substring, `=` exact, `~` regex, `*`/`?` glob and `!` negation; matching is case-sensitive and factors of all matching rules multiply. Invalid rules are ignored with a WARN. Full grammar in [Priority and pinning](/en/priority-and-pinning/).',
  },
  {
    name: 'interrupt_exist_connections',
    type: 'bool',
    default: 'false',
    zh: '开启后，通过 Clash API 指定或取消指定节点、调用 `clear-selection` 时，会中断本组已建立的 TCP 连接；某条连接被判定劣化时，也会关闭同一目标、同一节点上的其他连接。UDP 连接不受影响。\n\n无论是否开启，Watchdog 判定卡死的连接都会被关闭，网络切换时所有连接也都会被关闭。',
    en: 'When on, pinning or unpinning a node through the Clash API, or calling `clear-selection`, interrupts the group\'s existing TCP connections; when a connection is judged degraded, other connections to the same target on the same node are closed too. UDP is not affected.\n\nRegardless of this flag, the watchdog closes stalled connections and a network change closes all connections.',
  },
  {
    name: 'disable_udp',
    type: 'bool',
    default: 'false',
    zh: '本组只处理 TCP。UDP 请求会直接失败并返回 `smart: UDP disabled`，需要由路由规则把 UDP 交给其他出站。',
    en: 'The group handles TCP only. UDP requests fail with `smart: UDP disabled`; route UDP to another outbound with rules.',
  },
];

export const learningFields: Field[] = [
  {
    name: 'use_lightgbm',
    type: 'bool',
    default: 'false',
    zh: '使用 `experimental.smart.lightgbm` 中的共享 LightGBM 模型为节点评分。模型尚未下载或加载失败时自动退回传统权重公式。启动日志中的 `ml=loaded|pending|unusable|off` 显示模型状态。详见 [LightGBM 模型](/zh/lightgbm/)。',
    en: 'Scores nodes with the shared LightGBM model from `experimental.smart.lightgbm`. While the model is not downloaded or fails to load, the classic weight formula is used. The startup log shows the model state as `ml=loaded|pending|unusable|off`. See [LightGBM model](/en/lightgbm/).',
  },
  {
    name: 'collect_data',
    type: 'bool',
    default: 'false',
    zh: '把本组每条连接的特征与结果写入 `experimental.smart.collector.path` 指定的 CSV，用于离线训练模型。',
    en: 'Writes each connection\'s features and outcome to the CSV at `experimental.smart.collector.path` for offline model training.',
  },
  {
    name: 'sample_rate',
    type: 'float',
    default: '1.0',
    zh: '训练数据采样比例，取值 (0, 1]。`0`、负数或大于 1 的值都按 `1.0` 处理，因此 `0` 不能关闭采集；要关闭请设 `collect_data: false`。',
    en: 'Sampling ratio for training data, in (0, 1]. `0`, negative values and values above 1 all become `1.0`, so `0` does not turn collection off; use `collect_data: false` instead.',
  },
  {
    name: 'max_host_failed_times',
    type: 'int',
    default: '10',
    zh: '按（组, 目标）计数：连接被判定劣化时 +1，正常结束时 −1。计数达到该值后，认为问题出在目标本身，不再因为该目标的失败给节点降权或屏蔽。`0` 或负数按 `10` 处理。',
    en: 'A counter per (group, target): +1 when a connection is judged degraded, −1 when one ends normally. Once it reaches this value, the target itself is assumed to be broken, and its failures stop demoting or blocking nodes. `0` or negative values become `10`.',
  },
];

export const asnFields: Field[] = [
  {
    name: 'use_asn',
    type: 'bool',
    default: 'false',
    zh: '按目标 IP 所属的自治系统（ASN）分组学习节点表现，见 [ASN 与 GeoX](/zh/asn-geox/)。开启后，只有域名的目标会在连接关闭时额外做一次最长 200 ms 的 DNS 查询。',
    en: 'Learns node performance per autonomous system (ASN) of the destination IP; see [ASN and GeoX](/en/asn-geox/). For domain-only targets, an extra DNS lookup of up to 200 ms runs when a connection closes.',
  },
  {
    name: 'asn_database',
    type: 'string | string[]',
    zh: 'ASN mmdb 文件路径，可写多个，查询时依次尝试，取第一个非零结果。路径**按原样使用**，不会拼接数据目录；图形客户端中相对路径相对于进程工作目录，建议写绝对路径。\n\n留空时依次使用 `experimental.geox.url.asn` 下载的文件，或自动下载 GeoLite2-ASN.mmdb。',
    en: 'Path(s) to ASN mmdb files. With several, they are tried in order and the first non-zero result wins. Paths are **used as written**, not joined with the data directory; in GUI clients a relative path resolves against the process working directory, so prefer absolute paths.\n\nWhen empty, the files downloaded through `experimental.geox.url.asn` are used, or GeoLite2-ASN.mmdb is downloaded automatically.',
  },
];

export const displayFields: Field[] = [
  {
    name: 'hidden',
    type: 'bool',
    default: 'false',
    zh: '在 Clash API 返回的组信息中带上 `hidden: true`，供面板隐藏本组。不影响路由。',
    en: 'Adds `hidden: true` to the group in Clash API output so dashboards can hide it. Routing is unaffected.',
  },
  {
    name: 'icon',
    type: 'string',
    zh: '面板图标，原样通过 Clash API 返回，可以是 URL、data URI 或 emoji。',
    en: 'Dashboard icon, returned verbatim by the Clash API: a URL, data URI or emoji.',
  },
];

export const lightgbmFields: Field[] = [
  {
    name: 'model_path',
    type: 'string',
    default: 'smart_lgbm_model.bin',
    zh: '模型文件路径，相对路径基于 sing-box 数据目录。',
    en: 'Model file path; relative paths resolve against the sing-box data directory.',
  },
  {
    name: 'url',
    type: 'string',
    default: 'vernesong/mihomo Model-large.bin',
    zh: '模型下载地址。默认值为 `https://github.com/vernesong/mihomo/releases/download/LightGBM-Model/Model-large.bin`。',
    en: 'Model download URL. Defaults to `https://github.com/vernesong/mihomo/releases/download/LightGBM-Model/Model-large.bin`.',
  },
  {
    name: 'auto_update',
    type: 'bool',
    default: 'false',
    zh: '开启后，模型缺失时立即下载，之后每隔 `update_interval` 借助 ETag / Last-Modified 检查更新，下载成功后热加载。关闭时，模型文件缺失也会在后台下载一次；文件已存在则不再下载，即使它无法使用。',
    en: 'When on, a missing model is downloaded at once, then updates are checked every `update_interval` using ETag / Last-Modified, and a new model is hot-reloaded. When off, a missing model is still downloaded once in the background; an existing file is never downloaded again, even if it cannot be used.',
  },
  {
    name: 'update_interval',
    type: 'duration',
    default: '72h',
    zh: '自动更新间隔，仅在 `auto_update` 开启时生效。`0` 或负数按 `72h` 处理。',
    en: 'Auto-update interval; only used with `auto_update`. `0` or negative values become `72h`.',
  },
  {
    name: 'http_client',
    type: 'string | object',
    zh: '下载使用的 HTTP 客户端，可写 `http_clients` 中的标签或内联对象，其中的全部设置都会生效：出站与其他拨号选项、TLS、请求头、HTTP 版本。未设置时使用 `download_detour`，两者都没有则使用默认 HTTP 客户端（`route.default_http_client`）。',
    en: 'HTTP client for the download, as a tag from `http_clients` or an inline object. All of its settings apply: the outbound and other dial options, TLS, headers and HTTP version. Without it, `download_detour` is used, and without either, the default HTTP client (`route.default_http_client`).',
  },
  {
    name: 'download_detour',
    type: 'string',
    zh: '旧字段：未设置 `http_client` 时，经这个出站下载。同时设置时忽略它并记录一条 WARN。出站不存在时下载失败，日志记录 `outbound detour not found`。',
    en: 'Legacy field: without `http_client`, downloads go through this outbound. When both are set, it is ignored with a WARN. If the outbound does not exist, the download fails and the log shows `outbound detour not found`.',
  },
];

export const collectorFields: Field[] = [
  {
    name: 'path',
    type: 'string',
    default: 'smart_weight_data.csv',
    zh: '训练数据 CSV 路径，相对路径基于数据目录。已有文件的表头与当前格式不一致时，会被改名为 `<path>.bak.<时间戳>` 后重新创建。',
    en: 'Training-data CSV path, relative to the data directory. If an existing file\'s header does not match the current format, it is renamed to `<path>.bak.<timestamp>` and a new one is created.',
  },
  {
    name: 'size_limit_mb',
    type: 'int',
    default: '100',
    zh: '文件大小上限（MB），`0` 或负数按 `100` 处理。达到上限后丢弃新样本并记录一次 WARN，不会轮转。删除或截短文件后，30 秒内自动恢复采集。',
    en: 'File size cap in MB; `0` or negative values become `100`. At the cap, new samples are dropped with a single WARN, and there is no rotation. Collection resumes within 30 s after the file is deleted or truncated.',
  },
];

export const geoxFields: Field[] = [
  {
    name: 'enabled',
    type: 'bool',
    default: 'false',
    zh: '总开关。关闭时不下载 `url` 中的文件，Smart 也不会从这里取得数据库路径。Smart 需要的默认 ASN、国家数据库不受此开关影响，仍由 GeoX 按本节的下载设置下载。',
    en: 'Master switch. When off, the files under `url` are not downloaded and Smart gets no database paths from here. The default ASN and country databases Smart needs are not affected: GeoX still downloads them with the download settings in this section.',
  },
  {
    name: 'url.asn',
    type: 'string | string[]',
    zh: 'ASN mmdb 下载地址，可写多个。第一个保存为 `GeoLite2-ASN.mmdb`，其余依次保存为 `GeoLite2-ASN-<i>.mmdb`。所有 `use_asn` 且未设置 `asn_database` 的 Smart 组都会使用这些文件。',
    en: 'ASN mmdb download URL(s). The first is saved as `GeoLite2-ASN.mmdb`, the rest as `GeoLite2-ASN-<i>.mmdb`. Every Smart group with `use_asn` and no `asn_database` uses these files.',
  },
  {
    name: 'url.mmdb',
    type: 'string',
    zh: '国家 mmdb 下载地址，保存为 `country.mmdb`。Smart 用它为 LightGBM 和训练数据提供目标国家特征。',
    en: 'Country mmdb download URL, saved as `country.mmdb`. Smart uses it for the destination-country feature in LightGBM scoring and training data.',
  },
  {
    name: 'url.geoip',
    type: 'string',
    zh: 'geoip.dat 下载地址。目前没有任何组件读取该文件。',
    en: 'geoip.dat download URL. Nothing reads this file at the moment.',
  },
  {
    name: 'url.geosite',
    type: 'string',
    zh: 'geosite.dat 下载地址。目前没有任何组件读取该文件。',
    en: 'geosite.dat download URL. Nothing reads this file at the moment.',
  },
  {
    name: 'auto_update',
    type: 'bool',
    default: 'false',
    zh: '开启后按 `update_interval` 定期更新每个文件；关闭时只在文件缺失时下载，已有的文件不再更新。缺失文件下载失败时，按 30 秒起、逐次翻倍、最长 30 分钟的间隔重试。mmdb 更新后立即重新加载，无需重启。',
    en: 'When on, every file is refreshed every `update_interval`; when off, a file is downloaded only while it is missing, and an existing file is never updated. A failed download of a missing file is retried after 30 seconds, doubling up to 30 minutes. An updated mmdb is reloaded at once, with no restart.',
  },
  {
    name: 'update_interval',
    type: 'duration',
    default: '24h',
    zh: '自动更新间隔。',
    en: 'Auto-update interval.',
  },
  {
    name: 'http_client / download_detour',
    type: 'string | object',
    zh: '下载使用的 HTTP 客户端，规则与 `experimental.smart.lightgbm` 相同：`http_client` 的全部设置都会生效，未设置时使用 `download_detour`，都没有则使用默认 HTTP 客户端。`http_client` 引用的标签不存在时，GeoX 启用则启动失败，未启用则只有默认数据库无法下载并记录 WARN。',
    en: 'HTTP client for downloads, with the same rules as `experimental.smart.lightgbm`: all `http_client` settings apply; without it `download_detour` is used, and without either the default HTTP client. An `http_client` tag that does not exist fails startup when GeoX is enabled; otherwise only the default databases cannot be downloaded, with a WARN.',
  },
];

export interface EnvVar {
  name: string;
  default: { zh: string; en: string };
  range: { zh: string; en: string };
  zh: string;
  en: string;
}

export const envVars: EnvVar[] = [
  {
    name: 'SMART_CACHE_BUDGET_MB',
    default: { zh: '32（Android / iOS 为 8）', en: '32 (8 on Android / iOS)' },
    range: { zh: '正整数', en: 'positive integer' },
    zh: 'Smart 内存缓存的字节预算，按实际字节计量，平分给 6 个缓存，同时影响批量写盘阈值。',
    en: 'Byte budget for Smart\'s in-memory caches, measured in real bytes and split across 6 caches; also scales the batch-flush threshold.',
  },
  {
    name: 'SMART_DECAY_HALF_LIFE_HOURS',
    default: { zh: '168', en: '168' },
    range: { zh: '1 – 8760', en: '1 – 8760' },
    zh: '历史统计按时间衰减的半衰期（小时）。',
    en: 'Half-life, in hours, for the time decay of historical stats.',
  },
  {
    name: 'SMART_FAILURE_STICKY',
    default: { zh: '2.0', en: '2.0' },
    range: { zh: '1.0 – 8.0', en: '1.0 – 8.0' },
    zh: '失败记录相对成功记录的半衰期倍数，越大失败被记住得越久。',
    en: 'Half-life multiplier for failures relative to successes; larger values make failures linger longer.',
  },
  {
    name: 'SMART_LEGACY',
    default: { zh: 'false', en: 'false' },
    range: { zh: '1 / true / yes / on', en: '1 / true / yes / on' },
    zh: '改用旧版分段式时间衰减曲线。',
    en: 'Switches to the old stepwise time-decay curve.',
  },
];
