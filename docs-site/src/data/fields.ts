// Config reference data. Mirrors option/smart.go and option/group.go
// (GroupCommonOption); defaults come from newSmart (protocol/group/smart.go),
// newSmartBalance and friends (protocol/group/smart_lb*.go, smart_region.go),
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
    zh: '本组的成员，写出站的标签（tag）。成员可以是普通节点，也可以是 `selector`、`urltest` 等其他策略组。\n\n`outbounds` 与 `providers` 至少写一个，否则启动时报错 `missing outbound and provider tags`。这里写出的出站一定会加入本组，不受 `include` / `exclude` 筛选。写了不存在的标签时，启动报错 `dependency[<tag>] not found for outbound[<本组>]`。',
    en: 'Members of the group, as outbound tags. A member can be a plain node or another group such as `selector` or `urltest`.\n\nSet at least one of `outbounds` and `providers`, otherwise startup fails with `missing outbound and provider tags`. Outbounds listed here always join the group; `include` and `exclude` do not filter them. A tag that does not exist fails startup with `dependency[<tag>] not found for outbound[<group>]`.',
  },
  {
    name: 'providers',
    type: 'string[]',
    zh: '要使用的订阅（Provider）的标签。订阅中的节点全部成为本组成员，可以再用 `include` / `exclude` 筛选。订阅加载或更新后，本组会自动重建成员列表，不需要重启。\n\n订阅节点的标签形如 `<订阅标签>/<节点名>`，例如 `my-subscription/🇭🇰 香港 01`。写了不存在的订阅时，启动报错 `outbound provider <i> not found: <tag>`。',
    en: 'Tags of the subscriptions (providers) to use. Every node of a subscription becomes a member of the group, optionally narrowed with `include` / `exclude`. When a subscription loads or updates, the group rebuilds its member list on its own; no restart is needed.\n\nSubscription members are tagged `<provider tag>/<node name>`, for example `my-subscription/🇭🇰 Hong Kong 01`. A provider that does not exist fails startup with `outbound provider <i> not found: <tag>`.',
  },
  {
    name: 'use_all_providers',
    type: 'bool',
    default: 'false',
    zh: '把配置中的所有订阅都加入本组，相当于在 `providers` 里列出全部订阅。开启后不要再在 `providers` 里写同一个订阅，否则它的节点会被加入两次。',
    en: 'Adds every subscription in the configuration to the group, as if all of them were listed in `providers`. Do not also list one of them in `providers`, or its nodes join twice.',
  },
  {
    name: 'include',
    type: 'regex',
    zh: '只保留标签匹配这个正则（Go RE2 语法）的订阅节点，例如 `香港|HK`。\n\n匹配的是完整标签 `<订阅标签>/<节点名>`：用 `^` 锚定开头时要把订阅标签算进去，一般写不锚定的模式即可。只作用于订阅节点，不影响 `outbounds` 中写出的出站。正则写错时，读取配置就会报错。',
    en: 'Keeps only the subscription members whose tag matches this regex (Go RE2 syntax), for example `Hong Kong|HK`.\n\nThe pattern is matched against the full tag `<provider tag>/<node name>`, so a `^` anchor must account for the provider tag; an unanchored pattern is usually what you want. It only filters subscription members, never the outbounds listed in `outbounds`. An invalid regex is a config error.',
  },
  {
    name: 'exclude',
    type: 'regex',
    zh: '去掉标签匹配这个正则的订阅节点，常用来排除“剩余流量”“到期时间”之类的提示条目，例如 `(?i)剩余|到期|官网`（`(?i)` 表示不区分大小写）。同样匹配完整标签。\n\n先按 `exclude` 排除，再按 `include` 筛选。筛选后一个成员都不剩时，本组改用内置的直连出站，**流量会直接连出、不经过代理**，请确认筛选条件没有写错。',
    en: 'Drops the subscription members whose tag matches this regex, typically the "traffic left" or "expires on" entries some subscriptions include, for example `(?i)traffic|expire` (`(?i)` makes it case-insensitive). It is also matched against the full tag.\n\n`exclude` is applied before `include`. If no member is left, the group falls back to the built-in direct outbound and **traffic goes out directly, without a proxy**, so double-check your patterns.',
  },
];

export const probeFields: Field[] = [
  {
    name: 'url',
    type: 'string',
    default: 'https://www.gstatic.com/generate_204',
    zh: '健康检查访问的地址。Smart 经每个节点向它发一个 HTTP HEAD 请求，不跟随重定向，超时 5 秒：成功就记下延迟，失败就暂时把节点判为不可用。\n\n默认地址返回 204、没有正文，适合测速。改用其他地址时，最好同时设置 `expected_status`。多个 Smart 组共用一个探测队列，同一节点 1 秒内的探测结果会直接给其他组复用。',
    en: 'The address health checks request. Through each node, Smart sends an HTTP HEAD request to it, without following redirects and with a 5 s timeout: on success the latency is recorded, on failure the node is treated as unavailable for a while.\n\nThe default address answers 204 with no body, which suits latency tests. If you use another address, set `expected_status` as well. Smart groups share one probe queue, and a node\'s probe result is reused by other groups for 1 s.',
  },
  {
    name: 'interval',
    type: 'duration',
    default: '3m',
    zh: '健康检查的周期。`0` 或负数按 `3m` 处理，没有下限。\n\n与它相关的三条规则：节点最近一次成功探测超过 3 × `interval` 就不再算可用；5 分钟内（`interval` 更长时以它为准）探测过、或刚有连接成功经过的节点，本轮不再探测；本组 2 分钟内没有任何成功连接时（包括启动后还没有连接时）跳过健康检查，手机待机时不耗电。\n\n因此**不要把 `interval` 设得低于 100 秒**：节点会在 3 × `interval` 之后、5 分钟之前被当作不可用，却又不会重测。手机上建议 `5m` 或更长。',
    en: 'Health-check period. `0` or negative values become `3m`; there is no lower bound.\n\nThree rules depend on it: a node whose last successful probe is older than 3 × `interval` no longer counts as available; nodes probed within the last 5 minutes (or `interval`, if longer), or that just carried a successful connection, are skipped in this round; and when the group has had no successful connection for 2 minutes (including right after start, before any connection), health checks are skipped so an idle phone does not spend battery on them.\n\nSo **do not set `interval` below 100 s**: nodes would count as unavailable between 3 × `interval` and 5 minutes without being re-probed. On phones, `5m` or more is a good choice.',
  },
  {
    name: 'expected_status',
    type: 'string',
    default: '""',
    zh: '哪些 HTTP 状态码算探测成功。写法与 `urltest` 相同：单个状态码 `204`、范围 `200-299`，或用 `/` 连接多项，如 `204/300-399`；状态码须在 100–599 之间。\n\n**留空或写 `*` 时，收到任何 HTTP 响应都算成功**，包括强制门户（酒店、机场 Wi-Fi 的登录页）返回的重定向和错误页。要严格判断节点能否真正上网，写 `204`（配合默认的 `url`）。格式错误时启动报错，如 `urltest: invalid expected-status: <part>`。',
    en: 'Which HTTP status codes count as a successful probe. The syntax is the same as in `urltest`: a single code `204`, a range `200-299`, or several joined by `/`, such as `204/300-399`; codes must be between 100 and 599.\n\n**Empty or `*` accepts any HTTP response**, including the redirects and error pages a captive portal (hotel or airport Wi-Fi login) returns. To check that a node really reaches the internet, set `204` (with the default `url`). Bad syntax fails startup, for example `urltest: invalid expected-status: <part>`.',
  },
];

export const selectionFields: Field[] = [
  {
    name: 'algorithm',
    type: 'string',
    default: 'strict-best',
    zh: '选路算法：在排好序的候选节点中先用哪一个，共 10 种，见 [选路算法](/zh/algorithms/)。不区分大小写，`_` 和空格等同于 `-`，也接受一些别名（如 `rr`、`p2c`、`chash`）。\n\n写错**不会报错**：会记录一条 WARN 并改用 `strict-best`，以启动日志中的 `algorithm=` 为准。运行时可以用 `PUT /smart/groups/{name}/algorithm` 切换，但不会写回配置，重启后恢复配置中的值。`smart-loadbalance` 组忽略这个字段，改用 `balance.strategy`。',
    en: 'Selection algorithm: which of the ranked candidates to try first. There are 10; see [Algorithms](/en/algorithms/). Case-insensitive; `_` and spaces count as `-`, and several aliases are accepted (such as `rr`, `p2c`, `chash`).\n\nA misspelt value **is not an error**: a WARN is logged and `strict-best` is used, so check `algorithm=` in the startup log. `PUT /smart/groups/{name}/algorithm` switches it at runtime, but the change is not written back to the config, and the configured value returns after a restart. `smart-loadbalance` groups ignore this field and use `balance.strategy` instead.',
  },
  {
    name: 'hysteresis',
    type: 'duration',
    default: '0',
    zh: '防抖窗口，用来减少同一网站在几个相近节点之间来回切换。大于 0 时，同一目标在窗口内继续使用上一次成功的节点（TCP 与 UDP 分开记录），前提是这个节点仍在候选列表中。每次成功连接都会重新计时，所以网站一直有流量时，会一直停留在同一节点。`0` 表示关闭。\n\n`smart-loadbalance` 组忽略这个字段，改用 `region.sticky` 与 `balance.affinity`。',
    en: 'Anti-flap window, so a site does not bounce between nodes of similar quality. When above 0, a target keeps using the node it last used successfully (tracked separately for TCP and UDP) within the window, as long as that node is still a candidate. Every successful connection restarts the window, so a site with steady traffic stays on one node. `0` turns it off.\n\n`smart-loadbalance` groups ignore this field and use `region.sticky` and `balance.affinity` instead.',
  },
  {
    name: 'policy_priority',
    type: 'string',
    zh: '按节点名称调整优先级，规则之间用 `;` 分隔，例如 `HK:1.5;JP:1.2;US:0.7`：名称含 `HK` 的节点系数为 1.5，大于 1 表示更优先，小于 1 表示更靠后。\n\n支持子串（默认）、`=` 精确、`~` 正则、`*` / `?` 通配与 `!` 取反；区分大小写；一个节点命中多条规则时系数相乘。系数为 0、负数或恰好为 1 的规则，以及格式错误的规则，会被忽略并记录 WARN。注意系数大于 1 的节点会排在所有系数为 1 的节点前面。完整语法见 [节点偏好与手动指定](/zh/priority-and-pinning/)。',
    en: 'Adjusts priority by node name. Rules are separated by `;`, for example `HK:1.5;JP:1.2;US:0.7`: nodes whose name contains `HK` get a factor of 1.5. Above 1 means preferred, below 1 means pushed back.\n\nSupports substring (the default), `=` exact, `~` regex, `*` / `?` glob and `!` negation; matching is case-sensitive, and when a node matches several rules their factors multiply. Rules whose factor is 0, negative or exactly 1, and rules with bad syntax, are ignored with a WARN. Note that nodes with a factor above 1 rank ahead of every node at 1. Full grammar in [Priority and pinning](/en/priority-and-pinning/).',
  },
  {
    name: 'interrupt_exist_connections',
    type: 'bool',
    default: 'false',
    zh: '切换选择时是否立即断开已有连接。默认关闭：新连接使用新的选择，已经建立的连接（如正在进行的下载、视频）继续使用原来的节点。\n\n开启后，以下操作会立即关闭本组已有的连接（TCP 与 UDP），让客户端重新连接：在 Clash API 或面板中指定、取消指定节点，调用 `clear-selection`，以及 `smart-loadbalance` 组锁定或解锁地区。此外，某条 TCP 连接被判定劣化时，同一目标经同一节点的其他 TCP 连接也会被关闭。\n\n无论是否开启，Watchdog 判定卡死的连接都会被关闭；sing-box 重置网络（如切换 Wi-Fi 与移动网络）时，所有连接也会被关闭。',
    en: 'Whether changing the selection cuts existing connections at once. Off by default: new connections follow the new selection, while established ones (a download or video in progress, say) stay on their node.\n\nWhen on, these actions immediately close the group\'s existing connections (TCP and UDP) so clients reconnect: pinning or unpinning a node in the Clash API or a dashboard, calling `clear-selection`, and locking or unlocking a region of a `smart-loadbalance` group. In addition, when a TCP connection is judged degraded, other TCP connections to the same target through the same node are closed too.\n\nRegardless of this flag, the watchdog closes stalled connections, and all connections are closed when sing-box resets the network (switching between Wi-Fi and mobile data, for example).',
  },
  {
    name: 'disable_udp',
    type: 'bool',
    default: 'false',
    zh: '本组只处理 TCP。经本组的 UDP 请求会直接失败，报错 `smart: UDP disabled`，所以要用路由规则把 UDP（如 QUIC、游戏、语音）交给其他出站。',
    en: 'The group handles TCP only. UDP requests through it fail with `smart: UDP disabled`, so route UDP traffic (QUIC, games, voice) to another outbound with rules.',
  },
];

export const learningFields: Field[] = [
  {
    name: 'use_lightgbm',
    type: 'bool',
    default: 'false',
    zh: '用 LightGBM 模型（`experimental.smart.lightgbm` 中所有组共用的那一个）给节点打分，代替传统权重公式。模型还没下载好或无法加载时，自动使用传统公式。启动日志中的 `ml=loaded|pending|unusable|off` 显示模型状态。详见 [LightGBM 模型](/zh/lightgbm/)。',
    en: 'Scores nodes with the LightGBM model shared by all groups (`experimental.smart.lightgbm`) instead of the classic weight formula. While the model is not downloaded yet or cannot be loaded, the classic formula is used. The startup log shows the model state as `ml=loaded|pending|unusable|off`. See [LightGBM model](/en/lightgbm/).',
  },
  {
    name: 'collect_data',
    type: 'bool',
    default: 'false',
    zh: '把本组每条连接的特征与结果写入 CSV（路径见 `experimental.smart.collector.path`），用来离线训练自己的模型。单独开启这一项即可，不需要写 `experimental.smart`。不打算训练模型时不要开启。',
    en: 'Writes the features and outcome of each connection through the group to a CSV (path in `experimental.smart.collector.path`) for training your own model offline. This flag alone is enough; `experimental.smart` is optional. Leave it off unless you plan to train a model.',
  },
  {
    name: 'sample_rate',
    type: 'float',
    default: '1.0',
    zh: '训练数据的采样比例，取值 (0, 1]：`0.3` 表示约 30% 的连接被写入 CSV。`0`、负数或大于 1 的值都按 `1.0` 处理，所以 `0` 不能关闭采集；要关闭请设 `collect_data: false`。',
    en: 'Share of connections written to the training CSV, in (0, 1]: `0.3` means about 30% of connections are recorded. `0`, negative values and values above 1 all become `1.0`, so `0` does not turn collection off; use `collect_data: false` for that.',
  },
  {
    name: 'max_host_failed_times',
    type: 'int',
    default: '10',
    zh: '用来区分“节点有问题”和“网站本身有问题”。Smart 按（组, 目标）计数：连接被判定劣化时 +1，正常结束时 −1（不低于 0）。计数达到这个值后，认为是目标网站本身出了问题，不再因为它的失败给节点降权或屏蔽，以免一个宕机的网站拖累所有节点。`0` 或负数按 `10` 处理。',
    en: 'Tells "the node is bad" apart from "the website itself is down". Smart keeps a counter per (group, target): +1 when a connection is judged degraded, −1 when one ends normally (never below 0). Once it reaches this value, the target is assumed to be broken, and its failures no longer demote or block nodes, so one dead website cannot drag every node down. `0` or negative values become `10`.',
  },
];

export const asnFields: Field[] = [
  {
    name: 'use_asn',
    type: 'bool',
    default: 'false',
    zh: '按目标 IP 所属的自治系统（ASN，即网络运营者，例如 Google 的 AS15169）汇总学习结果：同一运营者的网站共享节点表现，新网站也能沿用已有的经验。Cloudflare、Akamai、Fastly 等常见 CDN 的 ASN 不参与汇总，因为同一 CDN 上的网站差别太大。见 [ASN 与 GeoX](/zh/asn-geox/)。\n\n开启后，只有域名、没有 IP 的目标会在连接关闭时额外做一次最长 200 ms 的 DNS 查询，不影响连接本身。',
    en: 'Aggregates what Smart learns by the autonomous system (ASN, the network operator, such as AS15169 for Google) of the destination IP: sites run by the same operator share node results, so a new site benefits from what was learned elsewhere. The ASNs of common CDNs such as Cloudflare, Akamai and Fastly are left out, because the sites behind one CDN differ too much. See [ASN and GeoX](/en/asn-geox/).\n\nFor destinations known only by domain, an extra DNS lookup of up to 200 ms runs when a connection closes; it does not delay the connection itself.',
  },
  {
    name: 'asn_database',
    type: 'string | string[]',
    zh: 'ASN mmdb 文件的路径，可以写多个，查询时依次尝试，取第一个查到的结果。路径**按原样使用**，不会拼接数据目录；图形客户端中相对路径相对于进程的工作目录，建议写绝对路径。本地文件只在启动时读取，替换后需要重启。\n\n不写时，使用 `experimental.geox.url.asn` 下载的文件（需开启 GeoX）；也没有时，自动下载 GeoLite2-ASN.mmdb。',
    en: 'Path(s) to ASN mmdb files. With several, they are tried in order and the first hit wins. Paths are **used as written**, not joined with the data directory; in GUI clients a relative path resolves against the process working directory, so prefer absolute paths. Local files are read only at startup, so replacing one requires a restart.\n\nWhen empty, the files downloaded through `experimental.geox.url.asn` are used (with GeoX enabled); without those, GeoLite2-ASN.mmdb is downloaded automatically.',
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
    default: 'smart_lgbm_model.bin',
    zh: '模型文件的路径。相对路径基于 sing-box 的数据目录：命令行版本是 `-D` 指定的目录（未指定时为当前工作目录），图形客户端是应用自己的数据目录。',
    en: 'Path of the model file. A relative path resolves against the sing-box data directory: the directory given with `-D` for the command-line version (the current working directory without it), or the app\'s own data directory in GUI clients.',
  },
  {
    name: 'url',
    type: 'string',
    default: 'vernesong/mihomo Model-large.bin',
    zh: '模型的下载地址，默认为 `https://github.com/vernesong/mihomo/releases/download/LightGBM-Model/Model-large.bin`。换成自己训练的模型时改这里。',
    en: 'Model download URL; defaults to `https://github.com/vernesong/mihomo/releases/download/LightGBM-Model/Model-large.bin`. Point it at your own model if you train one.',
  },
  {
    name: 'auto_update',
    type: 'bool',
    default: 'false',
    zh: '是否定期更新模型。开启后，模型缺失时立即下载，之后每隔 `update_interval` 检查一次（借助 ETag / Last-Modified，没有变化不会重复下载），下载成功后直接换用新模型，无需重启。\n\n关闭时，模型文件缺失也会在后台下载一次；文件已存在就不再下载，即使它无法使用。',
    en: 'Whether to keep the model up to date. When on, a missing model is downloaded at once, and then checked every `update_interval` (using ETag / Last-Modified, so an unchanged file is not downloaded again); a new model takes over without a restart.\n\nWhen off, a missing model file is still downloaded once in the background; an existing file is never downloaded again, even if it cannot be used.',
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
    zh: '下载模型使用的 HTTP 客户端，可以写顶层 `http_clients` 中的标签，也可以直接写一个对象。其中的全部设置都会生效：出站与其他拨号选项、TLS、请求头、HTTP 版本。\n\n不写时使用 `download_detour`；两者都没有时，使用默认 HTTP 客户端（`route.default_http_client`）。',
    en: 'HTTP client for the model download: a tag from the top-level `http_clients`, or an inline object. All of its settings apply: the outbound and other dial options, TLS, headers and HTTP version.\n\nWithout it, `download_detour` is used; without either, the default HTTP client (`route.default_http_client`).',
  },
  {
    name: 'download_detour',
    type: 'string',
    zh: '旧字段：没有设置 `http_client` 时，经这个出站下载模型，例如写 `direct` 直连下载。两个都设置时忽略它，并记录一条 WARN。出站不存在时下载失败，日志显示 `outbound detour not found`。',
    en: 'Legacy field: without `http_client`, the model is downloaded through this outbound, for example `direct` to download without a proxy. When both are set it is ignored with a WARN. If the outbound does not exist, the download fails and the log shows `outbound detour not found`.',
  },
];

export const collectorFields: Field[] = [
  {
    name: 'path',
    type: 'string',
    default: 'smart_weight_data.csv',
    zh: '训练数据 CSV 的路径，相对路径基于数据目录。已有文件的表头与当前格式不一致时，会先改名为 `<path>.bak.<时间戳>` 备份，再新建文件。',
    en: 'Path of the training-data CSV, relative to the data directory. If an existing file\'s header does not match the current format, the file is renamed to `<path>.bak.<timestamp>` as a backup and a new one is created.',
  },
  {
    name: 'size_limit_mb',
    type: 'int',
    default: '100',
    zh: 'CSV 文件的大小上限（MB）。`0` 或负数按 `100` 处理。达到上限后不再写入新样本，只记录一次 WARN，不会自动轮转；删除或截短文件后，30 秒内自动恢复采集。',
    en: 'Size cap of the CSV in MB. `0` or negative values become `100`. At the cap, new samples are dropped with a single WARN; there is no rotation. Collection resumes within 30 s after you delete or truncate the file.',
  },
];

export const geoxFields: Field[] = [
  {
    name: 'enabled',
    type: 'bool',
    default: 'false',
    zh: '是否下载 `url` 中配置的文件。关闭时不下载这些文件，Smart 也不会从这里取得数据库路径。\n\nSmart 需要的默认 ASN、国家数据库不受这个开关影响：需要时仍由 GeoX 在后台下载，并使用本节的下载设置（`http_client`、`auto_update`、`update_interval`）。',
    en: 'Whether to download the files configured under `url`. When off, those files are not downloaded and Smart gets no database paths from here.\n\nThe default ASN and country databases Smart needs are not affected: when needed, GeoX still downloads them in the background with the download settings of this section (`http_client`, `auto_update`, `update_interval`).',
  },
  {
    name: 'url.asn',
    type: 'string | string[]',
    zh: 'ASN mmdb 的下载地址，可以写多个。第一个保存为 `GeoLite2-ASN.mmdb`，其余依次保存为 `GeoLite2-ASN-1.mmdb`、`GeoLite2-ASN-2.mmdb`……所有开启 `use_asn` 且没有设置 `asn_database` 的 Smart 组都会使用这些文件，按顺序查询。',
    en: 'ASN mmdb download URL(s). The first is saved as `GeoLite2-ASN.mmdb`, the rest as `GeoLite2-ASN-1.mmdb`, `GeoLite2-ASN-2.mmdb` and so on. Every Smart group with `use_asn` and no `asn_database` uses these files, queried in order.',
  },
  {
    name: 'url.mmdb',
    type: 'string',
    zh: '国家 mmdb 的下载地址，保存为 `country.mmdb`。Smart 用它查询目标所在国家：供 LightGBM 评分、训练数据采集，以及 `smart-loadbalance` 的 `destination` 模式使用。不写时，需要国家数据库的组会自动下载默认的 GeoLite2-Country。',
    en: 'Country mmdb download URL, saved as `country.mmdb`. Smart uses it to look up the destination country for LightGBM scoring, training-data collection and the `destination` mode of `smart-loadbalance`. Without it, groups that need a country database download the default GeoLite2-Country.',
  },
  {
    name: 'url.geoip',
    type: 'string',
    zh: 'geoip.dat 的下载地址。目前没有任何组件读取这个文件。',
    en: 'geoip.dat download URL. Nothing reads this file at the moment.',
  },
  {
    name: 'url.geosite',
    type: 'string',
    zh: 'geosite.dat 的下载地址。目前没有任何组件读取这个文件。',
    en: 'geosite.dat download URL. Nothing reads this file at the moment.',
  },
  {
    name: 'auto_update',
    type: 'bool',
    default: 'false',
    zh: '是否定期更新。开启后每隔 `update_interval` 更新一次每个文件；关闭时只在文件缺失时下载，已有文件不再更新。\n\n缺失的文件下载失败时，按 30 秒起、每次翻倍、最长 30 分钟的间隔重试。mmdb 下载或更新后立即生效，无需重启。',
    en: 'Whether to keep the files up to date. When on, every file is refreshed every `update_interval`; when off, a file is downloaded only while it is missing, and an existing file is never updated.\n\nA failed download of a missing file is retried after 30 seconds, doubling each time up to 30 minutes. A downloaded or updated mmdb takes effect at once, with no restart.',
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
    zh: '下载使用的 HTTP 客户端，规则与 `experimental.smart.lightgbm` 相同：`http_client` 的全部设置都会生效；不写时使用 `download_detour`；都没有时使用默认 HTTP 客户端。\n\n`http_client` 引用的标签不存在时：开启了 GeoX 则启动失败；没有开启则只有默认数据库无法下载，并记录 WARN。',
    en: 'HTTP client for downloads, with the same rules as `experimental.smart.lightgbm`: all `http_client` settings apply; without it `download_detour` is used; without either, the default HTTP client.\n\nIf `http_client` names a tag that does not exist, startup fails when GeoX is enabled; otherwise only the default databases cannot be downloaded, with a WARN.',
  },
];

// smart-loadbalance (option.SmartLoadBalanceOutboundOptions). Defaults
// come from newSmartBalance and friends in protocol/group/smart_lb*.go.

export const lbBalanceFields: Field[] = [
  {
    name: 'strategy',
    type: 'string',
    default: 'smart',
    zh: '在选中地区的节点池内分配连接的方式，见 [分配策略](/zh/smart-loadbalance/#分配策略)：\n\n`smart` 按质量加权分配，质量越好、当前连接越少的节点越容易被选中，适合大多数场景；`least-connections` 选当前连接最少的节点；`round-robin` 轮流使用；`weighted-round-robin` 按质量比例轮流；`weighted-random` 按质量加权随机；`random` 均匀随机；`consistent-hashing` 让同一网站（或同一亲和键）固定落到同一节点。\n\n不区分大小写，`_` 和空格等同于 `-`，接受别名（如 `lc`、`rr`、`wrr`、`chash`）。与 `smart` 组的 `algorithm` 不同，写错**会报错**：`unknown balance strategy: ...`。运行时可用 `PUT /smart/groups/{name}/balance` 切换，切换会保存到缓存文件，重启后保持。',
    en: 'How connections are spread across the node pool of the chosen region; see [Strategies](/en/smart-loadbalance/#strategies):\n\n`smart` weights by quality, so better nodes with fewer live connections are picked more often, and suits most setups; `least-connections` picks the node with the fewest live connections; `round-robin` takes turns; `weighted-round-robin` takes turns in proportion to quality; `weighted-random` draws at random weighted by quality; `random` draws uniformly; `consistent-hashing` keeps the same site (or the same affinity key) on the same node.\n\nCase-insensitive; `_` and spaces count as `-`, and aliases such as `lc`, `rr`, `wrr`, `chash` are accepted. Unlike the `algorithm` of `smart`, an unknown value **is an error**: `unknown balance strategy: ...`. `PUT /smart/groups/{name}/balance` switches it at runtime; the change is saved to the cache file and survives a restart.',
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
    zh: '选中的地区无法服务时怎么办：`auto` 改用评分最高的其他地区，并在候选列表末尾附上其他地区的节点，拨号失败时可以切过去；`priority` 只按 `priority` 的顺序回退；`none` 不离开选中的地区。需要严格保证出口地区时用 `none`。\n\n所有能用的地区都没有健康节点时，组不会直接放弃，而是忽略健康状态尝试这些节点（锁定了地区且为 `none` 时，只尝试该地区的节点），因为健康数据可能已经过时，一次成功就能恢复。只有在别处明明有健康节点，却因为这里设为 `none`（或 `priority` 而列出的地区都没有健康节点）不能使用时，连接才会失败，报错 `no node can serve ...`。',
    en: 'What happens when the chosen region cannot serve: `auto` switches to the best-scoring other region, and appends nodes of other regions to the candidate list so a failed dial can move there; `priority` falls back only along `priority`; `none` never leaves the chosen region. Use `none` when the exit region must not change.\n\nWhen no usable region has a healthy node at all, the group does not give up: it tries those nodes anyway, ignoring health (only the locked region\'s nodes when a region is locked with `none`), because health data may be stale and one success brings the group back. A connection only fails, with `no node can serve ...`, when healthy nodes exist elsewhere but this setting keeps the connection away from them (`none`, or `priority` with no listed region healthy).',
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
    zh: '探测周期，首次约在启动 90 秒后。结果在 3 个周期内有效。本组空闲（2 分钟内没有成功连接）或网络故障期间跳过。`0` 或负数按 `10m` 处理。',
    en: 'Probe period; the first run is about 90 s after start. Results stay valid for 3 periods. Skipped while the group is idle (no successful connection for 2 minutes) or the network is down. `0` or negative values become `10m`.',
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
    zh: 'Smart 内存缓存的总预算（MB），按实际占用的字节计量，平分给 6 个缓存，同时影响批量写盘的阈值。内存紧张的设备可以调低。',
    en: 'Total budget, in MB, for Smart\'s in-memory caches, measured in real bytes and split across 6 caches; it also scales the batch-write threshold. Lower it on memory-constrained devices.',
  },
  {
    name: 'SMART_DECAY_HALF_LIFE_HOURS',
    default: { zh: '168', en: '168' },
    range: { zh: '1 – 8760', en: '1 – 8760' },
    zh: '历史统计按时间衰减的半衰期（小时），默认一周：一周前的记录权重减半。调小后 Smart 更看重最近的表现。',
    en: 'Half-life, in hours, of the time decay applied to historical stats; one week by default, so week-old records count half. Lower it to make Smart weigh recent results more.',
  },
  {
    name: 'SMART_FAILURE_STICKY',
    default: { zh: '2.0', en: '2.0' },
    range: { zh: '1.0 – 8.0', en: '1.0 – 8.0' },
    zh: '失败记录的半衰期是成功记录的几倍。值越大，失败被记住得越久；`1.0` 表示与成功记录相同。',
    en: 'How many times longer failures are remembered than successes. Larger values keep failures around longer; `1.0` treats them like successes.',
  },
  {
    name: 'SMART_LEGACY',
    default: { zh: 'false', en: 'false' },
    range: { zh: '1 / true / yes / on', en: '1 / true / yes / on' },
    zh: '改用旧版的分段式时间衰减曲线，只在对比新旧行为时使用。',
    en: 'Switches to the old stepwise time-decay curve; only useful to compare old and new behavior.',
  },
];
