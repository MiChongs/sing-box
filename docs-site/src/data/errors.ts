// Messages the Smart groups can produce, grouped by where they show up.
// Every message is grepped from the Go source: protocol/group/smart*.go,
// protocol/group/member_filter.go, common/smart/priority.go,
// common/urltest/expected_status.go, experimental/clashapi/{smart,cache,
// proxies,connections}.go. `<…>` marks a value filled in at runtime.

export interface ErrorEntry {
  message: string;
  zh: string;
  en: string;
}

export interface ErrorFamily {
  id: string;
  zh: string;
  en: string;
  entries: ErrorEntry[];
}

export const errorFamilies: ErrorFamily[] = [
  {
    id: 'config',
    zh: '启动与配置',
    en: 'Startup and configuration',
    entries: [
      {
        message: 'json: unknown field "<field>"',
        zh: '配置中有不认识的字段，例如旧版 Smart 的 `algorithm`、`hysteresis`、`use_asn`、`asn_database`、`max_host_failed_times`。删除它，对照 [变更记录](/zh/changelog/) 换成新字段。',
        en: 'The configuration has a field that does not exist, such as the old Smart `algorithm`, `hysteresis`, `use_asn`, `asn_database` or `max_host_failed_times`. Remove it; the [Changelog](/en/changelog/) lists the replacements.',
      },
      {
        message: 'interval must be less or equal than idle_timeout',
        zh: '`interval` 比 `idle_timeout`（默认 30 分钟）还长。缩短 `interval`，或同时调大 `idle_timeout`。',
        en: '`interval` is longer than `idle_timeout` (30 minutes by default). Shorten `interval`, or raise `idle_timeout` with it.',
      },
      {
        message: 'missing outbound and provider tags',
        zh: '`outbounds` 与 `providers` 都没有写（且没有开启 `use_all_providers`）。',
        en: 'Neither `outbounds` nor `providers` is set (and `use_all_providers` is off).',
      },
      {
        message: 'duplicate tag: <tag>',
        zh: '`outbounds` 中同一个标签写了两次。',
        en: 'The same tag appears twice in `outbounds`.',
      },
      {
        message: 'outbound <i> not found: <tag>',
        zh: '`outbounds` 中的第 i 个标签不存在。',
        en: 'Tag number i of `outbounds` does not exist.',
      },
      {
        message: 'outbound provider <i> not found: <tag>',
        zh: '`providers` 中的第 i 个订阅不存在。',
        en: 'Provider number i of `providers` does not exist.',
      },
      {
        message: "policy_priority: \"<rule>\" must be in 'pattern:factor' format",
        zh: '某条规则没有 `:`，或模式、系数为空。模式本身含 `:` 时写成 `\\:`。',
        en: 'A rule has no `:`, or an empty pattern or factor. Write a `:` inside a pattern as `\\:`.',
      },
      {
        message: 'policy_priority: "<rule>": factor must be positive',
        zh: '系数是 0 或负数。想回避某些节点，用小于 1 的正数，如 `0.5`。',
        en: 'The factor is 0 or negative. To avoid nodes, use a positive factor below 1, such as `0.5`.',
      },
      {
        message: 'policy_priority: "<rule>": strconv.ParseFloat: …',
        zh: '系数不是数字。',
        en: 'The factor is not a number.',
      },
      {
        message: 'urltest: invalid expected-status: <part>',
        zh: '`expected_status` 写法错误；范围写错时为 `invalid expected-status range`，超出 100–599 时为 `out-of-range expected-status`。',
        en: '`expected_status` has bad syntax; a bad range gives `invalid expected-status range`, a code outside 100–599 gives `out-of-range expected-status`.',
      },
      {
        message: 'include_type: unknown outbound type: <type>',
        zh: '`include_type` / `exclude_type` 中有不认识的协议类型。',
        en: '`include_type` / `exclude_type` lists an unknown protocol type.',
      },
      {
        message: 'include_transport: unknown transport: <name>',
        zh: '`include_transport` / `exclude_transport` 中有不认识的传输层。',
        en: '`include_transport` / `exclude_transport` lists an unknown transport.',
      },
    ],
  },
  {
    id: 'dial',
    zh: '连接失败',
    en: 'Connection failures',
    entries: [
      {
        message: 'no available member for <host>',
        zh: '过滤后一个可拨的成员都没有：所有成员都被手动封锁了这个网站（`DELETE /connections/smart/{id}` 留下的 `manual` 封锁），或都因出口嫌疑被推迟。清空本组数据即可解除手动封锁。UDP 连接为 `no available member for UDP to <目标>`。`smart-loadbalance` 在 `fallback` 不允许离开地区、而地区内没有节点时也报这个错。',
        en: 'No dialable member is left after filtering: every member was manually blocked for this site (a `manual` block from `DELETE /connections/smart/{id}`), or deferred by an exit suspicion. Flushing the group lifts manual blocks. For UDP the message is `no available member for UDP to <destination>`. `smart-loadbalance` also reports it when `fallback` keeps the connection in a region that has no node.',
      },
      {
        message: 'all members failed for <host>: <errors>',
        zh: '本次连接拨过的成员全部失败（最多 10 个），后面附上各自的错误。目标域名解析不存在（NXDOMAIN）时会立即停止，不再尝试其他成员。',
        en: 'Every member dialed for this connection failed (at most 10), followed by their errors. When the destination does not resolve (NXDOMAIN), dialing stops at once without trying more members.',
      },
      {
        message: 'UDP is disabled for <tag>',
        zh: '本组设置了 `disable_udp`。',
        en: 'The group has `disable_udp` set.',
      },
    ],
  },
  {
    id: 'api',
    zh: 'Clash API',
    en: 'Clash API',
    entries: [
      {
        message: 'group not found: <name>',
        zh: '`/smart/groups/{name}/…` 中的组不存在（404）。组名含中文或空格时要做 URL 编码。',
        en: 'The group in `/smart/groups/{name}/…` does not exist (404). URL-encode names with spaces or non-ASCII characters.',
      },
      {
        message: 'not a Smart group: <name>',
        zh: '`/smart/groups/{name}/…` 指向的出站不是 `smart` / `smart-loadbalance` 组（404）。`/proxies/{name}/weights` 对非 Smart 组返回 400 `{"weights": [], "error": "not a Smart group"}`。',
        en: 'The outbound behind `/smart/groups/{name}/…` is not a `smart` / `smart-loadbalance` group (404). `/proxies/{name}/weights` answers non-Smart groups with 400 `{"weights": [], "error": "not a Smart group"}`.',
      },
      {
        message: 'node not a member of this group: <tag>',
        zh: '`POST /smart/groups/{name}/block/{node}` 中的节点不是本组成员（404）。',
        en: 'The node in `POST /smart/groups/{name}/block/{node}` is not a member of the group (404).',
      },
      {
        message: 'Smart update error: not found',
        zh: '`PUT /proxies/{name}` 指定的节点不是本组成员；对 `smart-loadbalance` 组，也不是地区代码、名称或地区出站（400）。',
        en: 'The node given to `PUT /proxies/{name}` is not a member; for `smart-loadbalance`, not a region code, name or region outbound either (400).',
      },
      {
        message: 'not a smart-loadbalance group: <name>',
        zh: '对普通 `smart` 组调用了地区或分配接口（400）。',
        en: 'A region or balance endpoint was called on a plain `smart` group (400).',
      },
      {
        message: 'unknown region: <value>',
        zh: '锁定的地区不存在或没有成员（400）。',
        en: 'The region to lock does not exist or has no members (400).',
      },
      {
        message: 'invalid JSON body: <error>',
        zh: '`PUT /smart/groups/{name}/regions` 或 `/balance` 的请求体不是合法 JSON（400）。',
        en: 'The body of `PUT /smart/groups/{name}/regions` or `/balance` is not valid JSON (400).',
      },
    ],
  },
  {
    id: 'log',
    zh: '日志中的警告',
    en: 'Warnings in the log',
    entries: [
      {
        message: 'failures are flooding in, learning paused until a connection succeeds',
        zh: '短时间内连续 50 次失败（每次间隔不超过 2 秒），通常是网络断了。期间失败不计入任何节点，下一次成功连接后恢复学习。见 [失败风暴](/zh/blocks-and-probes/#失败风暴)。',
        en: '50 failures in a row, each within 2 s of the previous, which usually means the network is down. Failures are not held against any node until the next successful connection. See [Failure floods](/en/blocks-and-probes/#failure-floods).',
      },
      {
        message: 'lightgbm: cannot use model <path>: <error>',
        zh: '模型文件存在但无法加载，期间用场景公式计算质量。',
        en: 'The model file exists but cannot be loaded; quality falls back to the scene formula.',
      },
      {
        message: 'open ASN database <path>: <error>',
        zh: 'ASN 数据库存在但无法打开（格式错误等）。文件还在下载时只记录 debug 日志，下载完成后自动启用。',
        en: 'The ASN database exists but cannot be opened (bad format, …). While the file is still downloading only a debug line is logged, and it is used as soon as it arrives.',
      },
      {
        message: 'save smart evidence: <error>',
        zh: '把学习数据写入缓存文件失败，通常是磁盘满或缓存文件被其他进程占用。',
        en: 'Writing learned data to the cache file failed, usually a full disk or a cache file locked by another process.',
      },
    ],
  },
];
