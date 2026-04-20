// SmartOutboundOptions — mirrors option/group.go:58 (SmartOutboundOptions struct).
// Kept as a flat array of FieldDef so <ConfigSchema> can render them
// uniformly in either locale. Keep in lockstep with the Go source.

export interface FieldDef {
  name: string;
  type: string;
  default?: string;
  required?: boolean;
  descZh: string;
  descEn: string;
  notes?: string;
}

export const smartOutbound: FieldDef[] = [
  {
    name: 'url',
    type: 'string',
    default: 'https://www.gstatic.com/generate_204',
    descZh: 'URLTest 探测目标。默认走 gstatic 的 204 接口；国内环境可换为自建 204 或 cloudflare.com。',
    descEn: 'URLTest probe target. Defaults to gstatic 204; replace with your own 204 endpoint or cloudflare.com in restricted regions.',
  },
  {
    name: 'interval',
    type: 'duration',
    default: '3m',
    descZh: '主动健康检查 / 延迟探测的周期。太短浪费带宽，太长反应慢；家宽 3 分钟、机房 30 秒较常见。',
    descEn: 'Active health-check and latency-probe interval. Home ISPs ~3m, datacenter ~30s; too short wastes bandwidth, too long delays detection.',
  },
  {
    name: 'tolerance',
    type: 'uint16',
    default: '50',
    descZh: '与当前最快节点的延迟差（毫秒）在此值以内时不切换；避免抖动频繁切节点。',
    descEn: 'Delay difference (ms) below which the current top node is kept. Prevents thrashing between equally-fast nodes.',
  },
  {
    name: 'idle_timeout',
    type: 'duration',
    default: '30m',
    descZh: '健康检查在节点闲置超过此时长后暂停，首次新请求触发时再恢复；省电同时避免"僵尸节点"。',
    descEn: 'Health check pauses after this idle duration and resumes on next dial; saves battery without orphaning nodes.',
  },
  {
    name: 'policy_priority',
    type: 'string',
    descZh: '按节点 tag 子串加权。格式：`"香港:1.5;日本:1.2;美国:0.7"`。匹配到的节点权重乘以对应系数。',
    descEn: 'Manual weight multiplier by tag substring. Format: `"HK:1.5;JP:1.2;US:0.7"`. Matching nodes have their computed weight multiplied.',
  },
  {
    name: 'use_asn',
    type: 'bool',
    default: 'false',
    descZh: '启用 ASN 感知路由：按 (目标 ASN, 节点) 独立学习权重。需要提供 `asn_database` 或 `experimental.geox.url.asn`。',
    descEn: 'Enable ASN-aware routing: learn per-(target ASN, node) weights independently. Requires `asn_database` or `experimental.geox.url.asn`.',
  },
  {
    name: 'asn_database',
    type: 'string | string[]',
    descZh: 'ASN mmdb 路径；支持多源列表，多源时按顺序尝试直到命中。空则回落到 `experimental.geox.url.asn`。',
    descEn: 'ASN mmdb path(s); multi-source list is queried in order until hit. Empty falls back to `experimental.geox.url.asn`.',
    notes: 'Listable[string]',
  },
  {
    name: 'disable_udp',
    type: 'bool',
    default: 'false',
    descZh: '禁止 Smart 组参与 UDP 路由；QUIC / DNS-over-UDP 会绕过此组走 fallback。',
    descEn: 'Exclude Smart from UDP routing; QUIC / DNS-over-UDP falls back past this group.',
  },
  {
    name: 'interrupt_exist_connections',
    type: 'bool',
    default: 'false',
    descZh: '切换节点时是否中断已建立的旧连接。启用避免"卡住的长连接"，但会打断正在传输的流。',
    descEn: 'Interrupt existing conns on node switch. Prevents stuck streams but can cut ongoing transfers.',
  },
  {
    name: 'max_host_failed_times',
    type: 'int',
    default: '10',
    descZh: '对单个目标 host 累计失败达此值时，停止再降级该 host 对应的节点 —— 假设问题在目标而非节点。',
    descEn: 'Per-host cumulative failure cap; past this point we stop demoting nodes — assume the target, not the node, is broken.',
  },
  {
    name: 'use_lightgbm',
    type: 'bool',
    default: 'false',
    descZh: '每组级开关；打开后用 `experimental.smart.lightgbm` 的共享模型打分节点。模型未配置或未下载时自动回落到传统权重。',
    descEn: 'Per-group switch; when on, nodes are scored via the shared `experimental.smart.lightgbm` model. Falls back to classic weighting if model absent.',
  },
  {
    name: 'collect_data',
    type: 'bool',
    default: 'false',
    descZh: '把本组的 dial 结果追加到共享 CSV (`experimental.smart.collector.path`)，供离线重训练 LightGBM 模型使用。',
    descEn: 'Append this group\'s dial outcomes to the shared CSV (`experimental.smart.collector.path`) for offline LightGBM retraining.',
  },
  {
    name: 'sample_rate',
    type: 'float',
    default: '1.0',
    descZh: 'CSV 采样率 (0, 1]。1.0 全量写；流量极大时建议 0.1–0.3 防止 CSV 膨胀。',
    descEn: 'CSV sampling rate in (0, 1]. 1.0 writes every dial; under heavy traffic drop to 0.1–0.3 to cap file growth.',
  },
  {
    name: 'algorithm',
    type: 'enum',
    default: 'strict-best',
    descZh: '候选节点最终重排策略：`strict-best` / `weighted-random` / `least-loaded` / `fastest-recent` / `sticky-session` / `round-robin` / `weighted-rr` / `p2c` / `latency-banded` / `consistent-hashing`。其中 `consistent-hashing` 按目标域名做 jumpHash 到确定的候选槽位（同 target 总到同节点），是 selection-style 算法 —— 下次 dial 会把它 promote 到 position 0。',
    descEn: 'Candidate re-ranking strategy: `strict-best` / `weighted-random` / `least-loaded` / `fastest-recent` / `sticky-session` / `round-robin` / `weighted-rr` / `p2c` / `latency-banded` / `consistent-hashing`. `consistent-hashing` jumpHashes by target into a deterministic slot (same target → same node); selection-style — promotes its pick to position 0 on the next dial.',
    notes: '10 choices; hot-swappable via Clash API PUT /smart/groups/{name}/algorithm',
  },
  {
    name: 'hysteresis',
    type: 'duration',
    default: '0',
    descZh: '抗抖动窗口。0 时每次 dial 独立评估；推荐 1–5s：同 target 在窗口内保持上一个选择，除非那节点掉线。',
    descEn: 'Anti-flap window. 0 re-evaluates every dial; 1–5s keeps the previous pick within the window unless it dies. Prevents two-node ping-ponging.',
  },
  {
    name: 'outbounds',
    type: 'string[]',
    descZh: '手动指定组内节点 tag 列表。与 `providers` / `use_all_providers` 互补。',
    descEn: 'Manual list of node tags to include. Orthogonal to `providers` / `use_all_providers`.',
  },
  {
    name: 'providers',
    type: 'string[]',
    descZh: '订阅 provider tag 列表。其下所有节点自动加入本组（按 include/exclude 过滤）。',
    descEn: 'Subscription provider tags. All their outbounds auto-join (subject to include/exclude).',
  },
  {
    name: 'use_all_providers',
    type: 'bool',
    default: 'false',
    descZh: '忽略 `providers`，自动加入所有已注册的 provider。订阅侧为主的配置可省代码。',
    descEn: 'Ignore `providers`; auto-enrol every registered provider. Convenient for subscription-first setups.',
  },
  {
    name: 'include',
    type: 'regex',
    descZh: '只允许 tag 匹配此正则的节点进入本组。',
    descEn: 'Only nodes whose tag matches this regex enter the group.',
  },
  {
    name: 'exclude',
    type: 'regex',
    descZh: '排除 tag 匹配此正则的节点。优先级高于 include。',
    descEn: 'Exclude nodes whose tag matches this regex. Overrides include.',
  },
  {
    name: 'hidden',
    type: 'bool',
    default: 'false',
    descZh: 'Clash Dashboard 隐藏本组（仍可用于规则路由）。mihomo 兼容。',
    descEn: 'Hide from Clash Dashboard UI (still usable by rules). mihomo-compatible.',
  },
  {
    name: 'icon',
    type: 'string',
    descZh: 'Dashboard 图标：URL / data URI / 短 emoji。sing-box 不解析内容，仅透传给 Clash API。',
    descEn: 'Dashboard icon: URL / data URI / short emoji. sing-box passes through verbatim via Clash API.',
  },
];

export default smartOutbound;
