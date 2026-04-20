// Clash API — Smart-related endpoints. Verified against live routing
// tables in:
//   * experimental/clashapi/smart.go       (mount /smart)
//   * experimental/clashapi/proxies.go     (mount /proxies/{name})
//   * experimental/clashapi/cache.go       (mount /cache)
// Group order in the UI mirrors operator workflow: inspect → control → flush.

export type Group = 'inspect' | 'control' | 'flush';

export interface Endpoint {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  path: string;
  group: Group;
  zhTitle: string;
  enTitle: string;
  zhDesc: string;
  enDesc: string;
  curl: string;
}

// Shared `${BASE}` placeholder in curl samples, documented in page body.
const B = 'http://127.0.0.1:9090';

export const endpoints: Endpoint[] = [
  // Inspect ----------------------------------------------------------------
  {
    method: 'GET',
    path: '/smart/weights',
    group: 'inspect',
    zhTitle: '全部 Smart 组权重',
    enTitle: 'All Smart groups — weights',
    zhDesc: '返回每个 Smart 组内所有节点的 0-100 归一化 Score 与原始 Weight。UI 做权重条时用这个。',
    enDesc: 'Returns 0–100 Score and raw Weight for every node in every Smart group. What progress-bar dashboards read.',
    curl: `curl ${B}/smart/weights`,
  },
  {
    method: 'GET',
    path: '/smart/groups',
    group: 'inspect',
    zhTitle: '列出 Smart 组',
    enTitle: 'List Smart groups',
    zhDesc: '只返回所有 type=smart 的出站 tag 与当前 algorithm；不返回节点详情。',
    enDesc: 'Returns the set of type=smart outbound tags and their currently-configured algorithm. No node payload.',
    curl: `curl ${B}/smart/groups`,
  },
  {
    method: 'GET',
    path: '/smart/groups/{name}/diag',
    group: 'inspect',
    zhTitle: '组诊断',
    enTitle: 'Group diagnostics',
    zhDesc: '深度内部状态：当前算法 / hysteresis 窗口、policy_priority 解析结果、WeightRanking 当前 fallback 层 (snapshot/bbolt/live/delay)、每节点 TargetCount 与 SampleCount。调 bug 专用，只读。',
    enDesc: 'Deep internal state: current algorithm + hysteresis, parsed policy_priority rules, which WeightRanking fallback tier is active (snapshot / bbolt cache / live / delay), per-node TargetCount & SampleCount. Read-only, safe to hammer.',
    curl: `curl ${B}/smart/groups/auto/diag`,
  },
  {
    method: 'GET',
    path: '/proxies/{name}/weights',
    group: 'inspect',
    zhTitle: '单组权重',
    enTitle: 'Single-group weights',
    zhDesc: '返回 {name} 组的 NodeRank 列表。`?refresh=true` 触发同步重算（比 cached 慢一拍但能看最新值）。',
    enDesc: 'NodeRank list for group {name}. `?refresh=true` recomputes synchronously (slower than cached, always fresh).',
    curl: `curl "${B}/proxies/auto/weights?refresh=true"`,
  },
  {
    method: 'GET',
    path: '/proxies/{name}',
    group: 'inspect',
    zhTitle: 'Smart 组详情（含 pin 挂起状态）',
    enTitle: 'Smart group detail (pin suspend state)',
    zhDesc: '通用 Clash 代理详情端点。Smart 组在 mihomo 字段基础上追加 `fixed`（用户 pin 的 tag）/ `fixedSuspended`（pin 当前是否被 bypass，true 表示"节点死了自动 fallback 中"）/ `fixedActive`（实际在用的节点 tag，未挂起时等于 fixed）/ `algorithm` / `hysteresis` / `policyPriority` / `pinEndorsements`。UI 推荐：`fixedSuspended=true` 时展示"固定 A（暂不可用，当前走 B）"，`fixed==""` 表示自动模式。',
    enDesc: 'Standard Clash proxy-detail endpoint. Smart groups add: `fixed` (user pin tag), `fixedSuspended` (true ⇒ pin currently bypassed, auto-fallback in effect), `fixedActive` (the node actually carrying traffic; equals fixed when not suspended), plus `algorithm` / `hysteresis` / `policyPriority` / `pinEndorsements`. UI hint: render "pinned A (currently unavailable, routing via B)" when `fixedSuspended=true`; `fixed==""` means auto mode.',
    curl: `curl ${B}/proxies/auto`,
  },

  // Control ----------------------------------------------------------------
  {
    method: 'POST',
    path: '/smart/groups/{name}/block/{node}',
    group: 'control',
    zhTitle: '临时屏蔽节点',
    enTitle: 'Temporarily block a node',
    zhDesc: '把 {node} 在 {name} 组内立刻标记为 dead；下一次 dial 会跳过它。可选 `?duration=5m` 控制冷却长度；默认走 breaker 配置。',
    enDesc: 'Mark {node} within {name} as dead immediately; next dial skips it. Optional `?duration=5m` overrides the default breaker cooldown.',
    curl: `curl -X POST "${B}/smart/groups/auto/block/HK-slow?duration=5m"`,
  },
  {
    method: 'PUT',
    path: '/smart/groups/{name}/algorithm',
    group: 'control',
    zhTitle: '热切换算法',
    enTitle: 'Hot-swap algorithm',
    zhDesc: '运行时把 {name} 组的 algorithm 改成另一种。请求体是纯字符串，支持 10 种枚举：`strict-best` / `weighted-random` / `least-loaded` / `fastest-recent` / `sticky-session` / `round-robin` / `weighted-rr` / `p2c` / `latency-banded` / `consistent-hashing`。无需重启。',
    enDesc: 'Change the running algorithm of {name} at runtime. Body is a bare string, one of 10 names: `strict-best` / `weighted-random` / `least-loaded` / `fastest-recent` / `sticky-session` / `round-robin` / `weighted-rr` / `p2c` / `latency-banded` / `consistent-hashing`. No restart.',
    curl: `curl -X PUT -d 'consistent-hashing' ${B}/smart/groups/auto/algorithm`,
  },
  {
    method: 'PUT',
    path: '/proxies/{name}',
    group: 'control',
    zhTitle: '手动固定 / 解除节点',
    enTitle: 'Pin / unpin a node',
    zhDesc: '在 {name} 组内强制使用指定节点（mihomo 兼容的 SelectOutbound）。请求体 `{"name": "tag"}` 固定，`{"name": ""}` 解除。Smart 组 pin 有三层保护：(1) 若该节点 circuit breaker 开启则暂时 bypass，恢复后自动回归；(2) pin 节点首次 dial 失败时（breaker 未开）本次自动 fallback 到算法候选，pin 状态保留；(3) fallback 发生时 `fixedSuspended` 同步为 true，UI 可立即显示"暂不可用"。切换行为是否同时中断已建立连接由 `interrupt_exist_connections` 决定。',
    enDesc: 'Pin a specific node in {name} (mihomo-compatible SelectOutbound). Body `{"name": "tag"}` pins, `{"name": ""}` clears. Smart pin has three safeties: (1) when the pinned node\'s circuit breaker is open it is temporarily bypassed and auto-restored on recovery; (2) on first-dial failure (breaker not yet tripped), THIS dial silently falls back to algorithm candidates while the pin tag is retained; (3) during a fallback `fixedSuspended` flips to true so UIs render "currently unavailable". Whether to also interrupt existing conns is controlled by `interrupt_exist_connections`.',
    curl: `curl -X PUT -H 'Content-Type: application/json' -d '{"name":"HK-01"}' ${B}/proxies/auto`,
  },
  {
    method: 'DELETE',
    path: '/proxies/{name}',
    group: 'control',
    zhTitle: '清除 pin（Smart 专用 verbose 响应）',
    enTitle: 'Clear pin (Smart verbose response)',
    zhDesc: 'Smart 组的 "取消固定" 动词入口。响应体镜像 mihomo 风格：`{group, previous_pin, now, interrupted_mux, unwrap_cleared}`。Selector 请改用 `PUT` 传 `{"name":""}`。',
    enDesc: 'Smart-only "release pin" verb. Response mirrors mihomo: `{group, previous_pin, now, interrupted_mux, unwrap_cleared}`. For Selector groups use `PUT` with `{"name":""}` instead.',
    curl: `curl -X DELETE ${B}/proxies/auto`,
  },

  // Flush / cache reset ----------------------------------------------------
  {
    method: 'POST',
    path: '/cache/smart/flush',
    group: 'flush',
    zhTitle: '清空所有 Smart 组数据',
    enTitle: 'Flush every Smart group',
    zhDesc: '清空所有组的统计、节点状态、排名快照、prefetch 缓存、host 失败计数。DELETE 是 POST 的同义词（方便 dashboard 绑按钮）。',
    enDesc: 'Drops stats, node states, ranking snapshots, prefetch cache, and host-failure counters for every group. DELETE is an alias of POST for dashboard convenience.',
    curl: `curl -X POST ${B}/cache/smart/flush`,
  },
  {
    method: 'DELETE',
    path: '/cache/smart/flush',
    group: 'flush',
    zhTitle: '清空所有（DELETE 别名）',
    enTitle: 'Flush all (DELETE alias)',
    zhDesc: '与 POST /cache/smart/flush 行为一致。',
    enDesc: 'Same behavior as POST /cache/smart/flush.',
    curl: `curl -X DELETE ${B}/cache/smart/flush`,
  },
  {
    method: 'POST',
    path: '/cache/smart/flush/{name}',
    group: 'flush',
    zhTitle: '清空单个 Smart 组',
    enTitle: 'Flush one Smart group',
    zhDesc: '按组 tag 清空。适合想"重训一个组但保留其他组"的场景。',
    enDesc: 'Flush by group tag. Useful when you want to reset one group but keep the others warm.',
    curl: `curl -X POST ${B}/cache/smart/flush/auto`,
  },
  {
    method: 'DELETE',
    path: '/cache/smart/flush/{name}',
    group: 'flush',
    zhTitle: '清空单组（DELETE 别名）',
    enTitle: 'Flush one (DELETE alias)',
    zhDesc: '与 POST /cache/smart/flush/{name} 行为一致。',
    enDesc: 'Same behavior as POST /cache/smart/flush/{name}.',
    curl: `curl -X DELETE ${B}/cache/smart/flush/auto`,
  },
  {
    method: 'DELETE',
    path: '/proxies/{name}/weights',
    group: 'flush',
    zhTitle: '清空单组（/proxies 变体）',
    enTitle: 'Flush via /proxies (variant)',
    zhDesc: '作用等同 DELETE /cache/smart/flush/{name}，只是走 /proxies 资源路径，方便 UI "清除权重" 按钮绑 REST 动词。',
    enDesc: 'Same effect as DELETE /cache/smart/flush/{name}; exposed at /proxies/{name}/weights so dashboard "clear weights" buttons can use the natural REST verb.',
    curl: `curl -X DELETE ${B}/proxies/auto/weights`,
  },
];

export const groupLabels = {
  zh: { inspect: '查询 (只读)', control: '控制', flush: '清空 / 重置' },
  en: { inspect: 'Inspect (read-only)', control: 'Control', flush: 'Flush / reset' },
};

export default endpoints;
