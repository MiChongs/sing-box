// Metadata + bilingual narration for the 5 example JSON files under
// src/examples/. The actual JSON bodies are raw-imported by the page
// component so Shiki can syntax-highlight them verbatim.

export interface ExampleMeta {
  id: string;
  file: string;          // referenced title (also becomes the <CodeBlock filename>)
  zhTitle: string;
  enTitle: string;
  zhIntro: string;
  enIntro: string;
  zhNotes: string[];
  enNotes: string[];
}

export const examples: ExampleMeta[] = [
  {
    id: '01-minimal',
    file: '01-minimal.json',
    zhTitle: '01 · 最小配置',
    enTitle: '01 · Minimal',
    zhIntro: '把 selector 换成 Smart 的最低代价路径。只需订阅 provider，其余全走默认。',
    enIntro: 'The least-effort swap from selector to Smart. One provider subscription, everything else on defaults.',
    zhNotes: [
      'Smart 会自动按 URLTest 延迟给节点排序，初次启动 3 分钟后开始有稳定数据',
      '未开 use_lightgbm 时使用传统 mihomo 权重公式，无需模型文件',
      '把 url 换成 `https://www.gstatic.com/generate_204` 在国外更快，国内可换 204 自建',
    ],
    enNotes: [
      'Smart ranks nodes by URLTest latency out of the box; expect stable data after ~3 min warm-up',
      'Without use_lightgbm it uses the classic mihomo weight formula — no model file needed',
      'Swap url to a regional 204 endpoint (self-hosted or cloudflare.com) for the first probe to not eat bandwidth',
    ],
  },
  {
    id: '02-lightgbm',
    file: '02-lightgbm.json',
    zhTitle: '02 · 启用 LightGBM',
    enTitle: '02 · Enable LightGBM',
    zhIntro: '打开 ML 评分。首次启动会下载约 8 MB 模型，缓存到本地；同时开始采集训练 CSV（按 30% 采样率防撑爆）。',
    enIntro: 'Turn on ML scoring. First launch downloads the ~8 MB model; simultaneously emits a training CSV at 30 % sampling to cap growth.',
    zhNotes: [
      'download_detour 建议指向 `direct` 或已确认稳定的出站，避免用 smart 自身下载自己的模型',
      'size_limit_mb 达上限后静默丢弃新样本，定期 `rm` 那个 CSV 就能继续采',
      'sample_rate < 1 的样本仍足以重训练 — 模型对 1 周以上数据不敏感于密度',
    ],
    enNotes: [
      'Point download_detour at `direct` or a known-good proxy — never self-host with the smart group you\'re setting up',
      'Past size_limit_mb the collector silently drops new samples; `rm` the CSV periodically to keep collecting',
      'Sample rate < 1 still trains fine — models are insensitive to density past ~1 week of data',
    ],
  },
  {
    id: '03-geox-asn',
    file: '03-geox-asn.json',
    zhTitle: '03 · GeoX + ASN 感知',
    enTitle: '03 · GeoX + ASN awareness',
    zhIntro: '让 Smart 按目标 ASN 独立学习权重。policy_priority 额外按节点 tag 里的关键字给香港/日本节点加权。',
    enIntro: 'Let Smart learn weights per destination ASN. policy_priority adds manual multipliers by node-tag substring.',
    zhNotes: [
      'ASN 感知对多机场 / 多线路场景提升显著；节点对 Cloudflare 和 Google 的表现终于分开评估',
      'policy_priority 格式是分号分隔的 `关键字:系数`，关键字会和节点 tag 做子串匹配',
      'geox.enabled 为 false 时仍可工作 — asn_database 直接指本地 mmdb 即可',
    ],
    enNotes: [
      'ASN awareness shines with multi-provider setups — a node\'s Cloudflare performance and Google performance finally rank independently',
      'policy_priority format: `<keyword>:<multiplier>` semicolon-separated; keyword is a substring match against node tag',
      'Works fine with geox.enabled=false — just point asn_database at a local mmdb',
    ],
  },
  {
    id: '04-multi-asn-fallback',
    file: '04-multi-asn-fallback.json',
    zhTitle: '04 · 多源 ASN Fallback',
    enTitle: '04 · Multi-source ASN fallback',
    zhIntro: '三个 ASN 数据源 (MaxMind / IPinfo / DB-IP) 互补，Smart 查询时按顺序尝试，首个命中即返回。覆盖 CDN 与小众 ISP 盲区。',
    enIntro: 'Three ASN data sources (MaxMind / IPinfo / DB-IP) complement each other. Smart queries in order, returns on first hit. Covers CDN and small-ISP blind spots.',
    zhNotes: [
      '本地 asn_database 也可列多个，同样是顺序 fallback',
      '下载失败的源会静默跳过，运行日志可见 "smart: all configured ASN databases failed to open" 时说明全部失败',
      'MaxMind 免费版每周一更，IPinfo 每天，DB-IP 每月 —— 多源可以提高新 ISP 的命中率',
    ],
    enNotes: [
      'Local asn_database also supports a list — same "first hit wins" semantics',
      'Failed sources are skipped silently; watch for "smart: all configured ASN databases failed to open" to know when all failed',
      'MaxMind free refreshes weekly, IPinfo daily, DB-IP monthly — stacking sources catches new ISPs faster',
    ],
  },
  {
    id: '05-algorithms',
    file: '05-algorithms.json',
    zhTitle: '05 · 多 Smart 组 + 按算法分工',
    enTitle: '05 · Multiple Smart groups per algorithm',
    zhIntro: '不同路由规则路由到不同算法的 Smart 组：交互流量走 latency-banded，大流量走 least-loaded，一般流量走 p2c，有状态会话走 sticky。',
    enIntro: 'Route by traffic character: interactive → latency-banded, bulk → least-loaded, general → p2c, stateful → sticky-session.',
    zhNotes: [
      'latency-banded 把节点按 RTT 分箱，每次从最低箱均匀选 —— 避开长尾但不死盯最快',
      'least-loaded 读当前活跃连接数 (Smart.nodeLoad)，优先选连接少的节点，适合下载',
      'p2c (power-of-two choices) 随机挑 2 个候选，拨 RTT 更低那个；provably 负载均衡',
      'sticky-session 搭配 hysteresis 防止 TLS 会话中断，交互连接大幅减少重握手',
    ],
    enNotes: [
      'latency-banded buckets nodes by RTT; picks uniformly from the lowest non-empty band — avoids tail latency without locking onto the single fastest node',
      'least-loaded reads the current active-conn counter (Smart.nodeLoad); picks the least-busy node, ideal for bulk transfer',
      'p2c (power-of-two-choices) samples 2 candidates, dials the lower-RTT one — provably balanced load at O(1)',
      'sticky-session + hysteresis keeps TLS session reuse intact; drastically cuts handshake overhead on interactive flows',
    ],
  },
];

export default examples;
