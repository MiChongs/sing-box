// Landing page copy for /zh/ and /en/. Body strings accept the inline
// syntax from src/lib/inline.ts. `to` values are doc slugs.
import type { Lang } from '../data/nav';

interface Landing {
  hero: { eyebrow: string; title: string; subtitle: string; primary: string; secondary: string; codeCaption: string };
  features: { title: string; lead: string; items: { title: string; body: string; to: string }[] };
  comparison: { title: string; lead: string; headers: string[]; rows: string[][]; legend: string };
  paths: { title: string; items: { title: string; body: string; links: { label: string; to: string }[] }[] };
}

export const landing: Record<Lang, Landing> = {
  zh: {
    hero: {
      eyebrow: 'sing-box xiaobaf14g · Smart 出站组',
      title: '按目标学习，为每条连接选出合适的节点',
      subtitle:
        'Smart 记录每个节点访问每个目标的结果，综合成功率、延迟、抖动与吞吐计算权重；主动探测、连接级 Watchdog 与熔断器在节点变差时尽快绕开它。可选 LightGBM 模型评分与 ASN 分组学习，并通过 Clash API 查看与调整。',
      primary: '快速开始',
      secondary: '工作原理',
      codeCaption: '01-minimal.json',
    },
    features: {
      title: '核心能力',
      lead: '每一项都对应源码中的实际行为，点击进入对应章节查看细节与参数。',
      items: [
        {
          title: '按目标学习',
          body: '统计按（目标, 节点）分别记录，目标归并到可注册域名，如 `*.example.com`。同一个节点访问不同网站的表现分开评分。',
          to: 'how-it-works',
        },
        {
          title: '10 种选路算法',
          body: '`strict-best`、`p2c`、`latency-banded`、`consistent-hashing` 等，可通过 Clash API 热切换，无需重启。',
          to: 'algorithms',
        },
        {
          title: 'Watchdog 与熔断',
          body: '识别首字节超时、写出后 60 秒无响应、RST 及 TLS / HTTP/2 / QUIC / 代理帧致命错误，把节点对该目标软屏蔽 10 分钟；30 秒内两次拨号失败即熔断，探测失败的节点退避重测。',
          to: 'health',
        },
        {
          title: '按地区负载均衡',
          body: '`smart-loadbalance` 把全部节点按地区自动分池，为每个网站选定出口地区，再在地区内按学到的质量与连接数分摊；可锁定地区，也可生成地区出站作嵌套代理前置。',
          to: 'smart-loadbalance',
        },
        {
          title: 'LightGBM 评分',
          body: '预训练模型直接给出节点权重，按特征名兼容 vernesong/mihomo 的 v4 模型与 27 维旧模型；也可采集本地数据离线训练自己的模型。',
          to: 'lightgbm',
        },
        {
          title: '偏好与手动指定',
          body: '`policy_priority` 按节点名称加权；在面板中手动指定节点后，节点故障时临时改用其他节点，恢复后自动切回。',
          to: 'priority-and-pinning',
        },
      ],
    },
    comparison: {
      title: '与其他策略组对比',
      lead: '同一分支中的五种策略组。smart 适合节点多、质量波动大、不同网站最佳节点不同的场景；smart-loadbalance 适合要把连接分摊到多个节点、又要保持出口地区的场景。',
      headers: ['能力', 'selector', 'urltest', 'loadbalance', 'smart', 'smart-loadbalance'],
      rows: [
        ['选择依据', '手动', '测速延迟最低', '轮询 / 哈希 / 粘性会话', '按目标学习的权重 + 10 种算法', '按目标选地区，地区内按质量与连接数分摊'],
        ['定时测速', '—', '✓', '✓', '✓', '✓'],
        ['按目标区分节点表现', '—', '—', '—', '✓', '✓'],
        ['按地区自动分池', '—', '—', '—', '—', '✓'],
        ['连接级故障识别', '—', '—', '—', '✓', '✓'],
        ['熔断与按目标屏蔽', '—', '—', '—', '✓', '✓'],
        ['手动指定节点', '✓', '✓', '—', '✓', '✓（节点或地区）'],
        ['统计数据跨重启保留', '—', '—', '—', '✓', '✓'],
      ],
      legend: '✓ 支持　— 不支持',
    },
    paths: {
      title: '从哪里开始',
      items: [
        {
          title: '第一次使用',
          body: '用最小配置跑起来，再确认它确实在学习。',
          links: [
            { label: '快速开始', to: 'quick-start' },
            { label: '示例配置', to: 'examples' },
          ],
        },
        {
          title: '想知道它为什么选这个节点',
          body: '从目标识别、分层取候选到拨号竞速的完整流程。',
          links: [
            { label: '工作原理', to: 'how-it-works' },
            { label: '健康检查与故障处理', to: 'health' },
          ],
        },
        {
          title: '调参与排障',
          body: '字段默认值、Clash API 与常见问题。',
          links: [
            { label: '配置字段', to: 'config' },
            { label: 'Clash API', to: 'clash-api' },
            { label: '故障排查', to: 'troubleshooting' },
          ],
        },
      ],
    },
  },
  en: {
    hero: {
      eyebrow: 'sing-box xiaobaf14g · Smart outbound group',
      title: 'Learns per destination, picks the right node for every connection',
      subtitle:
        'Smart records how each node performs for each destination and turns success rate, latency, jitter and throughput into a weight. Active probing, a per-connection watchdog and a circuit breaker steer around nodes as soon as they degrade. LightGBM scoring and ASN-grouped learning are optional, and the Clash API lets you inspect and adjust it.',
      primary: 'Quick start',
      secondary: 'How it works',
      codeCaption: '01-minimal.json',
    },
    features: {
      title: 'What it does',
      lead: 'Each item maps to actual behaviour in the source; follow the link for details and parameters.',
      items: [
        {
          title: 'Per-destination learning',
          body: 'Stats are kept per (destination, node), with destinations folded to the registrable domain such as `*.example.com`. One node is scored separately for different sites.',
          to: 'how-it-works',
        },
        {
          title: '10 selection algorithms',
          body: '`strict-best`, `p2c`, `latency-banded`, `consistent-hashing` and more, hot-swappable through the Clash API without a restart.',
          to: 'algorithms',
        },
        {
          title: 'Watchdog and circuit breaker',
          body: 'Detects first-byte timeouts, writes left unanswered for 60 s, RSTs and fatal TLS / HTTP/2 / QUIC / proxy-frame errors, then soft-blocks the node for that destination for 10 minutes. Two dial failures within 30 s open the breaker, and nodes failing probes are retested with backoff.',
          to: 'health',
        },
        {
          title: 'Region-aware load balancing',
          body: '`smart-loadbalance` sorts every node into region pools, picks an exit region per site, then spreads connections across the region by learned quality and live load. Lock a region, or generate region outbounds to use as the front of chained proxies.',
          to: 'smart-loadbalance',
        },
        {
          title: 'LightGBM scoring',
          body: 'A pre-trained model produces node weights directly. Inputs are matched by feature name, so vernesong/mihomo v4 models and older 27-feature models both load. You can also collect local data to train your own.',
          to: 'lightgbm',
        },
        {
          title: 'Preferences and pinning',
          body: '`policy_priority` weights nodes by name. Pin a node in a dashboard and Smart falls back to others while it is down, then returns to it once it recovers.',
          to: 'priority-and-pinning',
        },
      ],
    },
    comparison: {
      title: 'Compared with other groups',
      lead: 'The five group types in this fork. smart fits large, uneven node pools where the best node differs from site to site; smart-loadbalance fits spreading connections over many nodes while keeping the exit region.',
      headers: ['Capability', 'selector', 'urltest', 'loadbalance', 'smart', 'smart-loadbalance'],
      rows: [
        ['Picks by', 'Hand', 'Lowest probe delay', 'Round-robin / hash / sticky', 'Learned per-destination weight + 10 algorithms', 'Region per destination, then quality- and load-weighted spread'],
        ['Periodic probing', '—', '✓', '✓', '✓', '✓'],
        ['Per-destination node quality', '—', '—', '—', '✓', '✓'],
        ['Automatic region pools', '—', '—', '—', '—', '✓'],
        ['Per-connection failure detection', '—', '—', '—', '✓', '✓'],
        ['Circuit breaker, per-destination blocks', '—', '—', '—', '✓', '✓'],
        ['Manual pin', '✓', '✓', '—', '✓', '✓ (node or region)'],
        ['Stats survive restarts', '—', '—', '—', '✓', '✓'],
      ],
      legend: '✓ supported　— not supported',
    },
    paths: {
      title: 'Where to start',
      items: [
        {
          title: 'First time',
          body: 'Run a minimal config, then confirm it is actually learning.',
          links: [
            { label: 'Quick start', to: 'quick-start' },
            { label: 'Examples', to: 'examples' },
          ],
        },
        {
          title: 'Why did it pick that node?',
          body: 'The full path from destination key and candidate tiers to the dial race.',
          links: [
            { label: 'How it works', to: 'how-it-works' },
            { label: 'Health and failures', to: 'health' },
          ],
        },
        {
          title: 'Tuning and debugging',
          body: 'Field defaults, the Clash API and common problems.',
          links: [
            { label: 'Configuration', to: 'config' },
            { label: 'Clash API', to: 'clash-api' },
            { label: 'Troubleshooting', to: 'troubleshooting' },
          ],
        },
      ],
    },
  },
};
