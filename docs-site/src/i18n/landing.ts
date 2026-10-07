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
      title: '按网站学习，让每条连接都走最合适的节点',
      subtitle:
        'Smart 记住每个节点访问每个网站的表现——成功率、延迟、抖动与速度——为新连接挑选当下最合适的节点；节点一变差，主动探测、连接级 Watchdog 与熔断器就会尽快绕开它。它还能按地区分摊连接、用 LightGBM 模型评分，并在面板里随时查看与调整。',
      primary: '快速开始',
      secondary: '工作原理',
      codeCaption: '01-minimal.json',
    },
    features: {
      title: '核心能力',
      lead: '每一项都对应源码中的实际行为。点击卡片，查看对应章节的细节与参数。',
      items: [
        {
          title: '按网站学习',
          body: '统计按（目标, 节点）分别记录：同一个节点访问不同网站的表现分开评分，各取所长。随机生成的子域名会归并，例如 `rr3---sn-abc.googlevideo.com` 记作 `*.googlevideo.com`。',
          to: 'how-it-works',
        },
        {
          title: '10 种选路算法',
          body: '从“只用最好的”到“几个好节点轮流用”：`strict-best`、`p2c`、`latency-banded`、`consistent-hashing` 等，可通过 Clash API 随时切换，无需重启。',
          to: 'algorithms',
        },
        {
          title: 'Watchdog 与熔断',
          body: '盯住每一条连接：首字节超时、写出后 60 秒无响应、被重置、TLS / HTTP/2 / QUIC / 代理协议出错，都会让节点对该网站暂停 10 分钟；30 秒内拨号失败两次即熔断，测速失败的节点逐步拉长重测间隔。',
          to: 'health',
        },
        {
          title: '按地区负载均衡',
          body: '`smart-loadbalance` 把全部节点按地区自动分池，为每个网站选定出口地区，再按学到的质量与连接数在地区内分摊连接。可以锁定地区，也可以为每个地区生成出站，用作嵌套代理的前置。',
          to: 'smart-loadbalance',
        },
        {
          title: 'LightGBM 评分',
          body: '用预训练模型直接给节点打分，按特征名兼容 vernesong/mihomo 的 v4 模型与 27 维旧模型；也可以采集自己的连接数据，离线训练专属模型。',
          to: 'lightgbm',
        },
        {
          title: '偏好与手动指定',
          body: '用 `policy_priority` 按节点名称加减分；在面板里手动指定节点后，它出故障时临时改用其他节点，恢复后自动切回。',
          to: 'priority-and-pinning',
        },
      ],
    },
    comparison: {
      title: '与其他策略组对比',
      lead: '本分支提供五种策略组。节点多、质量起伏大、不同网站适合不同节点时，用 smart；想把连接分摊到多个节点、又要保持出口地区不变时，用 smart-loadbalance。',
      headers: ['能力', 'selector', 'urltest', 'loadbalance', 'smart', 'smart-loadbalance'],
      rows: [
        ['怎么选节点', '手动', '测速延迟最低', '轮询 / 哈希 / 粘性会话', '按网站学到的权重 + 10 种算法', '先按网站选地区，再在地区内按质量与连接数分摊'],
        ['定时测速', '—', '✓', '✓', '✓', '✓'],
        ['按网站区分节点表现', '—', '—', '—', '✓', '✓'],
        ['按地区自动分池', '—', '—', '—', '—', '✓'],
        ['连接级故障识别', '—', '—', '—', '✓', '✓'],
        ['熔断与按网站屏蔽', '—', '—', '—', '✓', '✓'],
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
          body: '用最小配置跑起来，再确认它确实在学习；遇到不熟悉的词，查术语表。',
          links: [
            { label: '快速开始', to: 'quick-start' },
            { label: '示例配置', to: 'examples' },
            { label: '术语表', to: 'glossary' },
          ],
        },
        {
          title: '想知道它为什么选了这个节点',
          body: '从识别目标、分层取候选到拨号竞速，一条连接的完整流程。',
          links: [
            { label: '工作原理', to: 'how-it-works' },
            { label: '健康检查与故障处理', to: 'health' },
          ],
        },
        {
          title: '调参与排障',
          body: '查字段默认值、用 Clash API 查看与控制、按症状排查问题。',
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
      title: 'Learns each site, sends every connection through the best node',
      subtitle:
        'Smart remembers how every node performs for every site — success rate, latency, jitter and speed — and picks the best node for each new connection. When a node degrades, active probing, a per-connection watchdog and a circuit breaker route around it quickly. It can also spread connections by region, score nodes with a LightGBM model, and be inspected and tuned from your dashboard.',
      primary: 'Quick start',
      secondary: 'How it works',
      codeCaption: '01-minimal.json',
    },
    features: {
      title: 'What it does',
      lead: 'Every item describes what the code actually does. Open a card for the details and parameters.',
      items: [
        {
          title: 'Learns per site',
          body: 'Stats are kept per (destination, node), so one node is scored separately for every site and each site gets the node that suits it. Randomly generated subdomains are folded together: `rr3---sn-abc.googlevideo.com` counts as `*.googlevideo.com`.',
          to: 'how-it-works',
        },
        {
          title: '10 selection algorithms',
          body: 'From "only the best node" to "take turns among the good ones": `strict-best`, `p2c`, `latency-banded`, `consistent-hashing` and more, switchable through the Clash API without a restart.',
          to: 'algorithms',
        },
        {
          title: 'Watchdog and circuit breaker',
          body: 'Watches every connection: a first-byte timeout, a write left unanswered for 60 s, a reset, or a fatal TLS / HTTP/2 / QUIC / proxy-protocol error pauses the node for that site for 10 minutes. Two dial failures within 30 s open the breaker, and nodes failing probes are retested less and less often.',
          to: 'health',
        },
        {
          title: 'Region-aware load balancing',
          body: '`smart-loadbalance` sorts every node into region pools, picks an exit region for each site, then spreads connections across that region by learned quality and live load. Lock a region, or generate one outbound per region to use as the front of chained proxies.',
          to: 'smart-loadbalance',
        },
        {
          title: 'LightGBM scoring',
          body: 'A pre-trained model scores nodes directly. Inputs are matched by feature name, so vernesong/mihomo v4 models and older 27-feature models both load — or collect your own connection data and train a model offline.',
          to: 'lightgbm',
        },
        {
          title: 'Preferences and pinning',
          body: '`policy_priority` raises or lowers nodes by name. Pin a node in your dashboard: while it is down Smart uses others, and it switches back once the node recovers.',
          to: 'priority-and-pinning',
        },
      ],
    },
    comparison: {
      title: 'Compared with other groups',
      lead: 'This fork offers five group types. Use smart when you have many nodes of uneven quality and different sites suit different nodes; use smart-loadbalance to spread connections over many nodes while keeping the exit region steady.',
      headers: ['Capability', 'selector', 'urltest', 'loadbalance', 'smart', 'smart-loadbalance'],
      rows: [
        ['How it picks', 'By hand', 'Lowest probe delay', 'Round-robin / hash / sticky', 'Weights learned per site + 10 algorithms', 'A region per site, then a quality- and load-weighted spread'],
        ['Periodic probing', '—', '✓', '✓', '✓', '✓'],
        ['Node quality per site', '—', '—', '—', '✓', '✓'],
        ['Automatic region pools', '—', '—', '—', '—', '✓'],
        ['Per-connection failure detection', '—', '—', '—', '✓', '✓'],
        ['Circuit breaker, per-site blocks', '—', '—', '—', '✓', '✓'],
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
          body: 'Run a minimal config, then confirm it is actually learning; look up unfamiliar terms in the glossary.',
          links: [
            { label: 'Quick start', to: 'quick-start' },
            { label: 'Examples', to: 'examples' },
            { label: 'Glossary', to: 'glossary' },
          ],
        },
        {
          title: 'Why did it pick that node?',
          body: 'The full journey of a connection, from identifying the destination and gathering candidates to the dial race.',
          links: [
            { label: 'How it works', to: 'how-it-works' },
            { label: 'Health and failures', to: 'health' },
          ],
        },
        {
          title: 'Tuning and debugging',
          body: 'Look up field defaults, inspect and control groups through the Clash API, and troubleshoot by symptom.',
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
