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
      title: '按服务学习，为每条连接挑最可靠的节点',
      subtitle:
        'Smart 结合了 honk 的综合评分与 vernesong/mihomo Smart 的服务识别、封锁与探测：先看可靠性，延迟、吞吐与连接质量只在难分高下时起作用；同一服务收敛到一个出口，节点只在出问题的网站上被避开。它还能按地区分摊连接、用 LightGBM 计算连接质量，并在面板里随时查看与控制。',
      primary: '快速开始',
      secondary: '工作原理',
      codeCaption: '01-minimal.json',
    },
    features: {
      title: '核心能力',
      lead: '每一项都对应源码中的实际行为。点击卡片，查看对应章节的细节与参数。',
      items: [
        {
          title: '可靠性优先的综合评分',
          body: '来自 honk：按衰减的成功率与置信区间判断哪些节点“可靠”，再在可靠的节点之间比较延迟、吞吐与连接质量。已经在用的节点只有被证明更差时才会被换掉，不会来回跳。',
          to: 'scoring',
        },
        {
          title: '按服务归并与收敛',
          body: '来自 mihomo Smart：命中的路由规则（如 `RuleSet [geosite-netflix]`）就是一个服务，同一服务的所有域名共享学习结果并收敛到同一个出口；开启 `prefer_asn` 后按网络归并大合集规则。',
          to: 'service-keys',
        },
        {
          title: '封锁、响应探测与出口识别',
          body: '连接报错、长时间无响应、质量过低或丢包严重时，只对出问题的网站封锁节点；短连接经同一节点复查网站的真实响应，识别“该地区不可用”，并比较各节点的实际出口。',
          to: 'blocks-and-probes',
        },
        {
          title: '按地区负载均衡',
          body: '`smart-loadbalance` 把全部节点按地区自动分池，为每个网站选定出口地区，再按学到的质量与连接数在地区内分摊连接；可以锁定地区，也可以为每个地区生成出站。',
          to: 'smart-loadbalance',
        },
        {
          title: 'LightGBM 连接质量',
          body: '用 vernesong/mihomo 发布的模型（32 个特征，含节点实际出口）计算每条连接的质量，代替场景公式；也可以采集自己的数据训练模型。',
          to: 'lightgbm',
        },
        {
          title: '健康检查与稳定性',
          body: '只在组被使用时定期测速；按最近 10 次延迟的中位数绝对偏差找出抖动、变慢的节点，暂时移出候选。',
          to: 'health',
        },
      ],
    },
    comparison: {
      title: '与其他策略组对比',
      lead: '本分支提供五种策略组。节点多、质量起伏大、不同网站适合不同节点时，用 smart；想把连接分摊到多个节点、又要保持出口地区不变时，用 smart-loadbalance。',
      headers: ['能力', 'selector', 'urltest', 'loadbalance', 'smart', 'smart-loadbalance'],
      rows: [
        ['怎么选节点', '手动', '测速延迟最低', '轮询 / 哈希 / 粘性会话', '按服务的综合评分，可靠性优先', '先按网站选地区，再在地区内按质量与连接数分摊'],
        ['定时测速', '—', '✓', '✓', '✓', '✓'],
        ['按网站区分节点表现', '—', '—', '—', '✓', '✓'],
        ['按地区自动分池', '—', '—', '—', '—', '✓'],
        ['连接级故障识别', '—', '—', '—', '✓', '✓'],
        ['只对出问题的网站封锁节点', '—', '—', '—', '✓', '△'],
        ['手动指定节点', '✓', '✓', '—', '✓', '✓（节点或地区）'],
        ['学习数据跨重启保留', '—', '—', '—', '✓', '✓'],
      ],
      legend: '✓ 支持　△ 部分支持（只读取封锁记录）　— 不支持',
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
          body: '从识别服务、过滤候选、综合评分到拨号与判定，一条连接的完整流程。',
          links: [
            { label: '工作原理', to: 'how-it-works' },
            { label: '综合评分与选择', to: 'scoring' },
            { label: '封锁与探测', to: 'blocks-and-probes' },
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
      title: 'Learns each service, sends every connection through the most reliable node',
      subtitle:
        'Smart combines honk\'s comprehensive score with the service keys, blocks and probes of vernesong/mihomo Smart: reliability comes first, and latency, goodput and connection quality only break near-ties; a service converges on one exit, and a node is avoided only on the sites where it fails. It can also spread connections by region, score connection quality with LightGBM, and be inspected and controlled from your dashboard.',
      primary: 'Quick start',
      secondary: 'How it works',
      codeCaption: '01-minimal.json',
    },
    features: {
      title: 'What it does',
      lead: 'Every item describes what the code actually does. Open a card for the details and parameters.',
      items: [
        {
          title: 'Reliability-first score',
          body: 'From honk: decayed success rates with confidence bounds decide which nodes are reliable, and only then do latency, goodput and connection quality compare them. The node in use is replaced only when a challenger proves better, so choices do not flap.',
          to: 'scoring',
        },
        {
          title: 'Services and convergence',
          body: 'From mihomo Smart: the matched routing rule (such as `RuleSet [geosite-netflix]`) is a service, so all its domains share what was learned and converge on one exit; with `prefer_asn`, broad rules are grouped by network.',
          to: 'service-keys',
        },
        {
          title: 'Blocks, response probes, exits',
          body: 'Errors, stalls, low quality or heavy loss block a node only for the site that suffered. Short connections are rechecked through the same node to spot "not available in your region" answers, and the real exit of every node is compared.',
          to: 'blocks-and-probes',
        },
        {
          title: 'Region-aware load balancing',
          body: '`smart-loadbalance` sorts every node into region pools, picks an exit region per site, then spreads connections across that region by learned quality and live load. Lock a region, or generate one outbound per region.',
          to: 'smart-loadbalance',
        },
        {
          title: 'LightGBM connection quality',
          body: 'The model published by vernesong/mihomo (32 features, including the node\'s real exit) scores every connection instead of the scene formula; or collect your own data and train one.',
          to: 'lightgbm',
        },
        {
          title: 'Health and stability',
          body: 'Members are probed only while the group is in use; the median absolute deviation of the last 10 delays finds jittery or slowing nodes and takes them out for a while.',
          to: 'health',
        },
      ],
    },
    comparison: {
      title: 'Compared with other groups',
      lead: 'This fork offers five group types. Use smart when you have many nodes of uneven quality and different sites suit different nodes; use smart-loadbalance to spread connections over many nodes while keeping the exit region steady.',
      headers: ['Capability', 'selector', 'urltest', 'loadbalance', 'smart', 'smart-loadbalance'],
      rows: [
        ['How it picks', 'By hand', 'Lowest probe delay', 'Round-robin / hash / sticky', 'Comprehensive score per service, reliability first', 'A region per site, then a quality- and load-weighted spread'],
        ['Periodic probing', '—', '✓', '✓', '✓', '✓'],
        ['Node quality per site', '—', '—', '—', '✓', '✓'],
        ['Automatic region pools', '—', '—', '—', '—', '✓'],
        ['Per-connection failure detection', '—', '—', '—', '✓', '✓'],
        ['Blocks only for the failing site', '—', '—', '—', '✓', '△'],
        ['Manual pin', '✓', '✓', '—', '✓', '✓ (node or region)'],
        ['Learned data survives restarts', '—', '—', '—', '✓', '✓'],
      ],
      legend: '✓ supported　△ partly (reads block records only)　— not supported',
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
          body: 'The full journey of a connection: identifying the service, filtering members, the score, the dial and the verdict.',
          links: [
            { label: 'How it works', to: 'how-it-works' },
            { label: 'Score and selection', to: 'scoring' },
            { label: 'Blocks and probes', to: 'blocks-and-probes' },
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
