// Chinese UI strings — keep in lockstep with en.ts. Referenced by
// Header / Footer / LangSwitcher / page-level helpers. Add a new key
// to BOTH files simultaneously to avoid runtime holes.

export const zh = {
  site: {
    name: 'sing-box Smart',
    tagline: '机器学习驱动的智能出站',
    footerNote: 'xiaobaf14g fork · 基于 reF1nd/sing-box',
  },
  nav: {
    home: '首页',
    config: '配置',
    examples: '示例',
    api: 'Clash API',
    watchdog: 'Watchdog',
    github: 'GitHub',
  },
  common: {
    langLabel: '中文',
    switchTo: '切换到英文',
    edit: '编辑此页',
    copy: '复制',
    copied: '已复制',
  },
  hero: {
    eyebrow: '智能策略组',
    title: '让代理选择像决策者一样思考',
    subtitle:
      '把 mihomo 的 Smart 策略组移植到 sing-box，并叠加 LightGBM 机器学习、ASN 感知路由、RST 级 Watchdog 与 11 种排序算法——为每条连接挑最合适的节点，而不是最表面最快的那个。',
    primary: '查看示例配置',
    secondary: '阅读完整文档',
  },
  features: {
    title: '为什么是 Smart',
    items: [
      {
        title: 'LightGBM 节点评分',
        body: '离线训练的 GBDT 模型基于 27+ 维度 (延迟 / 抖动 / 吞吐 / 时段 / 握手分段) 输出 0–1 置信度，区分「目前最快」与「可信最快」。',
      },
      {
        title: 'ASN 感知路由',
        body: '每个 (目标 ASN, 节点) 独立权重。同一节点对 Google 和对 Cloudflare 不共用学习结果，避开 CDN 假相。',
      },
      {
        title: 'RST / TLS 级 Watchdog',
        body: '22 种致命错误识别 (TLS alert / h2 stream / QUIC / proxy 帧) — 中期 RST 立即把该节点对该目标软屏蔽 10 分钟，而不是「下次还选它」。',
      },
      {
        title: '11 种排序策略',
        body: 'strict-best / weighted-random / least-loaded / fastest-recent / sticky-session / round-robin / weighted-rr / p2c / latency-banded — 按业务特征切换，无需重启。',
      },
    ],
  },
  comparison: {
    title: '和其他策略组对比',
    headers: {
      feature: '维度',
      selector: 'selector',
      urltest: 'urltest',
      loadbalance: 'loadbalance',
      smart: 'smart',
    },
  },
  scenarios: {
    title: '典型使用场景',
    items: [
      {
        title: '家宽多线路',
        body: '电信 / 联通 / 移动三条出口 + 多个机场。Smart 学出哪个线路对 GitHub 稳、哪个对 YouTube 快，自动分流。',
      },
      {
        title: '机场聚合',
        body: '订阅 5 家机场共 200 节点。Smart 的 unwrap 缓存 + prefetch + ASN 分组，在不重新测速的前提下始终命中最优那一两个。',
      },
      {
        title: '跨境办公',
        body: '多国节点 + 会议 / IDE / 下载并行。latency-banded 把低延迟节点专门留给交互，大流量走备用 — 避免一把梭。',
      },
    ],
  },
  cta: {
    title: '30 秒上手',
    body: '一段最小配置就能跑 Smart，先用起来，再按需加 LightGBM 或 GeoX。',
    primary: '看 5 种示例',
    secondary: '看配置字段',
  },
};

export default zh;
