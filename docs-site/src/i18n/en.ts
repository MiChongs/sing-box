// English UI strings — lockstep with zh.ts.

export const en = {
  site: {
    name: 'sing-box Smart',
    tagline: 'ML-driven intelligent outbound',
    footerNote: 'xiaobaf14g fork · built on reF1nd/sing-box',
  },
  nav: {
    home: 'Home',
    config: 'Config',
    examples: 'Examples',
    api: 'Clash API',
    watchdog: 'Watchdog',
    github: 'GitHub',
  },
  common: {
    langLabel: 'English',
    switchTo: 'Switch to Chinese',
    edit: 'Edit this page',
    copy: 'Copy',
    copied: 'Copied',
  },
  hero: {
    eyebrow: 'Smart outbound group',
    title: 'Proxy selection that thinks like a routing engineer',
    subtitle:
      'The mihomo Smart group, ported to sing-box — and stacked with LightGBM ML scoring, ASN-aware routing, an RST-level watchdog, and 11 ranking algorithms. Picks the right node for each request, not just the one that looked fastest five seconds ago.',
    primary: 'Browse example configs',
    secondary: 'Read the full docs',
  },
  features: {
    title: 'Why Smart',
    items: [
      {
        title: 'LightGBM node scoring',
        body: 'Offline-trained GBDT model ingests 27+ dimensions (RTT, jitter, throughput, hour-of-day, split handshake timings) and emits a 0–1 confidence score — distinguishes "currently fastest" from "confidently fastest".',
      },
      {
        title: 'ASN-aware routing',
        body: 'Separate weights per (destination ASN, node) pair. A node\'s Google route and Cloudflare route learn independently — no more CDN-induced false positives.',
      },
      {
        title: 'RST / TLS watchdog',
        body: '22 fatal-error shapes recognized (TLS alerts, h2 stream errors, QUIC CRYPTO_ERROR, proxy-frame damage). Mid-transfer RST soft-bans the node for that target for 10 minutes — never the "same dead node next dial" loop.',
      },
      {
        title: '11 ranking algorithms',
        body: 'strict-best / weighted-random / least-loaded / fastest-recent / sticky-session / round-robin / weighted-rr / p2c / latency-banded. Hot-swap based on workload, no restart required.',
      },
    ],
  },
  comparison: {
    title: 'How it compares',
    headers: {
      feature: 'Dimension',
      selector: 'selector',
      urltest: 'urltest',
      loadbalance: 'loadbalance',
      smart: 'smart',
    },
  },
  scenarios: {
    title: 'Real-world scenarios',
    items: [
      {
        title: 'Home multi-WAN',
        body: 'Three ISPs + multiple proxy providers. Smart learns which path is stable for GitHub, which is fast for YouTube, and splits traffic accordingly.',
      },
      {
        title: 'Provider aggregation',
        body: 'Five subscribers, 200 nodes. Unwrap cache + prefetch + ASN grouping keeps the top 1-2 nodes hit consistently without re-probing.',
      },
      {
        title: 'Cross-border work',
        body: 'Latency-banded keeps low-RTT nodes for interactive use (IDE / calls), steers bulk transfers to standby nodes — no one-basket-everything.',
      },
    ],
  },
  cta: {
    title: 'Up and running in 30 seconds',
    body: 'A minimal Smart config works out of the box. Bolt on LightGBM or GeoX when you need them.',
    primary: 'See 5 example configs',
    secondary: 'Browse the schema',
  },
};

export default en;
