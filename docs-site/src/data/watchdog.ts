// Watchdog / RST error taxonomy and threshold constants.
// Mirrors protocol/group/smart_anomaly.go and smart_watchdog.go.

export interface ErrorFamily {
  id: string;
  zhTitle: string;
  enTitle: string;
  zhDesc: string;
  enDesc: string;
  patterns: string[];        // exact lower-case substrings matched
}

export const transferFatalFamilies: ErrorFamily[] = [
  {
    id: 'tls',
    zhTitle: 'TLS 层损坏',
    enTitle: 'TLS record-layer damage',
    zhDesc: '上游链路上的 RST 会让 TLS 流截断, 下游的 record MAC 校验失败, Go crypto/tls 在这个时刻给出的错误落在这五种。',
    enDesc: 'An upstream RST corrupts the TLS stream mid-record; Go crypto/tls surfaces MAC / message-type failures here.',
    patterns: [
      'remote error: tls:',
      'tls: bad record mac',
      'tls: unexpected message',
      'tls: internal error',
      'tls: alert',
    ],
  },
  {
    id: 'h2',
    zhTitle: 'HTTP/2 流终止',
    enTitle: 'HTTP/2 stream termination',
    zhDesc: 'h2 封装把底层 RST 翻译成 stream error / GOAWAY。只有 GOAWAY 带非 NO_ERROR 错误码才算致命；优雅关闭不应该误触发。',
    enDesc: 'The h2 transport translates the underlying RST into stream errors / GOAWAY. Only GOAWAY with a non-NO_ERROR code is fatal — graceful shutdown must not trigger.',
    patterns: [
      'http2: stream error',
      'http2: server closed',
      'stream closed',
      'stream terminated',
      'goaway (non-NO_ERROR only)',
    ],
  },
  {
    id: 'quic',
    zhTitle: 'QUIC / 代理 MUX',
    enTitle: 'QUIC / proxy mux',
    zhDesc: 'hysteria2 / tuic 等 QUIC 出站遇到中间人 RST 或服务端 close 时, quic-go 抛出这几类错误。application error 的语义是"服务端显式 close"。',
    enDesc: 'QUIC-based outbounds (hysteria2 / tuic) surface CRYPTO_ERROR / CONNECTION_CLOSE / stream reset when the tunnel breaks or the server closes explicitly.',
    patterns: [
      'crypto_error',
      'connection_close',
      'connection closed',
      'stream reset',
      'stream was reset',
      'application error',
    ],
  },
  {
    id: 'proxy',
    zhTitle: '代理帧解码',
    enTitle: 'Proxy-frame decoding',
    zhDesc: 'vmess / trojan / shadowsocks 等代理协议在流被截断时, 解码器报出这些错误. 识别它们让 Smart 知道问题发生在上游链路而不是代码 bug.',
    enDesc: 'When the upstream stream is torn mid-frame, vmess / trojan / shadowsocks decoders surface these. Recognising them tells Smart the damage happened upstream, not in the decoder.',
    patterns: [
      'protocol error',
      'invalid frame',
      'frame too large',
      'short read',
      'authentication failed',
      'mux: invalid',
      'vmess: invalid',
      'trojan: invalid',
      'shadowsocks: ',
    ],
  },
];

// Deliberately NOT matched to avoid false positives.
export const excluded = {
  zh: [
    '`io.EOF` / `io.ErrUnexpectedEOF` — 正常半关闭或 Content-Length 提前结束',
    '`context.Canceled` / `context.DeadlineExceeded` — 调用方主动取消',
    '`use of closed network connection` — 下游代码主动关了连接',
    'HTTP/2 `GOAWAY ErrCode=NO_ERROR` — 服务端优雅关闭',
  ],
  en: [
    '`io.EOF` / `io.ErrUnexpectedEOF` — clean half-close or upstream Content-Length short',
    '`context.Canceled` / `context.DeadlineExceeded` — caller-initiated',
    '`use of closed network connection` — downstream code closed the conn itself',
    'HTTP/2 `GOAWAY ErrCode=NO_ERROR` — graceful server shutdown',
  ],
};

// Threshold + cooldown constants. Keep in lockstep with the Go source.
export const constants = [
  {
    name: 'firstByteWatchdogTimeout',
    go: 'protocol/group/smart_watchdog.go',
    value: '5s',
    zh: '首次 Read 还没拿到字节的超时；常自适应到 URLTest 延迟 × 4 且 ≥ 1.5s。',
    en: 'Timeout before first byte; adaptively set to URLTest delay × 4, floored at 1.5s.',
  },
  {
    name: 'stalledTransferTimeout',
    go: 'protocol/group/smart_watchdog.go',
    value: '30s',
    zh: '已有字节流但陷入静默的最大容忍时间。',
    en: 'Maximum idle tolerated after the first byte has been received.',
  },
  {
    name: 'watchdogScanInterval',
    go: 'protocol/group/smart_watchdog.go',
    value: '2.5s',
    zh: '备份扫描周期；kernel SetReadDeadline 是主通道，扫描只为兜底。',
    en: 'Backstop scan cadence; kernel SetReadDeadline is the primary detection path, scanning is fallback.',
  },
  {
    name: 'resetEventThreshold',
    go: 'protocol/group/smart_anomaly.go',
    value: '2',
    zh: '同 (target, node) 内 N 次 RST 触发完全 markDead。',
    en: 'N RST events on the same (target, node) trigger full markDead.',
  },
  {
    name: 'resetEventWindow',
    go: 'protocol/group/smart_anomaly.go',
    value: '60s',
    zh: '上述阈值的滑动窗口。',
    en: 'Sliding window for the threshold above.',
  },
  {
    name: 'targetDebargoTTL',
    go: 'protocol/group/smart.go',
    value: '10min',
    zh: '单次 RST 后, 该节点对该目标自动软屏蔽的时长。到期自动解封。',
    en: 'After a single RST, how long the node stays soft-banned for that target. Auto-expires — no manual recovery.',
  },
];

// Runtime behaviours that sit on the same dial-time hot path as the
// watchdog but have their own narratives. Rendered as compact cards
// on the watchdog page so operators find "why did my pin flip to B"
// without hunting through source code.
export interface RuntimeBehaviour {
  id: string;
  zhTitle: string;
  enTitle: string;
  zhDesc: string;
  enDesc: string;
  file: string;
}

export const runtimeBehaviours: RuntimeBehaviour[] = [
  {
    id: 'pin-fallback',
    zhTitle: 'Pin 真死自动切换（TCP+UDP）',
    enTitle: 'Auto-fallback when a pinned node truly dies (TCP+UDP)',
    zhDesc:
      'Pin 节点 dial 失败时，如果 circuit breaker 还没触发（默认 2 次连续失败才 open），本次请求会自动 bypass pin 走算法候选，pin 状态仍保留。下次 pin 节点健康自动 snap back。TCP / UDP 路径对称；Clash API 通过 fixedSuspended / fixedActive 字段实时同步状态。仅 isBreakerOpen 作为强否决 —— urltest 的一次失败 / knownDead / 切网 warmup probe 失败都不会让 pin 静默失效。',
    enDesc:
      'When a pinned node fails to dial, Smart falls back to algorithm candidates for THIS request while the pin stays set. When the pin recovers the next dial snaps back automatically. TCP and UDP paths are symmetric; the Clash API surfaces the transient via fixedSuspended / fixedActive. Only an open circuit breaker overrides the pin — isolated URLTest misses / knownDead / network-switch warmup probe failures never silently drop the pin.',
    file: 'protocol/group/smart.go',
  },
  {
    id: 'net-change',
    zhTitle: '切网预热 & 在飞 dial 取消',
    enTitle: 'Network-switch warmup & in-flight dial cancel',
    zhDesc:
      '接入 sing-tun InterfaceMonitor。切网事件触发：(1) cancelInFlightDials 立即中止卡在老接口上的 dial（省掉 5-15s TCP 超时）；(2) 清 aliveAt + probe freshness；(3) 300ms 后调度 runHealthCheck，优先探 pin / lastSelected 节点。URLTest 探测的 TLS / QUIC 握手顺带把新路径上的代理 session 预热好，用户下一次请求直接命中活 session。',
    enDesc:
      'Subscribes to sing-tun\'s InterfaceMonitor. On default-interface change Smart (1) cancelInFlightDials aborts dials stuck on the old interface (saves 5-15s TCP timeout), (2) clears aliveAt and shared probe freshness, (3) schedules a one-shot runHealthCheck 300ms out that probes the pin / lastSelected first. URLTest\'s TLS/QUIC handshake doubles as session warmup on the new path — the next user request lands on a live session.',
    file: 'protocol/group/smart_netchange.go',
  },
  {
    id: 'request-scene',
    zhTitle: '请求级 scene 实时路由',
    enTitle: 'Request-level scene routing',
    zhDesc:
      '除了按节点历史流量形态分类的 weight.go 场景, dial 时额外根据当前请求的 SNI / Host / port 推断这次请求是什么（youtube → streaming / steam → realtime / ssh → interactive）。对 Top-5 候选做二次重排：streaming/transfer 按 maxDownloadRate 降序；realtime/voip/interactive 按 shortRTT 升序。selection-style 算法（sticky-session/consistent-hashing/RR/p2c/weighted-random）跳过重排防止破坏算法选择。',
    enDesc:
      'In addition to weight.go\'s history-based scene classification, Smart infers the CURRENT request type from SNI / Host / port (youtube → streaming, steam → realtime, ssh → interactive). It re-orders the top-5 candidates: streaming/transfer by maxDownloadRate desc, realtime/voip/interactive by shortRTT asc. Selection-style algorithms (sticky-session/consistent-hashing/RR/p2c/weighted-random) skip the rerank to avoid undoing their deterministic pick.',
    file: 'protocol/group/smart_request_scene.go',
  },
  {
    id: 'bandwidth-bonus',
    zhTitle: '带宽维度选路 — bandwidthBonus',
    enTitle: 'Bandwidth-aware ranking — bandwidthBonus',
    zhDesc:
      'streaming / transfer scene 下给高吞吐节点最多 +20% composite 奖励。触发门控：totalMB ≥ 1.0 + peakKBps > 100 KB/s + bpsScale log-ramp 到 5 MB/s 满值。防止小请求的 burst bps 骗过算法；web / api / realtime 不叠加（这些场景延迟优先）。',
    enDesc:
      'streaming / transfer scenes award up to +20% composite to high-throughput nodes. Gates: totalMB ≥ 1.0 + peakKBps > 100 KB/s + a log-ramped bpsScale that saturates at 5 MB/s. Small-request burst bps can\'t trick the algorithm; web / api / realtime don\'t stack (they\'re latency-dominated).',
    file: 'common/smart/weight.go',
  },
  {
    id: 'adaptive-parallel-dial',
    zhTitle: '自适应并行 dial',
    enTitle: 'Adaptive parallel dial',
    zhDesc:
      'Ranking-style 算法 round 0 读 Top1 节点的 ShortSuccessRate：≥ 0.95 收敛为单路 dial（稳态省电），否则保持 2 路并行（异常 fast-failover）。Selection-style 算法始终 1 路。典型场景下大多数请求只发一次 dial，省电 + 不污染上游统计。',
    enDesc:
      'Ranking-style algorithms read Top1\'s ShortSuccessRate on round 0: ≥ 0.95 → single dial (steady-state battery save); below → keep the 2-wide race for fast failover. Selection-style algorithms always dial one. In stable networks most requests fire exactly once — lower power, cleaner upstream stats.',
    file: 'protocol/group/smart.go (getBatch)',
  },
  {
    id: 'consistent-hashing',
    zhTitle: 'consistent-hashing 算法',
    enTitle: 'consistent-hashing algorithm',
    zhDesc:
      '按 target(+isUDP) 做 xxhash64 → jumpHash 映射到候选槽位并 promote 到 position 0。同 target 总命中同节点（会话亲和），不同 target 分散 — 适合依赖服务端状态的场景（购物车 / rate-limit / sticky TLS）。algoRound0Width=1，不并发竞速。Smart 组与 LoadBalance 组均支持；LoadBalance 版本基于完整 outbound 列表 + ring probe，节点 dead 仅影响命中它的 1/N key，恢复后自动回归。',
    enDesc:
      'xxhash64 the target(+isUDP) → jumpHash to a candidate slot, promote to position 0. Same target → same node (session affinity); distinct targets spread across the pool — perfect for server-side state (carts / rate-limit tokens / sticky TLS). algoRound0Width=1 (no parallel race). Available in both Smart and LoadBalance groups; the LoadBalance implementation jumpHashes over the FULL outbound list + ring-probes to the next alive so node death only remaps 1/N keys.',
    file: 'protocol/group/smart_algorithm_consistent.go, loadbalance.go',
  },
];

export const runtimeConstants = [
  {
    name: 'cbMaxConsecFail',
    go: 'protocol/group/smart.go',
    value: '2',
    zh: '连续 dial 失败阈值，到达后 circuit breaker 打开并强制 bypass pin。',
    en: 'Consecutive-dial-failure threshold; hit it and the circuit breaker opens, which is the only way to override a user pin.',
  },
  {
    name: 'cbWindow',
    go: 'protocol/group/smart.go',
    value: '30s',
    zh: '连续失败计数的窗口；窗口外失败计数清零。',
    en: 'Window over which the consecutive-failure counter resets.',
  },
  {
    name: 'netChangeDebounce',
    go: 'protocol/group/smart_netchange.go',
    value: '500ms',
    zh: 'Android / Windows 切网时会连发 2-3 个 callback，合并为一次预热。',
    en: 'Android / Windows emit 2-3 callbacks in a row during a Wi-Fi ↔ cellular handoff; they collapse into one warmup.',
  },
  {
    name: 'netChangeWarmupDelay',
    go: 'protocol/group/smart_netchange.go',
    value: '300ms',
    zh: '切网后等 DHCP / 路由表稳定再发探测；否则探测自己失败把节点标死。',
    en: 'Gap before the warmup probe fires so DHCP / routing stabilises on the new interface — otherwise the probe itself fails and mis-marks nodes dead.',
  },
  {
    name: 'bandwidthBonus cap',
    go: 'common/smart/weight.go',
    value: '+20%',
    zh: 'streaming / transfer scene 高吞吐节点的最大乘法 bonus。',
    en: 'Max multiplicative bonus for high-throughput nodes in streaming / transfer scenes.',
  },
  {
    name: 'rerank Top-K',
    go: 'protocol/group/smart_request_scene.go',
    value: '5',
    zh: '请求级 scene 重排只打乱候选列表的前 5 个；尾部保留算法/tier 顺序。',
    en: 'Request-scene rerank shuffles only the top 5 candidates; the tail preserves tier / algorithm ordering for retries.',
  },
];

export default { transferFatalFamilies, excluded, constants, runtimeBehaviours, runtimeConstants };
