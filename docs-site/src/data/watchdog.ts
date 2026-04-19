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

export default { transferFatalFamilies, excluded, constants };
