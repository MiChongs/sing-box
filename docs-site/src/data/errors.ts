// Error substrings the Smart watchdog matches, lower-cased.
// Mirrors isResetErr / isTransferFatalErr in protocol/group/smart_anomaly.go.

export interface ErrorFamily {
  id: string;
  zh: string;
  en: string;
  patterns: string[];
}

export const resetMarkers: string[] = [
  'connection reset by peer',
  'connection reset',
  'broken pipe',
  'forcibly closed',
  'forcibly closed by the remote',
  'reset by peer',
  'connection aborted',
];

export const transferFamilies: ErrorFamily[] = [
  {
    id: 'tls',
    zh: 'TLS 层',
    en: 'TLS layer',
    patterns: [
      'remote error: tls:',
      'tls: bad record mac',
      'tls: unexpected message',
      'tls: internal error',
      'tls: protocol version not supported',
      'tls: handshake failure',
      'tls: alert',
    ],
  },
  {
    id: 'h2',
    zh: 'HTTP/2 层',
    en: 'HTTP/2 layer',
    patterns: ['http2: stream error', 'http2: server closed', 'stream closed', 'stream terminated'],
  },
  {
    id: 'quic',
    zh: 'QUIC 层（hysteria2、tuic 等）',
    en: 'QUIC layer (hysteria2, tuic, …)',
    patterns: ['crypto_error', 'connection_close', 'connection closed', 'stream reset', 'stream was reset', 'application error'],
  },
  {
    id: 'proxy',
    zh: '代理协议帧',
    en: 'Proxy-protocol framing',
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
