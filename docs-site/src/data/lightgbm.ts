// LightGBM feature vector (common/smart/lightgbm/features.go PrepareFeatures,
// names from transform.go getDefaultFeatureOrder) and collector CSV tail
// columns (collector.go). Index order is the model contract.

export interface Feature {
  i: number;
  name: string;
  zh: string;
  en: string;
}

export const features: Feature[] = [
  { i: 0, name: 'success', zh: '累计成功次数', en: 'Lifetime successes' },
  { i: 1, name: 'failure', zh: '累计失败次数', en: 'Lifetime failures' },
  { i: 2, name: 'connect_time', zh: 'log1p(平滑建连耗时 ms)', en: 'log1p(smoothed connect time, ms)' },
  { i: 3, name: 'latency', zh: 'log1p(平滑首字节延迟 ms)', en: 'log1p(smoothed first-byte latency, ms)' },
  { i: 4, name: 'upload_mb', zh: 'log1p(本次上传 MB)', en: 'log1p(upload this connection, MB)' },
  { i: 5, name: 'history_upload_mb', zh: 'log1p(此前累计上传 MB)', en: 'log1p(upload before this connection, MB)' },
  { i: 6, name: 'maxuploadrate_kb', zh: 'log1p(本次峰值上传 KB/s)', en: 'log1p(peak upload this connection, KB/s)' },
  { i: 7, name: 'history_maxuploadrate_kb', zh: 'log1p(历史峰值上传 KB/s)', en: 'log1p(historical peak upload, KB/s)' },
  { i: 8, name: 'download_mb', zh: 'log1p(本次下载 MB)', en: 'log1p(download this connection, MB)' },
  { i: 9, name: 'history_download_mb', zh: 'log1p(此前累计下载 MB)', en: 'log1p(download before this connection, MB)' },
  { i: 10, name: 'maxdownloadrate_kb', zh: 'log1p(本次峰值下载 KB/s)', en: 'log1p(peak download this connection, KB/s)' },
  { i: 11, name: 'history_maxdownloadrate_kb', zh: 'log1p(历史峰值下载 KB/s)', en: 'log1p(historical peak download, KB/s)' },
  { i: 12, name: 'duration_minutes', zh: 'log1p(平均连接时长 分钟)', en: 'log1p(average connection duration, minutes)' },
  { i: 13, name: 'last_used_seconds', zh: 'log1p(距上次使用的秒数)', en: 'log1p(seconds since previous use)' },
  { i: 14, name: 'is_udp', zh: '是否 UDP（0/1）', en: 'UDP (0/1)' },
  { i: 15, name: 'is_tcp', zh: '是否 TCP（0/1）', en: 'TCP (0/1)' },
  { i: 16, name: 'asn_feature', zh: '目标 ASN 的分桶类别，未开启 `use_asn` 时为 0', en: 'Bucketed category of the destination ASN; 0 without `use_asn`' },
  { i: 17, name: 'country_feature', zh: '目标国家编码，需要国家数据库', en: 'Destination country code; needs the country database' },
  { i: 18, name: 'address_feature', zh: '域名类型，或 IP 类型（100 起）', en: 'Domain class, or IP class (100+)' },
  { i: 19, name: 'port_feature', zh: '端口类别', en: 'Port category' },
  { i: 20, name: 'traffic_ratio', zh: '上下行比例，带方向符号', en: 'Signed upload/download ratio' },
  { i: 21, name: 'traffic_density', zh: 'log1p(每分钟流量 MB)', en: 'log1p(MB per minute)' },
  { i: 22, name: 'connection_type_feature', zh: '由端口与地址推导的连接类型', en: 'Connection type derived from port and address' },
  { i: 23, name: 'asn_hash', zh: 'ASN 哈希分桶（500）', en: 'ASN hash bucket (500)' },
  { i: 24, name: 'host_hash', zh: '域名哈希分桶（1000）', en: 'Host hash bucket (1000)' },
  { i: 25, name: 'ip_hash', zh: 'IP 哈希分桶（10000）', en: 'IP hash bucket (10000)' },
  { i: 26, name: 'geoip_hash', zh: '国家哈希分桶（200）', en: 'Country hash bucket (200)' },
  { i: 27, name: 'latency_stddev', zh: 'log1p(首字节延迟标准差)', en: 'log1p(first-byte latency std-dev)' },
  { i: 28, name: 'connect_time_stddev', zh: 'log1p(建连耗时标准差)', en: 'log1p(connect time std-dev)' },
  { i: 29, name: 'short_long_rtt_delta', zh: '短期 RTT − 长期 RTT', en: 'Short-term RTT − long-term RTT' },
  { i: 30, name: 'short_success_rate', zh: '短期成功率', en: 'Short-term success rate' },
  { i: 31, name: 'active_conns', zh: 'log1p(节点当前活跃连接数)', en: 'log1p(live connections on the node)' },
  { i: 32, name: 'tls_handshake_time', zh: 'log1p(最近一次探测的 TLS 握手耗时)', en: 'log1p(TLS handshake time of the last probe)' },
  { i: 33, name: 'hour_bucket', zh: '本地小时 / 24', en: 'Local hour / 24' },
  { i: 34, name: 'tcp_retransmissions', zh: 'log1p(TCP 重传次数)，仅 Linux / Android', en: 'log1p(TCP retransmissions); Linux / Android only' },
];

export interface Column {
  range: string;
  name: string;
  zh: string;
  en: string;
}

// Header names come from collectorHeader in collector.go. A `_raw` suffix
// marks the untransformed value of a feature that shares the name.
export const csvColumns: Column[] = [
  { range: '0–34', name: 'success … tcp_retransmissions', zh: '35 个特征，列名与顺序同上表，格式 `%.6f`', en: 'The 35 features, with the names and order of the table above, formatted `%.6f`' },
  { range: '35', name: 'group_name', zh: 'Smart 组标签', en: 'Smart group tag' },
  { range: '36', name: 'node_name', zh: '节点标签', en: 'Node tag' },
  { range: '37–41', name: 'asn_raw, host_raw, ip_raw, port_raw, geoip_raw', zh: '原始的 ASN、域名、IP、端口、国家，缺失时为 `unknown`', en: 'Raw ASN, host, IP, port and country; `unknown` when missing' },
  { range: '42', name: 'weight', zh: '训练标签：最终权重除以优先级系数', en: 'Training label: final weight divided by the priority factor' },
  { range: '43', name: 'weight_source', zh: '`traditional` 或 `lightgbm`，手动指定期间追加 `:manual`', en: '`traditional` or `lightgbm`, with `:manual` appended while pinned' },
  { range: '44', name: 'timestamp', zh: 'RFC 3339 时间', en: 'RFC 3339 time' },
  {
    range: '45–53',
    name: 'latency_stddev_delta, connect_time_stddev_delta, active_conns_raw, tls_session_resumed, dns_resolve_time, tls_handshake_time_raw, http3_fallback_count, lightgbm_confidence, hour_bucket_raw',
    zh: '延迟标准差变化、建连标准差变化、活跃连接数、TLS 会话是否复用、DNS 耗时、TLS 握手耗时、HTTP/3 回退次数、模型置信度、小时（0–23）。带 `_raw` 后缀的是同名特征未经变换的原始值',
    en: 'Latency std-dev delta, connect std-dev delta, active connections, TLS session resumed, DNS time, TLS handshake time, HTTP/3 fallback count, model confidence, hour (0–23). A `_raw` suffix marks the untransformed value of the feature with the same name',
  },
  {
    range: '54–59',
    name: 'tcp_retransmissions_raw, tcp_losses, path_mtu, long_rtt, long_success_rate, schema_version',
    zh: 'TCP 重传、TCP 丢包、路径 MTU、长期 RTT、长期成功率、格式版本（固定为 `4`）',
    en: 'TCP retransmissions, TCP losses, path MTU, long-term RTT, long-term success rate, schema version (always `4`)',
  },
];
