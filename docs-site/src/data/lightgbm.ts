// LightGBM feature catalog (common/smart/lightgbm/features.go fillCatalog,
// names from transform.go getDefaultFeatureOrder and layout.go
// featureSlots) and collector CSV columns (collector.go). Models pick
// catalog features by the names in their feature_names; `i` is the
// position in the 35-feature layout that unnamed models and the CSV use.

export interface Feature {
  i: number;
  name: string;
  zh: string;
  en: string;
  // Only reachable by name: not part of the 35-feature layout.
  extra?: boolean;
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
  { i: 12, name: 'duration_minutes', zh: 'log1p(平均连接时长 分钟)。模型同时使用 `history_duration_minutes` 时（如默认模型），改为 log1p(本次连接时长 分钟)', en: 'log1p(average connection duration, minutes). When the model also uses `history_duration_minutes` (as the default model does), log1p(duration of this connection, minutes) instead' },
  { i: 13, name: 'last_used_seconds', zh: 'log1p(距上次使用的秒数)', en: 'log1p(seconds since previous use)' },
  { i: 14, name: 'is_udp', zh: '是否 UDP（0/1）', en: 'UDP (0/1)' },
  { i: 15, name: 'is_tcp', zh: '是否 TCP（0/1）', en: 'TCP (0/1)' },
  { i: 16, name: 'asn_feature', zh: '目标 ASN 的号段类别：编号小于 1000 为 50，小于 10000 为 51，小于 50000 为 52，小于 150000 为 53，更大为 54；未开启 `use_asn` 或查不到时为 0', en: 'Range class of the destination ASN: below 1000 → 50, below 10000 → 51, below 50000 → 52, below 150000 → 53, larger → 54; 0 without `use_asn` or when unknown' },
  { i: 17, name: 'country_feature', zh: '目标国家的类别：常见国家有固定编号（如 CN 为 1、HK 为 2、JP 为 4、US 为 7），其他国家按代码散列到 30–49；需要国家数据库，查不到时为 0', en: 'Destination country class: common countries have fixed numbers (CN 1, HK 2, JP 4, US 7, …), others hash into 30–49; needs the country database, 0 when unknown' },
  { i: 18, name: 'address_feature', zh: '目标地址类型。有域名时按域名分类：1 为 IP 字面量，2 流媒体，3 游戏，4 通讯，5 API，6 DNS，10–15 依次为 .cn / .com / .net / .org / .gov / .edu，30、31 为其他三级及以上 / 二级域名；只有 IP 时从 100 起（私有网段 100 + 网段类别，公网 IPv4 为 110，IPv6 为 111）', en: 'Destination address class. With a domain: 1 IP literal, 2 streaming, 3 gaming, 4 messaging, 5 API, 6 DNS, 10–15 for .cn / .com / .net / .org / .gov / .edu, 30 / 31 for other domains with three-plus / two labels. With only an IP: 100 and up (private ranges 100 + range class, public IPv4 110, IPv6 111)' },
  { i: 19, name: 'port_feature', zh: '目标端口类别：DNS 端口 36，API 服务端口 35，游戏端口 30，通讯端口 31，常见端口（22、25、80、443、3306 等）有固定编号 1–20，其余按端口段分为 20（0–1023）、21（1024–49151）、22（49152 起）', en: 'Destination port class: DNS ports 36, API ports 35, game ports 30, messaging ports 31, well-known ports (22, 25, 80, 443, 3306, …) fixed numbers 1–20, others by range: 20 (0–1023), 21 (1024–49151), 22 (49152 and up)' },
  { i: 20, name: 'traffic_ratio', zh: '上下行比例：上传多于下载时为 下载 ÷ 上传（正数），否则为 −上传 ÷ 下载；任一方向没有流量时为 0', en: 'Upload/download ratio: download ÷ upload (positive) when more was uploaded, otherwise −upload ÷ download; 0 when either direction had no traffic' },
  { i: 21, name: 'traffic_density', zh: 'log1p(本次连接平均每分钟流量 MB)', en: 'log1p(MB per minute over this connection)' },
  { i: 22, name: 'connection_type_feature', zh: '由端口与地址推导的连接类型：1 网页（80 / 443），2 流媒体，3 游戏、通讯或高位端口，4 数据库，5 文件传输与 SSH，6 API，7 DNS，0 其他', en: 'Connection type derived from port and address: 1 web (80 / 443), 2 streaming, 3 gaming, messaging or high ports, 4 database, 5 file transfer and SSH, 6 API, 7 DNS, 0 other' },
  { i: 23, name: 'asn_hash', zh: 'ASN 哈希分桶（500）', en: 'ASN hash bucket (500)' },
  { i: 24, name: 'host_hash', zh: '域名哈希分桶（1000）', en: 'Host hash bucket (1000)' },
  { i: 25, name: 'ip_hash', zh: 'IP 哈希分桶（10000）', en: 'IP hash bucket (10000)' },
  { i: 26, name: 'geoip_hash', zh: '国家哈希分桶（200）', en: 'Country hash bucket (200)' },
  { i: 27, name: 'latency_stddev', zh: 'log1p(首字节延迟标准差)', en: 'log1p(first-byte latency std-dev)' },
  { i: 28, name: 'connect_time_stddev', zh: 'log1p(建连耗时标准差)', en: 'log1p(connect time std-dev)' },
  { i: 29, name: 'short_long_rtt_delta', zh: '短期 RTT − 长期 RTT（ms），为正说明节点最近变慢', en: 'Short-term RTT − long-term RTT (ms); positive means the node has slowed down lately' },
  { i: 30, name: 'short_success_rate', zh: '短期成功率', en: 'Short-term success rate' },
  { i: 31, name: 'active_conns', zh: 'log1p(节点当前活跃连接数)', en: 'log1p(live connections on the node)' },
  { i: 32, name: 'tls_handshake_time', zh: 'log1p(最近一次探测的 TLS 握手耗时)', en: 'log1p(TLS handshake time of the last probe)' },
  { i: 33, name: 'hour_bucket', zh: '本地小时 / 24', en: 'Local hour / 24' },
  { i: 34, name: 'tcp_retransmissions', zh: 'log1p(最近一次探测的 TCP 重传次数)，仅 Linux / Android', en: 'log1p(TCP retransmissions of the last probe); Linux / Android only' },
  { i: 35, extra: true, name: 'history_duration_minutes', zh: 'log1p(平均连接时长 分钟)', en: 'log1p(average connection duration, minutes)' },
  { i: 36, extra: true, name: 'loss_rate', zh: '本次连接的 TCP 重传率（0–1）', en: 'TCP retransmission rate of this connection (0–1)' },
  { i: 37, extra: true, name: 'cumul_loss_rate', zh: '该（目标, 节点）所有连接累计的 TCP 重传率（0–1），保存在缓存文件中', en: 'TCP retransmission rate accumulated over all connections of the (destination, node) pair (0–1), kept in the cache file' },
];

// Input order of the default model, vernesong/mihomo's Model-large.bin.
export const defaultModelInputs = [
  'success', 'failure', 'connect_time', 'latency', 'upload_mb', 'history_upload_mb',
  'maxuploadrate_kb', 'history_maxuploadrate_kb', 'download_mb', 'history_download_mb',
  'maxdownloadrate_kb', 'history_maxdownloadrate_kb', 'duration_minutes', 'history_duration_minutes',
  'last_used_seconds', 'is_udp', 'is_tcp', 'loss_rate', 'cumul_loss_rate', 'asn_feature',
  'country_feature', 'address_feature', 'port_feature', 'traffic_ratio', 'traffic_density',
  'connection_type_feature', 'asn_hash', 'host_hash', 'ip_hash', 'geoip_hash',
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
    range: '54–58',
    name: 'tcp_retransmissions_raw, tcp_losses, path_mtu, long_rtt, long_success_rate',
    zh: 'TCP 重传、TCP 丢包、路径 MTU、长期 RTT、长期成功率',
    en: 'TCP retransmissions, TCP losses, path MTU, long-term RTT, long-term success rate',
  },
  {
    range: '59–61',
    name: 'current_duration_minutes, loss_rate, cumul_loss_rate',
    zh: '不在 35 维中的特征，取值与模型输入相同：log1p(本次连接时长 分钟)、本次连接的 TCP 重传率、累计 TCP 重传率',
    en: 'Features outside the 35, with the values the model receives: log1p(duration of this connection, minutes), TCP retransmission rate of this connection, accumulated TCP retransmission rate',
  },
  { range: '62', name: 'schema_version', zh: '格式版本，固定为 `5`，始终是最后一列', en: 'Format version, always `5`, and always the last column' },
];
