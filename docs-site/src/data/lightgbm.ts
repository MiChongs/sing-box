// LightGBM feature layout (common/smart/lightgbm/lightgbm.go prepareFeatures,
// names from transform.go defaultFeatureOrder) and the collector CSV columns
// (collector.go). Features are positional: slot i of the model input is
// feature i below, whatever names the model file carries.

export interface Feature {
  i: number;
  name: string;
  zh: string;
  en: string;
}

export const features: Feature[] = [
  { i: 0, name: 'success', zh: '该节点对这个服务的累计成功次数（含本次）', en: 'Lifetime successes of the node for this service (this connection included)' },
  { i: 1, name: 'failure', zh: '该节点对这个服务的累计失败次数（含本次）', en: 'Lifetime failures of the node for this service (this connection included)' },
  { i: 2, name: 'connect_time', zh: 'log1p(建连耗时 ms)，历史均值与本次按 1 : 2 合并', en: 'log1p(connect time, ms), history and this connection blended 1 : 2' },
  { i: 3, name: 'latency', zh: 'log1p(首次响应耗时 ms)，合并方式同上', en: 'log1p(first-response time, ms), blended the same way' },
  { i: 4, name: 'upload_mb', zh: 'log1p(本次上传 MB)', en: 'log1p(upload this connection, MB)' },
  { i: 5, name: 'history_upload_mb', zh: 'log1p(累计上传 MB)', en: 'log1p(total upload, MB)' },
  { i: 6, name: 'maxuploadrate_kb', zh: 'log1p(本次峰值上传 KB/s)，按 100 ms 窗口计算', en: 'log1p(peak upload this connection, KB/s), over 100 ms buckets' },
  { i: 7, name: 'history_maxuploadrate_kb', zh: 'log1p(历史峰值上传 KB/s)', en: 'log1p(historical peak upload, KB/s)' },
  { i: 8, name: 'download_mb', zh: 'log1p(本次下载 MB)', en: 'log1p(download this connection, MB)' },
  { i: 9, name: 'history_download_mb', zh: 'log1p(累计下载 MB)', en: 'log1p(total download, MB)' },
  { i: 10, name: 'maxdownloadrate_kb', zh: 'log1p(本次峰值下载 KB/s)', en: 'log1p(peak download this connection, KB/s)' },
  { i: 11, name: 'history_maxdownloadrate_kb', zh: 'log1p(历史峰值下载 KB/s)', en: 'log1p(historical peak download, KB/s)' },
  { i: 12, name: 'duration_minutes', zh: 'log1p(本次连接时长 分钟)', en: 'log1p(duration of this connection, minutes)' },
  { i: 13, name: 'history_duration_minutes', zh: 'log1p(平均连接时长 分钟)', en: 'log1p(average connection duration, minutes)' },
  { i: 14, name: 'last_used_seconds', zh: 'log1p(距上次使用的秒数)', en: 'log1p(seconds since the previous use)' },
  { i: 15, name: 'is_udp', zh: '是否 UDP（0/1）', en: 'UDP (0/1)' },
  { i: 16, name: 'is_tcp', zh: '是否 TCP（0/1）', en: 'TCP (0/1)' },
  { i: 17, name: 'loss_rate', zh: '本次连接的 TCP 重传率（0–1），没有可判定的发送窗口时为 0', en: 'TCP retransmission rate of this connection (0–1); 0 without a judged send window' },
  { i: 18, name: 'cumul_loss_rate', zh: '该节点对这个服务的累计 TCP 重传率（0–1）', en: 'Accumulated TCP retransmission rate of the node for this service (0–1)' },
  { i: 19, name: 'asn_feature', zh: '目标网络：运营商关键字命中时为 100 起的编号（如 google 100、cloudflare 105、china telecom 120），否则按 ASN 号段为 1–5；未知为 0', en: 'Destination network: a number from 100 up when an operator keyword matches (google 100, cloudflare 105, china telecom 120, …), otherwise 1–5 by ASN range; 0 when unknown' },
  { i: 20, name: 'country_feature', zh: '目标国家：常见国家 100–160（CN 100、HK 101、TW 102、JP 103、US 106 等），其他国家散列到 1–20；未知为 0', en: 'Destination country: common countries 100–160 (CN 100, HK 101, TW 102, JP 103, US 106, …), others hashed into 1–20; 0 when unknown' },
  { i: 21, name: 'address_feature', zh: '目标类别。有域名时：流媒体 100、游戏 101、通讯 102、API 103、DNS 104（按关键字），否则 .cn 110、.com 111、.net 112、.org 113、.gov 114、.edu 115，其他域名 2 / 3，IP 字面量 1。只有 IP 时：私有 10、回环 11、链路本地 12、保留 13、公网 IPv4 14、公网 IPv6 15', en: 'Destination class. With a domain: streaming 100, gaming 101, messaging 102, API 103, DNS 104 (by keyword), otherwise .cn 110, .com 111, .net 112, .org 113, .gov 114, .edu 115, other domains 2 / 3, IP literal 1. With only an IP: private 10, loopback 11, link-local 12, reserved 13, public IPv4 14, public IPv6 15' },
  { i: 22, name: 'port_feature', zh: '目标端口类别：DNS 7、API 6、游戏 1、通讯 2，常见端口 100 起的编号，游戏 / 通讯端口段 3–5，其余按端口段 8（0–1023）、9（1024–49151）、10（49152 起）', en: 'Destination port class: DNS 7, API 6, gaming 1, messaging 2, well-known ports numbered from 100, game / messaging ranges 3–5, others by range 8 (0–1023), 9 (1024–49151), 10 (49152 and up)' },
  { i: 23, name: 'traffic_ratio', zh: '上下行比例：上传多于下载时为 下载 ÷ 上传（0–1），否则为 −上传 ÷ 下载；任一方向没有流量时为 0', en: 'Traffic ratio: download ÷ upload (0–1) when more was uploaded, otherwise −upload ÷ download; 0 when either direction had no traffic' },
  { i: 24, name: 'traffic_density', zh: 'log1p(本次连接平均每分钟流量 MB)', en: 'log1p(MB per minute over this connection)' },
  { i: 25, name: 'connection_type_feature', zh: '连接类型：网页 1、流媒体 2、实时（游戏、通讯、10000–65000 高位端口）3、数据库 4、文件传输与 SSH 5、API 6、DNS 7，其他 0', en: 'Connection type: web 1, streaming 2, real-time (games, messaging, high ports 10000–65000) 3, database 4, file transfer and SSH 5, API 6, DNS 7, other 0' },
  { i: 26, name: 'asn_hash', zh: '目标 ASN 的哈希分桶（1–500）', en: 'Hash bucket of the destination ASN (1–500)' },
  { i: 27, name: 'host_hash', zh: '目标通配主机（如 `*.example.com`）的哈希分桶（1–1000）', en: 'Hash bucket of the destination wildcard host, such as `*.example.com` (1–1000)' },
  { i: 28, name: 'ip_hash', zh: '目标 IP 的哈希分桶（1–10000）', en: 'Hash bucket of the destination IP (1–10000)' },
  { i: 29, name: 'geoip_hash', zh: '目标国家的哈希分桶（1–200）', en: 'Hash bucket of the destination country (1–200)' },
  { i: 30, name: 'exit_region', zh: '节点对这个网站实际落地的国家或地区（出口探测结果），编码同 `country_feature`；未知为 0', en: 'Country or region where the node really lands for this site (from exit probes), coded like `country_feature`; 0 when unknown' },
  { i: 31, name: 'exit_asn_hash', zh: '节点落地网络 ASN 的哈希分桶（1–500），只在开启 `prefer_asn` 时有值', en: 'Hash bucket of the network the node lands on (1–500); only set with `prefer_asn`' },
];

export interface Column {
  range: string;
  name: string;
  zh: string;
  en: string;
}

// Header names come from initializeWriter in collector.go: 32 features and
// 10 metadata columns.
export const csvColumns: Column[] = [
  { range: '0–31', name: 'success … exit_asn_hash', zh: '32 个特征，列名与顺序同上表，格式 `%.6f`', en: 'The 32 features, with the names and order of the table above, formatted `%.6f`' },
  { range: '32', name: 'group_name', zh: 'Smart 组标签', en: 'Smart group tag' },
  { range: '33', name: 'node_name', zh: '节点标签', en: 'Node tag' },
  { range: '34–38', name: 'asn_raw, host_raw, ip_raw, port_raw, geoip_raw', zh: '原始的 ASN（`号码 组织`）、域名、IP、端口、国家，缺失时为 `unknown`', en: 'Raw ASN (`number organization`), host, IP, port and country; `unknown` when missing' },
  { range: '39', name: 'weight', zh: '训练标签：本次连接的质量（不含 `policy_priority` 系数）。连接被判为劣化或触发封锁时，不低于 0.4 的标签压到原值的 10%，为 0 的标签改取 0–0.4 的随机值', en: 'Training label: the quality of this connection (without the `policy_priority` factor). When the connection degraded the node or triggered a block, a label of 0.4 or more is cut to 10%, and a label of 0 becomes a random value in 0–0.4' },
  { range: '40', name: 'weight_source', zh: '`Traditional`（场景公式）或 `LightGBM`', en: '`Traditional` (scene formula) or `LightGBM`' },
  { range: '41', name: 'timestamp', zh: 'RFC 3339 时间', en: 'RFC 3339 time' },
];
