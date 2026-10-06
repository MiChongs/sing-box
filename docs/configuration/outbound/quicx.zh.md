---
icon: material/new-box
---

### 结构

```json
{
  "type": "quicx",
  "tag": "quicx-out",

  "server": "127.0.0.1",
  "server_port": 443,
  "password": "hello",
  "heartbeat": "10s",
  "bbr_profile": "",
  "qlog_directory": "",
  "qlog_max_size": "300MB",
  "network": "tcp",
  "tls": {
    "enabled": true,
    "server_name": "example.com",
    "alpn": ["h3"]
  },

  ... // QUIC 字段

  ... // 拨号字段
}
```

需要构建标签 `with_quic`。

### 字段

#### server

==必填==

服务器地址。

#### server_port

==必填==

服务器端口。

#### password

==必填==

QUICX 用户密码。

#### heartbeat

发送心跳包以保持连接存活的时间间隔。

默认使用 `10s`。

#### bbr_profile

BBR 拥塞控制算法配置，可选 `conservative` `standard` `aggressive`。

默认使用 `conservative`。

#### qlog_directory

为每个 QUIC 连接向该目录写入一份 [qlog](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/) 日志，文件名为 `<连接 ID>_client.sqlog`。

默认关闭。相对路径基于工作目录解析，支持环境变量。目录会在启动时创建，路径不可写会导致 sing-box 启动失败，而不是静默地不记录日志。

日志可用 [qvis](https://qvis.quictools.info/) 打开分析。

#### qlog_max_size

qlog 目录的总大小上限，可以直接写字节数，也可以带单位，例如 `300MB`。

默认使用 `300MB`。

目录超过上限后会从最旧的已完成日志开始删除，因此目录不会无限增长。仍在记录中的连接日志不会被删除或截断，所以连接打开期间目录可能暂时超过上限，并随连接关闭回落到上限以内。多个端点写入同一目录时共享同一个上限，取其中最小的配置值。

#### network

启用的网络协议。

`tcp` 或 `udp`。

默认所有。

#### tls

==必填==

TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/#出站)。

ALPN 应为 `h3`，省略时默认使用 `h3`。

### 0-RTT

当存在上一次连接留下的会话票据时，QUICX 会尝试 0-RTT 连接握手，在隧道重建时节省一个往返。由于协议是完全复用的，只有重建后的首个请求会从中受益，而客户端的 0-RTT 数据里装的正是它：认证请求、CONNECT 请求（目标地址）以及被代理连接的首段数据都会随第一个航班发出。

当服务端拒绝 0-RTT（例如服务端重启、会话票据密钥变化或被 anti-replay 拒绝）时，客户端会在握手完成后重新发送认证与首个请求，不会因此关闭连接。

客户端为每个连接生成一个随机 nonce 并随认证请求发送，服务端会记住已认证会话的 nonce，并拒绝另一个会话使用同一 nonce 的认证请求（参阅入站文档中的 0-RTT 与重放）。因此重放的 0-RTT 航班无法通过认证，也就不会建立到目标的代理连接。

!!! warning ""

    0-RTT 数据本身容易受到重放攻击：抓到客户端 0-RTT 航班的人可以把它原样再发给服务端一次，传输层无法区分副本与原件。攻击者无法借此得到可用隧道（他没有握手密钥，无法解密响应，也无法构造 1-RTT 数据），但如果没有上述 nonce 检查，服务端会再次认证、再次连接目标并把首段数据再投递一次，对非幂等请求（例如明文 HTTP POST）存在实际风险。

### QUIC 字段

参阅 [QUIC 字段](/zh/configuration/shared/quic/) 了解详情。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/) 了解详情。
