---
icon: material/new-box
---

### 结构

```json
{
  "type": "quicx",
  "tag": "quicx-in",

  ... // 监听字段

  "users": [
    {
      "name": "sekai",
      "password": "hello"
    }
  ],
  "auth_timeout": "3s",
  "heartbeat": "10s",
  "auth_failure_policy": "h3_close",
  "bbr_profile": "",
  "qlog_directory": "",
  "qlog_max_size": "300MB",
  "tls": {
    "enabled": true,
    "certificate_path": "/path/to/certificate.crt",
    "key_path": "/path/to/private.key",
    "alpn": ["h3"]
  },

  ... // QUIC 字段
}
```

QUICX 是一个外观与标准 HTTP/3 服务器一致的 QUIC 代理协议：TCP 通过 QUIC
双向流转发，UDP 通过 QUIC DATAGRAM（必要时分片）转发，认证与请求可以随
0-RTT 首个航班发出。

需要构建标签 `with_quic`。

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### users

QUICX 用户。

#### users.name

用户名，用于日志与路由规则中的 `auth_user`。

#### users.password

==必填==

QUICX 用户密码。

#### auth_timeout

服务器等待客户端发送认证命令的时间。

默认使用 `3s`。

#### heartbeat

发送心跳包以保持连接存活的时间间隔。

默认使用 `10s`。

#### auth_failure_policy

服务器处理 QUICX 鉴权失败以及非 QUICX 标准 HTTP/3 请求的方式，同时保持传输层与标准 HTTP/3 服务器不可分辨。

| 策略            | 描述                                                                                                                       |
|---------------|--------------------------------------------------------------------------------------------------------------------------|
| `h3_close`    | 以 `H3_NO_ERROR` 关闭 QUIC 连接，等同标准 HTTP/3 正常关闭。                                                                              |
| `silent_drop` | 静默丢弃连接、不立即发送 `CONNECTION_CLOSE`，探测者只能得到超时；服务端仅在宽限期（30 秒）内保留该连接，之后本地回收，避免对端 keepalive 长期占用资源。 |

默认使用 `h3_close`。

#### bbr_profile

BBR 拥塞控制算法配置，可选 `conservative` `standard` `aggressive`。

默认使用 `conservative`。

#### qlog_directory

为每个 QUIC 连接向该目录写入一份 [qlog](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/) 日志，文件名为 `<连接 ID>_server.sqlog`。

默认关闭。相对路径基于工作目录解析，支持环境变量。目录会在启动时创建，路径不可写会导致 sing-box 启动失败，而不是静默地不记录日志。

日志可用 [qvis](https://qvis.quictools.info/) 打开分析。

#### qlog_max_size

qlog 目录的总大小上限，可以直接写字节数，也可以带单位，例如 `300MB`。

默认使用 `300MB`。

目录超过上限后会从最旧的已完成日志开始删除，因此目录不会无限增长。仍在记录中的连接日志不会被删除或截断，所以连接打开期间目录可能暂时超过上限，并随连接关闭回落到上限以内。多个端点写入同一目录时共享同一个上限，取其中最小的配置值。

#### tls

==必填==

TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/#入站)。

ALPN 应为 `h3`，省略时默认使用 `h3`。

### 0-RTT 与重放

服务端接受 0-RTT 数据，以便传输层与标准 HTTP/3 服务器不可分辨。由于 QUIC 0-RTT 本身没有重放保护，客户端会在认证请求中携带一个每连接随机的 nonce，服务端则记住已认证会话的 nonce：

- 另一个会话使用同一 nonce 认证会被当作重放的 0-RTT 航班，按 `auth_failure_policy` 关闭，因此不会建立到目标的代理连接；
- 同一会话重复使用自己的 nonce（客户端并发两个认证流，或 0-RTT 被拒后重发认证）不算重放。

服务端只记住最近 65536 个已认证会话的 nonce，并最多保留 24 小时，超出窗口后不再保证拒绝重复的 nonce。该状态是每个实例独立的内存状态：多实例部署或进程重启都会让窗口重置。

### QUIC 字段

参阅 [QUIC 字段](/zh/configuration/shared/quic/) 了解详情。

非 QUICX 代理流量的标准 HTTP/3 请求不会建立代理连接，而是按 `auth_failure_policy` 关闭：
`h3_close` 时以 `H3_NO_ERROR` 标准关闭，`silent_drop` 时静默丢弃（宽限期内不发送任何关闭帧）。
