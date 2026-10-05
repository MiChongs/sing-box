# sing-box（xiaobaf14g）

[![Latest Release](https://img.shields.io/github/v/release/MiChongs/sing-box?include_prereleases&sort=semver)](https://github.com/MiChongs/sing-box/releases)
[![Release Workflow](https://github.com/MiChongs/sing-box/actions/workflows/xiaobaf14g-release.yml/badge.svg?branch=xiaobaf14g-testing)](https://github.com/MiChongs/sing-box/actions/workflows/xiaobaf14g-release.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/MiChongs/sing-box?filename=go.mod)](go.mod)
[![License](https://img.shields.io/github/license/MiChongs/sing-box)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/MiChongs/sing-box/xiaobaf14g-testing)](https://github.com/MiChongs/sing-box/commits/xiaobaf14g-testing)
[![Code Size](https://img.shields.io/github/languages/code-size/MiChongs/sing-box)](https://github.com/MiChongs/sing-box)

本项目是 [sing-box](https://github.com/SagerNet/sing-box) 的衍生版本，基于 [reF1nd/sing-box](https://github.com/reF1nd/sing-box) 维护。在兼容上游配置格式的前提下，本分支新增 Smart 出站组、XHTTP 传输、VLESS Encryption 与 EasyTier 端点，扩展了 Clash API，并为 Windows、Linux、macOS、FreeBSD 与 Android 提供命令行程序及 SFA、SFW、SFL 图形客户端的发布构建。

## 目录

- [分支关系与功能来源](#分支关系与功能来源)
- [Smart 出站组](#smart-出站组)
- [XHTTP 传输](#xhttp-传输)
- [VLESS Encryption](#vless-encryption)
- [EasyTier 端点](#easytier-端点)
- [eBPF 入站](#ebpf-入站)
- [Clash API 扩展](#clash-api-扩展)
- [其他改进](#其他改进)
- [继承自 reF1nd 的功能](#继承自-ref1nd-的功能)
- [发布产物](#发布产物)
- [图形客户端](#图形客户端)
- [从源码构建](#从源码构建)
- [文档](#文档)
- [许可证](#许可证)

## 分支关系与功能来源

代码沿 SagerNet/sing-box、reF1nd/sing-box、本分支（`xiaobaf14g-testing`）的顺序演进，并定期同步上游变更。下表列出相对于 SagerNet 上游的主要功能差异及其来源。

| 功能 | 来源 | 构建标记 |
|---|---|---|
| Smart 出站组 | 本分支 | 无需 |
| XHTTP 传输 | 本分支 | `with_xhttp`（默认启用） |
| VLESS Encryption（`mlkem768x25519plus`）及其上的 XTLS Vision | 本分支 | 无需 |
| EasyTier 端点与 Magic DNS | 本分支 | `with_easytier`（实验性，默认不启用） |
| Clash API 扩展：规则命中统计、Smart 管理接口 | 本分支 | `with_clash_api`（默认启用） |
| eBPF 入站 | reF1nd；本分支改用 [MiChongs/sing-ebpf](https://github.com/MiChongs/sing-ebpf) | `with_ebpf`（默认不启用） |
| 订阅 Provider | reF1nd | 无需 |
| URLTest 故障转移、`loadbalance` 出站组、`pass` 出站 | reF1nd | 无需 |
| TLS `server_names` 与 `reject_unknown_sni`、TCP Keep-Alive 选项、DNS 缓存选项 | reF1nd | 无需 |

## Smart 出站组

`smart` 出站组根据各节点对不同目标的历史表现选择出站。节点评分基于 EWMA 短窗口与长窗口统计，并可选择启用 LightGBM 模型。统计数据保存在缓存文件（`experimental.cache_file`）中，进程重启后恢复；未启用缓存文件时仅保存在内存中。

主要特性如下：

- **选路算法**：`algorithm` 支持 `strict-best`（默认）、`weighted-random`、`least-loaded`、`fastest-recent`、`sticky-session`、`round-robin`、`weighted-rr`、`p2c`、`latency-banded` 与 `consistent-hashing`。
- **节点优先级**：`policy_priority` 按节点名称规则设置权重系数，支持子串、`=`、`~`、`!` 与通配符匹配，多条规则的系数相乘。
- **手动指定**：通过 Clash API 指定节点后，若该节点不可用，则临时改用其他节点，待其恢复后自动切回。手动指定状态在重启后保留。
- **故障判定**：拨号或探测失败的节点被标记为不可用，标记持续 3 分钟，期间任意一次成功的拨号或探测即解除标记。60 秒内出现两次 TCP RST 的节点同样被判定为不可用。
- **对冲拨号**：首选节点状态异常且 250 ms 内未完成连接时，并行向次优节点发起拨号，采用先建立的连接。
- **连接监测**：客户端写入后 5 秒内未收到首字节，或写入后 60 秒内无任何响应，即判定连接停滞。空闲的长连接（如 WebSocket 与推送连接）不受影响。
- **网络切换**：检测到网络变化时清除可用性与探测缓存，并取消进行中的拨号；30 秒内失败达到 5 次时暂停后台探测。

### 配置示例

```json
{
  "outbounds": [
    {
      "type": "smart",
      "tag": "auto",
      "outbounds": ["hk-01", "jp-01", "us-01"],
      "algorithm": "strict-best",
      "use_lightgbm": true
    }
  ],
  "experimental": {
    "cache_file": { "enabled": true },
    "smart": {
      "lightgbm": { "auto_update": true, "update_interval": "72h" }
    }
  }
}
```

### 出站组字段

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `outbounds` | 字符串数组 | | 成员出站 |
| `providers` | 字符串数组 | | 引用的订阅 Provider |
| `use_all_providers` | 布尔 | `false` | 使用全部订阅 Provider 的节点 |
| `include` / `exclude` | 正则表达式 | | 按名称筛选节点 |
| `url` | 字符串 | `https://www.gstatic.com/generate_204` | 探测地址 |
| `interval` | 时长 | `3m` | 探测间隔 |
| `expected_status` | 字符串 | | 视为探测成功的 HTTP 状态码 |
| `algorithm` | 字符串 | `strict-best` | 选路算法 |
| `hysteresis` | 时长 | `0` | 防抖窗口，大于 0 时同一目标优先沿用上次选择的节点；`0` 表示关闭 |
| `policy_priority` | 字符串 | | 节点优先级规则 |
| `use_lightgbm` | 布尔 | `false` | 使用 LightGBM 模型评分 |
| `collect_data` | 布尔 | `false` | 采集模型训练数据 |
| `sample_rate` | 浮点数 | `1.0` | 训练数据采样比例，取值范围 (0, 1] |
| `use_asn` | 布尔 | `false` | 启用 ASN 特征 |
| `asn_database` | 字符串或数组 | | ASN 数据库地址；未指定时使用 `experimental.geox` 中的配置 |
| `max_host_failed_times` | 整数 | `10` | 目标主机失败次数上限（与 mihomo 一致） |
| `interrupt_exist_connections` | 布尔 | `false` | 切换节点时中断现有连接 |
| `disable_udp` | 布尔 | `false` | 禁用 UDP |
| `hidden` / `icon` | 布尔 / 字符串 | | Clash 面板中的显示属性 |

### 全局字段（`experimental.smart`）

| 字段 | 默认值 | 说明 |
|---|---|---|
| `lightgbm.model_path` | `smart_lgbm_model.bin` | 模型文件路径 |
| `lightgbm.url` | vernesong/mihomo 发布的 `Model-large.bin` | 模型下载地址 |
| `lightgbm.auto_update` | `false` | 定期更新模型；关闭时仍会在模型文件缺失时下载一次 |
| `lightgbm.update_interval` | `72h` | 模型更新间隔 |
| `lightgbm.http_client` / `lightgbm.download_detour` | | 下载模型使用的 HTTP 客户端或出站 |
| `collector.path` | `smart_weight_data.csv` | 训练数据文件路径 |
| `collector.size_limit_mb` | `100` | 训练数据文件大小上限（MB） |

完整说明参见 [Smart 出站组文档站](https://michongs.github.io/sing-box/zh/)。

## XHTTP 传输

`xhttp` 传输实现 XTLS/Xray-core 的 XHTTP（SplitHTTP）协议，行为与 Xray-core v26.9.30 对齐，同时提供入站（服务端）与出站（客户端）实现，可用于所有支持 V2Ray 传输层的协议。订阅解析同样支持 XHTTP，包括 Clash 配置中的 `xhttp-opts`，以及 VLESS、VMess、Trojan 分享链接中的 `type=xhttp`（含 `splithttp`）。

### 传输模式

| 模式 | 请求形态 |
|---|---|
| `stream-one` | 单个 POST 请求，请求体承载上行，响应体承载下行，适用于 HTTP/2 与 HTTP/3 |
| `stream-up` | GET 请求承载下行，POST 长请求体承载上行 |
| `packet-up` | GET 请求承载下行，上行数据分批以独立请求发送，由服务端按序号重排；兼容性最好 |
| `auto` | 客户端：使用 REALITY 时为 `stream-one`（配置 `download_settings` 时为 `stream-up`），其余情况为 `packet-up`。服务端：接受全部模式 |

客户端按以下规则选择 HTTP 版本：使用 REALITY 时为 HTTP/2；未启用 TLS 或 ALPN 仅为 `http/1.1` 时为 HTTP/1.1；ALPN 仅为 `h3` 时为 HTTP/3；其余情况为 HTTP/2。服务端在 ALPN 仅为 `h3` 时监听 UDP 并提供 HTTP/3 服务（需要 `with_quic`）。

### 功能

- **请求特征混淆**：启用 `x_padding_obfs_mode` 后，可自定义填充数据的字段名、位置（`queryInHeader`、`header`、`cookie`、`query`）及生成方式（`repeat-x`、`tokenish`），以规避基于固定 `x_padding` 特征的 CDN 规则。
- **元数据位置**：`session_placement` 与 `seq_placement` 可将会话标识与序号从路径移至请求头、Cookie 或查询参数；`session_id_table` 与 `session_id_length` 用于自定义会话标识的字符集与长度。
- **上行方法与数据位置**：`uplink_http_method` 可改用 `PUT`、`PATCH` 或 `GET`；在 `packet-up` 模式下，`uplink_data_placement` 可将上行数据分片置于请求头或 Cookie 中，适用于仅允许 GET 请求的 CDN。
- **浏览器特征**：`user_agent` 取值为 `chrome`、`firefox`、`safari`、`edge`、`curl` 或 `golang` 时，按对应客户端生成请求头（含 Sec-CH-UA 客户端提示）；其他取值作为 User-Agent 原样发送。
- **连接复用（XMUX）**：`xmux` 控制连接池的并发数、连接数及轮换策略，默认值与 Xray 一致。
- **上下行分离**：`download_settings` 为下行请求指定独立的服务器、TLS、拨号及 XHTTP 参数。
- **HTTP/3 拥塞控制**：`quic_congestion` 支持 `bbr`（默认）、`reno` 与 `force-brutal`。
- **HTTP/1.1 上行连接池**：HTTP/1.1 下 `packet-up` 模式的上行请求预先完整序列化，并通过连接池复用连接；写入或读取响应失败时自动重试。

### 配置示例

XHTTP 字段直接写在 `transport` 对象中，与 `type` 同级。

服务端（入站）：

```json
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 443,
      "users": [{ "name": "user1", "uuid": "00000000-0000-0000-0000-000000000000" }],
      "tls": {
        "enabled": true,
        "server_name": "example.com",
        "alpn": ["h2", "http/1.1"],
        "certificate_path": "cert.pem",
        "key_path": "key.pem"
      },
      "transport": {
        "type": "xhttp",
        "path": "/your-path",
        "host": "example.com",
        "mode": "auto"
      }
    }
  ]
}
```

客户端（出站）：

```json
{
  "outbounds": [
    {
      "type": "vless",
      "tag": "proxy",
      "server": "example.com",
      "server_port": 443,
      "uuid": "00000000-0000-0000-0000-000000000000",
      "tls": { "enabled": true, "server_name": "example.com" },
      "transport": {
        "type": "xhttp",
        "path": "/your-path",
        "host": "example.com",
        "mode": "auto"
      }
    }
  ]
}
```

客户端使用 HTTP/3 与 BBR 拥塞控制：

```json
{
  "type": "vless",
  "tag": "proxy-h3",
  "server": "example.com",
  "server_port": 443,
  "uuid": "00000000-0000-0000-0000-000000000000",
  "tls": { "enabled": true, "server_name": "example.com", "alpn": ["h3"] },
  "transport": {
    "type": "xhttp",
    "path": "/your-path",
    "host": "example.com",
    "quic_congestion": "bbr"
  }
}
```

客户端启用请求特征混淆：

```json
{
  "type": "vless",
  "tag": "proxy-obfs",
  "server": "cdn.example.com",
  "server_port": 443,
  "uuid": "00000000-0000-0000-0000-000000000000",
  "tls": { "enabled": true, "server_name": "cdn.example.com" },
  "transport": {
    "type": "xhttp",
    "path": "/api",
    "host": "cdn.example.com",
    "mode": "packet-up",
    "x_padding_obfs_mode": true,
    "x_padding_method": "tokenish",
    "x_padding_placement": "queryInHeader",
    "x_padding_key": "_dc",
    "x_padding_header": "X-Cache",
    "uplink_http_method": "PUT",
    "session_placement": "header",
    "session_key": "X-Auth-Token",
    "seq_placement": "cookie",
    "seq_key": "chunk",
    "user_agent": "chrome"
  }
}
```

客户端通过仅允许 GET 请求的 CDN 传输（上行数据置于请求头）：

```json
{
  "type": "vless",
  "tag": "proxy-get-only",
  "server": "cdn.example.com",
  "server_port": 443,
  "uuid": "00000000-0000-0000-0000-000000000000",
  "tls": { "enabled": true, "server_name": "cdn.example.com" },
  "transport": {
    "type": "xhttp",
    "path": "/api",
    "host": "cdn.example.com",
    "mode": "packet-up",
    "uplink_http_method": "GET",
    "uplink_data_placement": "header",
    "uplink_data_key": "X-Payload",
    "uplink_chunk_size": "3000-4000",
    "session_placement": "header",
    "seq_placement": "query",
    "seq_key": "page"
  }
}
```

客户端上下行分离（上行与下行经由不同入口到达同一服务端）：

```json
{
  "type": "vless",
  "tag": "proxy-split",
  "server": "up.example.com",
  "server_port": 443,
  "uuid": "00000000-0000-0000-0000-000000000000",
  "tls": { "enabled": true, "server_name": "up.example.com" },
  "transport": {
    "type": "xhttp",
    "path": "/your-path",
    "host": "up.example.com",
    "mode": "stream-up",
    "download_settings": {
      "server": "down.example.com",
      "server_port": 443,
      "tls": { "enabled": true, "server_name": "down.example.com" },
      "path": "/your-path",
      "host": "down.example.com"
    }
  }
}
```

### 字段参考

范围类字段（类型标注为“范围”）可写为整数（`1000`）或字符串（`"100-1000"`），每次使用时在范围内随机取值。

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `host` | 字符串或数组 | TLS SNI 或服务器地址 | Host 请求头；配置多个值时每次拨号随机选取 |
| `path` | 字符串 | `/` | 请求路径，可附带查询参数（如 `/path?key=value`） |
| `mode` | 字符串 | `auto` | `auto` / `stream-one` / `stream-up` / `packet-up` |
| `headers` | 对象 | | 附加请求头，不得包含 Host |
| `user_agent` | 字符串 | `chrome` | 浏览器特征：`chrome` / `firefox` / `safari` / `edge` / `curl` / `golang`，其他取值原样作为 User-Agent |
| `x_padding_bytes` | 范围 | `100-1000` | 填充数据长度，不可关闭 |
| `x_padding_obfs_mode` | 布尔 | `false` | 启用填充混淆；以下四个 `x_padding_*` 字段仅在启用后生效 |
| `x_padding_key` | 字符串 | `x_padding` | 填充字段名 |
| `x_padding_header` | 字符串 | `X-Padding` | 承载填充数据的请求头 |
| `x_padding_placement` | 字符串 | `queryInHeader` | `queryInHeader` / `header` / `cookie` / `query` |
| `x_padding_method` | 字符串 | `repeat-x` | `repeat-x` / `tokenish` |
| `uplink_http_method` | 字符串 | `POST` | `POST` / `PUT` / `PATCH` / `GET`；`GET` 仅限 `packet-up` 模式 |
| `session_placement` | 字符串 | `path` | `path` / `header` / `cookie` / `query` |
| `session_key` | 字符串 | 按位置而定 | 请求头位置为 `X-Session`，Cookie 与查询参数位置为 `x_session` |
| `session_id_table` | 字符串 | | 会话标识字符集，可使用预定义名称（`hex`、`HEX`、`number`、`alphabet`、`ALPHABET`、`Alphabet`、`base36`、`BASE36`、`Base62`）或自定义 ASCII 字符串；未设置时使用 UUID |
| `session_id_length` | 范围 | | 会话标识长度，配合 `session_id_table` 使用 |
| `seq_placement` | 字符串 | `path` | `path` / `header` / `cookie` / `query` |
| `seq_key` | 字符串 | 按位置而定 | 请求头位置为 `X-Seq`，Cookie 与查询参数位置为 `x_seq` |
| `uplink_data_placement` | 字符串 | `auto` | `auto` / `body` / `header` / `cookie`；`header` 与 `cookie` 仅限 `packet-up` 模式 |
| `uplink_data_key` | 字符串 | 按位置而定 | Cookie 位置为 `x_data`，其余为 `X-Data` |
| `uplink_chunk_size` | 范围 | 按位置而定 | 上行分片大小，最小 64；Cookie 位置默认 `2048-3072`，请求头位置默认 `3000-4000`，其余与 `sc_max_each_post_bytes` 相同 |
| `no_grpc_header` | 布尔 | `false` | 不发送 `Content-Type: application/grpc` |
| `no_sse_header` | 布尔 | `false` | 下行响应不使用 `Content-Type: text/event-stream` |
| `sc_max_each_post_bytes` | 范围 | `1000000` | `packet-up` 单个上行请求的最大字节数 |
| `sc_min_posts_interval_ms` | 范围 | `30` | `packet-up` 上行请求的最小间隔（毫秒） |
| `sc_max_buffered_posts` | 整数 | `30` | 服务端乱序缓冲的请求数上限 |
| `sc_stream_up_server_secs` | 范围 | `20-80` | `stream-up` 服务端保持上行请求的时长（秒） |
| `server_max_header_bytes` | 整数 | `8192` | 服务端请求头大小上限 |
| `xmux` | 对象 | 见下表 | 连接复用设置 |
| `download_settings` | 对象 | | 下行请求设置，包含服务器、TLS、拨号字段及全部 XHTTP 字段；XHTTP 字段不从上行继承，服务器地址未设置时沿用上行地址 |
| `quic_congestion` | 字符串 | `bbr` | `bbr` / `reno` / `force-brutal`，仅用于 HTTP/3 |
| `quic_up` | 整数 | | `force-brutal` 的发送带宽（字节/秒），不低于 65536 |

`xmux` 字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `max_concurrency` | 范围 | 单个连接的最大并发请求数，不可与 `max_connections` 同时设置 |
| `max_connections` | 范围 | 最大连接数 |
| `c_max_reuse_times` | 范围 | 单个连接的最大复用次数 |
| `h_max_request_times` | 范围 | 单个连接的最大请求次数 |
| `h_max_reusable_secs` | 范围 | 单个连接的最长可复用时间（秒） |
| `h_keep_alive_period` | 整数 | 保活间隔（秒）；`0` 表示默认值（HTTP/2 为 45 秒，HTTP/3 为 10 秒），负数表示关闭 |

`xmux` 全部字段均未设置时，采用 Xray 默认值：`max_connections` 为 `3`，`h_max_request_times` 为 `600-900`，`h_max_reusable_secs` 为 `1800-3000`。

## VLESS Encryption

VLESS 入站的 `decryption` 与出站的 `encryption` 字段实现 Xray-core 的 VLESS Encryption（`mlkem768x25519plus`），与 Xray-core 互通。该加密层位于传输层与 VLESS 头部之间：通过 ML-KEM-768 与 X25519 混合密钥交换建立具备前向安全的会话，以 X25519 或 ML-KEM-768（抗量子）密钥认证服务端，支持 0-RTT 会话复用及重放检测。

启用加密后，`xtls-rprx-vision` 流控以加密层代替外层 TLS 工作，因此可用于 XHTTP、WebSocket、gRPC 等任意传输层，也可在不启用 TLS 的情况下使用；内层 TLS 1.3 流量切换为直接转发时绕过加密层，与 Xray-core 行为一致。未启用加密时，Vision 仍仅支持直接基于 TLS 或 REALITY 的连接。

订阅解析支持分享链接中的 `encryption` 参数与 Clash 配置中的 `encryption` 字段。

取值格式与 Xray-core 相同：

| 字段 | 格式 |
|---|---|
| 入站 `decryption` | `mlkem768x25519plus.<外观>.<票据有效期>.[填充.]<服务端密钥>` |
| 出站 `encryption` | `mlkem768x25519plus.<外观>.<0rtt 或 1rtt>.[填充.]<客户端密钥>` |

- **外观**：`native` 为 TLS 记录形态；`xorpub` 额外混淆公钥；`random` 使全部流量呈现为随机字节。双方取值必须一致。
- **票据有效期**：服务端签发的 0-RTT 票据有效期，如 `600s` 或范围 `300-600s`；`0s` 表示禁用 0-RTT。
- **填充**：可选，如 `100-111-1111.75-0-111.50-0-3333`，依次为长度与间隔参数，未设置时采用 Xray 默认值。
- **密钥**：执行 `sing-box generate vless-encryption` 生成成对的 `decryption` 与 `encryption`；X25519 与 ML-KEM-768 认证任选其一。

```json
{
  "type": "vless",
  "server": "example.com",
  "server_port": 443,
  "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
  "flow": "xtls-rprx-vision",
  "encryption": "mlkem768x25519plus.native.0rtt.<client key>",
  "tls": {
    "enabled": true,
    "server_name": "example.com"
  },
  "transport": {
    "type": "xhttp",
    "path": "/xhttp"
  }
}
```

## EasyTier 端点

`easytier` 端点将 sing-box 接入 [EasyTier](https://github.com/EasyTier/EasyTier) 虚拟网络。EasyTier 内核以 WebAssembly 形式内嵌并由 wazero 执行，无需另行部署 `easytier-core`。该功能为实验性功能，需使用 `with_easytier` 构建标记，二进制文件体积约增加 11 MB。

- **组网**：支持配置对等节点（`peers`）、监听地址（`listeners`）、虚拟地址（`address`，省略时通过 DHCP 分配）、加密算法、安全模式（基于 X25519 的节点认证）以及打洞与中继相关选项。
- **子网代理与出口节点**：`proxy_networks` 向虚拟网络发布本地子网，并可通过 `mapped_cidr` 映射为其他网段；`enable_exit_node` 允许本节点作为出口；`exit_nodes` 指定所使用的出口节点。来自对等节点的流量作为该端点的入站流量进入 sing-box 路由，源地址为对端的虚拟 IP。
- **端口转发**：`port_forwards` 将本地端口转发至虚拟网络中的地址。
- **Web 配置**：`web` 连接 EasyTier Web 配置服务器（easytier-web），运行服务器下发的网络，并随服务器配置变更自动增删。
- **Magic DNS**：`easytier` 类型的 DNS 服务器以 `<hostname>.<zone>` 形式解析虚拟网络中各节点的地址，默认区域为 `et.net`。
- **协议**：支持 TCP、UDP 与 ICMP。

wazero 仅在 amd64 与 arm64 架构上以编译方式执行，其他架构使用解释器执行。因此，发布构建仅提供 Windows、Linux、macOS 的 amd64 与 arm64 版本，以及 Android 的 arm64 版本。

```json
{
  "dns": {
    "servers": [
      { "type": "local", "tag": "local" },
      { "type": "easytier", "tag": "easytier-dns", "endpoint": "easytier-ep" }
    ],
    "rules": [
      { "preferred_by": "easytier-dns", "action": "route", "server": "easytier-dns" }
    ]
  },
  "endpoints": [
    {
      "type": "easytier",
      "tag": "easytier-ep",
      "network_name": "my-network",
      "network_secret": "my-secret",
      "hostname": "laptop",
      "address": "10.144.144.2/24",
      "peers": ["tcp://public.easytier.cn:11010"]
    }
  ],
  "route": {
    "rules": [
      { "preferred_by": "easytier-ep", "outbound": "easytier-ep" }
    ],
    "default_domain_resolver": "local"
  }
}
```

完整字段说明参见 [EasyTier 端点](./docs/configuration/endpoint/easytier.zh.md)与 [EasyTier DNS 服务器](./docs/configuration/dns/server/easytier.zh.md)。

## eBPF 入站

`ebpf` 入站无需创建 TUN 设备，即可将本机或下游设备的 TCP / UDP 流量透明导入 sing-box 路由。该入站源自 reF1nd，本分支改用 [MiChongs/sing-ebpf](https://github.com/MiChongs/sing-ebpf)（当前版本 v0.1.0-alpha.17）并同步维护集成代码。运行时为纯 Go 实现，使用 `with_ebpf` 构建时不需要 cgo 或 Android NDK。

| 拦截范围 | 数据面 | 工作方式 |
|---|---|---|
| `local`（本机） | `cgroup`（默认） | 通过 cgroup v2 钩子改写本机连接的目标地址，不挂载网卡 |
| `local`（本机） | `tc` | 在默认网卡出口挂载 TC 程序，经由 veth 投递 |
| `shared`（下游设备） | `packet_rewrite`（默认） | 在下游网卡入口改写请求、出口还原响应，仅支持以太网 |
| `shared`（下游设备） | `socket_assign` | 将数据包分配至透明监听套接字，支持原始 IP、PPP、SLIP 及 IPIP / SIT / GRE 链路 |

- sing-box 自身的套接字通过 socket cookie 排除在本机拦截之外。
- 在 Android 15 及以上版本中，入站运行期间替换 netd 在 cgroup v2 根节点挂载的占位程序，停止时恢复原状。
- 支持按 UID、Android 用户、应用包名、源地址、MAC 地址、目标端口及规则集过滤流量。
- `sing-box tools ebpf status` 可在不挂载任何程序的情况下检查内核支持情况。

运行要求：Linux 或 Android 系统，内核启用 BPF 相关选项，`cgroup` 数据面需挂载 cgroup v2。建议以 root 权限运行，或至少具备 `CAP_NET_ADMIN` 与 `CAP_BPF` 权限。

```json
{
  "inbounds": [
    {
      "type": "ebpf",
      "tag": "ebpf-in",
      "local": {
        "enabled": true,
        "data_plane": "cgroup",
        "bypass_private_address": true
      }
    }
  ]
}
```

完整说明参见 [eBPF 入站](./docs/configuration/inbound/ebpf.zh.md)、[内核要求](./docs/manual/misc/ebpf-kernel-requirements.zh.md)与[故障排查](./docs/manual/misc/ebpf-troubleshooting.zh.md)。

## Clash API 扩展

### 规则命中统计

与 mihomo 一致，`GET /rules` 返回的每条规则均包含 `extra` 字段：

| 字段 | 说明 |
|---|---|
| `disabled` | 规则是否已禁用 |
| `hitCount` / `hitAt` | 命中次数与最近命中时间 |
| `missCount` / `missAt` | 未命中次数与最近未命中时间 |

规则列表依次包含 DNS 规则与路由规则，`index` 为规则在合并列表中的位置。`PATCH /rules/disable` 按索引批量启用或禁用规则，请求体为索引到布尔值的映射，例如 `{"0": true, "5": false}`，成功时返回 204。

统计仅计入顶层规则，已禁用的规则及位于首条终止规则之后的规则不参与计数。统计数据保存在内存中，重启或重新加载配置后清零。

### Smart 管理接口

| 接口 | 说明 |
|---|---|
| `DELETE /proxies/{name}` | 清除手动指定的节点 |
| `PATCH /proxies/{name}` | 与 `PUT /proxies/{name}` 相同 |
| `GET` / `DELETE /proxies/{name}/weights` | 查询或清除 Smart 组的节点权重 |
| `GET /smart/weights` | 查询全部 Smart 组的节点权重 |
| `GET /smart/groups` | 列出 Smart 组 |
| `GET /smart/groups/{name}/diag` | 获取 Smart 组诊断信息 |
| `POST /smart/groups/{name}/block/{node}` | 屏蔽指定节点 |
| `PUT /smart/groups/{name}/algorithm` | 修改选路算法 |
| `POST /smart/groups/{name}/recompute` | 重新计算节点评分 |
| `POST /smart/groups/{name}/clear-selection` | 清除已记录的节点选择 |
| `POST` / `DELETE /cache/smart/flush[/{name}]` | 清除全部或指定 Smart 组的缓存 |
| `DELETE /connections/smart/{id}` | 关闭连接并屏蔽其所用节点 |

接口说明参见 [Clash API](./docs/configuration/experimental/clash-api.zh.md)。

## 其他改进

- **URLTest 健康检查**：每个检查周期优先探测热点节点（手动指定的节点、当前选择的节点及延迟最低的 4 个节点）与尚未探测的节点，其余节点按探测时间先后轮流检查。持续失败的节点按 1、2、4、8 个周期退避，网络变化时重置。当前选择的节点在连续 2 次探测失败或 5 次拨号失败后才会更换。
- **缓存一致性**：规则集与订阅 Provider 的缓存记录与磁盘文件不一致时，直接加载磁盘文件，不再重新下载。远程规则集的下载体积上限为 50 MiB。
- **订阅解析**：支持 XHTTP 配置与 VLESS Encryption；正确解析 ECH 配置中的 `query-server-name`；修复 VMess `cipher: auto` 在 TLS 下被转换为 `zero` 的问题。
- **网络切换**：尚未获取默认网卡时由内核选择路由；网络切换期间的不可达错误降为 Debug 级别，且每秒至多记录一次。
- **日志**：没有日志订阅者时，不再格式化超出日志级别的条目。
- **配置语法预校验**：命令行程序在解析配置前进行轻量语法检查，可识别 `//`、`#` 与 `/* */` 注释。未闭合的字符串、未闭合的块注释以及多余的 `}` 或 `]` 将报告行号与列号，文件末尾未闭合的括号将报告缺失数量。此项检查用于避免上游 JSON 注释解析器在遇到格式错误的配置时持续占用内存直至进程被终止。

## 继承自 reF1nd 的功能

- **订阅 Provider**：支持本地与远程订阅，可解析 Clash、sing-box、SIP008 及分享链接格式。远程订阅启动时优先加载缓存，拉取失败不影响启动，并支持 ETag 条件请求。订阅节点的标签为 `<provider>/<tag>`，重复标签自动追加序号。参见 [Provider 文档](./docs/configuration/provider/index.zh.md)。
- **URLTest 故障转移**：`urltest` 出站组的 `fallback` 选项按配置顺序选择第一个可用且延迟不超过 `max_delay` 的节点；所有已测试节点的延迟均超过 `max_delay` 时，选择其中延迟最低的节点。手动指定的节点优先于故障转移逻辑。

  ```json
  {
    "type": "urltest",
    "tag": "fallback",
    "outbounds": ["A", "B", "C"],
    "fallback": {
      "enabled": true,
      "max_delay": "200ms"
    }
  }
  ```

- **`loadbalance` 出站组**：支持 `round-robin`（默认）、`consistent-hashing` 与 `sticky-sessions` 策略。参见 [loadbalance 文档](./docs/configuration/outbound/loadbalance.zh.md)。
- **`pass` 出站**：路由规则指向 `pass`（或当前选择为 `pass` 的 `selector`）时，跳过该规则并继续匹配后续规则。
- **入站 TLS**：`server_names` 支持配置多个服务器名称；启用 `reject_unknown_sni` 后，SNI 既不匹配 `server_name` / `server_names`，也不在证书覆盖范围内的连接将被拒绝。
- **TCP Keep-Alive**：入站与出站均可独立配置 `tcp_keep_alive`、`tcp_keep_alive_interval`、`tcp_keep_alive_count` 与 `disable_tcp_keep_alive`。
- **DNS 缓存**：新增 `round_robin_cache`、`min_cache_ttl` 与 `max_cache_ttl` 选项。
- **TUN**：新增 `auto_redirect_disable_mark_mode` 选项。
- **Clash API**：`/providers/proxies` 与 `/providers/rules` 提供完整实现；`PUT /rules/{uuid}` 用于启用或禁用单条规则。

## 发布产物

推送 `v*` 标签或手动触发 `xiaobaf14g-release.yml` 工作流后，将构建全部产物并发布至 [Releases](https://github.com/MiChongs/sing-box/releases)。版本号格式为 `<上游版本>-xiaobaf14g.<序号>`（例如 `1.15.0-alpha.10-xiaobaf14g.1`），包含 `-alpha`、`-beta` 或 `-rc` 的版本标记为预发布版本。

命令行程序的文件名格式为 `sing-box-<版本>-<系统>-<架构>[<后缀>].tar.gz`。

| 系统 | 架构 |
|---|---|
| Windows | `amd64`、`amd64-v3`、`amd64-v4`、`arm64`、`386` |
| Linux | `amd64`、`amd64-v3-glibc`、`arm64`、`arm64-musl`、`386`、`arm-v7`、`mipsle-softfloat`、`mips64le-softfloat`、`riscv64`、`loong64` |
| macOS | `amd64`、`arm64` |
| FreeBSD | `amd64`、`arm64` |
| Android | `arm64-v8a` |

| 后缀 | 说明 |
|---|---|
| `-v3` / `-v4` | 以 `GOAMD64=v3` / `GOAMD64=v4` 编译，分别要求 x86-64-v3（Haswell 及以上）与 x86-64-v4（支持 AVX-512）处理器 |
| `-v3-glibc` | 以 `GOAMD64=v3` 编译并启用 CGO，动态链接 glibc |
| `-musl` | 启用 CGO，基于 musl 完全静态链接 |
| `-ebpf` | 额外启用 `with_ebpf`，提供于全部 Linux 目标及 Android |
| `-easytier` | 额外启用 `with_easytier`，实验性构建，提供于 Windows、Linux、macOS 的 amd64 与 arm64 以及 Android |
| `-ebpf-easytier` | 同时启用 `with_ebpf` 与 `with_easytier`，实验性构建，仅提供于 Android |

桌面平台的命令行程序不包含 NaiveProxy 出站（`with_naive_outbound`）。每次发布同时附带 `SHA256SUMS` 校验文件。

## 图形客户端

图形客户端基于 reF1nd 客户端维护，与命令行程序使用同一提交的内核构建，版本号保持一致。

| 客户端 | 平台 | 源码仓库 | 安装包 |
|---|---|---|---|
| SFA | Android | [MiChongs/sing-box-for-android](https://github.com/MiChongs/sing-box-for-android)（`xiaobaf14g-testing`） | APK：标准版（Android 7.0 及以上）、legacy 版（Android 5.0 及以上） |
| SFW | Windows x64 / x86 / arm64 | [MiChongs/sing-box-for-desktop](https://github.com/MiChongs/sing-box-for-desktop)（`xiaobaf14g-dev`） | `.exe` 安装程序 |
| SFL | Linux x64 / arm64 / armv7l | [MiChongs/sing-box-for-desktop](https://github.com/MiChongs/sing-box-for-desktop)（`xiaobaf14g-dev`） | `.deb`、`.rpm`、`.pkg.tar.zst` |

签名说明：

- SFA 使用发布密钥签名，应用包名为 `io.reF1nd.sfa`。
- SFW 使用自签名代码签名证书，安装时 Windows SmartScreen 将提示未知发布者；应用内更新要求新旧版本使用同一证书签名。
- SFL 的 `.deb` 与 `.rpm` 安装包使用 GPG 签名，公钥 `SFL-signing-key.asc` 随 Release 发布，可通过 `rpm --import` 或 `debsig-verify` 校验；`.pkg.tar.zst` 安装包未签名。

## 从源码构建

发布构建当前使用 Go 1.27.1，构建标记与链接器参数分别维护在 `release/DEFAULT_BUILD_TAGS_*` 与 `release/LDFLAGS` 中。以 Linux、macOS 或 FreeBSD 为目标时，可使用以下命令构建：

```bash
go build -trimpath \
  -tags "$(cat release/DEFAULT_BUILD_TAGS_OTHERS)" \
  -ldflags "-s -w -buildid= $(cat release/LDFLAGS)" \
  ./cmd/sing-box
```

- 以 Windows 为目标时，改用 `release/DEFAULT_BUILD_TAGS_WINDOWS`，并移除其中的 `with_naive_outbound`。
- 在标记列表末尾追加 `,with_ebpf`（仅 Linux 与 Android）或 `,with_easytier`，即可启用对应功能。
- 通过 `-ldflags "-X github.com/sagernet/sing-box/constant.Version=<版本>"` 写入版本号。
- 以 `amd64` 为目标时，可设置 `GOAMD64=v3` 或 `GOAMD64=v4` 构建针对新型处理器优化的版本。

仓库附带的 `build-all.sh` 以 `CGO_ENABLED=0` 并行交叉编译 15 个桌面目标，产物输出至 `dist/`。依赖 CGO 的目标（`linux-amd64-v3-glibc`、`linux-arm64-musl`）以及 Android 与图形客户端仅在 CI 中构建。

## 文档

- 上游文档：<https://sing-box.sagernet.org>
- Smart 出站组文档站：<https://michongs.github.io/sing-box/>
- 本仓库扩展功能文档：
  - [订阅 Provider](./docs/configuration/provider/index.zh.md)（[English](./docs/configuration/provider/index.md)）
  - [EasyTier 端点](./docs/configuration/endpoint/easytier.zh.md)（[English](./docs/configuration/endpoint/easytier.md)）
  - [EasyTier DNS 服务器](./docs/configuration/dns/server/easytier.zh.md)（[English](./docs/configuration/dns/server/easytier.md)）
  - [eBPF 入站](./docs/configuration/inbound/ebpf.zh.md)（[English](./docs/configuration/inbound/ebpf.md)）
  - [URLTest](./docs/configuration/outbound/urltest.zh.md)（[English](./docs/configuration/outbound/urltest.md)）
  - [Clash API](./docs/configuration/experimental/clash-api.zh.md)（[English](./docs/configuration/experimental/clash-api.md)）
  - [从源码构建](./docs/installation/build-from-source.zh.md)（[English](./docs/installation/build-from-source.md)）

## 许可证

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```
