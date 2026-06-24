# sing-box (xiaobaf14g)

[![Latest Release](https://img.shields.io/github/v/release/MiChongs/sing-box?include_prereleases&sort=semver)](https://github.com/MiChongs/sing-box/releases)
[![Release Workflow](https://github.com/MiChongs/sing-box/actions/workflows/xiaobaf14g-release.yml/badge.svg?branch=xiaobaf14g-testing)](https://github.com/MiChongs/sing-box/actions/workflows/xiaobaf14g-release.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/MiChongs/sing-box?filename=go.mod)](go.mod)
[![License](https://img.shields.io/github/license/MiChongs/sing-box)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/MiChongs/sing-box/xiaobaf14g-testing)](https://github.com/MiChongs/sing-box/commits/xiaobaf14g-testing)
[![Code Size](https://img.shields.io/github/languages/code-size/MiChongs/sing-box)](https://github.com/MiChongs/sing-box)

本仓库 fork 自 [reF1nd/sing-box](https://github.com/reF1nd/sing-box)，再上游是 [SagerNet/sing-box](https://github.com/SagerNet/sing-box)。改动集中在 Smart 出站组、XHTTP 传输，以及订阅 / 规则集的容错和性能。Windows、Linux、macOS、Android 都能编译。

推 `v*` tag 触发 `xiaobaf14g-release.yml`，产物文件名带 `xiaobaf14g` 后缀。

## 与上游的主要差异

### Smart 出站组

基于 LightGBM 模型加在线 EWMA / t-digest 评分选节点，权重持久化到磁盘。

- sticky session、断点恢复、人工 pin、节点 priority、anomaly 抑制、watchdog
- 网络切换或中断时给连接池加背压封顶和 storm 闸门，清理缓存防止内存炸开
- 故障节点标记 dead，恢复路径并发 hedged dial
- 可选 `lightgbm.url` / `auto_update` / `update_interval` / `model_path`，权重收集器路径可配置

### XHTTP 传输 (v2rayxhttp)

完整对齐 XTLS/Xray-core v26.3.27 (PR#5414 / #5711 / #5720 / #5802 / #5803 / #5689)。同时支持 inbound (服务端) 和 outbound (客户端)。

**三种 mode**：`stream-one` (H2 全双工单流) / `stream-up` (POST 上行 + GET SSE 下行) / `packet-up` (每片 POST + GET SSE，兼容性最好)

**反 CDN 探测扩展 (PR#5414)**：
- `x_padding_obfs_mode`：把 padding 改名 / 改位置 / 改字符集，绕开按 `x_padding=XXX...` 匹配的 CDN 规则
- `uplink_http_method`：切换上行方法 (PUT / PATCH / GET)，绕开禁 POST 的 CDN
- `session_placement` / `seq_placement`：把 session UUID 和 seq 从 path 移到 header / cookie / query
- `uplink_data_placement`：上行数据走 header / cookie 切片 (GET-only CDN 兜底)
- `x_padding_method`：`tokenish` 模式用 base62 随机字符 + huffman 长度修正

**浏览器伪装 (PR#5802)**：`user_agent` 支持 `chrome` / `firefox` / `edge` / `golang`，配合 GREASE Sec-CH-UA 客户端提示。

**HTTP/3 拥塞控制 (PR#5711)**：`quic_congestion` 支持 `bbr` (默认) / `reno` / `force-brutal`。

**H1 手写序列化 + 连接池 (PR#5803)**：ALPN=`http/1.1` 时 packet-up 用预序列化 + sync.Pool 连接复用，支持安全重试。

#### 服务端示例 (inbound)

```jsonc
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
        "xhttp_settings": {
          "path": "/your-path",
          "host": "example.com",
          "mode": "auto"
        }
      }
    }
  ]
}
```

#### 客户端示例 (outbound)：基础

```jsonc
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
        "xhttp_settings": {
          "path": "/your-path",
          "host": "example.com",
          "mode": "auto"
        }
      }
    }
  ]
}
```

#### 客户端示例：HTTP/3 + BBR

```jsonc
{
  "type": "vless",
  "tag": "proxy-h3",
  "server": "example.com",
  "server_port": 443,
  "uuid": "00000000-0000-0000-0000-000000000000",
  "tls": { "enabled": true, "server_name": "example.com", "alpn": ["h3"] },
  "transport": {
    "type": "xhttp",
    "xhttp_settings": {
      "path": "/your-path",
      "host": "example.com",
      "mode": "auto",
      "quic_congestion": "bbr"
    }
  }
}
```

#### 客户端示例：绕 CDN 检测 (全混淆)

```jsonc
{
  "type": "vless",
  "tag": "proxy-obfs",
  "server": "cdn.example.com",
  "server_port": 443,
  "uuid": "00000000-0000-0000-0000-000000000000",
  "tls": { "enabled": true, "server_name": "cdn.example.com" },
  "transport": {
    "type": "xhttp",
    "xhttp_settings": {
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
}
```

#### 客户端示例：GET-only CDN (上行数据走 header)

```jsonc
{
  "type": "vless",
  "tag": "proxy-get-only",
  "server": "cdn.example.com",
  "server_port": 443,
  "uuid": "00000000-0000-0000-0000-000000000000",
  "tls": { "enabled": true, "server_name": "cdn.example.com" },
  "transport": {
    "type": "xhttp",
    "xhttp_settings": {
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
}
```

#### `xhttp_settings` 完整字段参考

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `host` | string / list | server addr | Host header，多值时随机轮选 |
| `path` | string | `/` | URL 路径前缀 |
| `headers` | map | | 额外请求头 |
| `mode` | string | `auto` | `auto` / `stream-one` / `stream-up` / `packet-up` |
| `no_sse_header` | bool | false | stream-up 下行不用 `text/event-stream` |
| `sc_max_each_post_bytes` | int | 1000000 | packet-up 单次 POST 最大字节 |
| `sc_min_posts_interval_ms` | int | 30 | packet-up POST 最小间隔 |
| `sc_max_buffered_posts` | int | 30 | 服务端乱序缓冲上限 |
| `x_padding_bytes` | string | `100-1000` | padding 长度范围 |
| `x_padding_obfs_mode` | bool | false | 启用 padding 混淆 |
| `x_padding_key` | string | `x_padding` | padding 字段名 |
| `x_padding_header` | string | `X-Padding` | 承载 padding 的 header |
| `x_padding_placement` | string | `queryInHeader` | `queryInHeader` / `cookie` / `header` / `query` |
| `x_padding_method` | string | `repeat-x` | `repeat-x` / `tokenish` |
| `uplink_http_method` | string | `POST` | `POST` / `PUT` / `PATCH` / `GET` |
| `session_placement` | string | `path` | `path` / `cookie` / `header` / `query` |
| `session_key` | string | 自动 | 默认 `x_session` / `X-Session` |
| `seq_placement` | string | `path` | `path` / `cookie` / `header` / `query` |
| `seq_key` | string | 自动 | 默认 `x_seq` / `X-Seq` |
| `uplink_data_placement` | string | `auto` | `auto` / `body` / `cookie` / `header` |
| `uplink_data_key` | string | 自动 | 默认 `x_data` / `X-Data` |
| `uplink_chunk_size` | string | 自动 | `min-max` 范围，cookie 默认 2048-3072，header 3000-4000 |
| `user_agent` | string | `chrome` | `chrome` / `firefox` / `edge` / `golang` |
| `no_grpc_header` | bool | false | 不设 `Content-Type: application/grpc` |
| `server_max_header_bytes` | int | 8192 | 服务端 `http.Server.MaxHeaderBytes` |
| `quic_congestion` | string | `bbr` | `bbr` / `reno` / `force-brutal` (仅 H3) |
| `quic_up` | uint64 | 0 | `force-brutal` 带宽 bytes/s，最小 65536 |

### URLTest Fallback

按可用性 + 顺序选出站，可选 `max_delay`：

```jsonc
{
  "tag": "fallback",
  "type": "urltest",
  "outbounds": ["A", "B", "C"],
  "fallback": {
    "enabled": true,
    "max_delay": "200ms"
  }
}
```

A、B、C 都可用时选 A；A 挂了选 B；以此类推。设了 `max_delay` 时超时节点被淘汰；如果全部不可用，就在被淘汰节点里选延迟最低的。

### 订阅 Provider

- 远端订阅 60s 超时，响应体 50 MiB 封顶 (`LimitReader` 兜恶意服务端)
- 拉取失败 60s 快速重试，指数退避到 30 min 封顶，±20% 抖动，启动期额外加 2s 错峰
- 拉取失败不阻塞启动，沿用本地缓存继续跑
- 刷新做了原子化和并发合并，内容 hash 一致就短路；删掉原来的 STW GC 和误杀连接池
- detour tag 自动加 provider 前缀，重复出站 tag 自动改名

### 规则集 / Rule Set

- 缓存校验不过时清掉 `cache.db` 里的旧脏数据，避免 IP-only 旧缓存被新 DNS 校验拒掉后反复炸进程
- 缓存加载失败也能起来，不阻塞主进程
- 拉取链路同样有超时和体积封顶
- `rule-provider` 接入 clash-api，远端规则集支持 `path` 字段

### DNS

- TCP / TLS 加 pipeline (RFC 9210)，同一连接连发多个查询
- TCP 加 `reuse`，开 pipeline 时被强制打开
- 新增 `round_robin_cache`、`min_cache_ttl`、`max_cache_ttl`
- `respond` action 现在要求前面先有一次成功的 `evaluate`，否则直接报错
- 启动 check / run 路径修了 `rawRules` 切片复用导致的引用残留

### 路由 / TUN

- 切网过渡期不再刷 "no route to internet" 和 ENETUNREACH，改成事件驱动 + 内核 FIB 兜底
- 多了 `auto_redirect_disable_mark_mode` 选项
- 切网防御和 HintUnreachable 钩子在 `route/network.go`

### 入站 TLS `reject_unknown_sni`

```json
{
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-in",
      "tls": {
        "enabled": true,
        "server_name": "sekai.love",
        "certificate_path": "cert.pem",
        "key_path": "key.key",
        "reject_unknown_sni": true
      }
    },
    {
      "type": "anytls",
      "tag": "anytls-in",
      "tls": {
        "enabled": true,
        "server_names": ["sagernet.sekai.love", "sekai.love"],
        "certificate_path": "cert.pem",
        "key_path": "key.key",
        "reject_unknown_sni": true
      }
    }
  ]
}
```

SNI 既不匹配 `server_name` / `server_names`，也不在证书覆盖范围内，则拒绝连接。

### Dialer

```json
{
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct",
      "tcp_keep_alive": "5m",
      "tcp_keep_alive_interval": "75s",
      "tcp_keep_alive_count": 0,
      "disable_tcp_keep_alive": false
    }
  ]
}
```

四个 TCP keep-alive 选项可独立配置。

### 出站类型

- `loadbalance`：上游引入的轮询负载均衡
- `pass`：透传
- `urltest` 内嵌 fallback

### 命令行防御

`cmd/sing-box` 在交给 sing 库解析前会先跑一遍状态机预校验：剥注释、配平引号和括号。遇到未闭合字符串、未闭合块注释或括号失衡时直接返回带行列号的错误。上游的 comment parser 碰到 malformed config 会死循环吃满 3GB 才被 OOM kill，这一步把它拦下来。

## 构建

推 `v*` tag 触发 `xiaobaf14g-release.yml` 跑全平台构建。手动编译：

```bash
TAGS="with_gvisor with_quic with_dhcp with_wireguard with_utls with_acme with_clash_api with_tailscale with_xhttp with_cloudflared with_usbip"

go build -tags "$TAGS" -trimpath \
  -ldflags "-s -w -X internal/godebug.defaultGODEBUG=multipathtcp=0 -checklinkname=0 -buildid=" \
  ./cmd/sing-box
```

Go 版本看 `go.mod`。

仓库带 `build-all.sh`，本地并行编译 15 个 desktop 目标到 `dist/`。Windows / Linux / macOS 还可以加 `GOAMD64=v3` 或 `GOAMD64=v4` 编出高性能变体（Haswell+ / Skylake-X+）。

## 文档

- 上游文档：<https://sing-box.sagernet.org>
- Provider：[中文](./docs/configuration/provider/index.zh.md) ｜ [English](./docs/configuration/provider/index.md)

## License

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
