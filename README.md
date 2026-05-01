# sing-box (xiaobaf14g)

[![Latest Release](https://img.shields.io/github/v/release/MiChongs/sing-box?include_prereleases&sort=semver)](https://github.com/MiChongs/sing-box/releases)
[![Release Workflow](https://github.com/MiChongs/sing-box/actions/workflows/xiaobaf14g-release.yml/badge.svg?branch=xiaobaf14g-testing)](https://github.com/MiChongs/sing-box/actions/workflows/xiaobaf14g-release.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/MiChongs/sing-box?filename=go.mod)](go.mod)
[![License](https://img.shields.io/github/license/MiChongs/sing-box)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/MiChongs/sing-box/xiaobaf14g-testing)](https://github.com/MiChongs/sing-box/commits/xiaobaf14g-testing)
[![Code Size](https://img.shields.io/github/languages/code-size/MiChongs/sing-box)](https://github.com/MiChongs/sing-box)
[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

本仓库 fork 自 [reF1nd/sing-box](https://github.com/reF1nd/sing-box)，再上游是 [SagerNet/sing-box](https://github.com/SagerNet/sing-box)。改动集中在 Smart 调度、XHTTP 传输、订阅与规则集的容错与性能；Windows、Linux、Android、Darwin 四个平台都能编译。

发布走 `xiaobaf14g-release.yml`，文件名后缀固定 `xiaobaf14g`。

## 与上游的主要差异

### Smart 出站组

- 基于 LightGBM 模型 + 在线 EWMA / t-digest 评分的节点选择，权重数据持久化到磁盘
- 支持 sticky session、断点恢复、人工 pin、节点 priority、anomaly 抑制、watchdog
- 网络切换或中断时给连接池加了背压封顶和 storm 闸门，并清理缓存，避免内存炸开
- 故障节点会被标记 dead；恢复路径并发 hedged dial
- 可选 `lightgbm.url` / `auto_update` / `update_interval` / `model_path`，权重收集器路径可配置

### XHTTP 传输（v2rayxhttp）

- 客户端按 XTLS/Xray + mihomo 协议规范重写
- 接入 quic-go，支持 HTTP/3（`alpn: ["h3"]`）
- 按 ALPN 派发底层 RoundTripper，避免 `http/1.1` 配置下整组节点 dial 失败
- 修复 `GotConn` 回调与错误路径 `close(chan)` 赛跑导致的 "send on closed channel" panic

### URLTest Fallback

按可用性 + 顺序选择出站，可选 `max_delay`：

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

- A、B、C 都可用时优选 A；A 不可用选 B；A、B 都不可用选 C；C 也不可用退回第一个出站
- 配置 `max_delay` 后超时节点被淘汰；若所有节点都不可用，则在被淘汰节点中选延迟最低的

### 订阅 Provider

- 远端订阅 60s 超时、响应体 50 MiB 封顶，用 `LimitReader` 兜住恶意服务端
- 拉取失败时 60s 快速重试，指数退避到 30 min 封顶，±20% 抖动，启动期再加 2s 错峰
- 拉取失败不阻塞启动，沿用本地缓存继续跑
- 刷新做了原子化和并发合并，内容 hash 一致就短路；删掉了原来的 STW GC 和误杀连接池
- detour tag 自动加 provider 前缀，重复出站 tag 自动改名

### 规则集 / Rule Set

- 缓存校验不过时主动清掉 `cache.db` 里的旧脏数据，避免 IP-only 旧缓存被新 DNS 校验拒掉后反复炸进程
- 缓存加载失败也能起来，不阻塞主进程
- 拉取链路同样有超时和体积封顶
- `rule-provider` 接入 clash-api，远端规则集支持 `path` 字段

### DNS

- TCP / TLS 加了 pipeline（RFC 9210），同一连接可以连发多个查询不用等响应
- TCP 多了 `reuse`，开 pipeline 时会被强制打开
- 新增 `round_robin_cache`、`min_cache_ttl`、`max_cache_ttl`
- `respond` action 现在要求前面先有过一次成功的 `evaluate`，否则直接报错
- 启动 check / run 路径修复 `rawRules` 切片复用导致的引用残留

### 路由 / TUN

- 切网过渡期不再刷 "no route to internet" 和 ENETUNREACH，改成事件驱动加内核 FIB 兜底
- 多了一个 `auto_redirect_disable_mark_mode` 选项
- 切网防御和 HintUnreachable 的钩子都在 `route/network.go`

### 入站 TLS

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

`reject_unknown_sni`：连接的 SNI 既不匹配 `server_name` / `server_names`，也不在证书覆盖范围内，则拒绝。

### Dialer 选项

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

### 出站类型

- `loadbalance`：上游引入的轮询负载均衡
- `pass`：透传
- `urltest` 内嵌 fallback

### 命令行防御

- `cmd/sing-box` 在交给 sing 库解析之前先跑一遍状态机预校验：剥注释、配平引号和括号。遇到未闭合字符串、未闭合块注释或括号失衡，直接返回带行列号的错误。原本上游的 comment parser 碰到 malformed config 会死循环吃满 3GB 内存才被杀，这一步把它拦在外面。

## 构建

推 `v*` tag 就会触发 `xiaobaf14g-release.yml` 跑四平台构建。手动编译：

```bash
TAGS="with_quic with_grpc with_dhcp with_wireguard with_utls with_acme with_clash_api with_v2ray_api with_gvisor with_xhttp"

go build -tags "$TAGS" -trimpath \
  -ldflags "-s -w -X internal/godebug.defaultGODEBUG=multipathtcp=0 -checklinkname=0 -buildid=" \
  ./cmd/sing-box
```

Go 版本看 `go.mod`。

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
