# sing-box (xiaobaf14g)

[![Latest Release](https://img.shields.io/github/v/release/MiChongs/sing-box?include_prereleases&sort=semver)](https://github.com/MiChongs/sing-box/releases)
[![Release Workflow](https://github.com/MiChongs/sing-box/actions/workflows/xiaobaf14g-release.yml/badge.svg?branch=xiaobaf14g-testing)](https://github.com/MiChongs/sing-box/actions/workflows/xiaobaf14g-release.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/MiChongs/sing-box?filename=go.mod)](go.mod)
[![License](https://img.shields.io/github/license/MiChongs/sing-box)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/MiChongs/sing-box/xiaobaf14g-testing)](https://github.com/MiChongs/sing-box/commits/xiaobaf14g-testing)
[![Code Size](https://img.shields.io/github/languages/code-size/MiChongs/sing-box)](https://github.com/MiChongs/sing-box)
[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

本仓库基于 [reF1nd/sing-box](https://github.com/reF1nd/sing-box)（其上游为 [SagerNet/sing-box](https://github.com/SagerNet/sing-box)）维护，目标是把 Smart 调度、XHTTP 传输、订阅与规则集的容错与性能改造，整合在一份可在 Windows / Linux / Android / Darwin 编译落地的发行物里。

发布产物随 `xiaobaf14g-release.yml` 工作流构建，命名后缀固定 `xiaobaf14g`。

## 与上游的主要差异

### Smart 出站组

- 基于 LightGBM 模型 + 在线 EWMA / t-digest 评分的节点选择，权重数据持久化到磁盘
- 支持 sticky session、断点恢复、人工 pin、节点 priority、anomaly 抑制、watchdog
- 网络切换 / 中断时引入 pool 背压封顶 + storm 闸门 + 缓存清理，防止内存膨胀
- 故障节点 markDead、并发 hedged dial、单节点恢复路径并行化
- 可选 `lightgbm.url` / `auto_update` / `update_interval` / `model_path`，权重收集器路径可配置

### XHTTP 传输（v2rayxhttp）

- 客户端按 XTLS/Xray + mihomo 协议规范重写
- 接入 quic-go，完整支持 HTTP/3 传输（`alpn: ["h3"]`）
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

- 远端订阅 60s 超时 + 50 MiB 响应体封顶 + `LimitReader` 防止恶意服务端拉爆内存
- 拉取失败 60s 快速重试，指数退避（封顶 30 min），±20% 抖动，启动期 2s jitter 错峰
- 拉取失败时不阻塞启动，沿用本地缓存继续运行
- 订阅刷新原子化、并发合并、内容 hash 短路；移除 STW GC 与误杀连接池
- detour tag 自动加 provider 前缀，重复出站 tag 自动改名

### 规则集 / Rule Set

- 缓存校验失败时清空 `cache.db` 中旧脏数据，避免 IP-only 旧缓存被新 DNS 校验拒绝后反复炸进程
- 缓存加载失败时容错启动，不再阻塞 sing-box 进程
- 拉取链路同样有超时 + 体积封顶
- `rule-provider` 接入 clash-api，支持远端规则集 `path` 字段

### DNS

- 新增 TCP / TLS pipeline（RFC 9210），同一连接连发多查询不等响应
- TCP 服务端复用支持 `reuse`，pipeline 启用时强制开启
- `round_robin_cache`、`min_cache_ttl`、`max_cache_ttl`
- DNS 规则评估链路对 `respond` action 的 `evaluatedResponse` 严格性更高，未先行 `evaluate` 直接报错
- 启动 check / run 路径修复 `rawRules` 切片复用导致的引用残留

### 路由 / TUN

- 切网过渡期消除 "no route to internet" + ENETUNREACH 刷屏，事件驱动 + 内核 FIB 兜底
- `auto_redirect_disable_mark_mode` 选项
- 切网防御与 HintUnreachable 钩子保留在 `route/network.go`

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

- `cmd/sing-box`：在调用 sing 库 JSON 解析器之前做一次轻量状态机预校验（注释剥离 + 引号 / 括号配平），未闭合字符串 / 块注释 / 括号失衡时返回精确行列号错误。规避上游 comment parser 在 malformed config 上死循环 OOM。

## 构建

仓库自带 `xiaobaf14g-release.yml`，推 `v*` tag 即触发四平台构建。手动构建：

```bash
TAGS="with_quic with_grpc with_dhcp with_wireguard with_utls with_acme with_clash_api with_v2ray_api with_gvisor with_xhttp"

go build -tags "$TAGS" -trimpath \
  -ldflags "-s -w -X internal/godebug.defaultGODEBUG=multipathtcp=0 -checklinkname=0 -buildid=" \
  ./cmd/sing-box
```

要求 Go 版本以 `go.mod` 中的 `go` 行为准。

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
