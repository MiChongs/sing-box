# sing-box 1.14.0-alpha.11-xiaobaf14g 更新日志

> **基线版本**：sing-box 1.14.0-alpha.11
> **Commit**：59fd85d2
> **发布日期**：2026-04-14
> **分发后缀**：`-xiaobaf14g`（区别于 upstream 与其他 fork）

---

## 🎯 一句话总结

本次更新把 **mihomo Smart 策略组完整移植到 sing-box**，新增 **LightGBM 机器学习节点评估**、**全局 GeoX 数据库管理**、**DNS 乐观缓存持久化** 三大能力，并修复了 URLTest/LoadBalance 偶发断网、macOS 跨编译失败等 4 处遗留问题。

---

## ✨ 新增功能

### 1. Smart 策略组（`type: "smart"`）

全新类型的出站组，按 **目标域名 + ASN** 学习每个节点的历史表现，自动选择最合适的节点。核心特性：

- **并行竞速拨号**：对前 3 个候选节点同时发起连接，首个成功者胜出；失败节点自动降级
- **历史权重学习**：按「成功率 × 连接时长 × 延迟 × 流量 × 场景」六维打分，数据落盘到 `cache.db`（重启保留）
- **场景识别**：自动分类 `interactive`（游戏/互动）、`streaming`（流媒体）、`transfer`（大流量）、`web`，不同场景采用不同权重系数
- **ASN 感知路由**：同一节点对不同 ASN 的目标记录独立权重（CDN ASN 除外）
- **节点降级保护**：连续失败会线性降权，超阈值屏蔽 30+ 分钟后自动恢复
- **Prefetch 预计算**：周期性为热门目标预算最优节点列表，首包延迟降至接近零
- **Policy Priority**：支持 `"香港:1.5;日本:1.2;美国:0.7"` 按节点名加权
- **Now() 显示真实节点**：Clash Dashboard 显示 Smart 当前最近使用的节点 tag（不再是固定占位符）

**最小配置**：
```json
{ "type": "smart", "tag": "🚀 Smart", "outbounds": ["A", "B", "C"] }
```

**完整字段**：`url` · `interval` · `policy_priority` · `use_asn` · `asn_database` · `disable_udp` · `interrupt_exist_connections` · `use_lightgbm` · `collect_data` · `sample_rate` · 以及继承自 GroupCommonOption 的 `providers` · `include` · `exclude` · `use_all_providers`

---

### 2. LightGBM 机器学习节点评估

> **放在 `experimental.smart` 顶层段**，多个 Smart 组共享一个模型文件。

```json
"experimental": {
  "smart": {
    "lightgbm": {
      "url": "https://github.com/vernesong/mihomo/releases/download/LightGBM-Model/Model-large.bin",
      "auto_update": true,
      "update_interval": "72h",
      "model_path": "smart_lgbm_model.bin",
      "download_detour": "direct"
    },
    "collector": {
      "size_limit_mb": 100,
      "path": "smart_weight_data.csv"
    }
  }
}
```

特性：

- **与 mihomo 二进制兼容**：可直接下载 mihomo 官方发布的 `.bin`，27 维特征工程完全对齐（54 ASN 编码 / 31 国家码 / 30+ 端口分类 / 5 组关键字词表全部 byte-identical）
- **纯 Go 推理引擎**：使用 `github.com/dmitryikh/leaves`，**无 CGO 依赖**，Android/iOS 直接可编译
- **自动下载 + 热重载**：ticker 到期后 HTTP 条件请求（Etag/Last-Modified），有新版本则原子替换 + 读写锁下热切，不中断推理
- **fallback 链**：模型未就绪 / 推理 panic / NaN → 自动回退到传统 `CalculateWeight`，业务永不中断
- **训练样本采集**（可选）：`collect_data: true` 组会把每次评估的 27 维特征+元数据写入共享 CSV，用于离线训练

组级开关（per-group）：
```json
{ "type": "smart", "use_lightgbm": true, "collect_data": false, "sample_rate": 1.0 }
```

---

### 3. 全局 GeoX 数据库管理（`experimental.geox`）

统一管理 geoip.dat / geosite.dat / country.mmdb / GeoLite2-ASN.mmdb 四个文件的下载与更新。当前主要消费方是 Smart 组的 `use_asn`，但四个文件都会被下载供外部工具或未来扩展使用。

```json
"experimental": {
  "geox": {
    "enabled": true,
    "auto_update": true,
    "update_interval": "24h",
    "download_detour": "direct",
    "url": {
      "geoip":   "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
      "geosite": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
      "mmdb":    "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
      "asn":     "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb"
    }
  }
}
```

**Smart 组 ASN 回退链**：

1. 组内显式填 `asn_database: "/path/to/mmdb"` → 优先使用
2. 未填且 `use_asn: true` → 自动使用 `geox.url.asn` 下载的本地文件
3. 都没有 → 打 warn 日志，ASN 功能静默关闭（不阻止启动）

**仅下载你配置的 URL**：只关心 ASN 时只配 `url.asn` 即可，其他三项不会触发任何网络请求。

---

### 4. DNS 乐观缓存持久化

DNS 服务器级别的乐观缓存（`optimistic: { enabled: true, timeout: "60s" }`）结合 `cache_file.store_dns: true`，实现：

- **TTL 过期瞬间客户端零等待**：返回旧记录，同时后台刷新
- **刷新失败宽限 60 秒**：期间继续用旧记录
- **重启后立刻可用**：`store_dns` 把 DNS 缓存落盘到 `cache.db`，冷启动后首次 DNS 查询无需等待上游

```json
"dns": {
  "servers": [{
    "type": "https",
    "tag": "dns-remote",
    "server": "1.1.1.1",
    "optimistic": { "enabled": true, "timeout": "60s" },
    "cache_capacity": 4096
  }]
},
"experimental": {
  "cache_file": { "enabled": true, "store_dns": true }
}
```

---

### 5. 共享资源下载器（`common/assetdl`）

新增通用资源下载框架（LightGBM / GeoX 都复用）：

- **条件请求**：支持 Etag 与 Last-Modified，服务端 304 时零流量
- **原子替换**：`.tmp → rename` 两步，下载失败不会破坏已有文件
- **Download Detour**：`download_detour: "🚀 Smart"` 通过 outbound tag 走代理；为空或找不到时自动降级到直连，不阻塞启动
- **失败容错**：单次刷新失败仅打 warn 日志，下次 ticker 重试，不影响已有数据

---

## 🔧 优化改进

### URLTest / LoadBalance 稳定性（修复多处断网原因）

历史版本在 URLTest/LoadBalance 策略组下会出现「每隔几分钟断一次网」的情况。本次彻底修复 **4 个根因**：

| 问题 | 原行为 | 新行为 |
|------|--------|--------|
| 健康检查 3 次失败 → 删除 history | 健康节点在测试 URL 暂时不通时被判「死亡」，触发切换 + Interrupt 杀连接 | 失败只计数记日志，history 保留；节点业务流量仍走老路 |
| `performUpdateCheck` 每次选中变化就 Interrupt | 延迟抖动超 tolerance 就杀所有连接 | 仅当用户显式 `interrupt_exist_connections: true` 时中断；老连接自然走完 |
| `Select()` 在 history 缺失时立即切换 | 触发 Interrupt 雪崩 | 给 current 节点 grace period：仍在 outbound 列表且 dial 失败 < 5 次 → 保留 |
| Dial 失败无反馈机制 | ISP 临时屏蔽节点 IP 要等下一 interval | 累计 5 次 dial 失败自动触发一次紧急健康检查 |

**迁移建议**：保持 `interrupt_exist_connections: false`（默认值）即可享受修复。如果你之前显式设为 `true` 试图规避断流，现在可以移除这个字段。

---

## 🐛 问题修复

### 构建系统

- **版本后缀保留**：`cmd/internal/build_shared/tag.go` 的 `ReadTag()` 经过 `badversion.Parse+String` 会剥离 `-xiaobaf14g` 后缀（导致二进制内嵌版本丢失 fork 标识）。改为直接用 `currentTagRev[1:]+"-"+shortCommit`，现在版本字符串为 `1.14.0-alpha.11-xiaobaf14g-59fd85d2`
- **darwin nocgo 编译**：`dns/transport/local/local_darwin.go` 的 `Transport` 类型在 `CGO_ENABLED=0` 下缺少 `Exchange()` 方法（upstream 预存 bug），导致 Windows 交叉编译 macOS 失败。修复：`local_shared.go` build tag 放宽为 `!darwin || !cgo`，新增 `local_darwin_nocgo.go` 提供 cgo-free 的 `Exchange` 实现

### Clash API

- Smart 组 `now` 字段现在返回真实节点 tag（而非 `"Smart - Select"`），与 Clash Dashboard 兼容
- 新增 Smart 专属字段：`testUrl` · `useASN` · `useLightGBM` · `collectData` · `lgbmModelAge`

---

## 📦 配置文件迁移提示

### 如果你从 upstream sing-box 1.12+ 升级

**无需改动**：所有新增配置字段都是可选的，不填完全按 upstream 默认行为。

### 如果你要启用 Smart 组

1. 在 `outbounds` 加一项 `{ "type": "smart", "tag": "🚀 Smart", "outbounds": [...] }`
2. 在 `route.final` 或规则里把流量指向这个 tag
3. （可选）在 `experimental.cache_file` 启用 `enabled: true` 开启持久化，让 Smart 权重数据跨重启保留

### 如果你要启用 LightGBM

1. 先启用 Smart 组（同上）
2. 在 `experimental.smart.lightgbm` 配置模型 URL 和下载选项
3. 在 Smart 组加 `"use_lightgbm": true`

### 如果你要启用全局 GeoX 自动下载

1. 配置 `experimental.geox.enabled: true` + `url.*` 填想下载的文件 URL
2. Smart 组的 `use_asn: true` 而不填 `asn_database` 即可自动用全局下载的 ASN mmdb

### 如果你从 mihomo 切换过来

mihomo 字段 → sing-box 字段对照：

| mihomo | sing-box（本版本） |
|--------|---------|
| `smart.uselightgbm: true` | 组内 `"use_lightgbm": true` |
| `smart.collectdata: true` | 组内 `"collect_data": true` |
| `smart.sample-rate: 0.5` | 组内 `"sample_rate": 0.5` |
| `smart.policy-priority: "..."` | 组内 `"policy_priority": "..."` |
| `smart.prefer-asn: true` | 组内 `"use_asn": true` |
| `lgbm-auto-update: true` | `experimental.smart.lightgbm.auto_update: true` |
| `lgbm-update-interval: 72` | `experimental.smart.lightgbm.update_interval: "72h"` |
| `lgbm-url: "..."` | `experimental.smart.lightgbm.url: "..."` |
| `geodata-mode: true` | `experimental.geox.enabled: true` |
| `geo-auto-update: true` | `experimental.geox.auto_update: true` |
| `geo-update-interval: 24` | `experimental.geox.update_interval: "24h"` |
| `geox-url.asn: "..."` | `experimental.geox.url.asn: "..."` |

---

## 🔨 构建变更

### 全功能 build tags（与 upstream 一致）

```
with_gvisor, with_quic, with_dhcp, with_wireguard, with_utls,
with_acme, with_clash_api, with_tailscale, with_ccm, with_ocm,
with_cloudflared, badlinkname, tfogo_checklinkname0
```

Android 额外加：`with_naive_outbound, netgo`

### 新依赖

- `github.com/dmitryikh/leaves`（纯 Go LightGBM 推理库，约 +300 KB 二进制体积）

### 二进制体积影响

在 `netgo` + trimpath + `-s -w` 构建下，相比相同 tags 的 upstream：
- Windows amd64：+约 800 KB
- Linux amd64：+约 800 KB
- Android arm64-v8a：+约 1.1 MB（含 leaves + smart + assetdl + geox 完整包）

### Android 打包约定

产物命名：`sing-box-<VERSION>-xiaobaf14g-android-<ABI>.7z`
压缩包内文件固定为 `sing-box`（无 ABI 后缀）
压缩：LZMA2 ultra（`-mx=9 -m0=lzma2:d=256m:fb=273 -ms=on -mmt=on`）

---

## 📋 已知行为（非 bug）

- **首次启动 10-30 秒内**：provider/ruleset/geox/lightgbm 并行下载，Smart 组在所有资源就绪前按传统算法工作，资源就绪后自动切换到 ML 路径
- **Smart 的 `now` 会不停变**：这是预期行为。Smart 按目标域名选节点，浏览不同站点时 `now` 自然变化
- **`experimental.geox` 下载的 geoip.dat / geosite.dat / country.mmdb**：当前只 ASN 文件被代码消费，其他三个下载到本地供用户手动使用或未来扩展
- **CSV 采集超 `size_limit_mb` 后静默停止**：不是挂了，是防止硬盘被撑爆；需要的话手动删文件或改大 limit 重启

---

## 📚 附录：完整配置示例

项目根目录新增 `example-config.json`，覆盖：

- 双订阅 provider（含 exclude 正则）
- 4 DNS 服务器（DoH×2 + local + fakeip）含乐观缓存
- TUN + Mixed 双入站
- Smart / URLTest / LoadBalance / Selector 全配齐
- 12 个远程 ruleset（AI/流媒体/广告/游戏/CN 全覆盖）
- experimental 全三件套：cache_file / smart / geox

`sing-box check -c example-config.json` 通过验证，可直接作为生产配置基础。

---

## ✅ 快速自检

启动后可运行以下命令确认功能正常：

```bash
# 版本（应含 -xiaobaf14g 后缀）
./sing-box version

# Smart 类型被识别
echo '{"outbounds":[{"type":"direct","tag":"A"},{"type":"smart","tag":"T","outbounds":["A"]}]}' > /tmp/t.json
./sing-box check -c /tmp/t.json

# Clash API 查看 Smart 状态（替换 secret 与 tag）
curl -s "http://127.0.0.1:9090/proxies/🚀%20Smart" \
  -H "Authorization: Bearer YOUR_SECRET" | jq \
  '{now, useLightGBM, useASN, lgbmModelAge}'
```

遇到问题按 "[我如何查看 Smart 是否成功]" 文档排查（或直接开 issue 附启动日志）。

---

## 🔗 相关链接

- 基线上游：https://github.com/SagerNet/sing-box/tree/dev-next
- 原始参考：https://github.com/MetaCubeX/mihomo
- LightGBM 模型下载：https://github.com/vernesong/mihomo/releases/tag/LightGBM-Model
- LightGBM 纯 Go 推理：https://github.com/dmitryikh/leaves
- Geo 数据库：https://github.com/MetaCubeX/meta-rules-dat
