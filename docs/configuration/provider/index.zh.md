# 订阅

!!! quote "sing-box 1.14.0 中的更改"

    :material-plus: [http_client](#http_client)

    :material-delete-clock: [download_detour](#download_detour)

### 结构

订阅源列表。

=== "本地文件"

    ```json
    {
      "providers": [
        {
          "type": "local",
          "tag": "provider",
          "path": "provider.txt",
          "health_check": {
            "enabled": false,
            "url": "",
            "interval": "",
            "timeout": "",
            "udp": {}
          },
          "override_dialer": {},
          "override_tls": {},
          "override_anytls": {}
        }
      ]
    }
    ```

=== "远程文件"

    ```json
    {
      "providers": [
        {
          "type": "remote",
          "tag": "provider",
          "health_check": {
            "enabled": false,
            "url": "",
            "interval": "",
            "timeout": "",
            "udp": {}
          },
          "url": "",
          "path": "",
          "exclude": "",
          "include": "",
          "user_agent": "",
          "http_client": "", // or {}
          "update_interval": "",
          "override_dialer": {},
          "override_tls": {},

          "override_anytls": {},

          // Deprecated

          "download_detour": ""
        }
      ]
    }
    ```

=== "内联"

    ```json
    {
      "providers": [
        {
          "type": "inline",
          "tag": "provider",
          "health_check": {
            "enabled": false,
            "url": "",
            "interval": "",
            "timeout": "",
            "udp": {}
          },
          "outbounds": [],
          "endpoints": []
        }
      ]
    }
    ```

### 字段

#### type

==必填==

订阅源的类型。`local`、`remote` 或 `inline`。

#### tag

==必填==

订阅源的标签。

来自 `provider` 的节点 `node_name`，导入后的标签为 `provider/node_name`。

### 通用字段

#### health_check

健康检查配置。

##### health_check.enabled

是否启用健康检查。

##### health_check.url

健康检查的 URL。

##### health_check.interval

健康检查的时间间隔。最小为 `1m`，默认为 `10m`。

##### health_check.timeout

健康检查的超时时间。默认为 `3s`。

##### health_check.udp

在每轮健康检查中探测节点真实的 UDP 能力，与 `health_check.enabled` 相互独立：

```json
{
  "enabled": true,
  "server": "1.1.1.1:53",
  "domain": "www.gstatic.com",
  "timeout": "5s",
  "ttl": ""
}
```

每个声明支持 UDP 的节点会经由自身向 `server` 发送一次 `domain` 的 UDP DNS 查询，在 `timeout` 内每秒重发一次。收到匹配的应答即证明节点能转发 UDP；`timeout` 内无应答则判定为不能转发 UDP。只声明 TCP 的节点不参与探测。

结果在 `ttl` 内有效，默认为三个健康检查间隔。仍有效的失败结果会：

* 把节点移出 `"network": "udp"` 的分组，之后探测成功时再加回；
* 让 urltest、loadbalance、smart 分组不再为 UDP 连接选择该节点，手动选择保持不变；
* 在 Clash API 中将节点显示为 `udp: false`，并以 `udpTest` 返回最近一次探测结果。

从未探测或结果已过期的节点仍按声明的 UDP 能力处理。

探测需要一个所有节点都能访问的 DNS 服务器，请选择节点不会屏蔽的地址。

### 本地或远程字段

#### override_anytls

覆写订阅内容的 AnyTLS 字段，参阅 [AnyTLS 字段覆写](/zh/configuration/provider/override_anytls/)。

#### override_dialer

覆写订阅内容的拨号字段, 参阅 [拨号字段覆写](/zh/configuration/provider/override_dialer/)。

#### override_tls

覆写订阅内容的 TLS 字段, 参阅 [TLS 字段覆写](/zh/configuration/provider/override_tls/)。

### Clash 订阅

Clash / mihomo 的 `proxies` 会转换为 sing-box 出站与端点：

| Clash 类型 | sing-box |
|---|---|
| `ss` `vmess` `vless` `trojan` `socks5` `http` `snell` `ssh` `anytls` `hysteria` `hysteria2` `tuic` `direct` | 同协议出站 |
| `wireguard` `tailscale` `openvpn` `easytier` | 端点 |

需要当前构建未实现的功能的节点会被跳过，并以警告记录原因，例如 `ssr`、`mieru`、`sudoku`、`shadowquic`、`gost-relay`、`trusttunnel`、`zerotier`、Cloudflare WARP 的 `masque`、`restls` / `jls` / `tlsmirror`、mKCP 与 mekya 传输、TUIC v4、AmneziaWG、基于 TLS 的 SOCKS5、`restls` / `gost-plugin` / `kcptun` 插件，以及 Clash 的 `dns` / `reject` 节点。

`shadow-tls`（Shadowsocks 插件与 `shadow-tls-opts`）会生成一个名为 `<name> (shadow-tls)` 的 shadowtls 出站，节点经由它拨号；这类出站不会加入分组。经 shadow-tls 的 Shadowsocks 节点在未启用 `udp-over-tcp` 时仅支持 TCP，因为 sing-box 无法让原生 UDP 绕过 detour。

没有对应项的选项会被忽略，节点使用 sing-box 默认行为：`ip-version`、gRPC 的 `grpc-user-agent` 与连接池、`v2ray-http-upgrade-fast-open`、Reality 的 `support-x25519mlkem768`、Hysteria 2 的 `cwnd` / `udp-mtu` / `handshake-timeout` / obfs 包长、接收窗口以外的 TUIC 调优项、WireGuard / OpenVPN 的 `dns` 与 `ip-stack`，以及 EasyTier 的 KCP / QUIC 代理开关。

### 本地字段

#### path

==必填==

!!! note ""

    自 sing-box 1.10.0 起， 文件更改将自动重新加载。

本地文件路径。

### 内联字段

#### outbounds

直接写在配置中的 [出站](/zh/configuration/outbound/) 列表。

指向同一订阅源内其他节点的 `detour` 会被改写为 `provider/node_name`；其他 `detour` 保持不变，因此内联节点可以经由 `outbounds` 中定义的分组做链式代理。

#### endpoints

直接写在配置中的 [端点](/zh/configuration/endpoint/) 列表。

### 远程字段

#### url

==必填==

订阅源的 URL。

#### path

用于存储已下载订阅源的路径。

缓存元数据存储于 `cache.db`。

与 `initial_path` 冲突。

#### initial_path

初始订阅源内容的路径。

仅在启用 `cache.db` 订阅缓存且不存在可用缓存时读取。该路径不会作为持久缓存路径使用。

与 `path` 冲突。

#### exclude

排除节点的正则表达式。

从 `path` 或 `cache.db` 恢复订阅时同样会应用该过滤。若缓存写入后 `include`、`exclude` 或任一 `override_*` 字段发生变化，会先按当前过滤规则提供缓存节点，并在后台忽略缓存的 ETag 重新拉取一次。

#### include

包含节点的正则表达式。

#### user_agent

用于下载订阅内容的 User-Agent。

#### http_client

!!! question "自 sing-box 1.14.0 起"

用于下载订阅内容的 HTTP 客户端。

参阅 [HTTP 客户端字段](/zh/configuration/shared/http-client/) 了解详情。

如果为空，将使用默认传输。

#### download_detour

!!! failure "已在 sing-box 1.14.0 废弃"

    `download_detour` 已在 sing-box 1.14.0 废弃且将在 sing-box 1.16.0 中被移除，请使用 `http_client` 代替。

用于下载订阅内容的出站的标签。

#### update_interval

更新订阅的时间间隔。最小为 `1h`，默认为 `24h`。
