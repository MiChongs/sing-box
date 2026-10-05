!!! quote "sing-box 1.15.0 中的更改"

    :material-plus: [external_ui_update_interval](#external_ui_update_interval)

!!! quote "sing-box 1.14.0 中的更改"

    :material-plus: [external_ui_http_client](#external_ui_http_client)
    :material-delete-clock: [external_ui_download_detour](#external_ui_download_detour)

!!! quote "sing-box 1.10.0 中的更改"

    :material-plus: [access_control_allow_origin](#access_control_allow_origin)  
    :material-plus: [access_control_allow_private_network](#access_control_allow_private_network)

!!! quote "sing-box 1.8.0 中的更改"

    :material-delete-alert: [store_mode](#store_mode)  
    :material-delete-alert: [store_selected](#store_selected)  
    :material-delete-alert: [store_fakeip](#store_fakeip)  
    :material-delete-alert: [cache_file](#cache_file)  
    :material-delete-alert: [cache_id](#cache_id)

### 结构

=== "结构"

    ```json
    {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "",
      "external_ui_download_url": "",
      "external_ui_http_client": "", // or {}
      "external_ui_update_interval": "",
      "secret": "",
      "default_mode": "",
      "access_control_allow_origin": [],
      "access_control_allow_private_network": false,
      
      // Deprecated

      "external_ui_download_detour": "",
      "store_mode": false,
      "store_selected": false,
      "store_fakeip": false,
      "cache_file": "",
      "cache_id": ""
    }
    ```

=== "示例 (在线)"

    !!! question "自 sing-box 1.10.0 起"

    ```json
    {
      "external_controller": "127.0.0.1:9090",
      "access_control_allow_origin": [
        "http://127.0.0.1",
        "http://yacd.haishan.me"
      ],
      "access_control_allow_private_network": true
    }
    ```

=== "示例 (下载)"

    !!! question "自 sing-box 1.10.0 起"

    ```json
    {
      "external_controller": "0.0.0.0:9090",
      "external_ui": "dashboard"
      // "external_ui_http_client": "my-http-client"
    }
    ```

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签

!!! info "可观测性 API"

    启用[实验性可观测性](observability.md)后，专用的 `/observability/v1`
    HTTP API 会挂载到该 Controller，并使用相同的 `secret` 保护。

!!! info "规则命中统计"

    `GET /rules` 依次列出路由规则与 DNS 规则。`type` 使用 mihomo 规则类型
    （`DomainSuffix`、`IPCIDR`、`RuleSet`、`InName`、`DstPort` 等；`ip_is_private`
    显示为 `GeoIP` `lan`，mihomo 中没有对应类型的条件使用字段名的驼峰形式，如
    `ClashMode`），`payload` 列出条件的值，以 `, ` 分隔，如 `DomainSuffix`
    `google.com, youtube.com`。

    含多个条件的规则类型为 `AND`、`OR` 或 `NOT`，载荷为以 `&`（且）、`|`（或）连接的
    `类型(值)` 表达式，嵌套的组加括号，如 `AND`
    `Network(tcp) & (DomainSuffix(a.com) | IPCIDR(1.1.1.1/32))`。嵌套的 `AND` /
    `OR`（含逻辑规则）展开到同一层，`OR` 中同类型条件的值合并，因此 `OR` 只并列
    不同类型的条件。没有条件的规则为 `Match`。

    `proxy` 为目标出站或 DNS 服务器的标签，其余动作为大写的动作名（`REJECT`、
    `REJECT-DROP`、`SNIFF`、`HIJACK-DNS` 等）。`/connections` 的 `rule` 与
    `rulePayload` 使用同样的格式，连接落到 `route.final` 时为 `Match`。

    与 mihomo 一致，每条规则返回 `index`、`size` 与 `extra`（`disabled`、`hitCount`、
    `hitAt`、`missCount`、`missAt`）：顶层规则每参与一次匹配计一次命中或未命中，
    被禁用的规则跳过不计。统计保存在内存中，重启或重载配置后清零。

    `PATCH /rules/disable` 接受 `{"<index>": true|false}`，按 `index` 禁用或启用规则；
    `PUT /rules/{uuid}` 仍可按 `uuid` 切换规则状态。

### Fields

#### external_controller

RESTful web API 监听地址。如果为空，则禁用 Clash API。

#### external_ui

到静态网页资源目录的相对路径或绝对路径。sing-box 会在 `http://{{external-controller}}/ui` 下提供它。

#### external_ui_download_url

静态网页资源的 ZIP 下载 URL，如果指定的 `external_ui` 目录为空，将使用。

默认使用 `https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip`。

#### external_ui_http_client

!!! question "自 sing-box 1.14.0 起"

用于下载静态网页资源的 HTTP 客户端。

参阅 [HTTP 客户端字段](/zh/configuration/shared/http-client/) 了解详情。

如果为空，将使用默认传输。

#### external_ui_download_detour

!!! failure "已在 sing-box 1.14.0 废弃"

    `external_ui_download_detour` 已在 sing-box 1.14.0 废弃且将在 sing-box 1.16.0 中被移除，请使用 `external_ui_http_client` 代替。

用于下载静态网页资源的出站的标签。

#### external_ui_update_interval

!!! question "自 sing-box 1.15.0 起"

外部用户界面的更新间隔。留空时禁用自动更新。

最小间隔为一小时。

启用 `cache_file.enabled` 时，更改 `external_ui_download_url` 会使外部用户界面重新下载。

#### secret

RESTful API 的密钥（可选）
通过指定 HTTP 标头 `Authorization: Bearer ${secret}` 进行身份验证
如果 RESTful API 正在监听 0.0.0.0，请始终设置一个密钥。

#### default_mode

Clash 中的默认模式，默认使用 `Rule`。

此设置没有直接影响，但可以通过 `clash_mode` 规则项在路由和 DNS 规则中使用。

#### access_control_allow_origin

!!! question "自 sing-box 1.10.0 起"

允许的 CORS 来源，默认使用 `*`。

要从公共网站访问私有网络上的 Clash API，必须在 `access_control_allow_origin` 中明确指定它而不是使用 `*`。

#### access_control_allow_private_network

!!! question "自 sing-box 1.10.0 起"

允许从私有网络访问。

要从公共网站访问私有网络上的 Clash API，必须启用 `access_control_allow_private_network`。

#### store_mode

!!! failure "已在 sing-box 1.8.0 废弃"

    `store_mode` 已在 Clash API 中废弃，且默认启用当 `cache_file.enabled`。

将 Clash 模式存储在缓存文件中。

#### store_selected

!!! failure "已在 sing-box 1.8.0 废弃"

    `store_selected` 已在 Clash API 中废弃，且默认启用当 `cache_file.enabled`。

!!! note ""

    必须为目标出站设置标签。

将 `Selector` 中出站的选定的目标出站存储在缓存文件中。

#### store_fakeip

!!! failure "已在 sing-box 1.8.0 废弃"

    `store_selected` 已在 Clash API 中废弃，且已迁移到 `cache_file.store_fakeip`。

将 fakeip 存储在缓存文件中。

#### cache_file

!!! failure "已在 sing-box 1.8.0 废弃"
 
    `cache_file` 已在 Clash API 中废弃，且已迁移到 `cache_file.enabled` 和 `cache_file.path`。

缓存文件路径，默认使用`cache.db`。

#### cache_id

!!! failure "已在 sing-box 1.8.0 废弃"
 
    `cache_id` 已在 Clash API 中废弃，且已迁移到 `cache_file.cache_id`。

缓存 ID。

如果不为空，配置特定的数据将使用由其键控的单独存储。
