---
icon: material/new-box
---

!!! question "自 sing-box 1.15.0 起"

# EasyTier

`easytier` DNS 服务器提供 [EasyTier 端点](/zh/configuration/endpoint/easytier) 的 Magic DNS 名称：与 EasyTier 守护进程的 Magic DNS 一样，其网络中的每个节点都可以通过 `<hostname>.<zone>` 解析。

### 结构

```json
{
  "dns": {
    "servers": [
      {
        "type": "easytier",
        "tag": "",

        "endpoint": "easytier-ep",
        "accept_search_domain": false
      }
    ]
  }
}
```

### 字段

#### endpoint

==必填==

[EasyTier 端点](/zh/configuration/endpoint/easytier) 的标签。

一个端点只能关联一个 EasyTier DNS 服务器。

#### accept_search_domain

启用后，单标签查询（例如 `nas`）在存在对应节点时按 `nas.<zone>` 应答，优先尝试最具体的区域。

### 记录

* 本节点以及每个带主机名的节点都以 `<hostname>.<zone>` 发布：虚拟 IPv4 地址对应 `A` 记录，虚拟 IPv6 地址对应 `AAAA` 记录。主机名相同的多个节点会解析到它们的全部地址。
* 区域为端点的 [`tld_dns_zone`](/zh/configuration/endpoint/easytier/#tld_dns_zone)，默认为 `et.net`。EasyTier Web 配置服务器下发的网络使用其自身配置中的区域。
* 主机名会转为小写，国际化名称编码为 punycode；无法构成 DNS 名称的主机名（例如包含空格）不会发布。
* 服务器对每个区域都是权威的：不存在的名称返回 `NXDOMAIN`，其他记录类型返回空应答，区域带有 `SOA` 记录。记录与否定应答的 TTL 均为 1 秒，因此名称随节点列表实时变化。
* 所有区域之外的查询返回 `NXDOMAIN`。

记录根据节点列表实时更新，查询时不访问网络。

### 路由

[`preferred_by`](/zh/configuration/dns/rule/#preferred_by) 匹配区域内的所有名称；启用 `accept_search_domain` 时，还匹配已存在节点的单标签名称。

当连接到域名的流量被路由到端点时，端点会自行解析 Magic DNS 名称，因此路由规则中的 [`preferred_by`](/zh/configuration/route/rule/#preferred_by) 同样匹配这些名称。

[`dns_search_domain`](/zh/configuration/route/rule/#dns_search_domain) 匹配各网络的区域。

### 示例

=== "Magic DNS"

    ```json
    {
      "dns": {
        "servers": [
          {
            "type": "local",
            "tag": "local"
          },
          {
            "type": "easytier",
            "tag": "easytier-dns",
            "endpoint": "easytier-ep"
          }
        ],
        "rules": [
          {
            "preferred_by": "easytier-dns",
            "action": "route",
            "server": "easytier-dns"
          }
        ]
      },
      "route": {
        "rules": [
          {
            "preferred_by": "easytier-ep",
            "outbound": "easytier-ep"
          }
        ]
      }
    }
    ```

=== "应答发往 100.100.100.101 的查询"

    EasyTier 守护进程在 `100.100.100.101` 上提供 Magic DNS。设备发往该地址的查询由 sing-box 应答，其他名称按 sing-box 的 DNS 规则解析：

    ```json
    {
      "route": {
        "rules": [
          {
            "ip_cidr": "100.100.100.101/32",
            "port": 53,
            "action": "hijack-dns"
          }
        ]
      }
    }
    ```
