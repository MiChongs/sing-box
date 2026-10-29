# 引言

sing-box 使用 JSON 作为配置文件格式，也接受 YAML，参阅 [YAML](#yaml)。
### 结构

```json
{
  "$schema": "https://raw.githubusercontent.com/reF1nd/sing-box/reF1nd-testing/docs/schema.json",
  "log": {},
  "dns": {},
  "ntp": {},
  "certificate": {},
  "certificate_providers": [],
  "http_clients": [],
  "network_namespaces": [],
  "endpoints": [],
  "inbounds": [],
  "outbounds": [],
  "providers": [],
  "route": {},
  "services": [],
  "experimental": {},

  "remote_verify": true,
  "remote_force_fetch": false,
  "filter_regex": "",
  "filter_reverse": false
}
```

### 字段

| Key            | Format                 |
|----------------|------------------------|
| `$schema`      | [JSON Schema](./schema/) |
| `log`          | [日志](./log/)           |
| `dns`          | [DNS](./dns/)          |
| `ntp`          | [NTP](./ntp/)          |
| `certificate`  | [证书](./certificate/)   |
| `certificate_providers` | [证书提供者](./shared/certificate-provider/) |
| `http_clients` | [HTTP 客户端](./shared/http-client/) |
| `network_namespaces` | [网络命名空间](./network-namespace/) |
| `endpoints`    | [端点](./endpoint/)      |
| `inbounds`     | [入站](./inbound/)       |
| `outbounds`    | [出站](./outbound/)      |
| `providers`    | [提供者](./provider/)         |
| `route`        | [路由](./route/)         |
| `services`     | [服务](./service/)       |
| `experimental` | [实验性](./experimental/) |

#### remote_verify

默认值：`true`。

关闭后，远程 rule-set 与 provider 只要本地文件存在，启动时就直接加载，即使 URL 在下载之后改变过，并把新 URL 记入缓存记录。否则 URL 改变会在启动时触发下载。

#### remote_force_fetch

为 `true` 时，远程 rule-set 或 provider 首次下载失败会导致启动失败。默认以空内容启动（失败的 rule-set 不匹配任何请求，空的 provider 使其分组退化为 `Compatible`），并在后台继续重试。

设为 `false` 同时关闭 `remote_verify`。

#### filter_regex / filter_reverse

配置过滤器，在解析配置之前生效。参阅 [配置过滤器](#配置过滤器)。

### 检查

```bash
sing-box check
```

### 格式化

```bash
sing-box format -w -c config.json -D config_directory
```

### 合并

```bash
sing-box merge output.json -c config.json -D config_directory
```

### YAML

以 `.yaml` / `.yml` 结尾的文件，以及不以 `{` 开头的内容按 YAML 解析；JSON 照常支持注释。顶层以 `.`、`_`、`x-` 开头的键会被忽略，可用来存放 YAML 锚点：

```yaml
x-tls: &tls
  enabled: true
  server_name: example.com
outbounds:
  - type: trojan
    tag: proxy
    server: example.com
    server_port: 443
    password: password
    tls: *tls
```

配置目录（`-C`）读取 `.json`、`.jsonc`、`.yaml` 与 `.yml` 文件。

### 配置过滤器

在解析之前保留或丢弃条目，让一份配置文件同时容纳多台设备的变体。

* `filter_regex`：与标记匹配的正则表达式。
* `filter_reverse`：改为保留**不**匹配的条目。
* `filter_mark`（任意对象）：字符串或字符串列表。标记匹配 `filter_regex`（列表须每一项都匹配）时保留该对象，否则丢弃。没有 `filter_mark` 的对象始终保留。
* `filter_option`（任意对象，`filter_reverse` 时不生效）：从标记到字段的映射。每个匹配 `filter_regex` 的标记，其字段会合并进该对象；值为 `null` 时删除该字段。

```json
{
  "filter_regex": "ebpf|tproxy",
  "inbounds": [
    { "type": "mixed", "tag": "mixed-in", "listen_port": 2080 },
    { "type": "ebpf", "tag": "ebpf-in", "filter_mark": "ebpf" },
    { "type": "tproxy", "tag": "tproxy-in", "listen_port": 7893, "filter_mark": "tproxy" },
    { "type": "tun", "tag": "tun-in", "filter_mark": "tun" }
  ],
  "route": {
    "auto_detect_interface": true,
    "filter_option": {
      "router": { "auto_detect_interface": null, "default_interface": "eth0" }
    }
  }
}
```
