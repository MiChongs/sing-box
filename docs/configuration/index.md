# Introduction

sing-box uses JSON for configuration files. YAML is accepted too, see [YAML](#yaml).
### Structure

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
  "experimental": {}
}
```

### Fields

| Key            | Format                          |
|----------------|---------------------------------|
| `$schema`      | [JSON Schema](./schema/)        |
| `log`          | [Log](./log/)                   |
| `dns`          | [DNS](./dns/)                   |
| `ntp`          | [NTP](./ntp/)                   |
| `certificate`  | [Certificate](./certificate/)   |
| `certificate_providers` | [Certificate Provider](./shared/certificate-provider/) |
| `http_clients` | [HTTP Client](./shared/http-client/) |
| `network_namespaces` | [Network Namespace](./network-namespace/) |
| `endpoints`    | [Endpoint](./endpoint/)         |
| `inbounds`     | [Inbound](./inbound/)           |
| `outbounds`    | [Outbound](./outbound/)         |
| `providers`    | [Provider](./provider/)         |
| `route`        | [Route](./route/)               |
| `services`     | [Service](./service/)           |
| `experimental` | [Experimental](./experimental/) |

#### remote_verify

Default: `true`.

When disabled, remote rule-sets and providers whose local file exists load it as is at startup, even when their URL changed since it was downloaded, and record the new URL. Otherwise a URL change triggers a download at startup.

#### remote_force_fetch

When `true`, startup fails if the initial download of a remote rule-set or provider fails. By default they start empty (a failed rule-set matches nothing, an empty provider leaves its groups on `Compatible`) and keep retrying in the background.

`false` also disables `remote_verify`.

#### filter_regex / filter_reverse

Configuration filter, applied before the configuration is parsed. See [Configuration filter](#configuration-filter).

### Check

```bash
sing-box check
```

### Format

```bash
sing-box format -w -c config.json -D config_directory
```

### Merge

```bash
sing-box merge output.json -c config.json -D config_directory
```

### YAML

Files ending in `.yaml` / `.yml`, and content that does not start with `{`, are parsed as YAML; JSON keeps supporting comments. Top-level keys starting with `.`, `_` or `x-` are ignored, so they can hold YAML anchors:

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

Configuration directories (`-C`) read `.json`, `.jsonc`, `.yaml` and `.yml` files.

### Configuration filter

Entries can be kept or dropped before parsing, so one file can carry variants for several devices.

* `filter_regex`: regular expression matched against marks.
* `filter_reverse`: keep the entries that do **not** match instead.
* `filter_mark` (any object): a string or a list of strings. The object is kept when its mark matches `filter_regex` (every item for a list), otherwise it is dropped. Objects without `filter_mark` are always kept.
* `filter_option` (any object, ignored with `filter_reverse`): a map from mark to fields. For each mark matching `filter_regex`, its fields are merged into the object; a `null` value removes the field.

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
