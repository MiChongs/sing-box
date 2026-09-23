### Structure

```json
{
  "type": "urltest",
  "tag": "auto",
  
  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "providers": [
    "provider-a",
    "provider-b",
  ],
  "exclude": "",
  "include": "",
  "url": "",
  "interval": "",
  "expected_status": "",
  "tolerance": 50,
  "idle_timeout": "",
  "use_all_providers": false,
  "hidden": false,
  "icon": "",
  "fallback": {
    "enabled": false,
    "max_delay": ""
  },
  "interrupt_exist_connections": false
}
```

!!! quote ""

    A member can be selected manually through the [Clash API](/configuration/experimental/clash-api/) or the graphical clients.
    The selection is kept across restarts and periodic tests, and is released by the next group delay test triggered by the user.

### Fields

#### outbounds

List of outbound tags to test.

#### providers

List of [Provider](/configuration/provider) tags to test.

#### exclude

Exclude regular expression to filter `providers` nodes.

#### include

Include regular expression to filter `providers` nodes.

#### url

The URL to test. `https://www.gstatic.com/generate_204` will be used if empty.

#### interval

The test interval. `3m` will be used if empty.

#### expected_status

HTTP status codes of the test URL treated as success, compatible with `expected-status` of mihomo:
`204`, a range `200-299`, several values or ranges joined by `/` such as `200/204` or `200-299/301-302`, or `*` for any status.

If empty, a `generate_204` URL must answer `204`, and any other URL must answer below `400`.

#### tolerance

The test tolerance in milliseconds. `50` will be used if empty.

#### idle_timeout

The idle timeout. `30m` will be used if empty.

#### use_all_providers

Whether to use all providers for testing. `false` will be used if empty.

#### fallback

Fallback selection configuration.

When enabled, the first available outbound is selected in configuration order instead of selecting the outbound with the lowest delay.

##### fallback.enabled

Enable fallback selection.

##### fallback.max_delay

Maximum acceptable delay.

An outbound whose delay exceeds this value is skipped. If every available outbound exceeds the value, the skipped outbound with the lowest delay is selected.

#### interrupt_exist_connections

Interrupt existing connections when the selected outbound has changed.

Only inbound connections are affected by this setting, internal connections will always be interrupted.

#### hidden

Hide this group from the proxy switcher of [Clash API](/configuration/experimental/clash-api/) dashboards. Routing is not affected.

#### icon

Icon of this group shown by [Clash API](/configuration/experimental/clash-api/) dashboards, as an URL, data URI or emoji.
