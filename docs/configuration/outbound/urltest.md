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
  "tolerance": 50,
  "idle_timeout": "",
  "use_all_providers": false,
  "fallback": {
    "enabled": false,
    "max_delay": ""
  },
  "interrupt_exist_connections": false
}
```

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

Every interval, the current selection and the fastest members are tested, along with members never tested before.
Other members are refreshed in turns, least recently tested first: groups of up to 64 members are fully refreshed every interval, larger groups at most every 8 intervals.
A member whose tests keep failing is retried after 1, 2, 4 and up to 8 intervals; a network change resets this.

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
