### Structure

```json
{
  "use_anyx": false,
  "client_metadata": "",
  "disable_reuse": false,
  "padding_scheme": [],
  "padding_scheme_interval": "30m",
  "min_idle_session": 0,
  "idle_session_timeout": "30s",
  "idle_session_min_timeout": "30s"
}
```

### Fields

Applies to `anytls` and `anyx` nodes.

#### use_anyx

Convert `anytls` nodes to [AnyX](/configuration/outbound/anyx/) nodes with the same server, password, TLS and session settings. The server must run AnyX.

#### client_metadata / disable_reuse / min_idle_session / idle_session_timeout

See [AnyTLS outbound](/configuration/outbound/anytls/) and [AnyX outbound](/configuration/outbound/anyx/).

#### padding_scheme / padding_scheme_interval / idle_session_min_timeout

AnyX only (nodes converted with `use_anyx` included), see [AnyX outbound](/configuration/outbound/anyx/).

Omitted fields preserve the subscription's values. An explicit empty `client_metadata`
clears the metadata, and `disable_reuse: false` explicitly re-enables reuse.
