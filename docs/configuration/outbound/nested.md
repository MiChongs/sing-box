### Structure

```json
{
  "type": "nested",
  "tag": "chain",

  "detour": "entry",
  "outbounds": [
    "exit-a",
    "exit-b"
  ],
  "providers": [],
  "default": "exit-a",

  ... // Selector Fields
}
```

A nested group chains two hops: every connection goes through `detour` (the entry) to the selected exit. It is a [Selector](/configuration/outbound/selector/) whose members are dialed through `detour`.

For each exit (static outbounds and provider nodes), the group creates a shadow outbound named `<tag>@<group>` with the exit's configuration and `detour` set to the entry, and registers it in the outbound manager. Shadows are reused while the exit's configuration is unchanged and rebuilt when a provider updates it. The original outbounds keep dialing directly. `direct` and `block` members are used as is.

When the group or `detour` falls back to `Compatible` (no usable member), the group blocks every connection, so the exit is never reached directly and the entry never sees the exit's traffic unwrapped.

The selection is controlled through the [Clash API](/configuration/experimental/clash-api/) like a selector; both `exit-a` and `exit-a@chain` select the same member.

### Fields

#### detour

==Required==

Tag of the entry outbound. Cannot be the group itself.

#### outbounds / providers / default / ...

See [Selector](/configuration/outbound/selector/). At least one of `outbounds` and `providers` is required.
