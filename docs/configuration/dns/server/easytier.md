---
icon: material/new-box
---

!!! question "Since sing-box 1.15.0"

# EasyTier

`easytier` DNS server serves the Magic DNS names of an [EasyTier Endpoint](/configuration/endpoint/easytier): every node of its networks is resolvable as `<hostname>.<zone>`, like the Magic DNS of the EasyTier daemon.

### Structure

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

### Fields

#### endpoint

==Required==

The tag of the [EasyTier Endpoint](/configuration/endpoint/easytier).

Only one EasyTier DNS server can be attached to an endpoint.

#### accept_search_domain

When enabled, single-label queries (e.g. `nas`) are answered as `nas.<zone>` when such a node exists, trying the most specific zone first.

### Records

* This node and every peer with a hostname are published as `<hostname>.<zone>`, with an `A` record for the virtual IPv4 address and an `AAAA` record for the virtual IPv6 address. Peers sharing a hostname resolve to all of their addresses.
* The zone is the endpoint's [`tld_dns_zone`](/configuration/endpoint/easytier/#tld_dns_zone), `et.net` by default. Networks assigned by an EasyTier Web configuration server use the zone in their own configuration.
* Hostnames are lowercased and internationalized names are encoded as punycode; hostnames that do not form a DNS name (for example ones containing spaces) are not published.
* The server is authoritative for each zone: names that do not exist return `NXDOMAIN`, other record types return an empty answer, and the zone has an `SOA` record. Records and negative answers use a TTL of 1 second, so names follow the peer list.
* Queries outside every zone return `NXDOMAIN`.

Records are kept up to date from the peer list, without querying the network.

### Routing

[`preferred_by`](/configuration/dns/rule/#preferred_by) matches every name inside the zones, and with `accept_search_domain`, single-label names of existing nodes.

The endpoint resolves Magic DNS names itself when a connection to a domain is routed to it, so [`preferred_by`](/configuration/route/rule/#preferred_by) in route rules also matches them.

[`dns_search_domain`](/configuration/route/rule/#dns_search_domain) matches the zones of the networks.

### Examples

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

=== "Answer queries sent to 100.100.100.101"

    The EasyTier daemon serves Magic DNS on `100.100.100.101`. Queries that devices send to this address are answered by sing-box, which resolves other names through its DNS rules:

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
