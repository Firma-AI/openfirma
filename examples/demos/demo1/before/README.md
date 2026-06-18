# Before Firma: host-level allowlist only

This folder shows the limits of governing an agent with only a network allowlist.

The platform team wants to allow access to an internal API. The control file allows the host:

| File                     | Surface        | Vocabulary |
| ------------------------ | -------------- | ---------- |
| `network-allowlist.yaml` | Network egress | Hostnames  |

That seems safe until the agent reaches the wrong endpoint on the right host.

## The gap

`api.internal` is allowed. The network layer sees a connection to `api.internal:443`, but it does not know whether the agent is calling `GET /usage` or `GET /billing`.

A path-aware proxy could try to keep up with every route, but then the policy becomes a hand-maintained copy of the application. When the API changes, stale rules silently create risk.

Firma moves the decision up a level: it asks what action the agent is performing, then applies policy to that action.
