# Before Firma — host-level allowlist only

This is the artifact a platform team would hand-roll today to govern the
agent's access to the internal service: an egress allowlist keyed on
hostname.

| File                     | Surface           | Vocabulary |
| ------------------------ | ----------------- | ---------- |
| `network-allowlist.yaml` | Network allowlist | Hostnames  |

## The gap

`api.internal` is on the allowlist. The egress firewall sees a TCP connection
to `api.internal:443` carrying a TLS handshake — and that is all it sees. The
HTTP method, the path, and the query string are inside the TLS stream and
opaque to the proxy. Once the host is permitted, every endpoint on the host
is permitted with it.

`GET /usage?user=user-123` and `GET /billing?user=user-123` are
indistinguishable to this layer. Both reach the upstream service.

A path-aware network rule could be attempted by terminating TLS at an
in-line proxy and matching on URL — but the result is a per-endpoint
allowlist tied to the application's routing, hand-edited every time the API
evolves. The blast radius of a stale rule is silent: a sensitive path is
added on the server, the allowlist is not updated, the agent reaches it.

That is the gap Firma closes. The decision is made on what the agent is
doing — the canonical action class — not on the host or the path. Two
endpoints on the same host evaluate against the same policy and produce two
different decisions because they describe two different actions.
