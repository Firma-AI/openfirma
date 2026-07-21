# Demo 1b — Same host and service, different path

With Firma, two endpoints on the same host can be governed differently — and
the policy is expressed against agent intent, not against routing.

## The point

Enforcement based on transport-layer signals (host, port, network) cannot see
what the agent is trying to do. Firma enforces on the semantic action, not on
the packet — so two endpoints on the same host can be governed differently
without rewriting the application or the network layer.

## The agent

A customer analytics agent. The user asks the agent to _"fetch customer
activity and summarize usage."_ The agent issues two HTTP calls against the
same internal service:

| Call | Endpoint                                         | What it returns |
| ---- | ------------------------------------------------ | --------------- |
| 1    | `GET https://api.internal/usage?user=user-123`   | Usage metrics   |
| 2    | `GET https://api.internal/billing?user=user-123` | Billing records |

Same host. Same TLS endpoint. Same agent. Same protocol. Different path.

The agent has a generic fetch surface and no awareness of which paths are
sensitive — it is behaving normally, neither compromised nor misconfigured.

## One surface, one blind spot

| Surface           | File                            | What it controls                                     | What it cannot see                                                                     |
| ----------------- | ------------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Network allowlist | `before/network-allowlist.yaml` | Which destination hosts the agent process can reach. | The HTTP method or path — once the host is allowed, every endpoint on it goes through. |

`api.internal` is on the allowlist. `/usage` and `/billing` ride the same
TLS connection to the same host. The allowlist is structurally incapable of
telling them apart.

## What goes wrong

| Action       | Request                    | What stops it today                          |
| ------------ | -------------------------- | -------------------------------------------- |
| Read usage   | `GET api.internal/usage`   | Host is allowed. Call goes through.          |
| Read billing | `GET api.internal/billing` | Host is allowed. **Call also goes through.** |

A path-aware network rule could be added — but every new endpoint on
`api.internal` then drifts into a per-route allowlist that has to be kept in
sync with the application by hand. That is the gap.

## The Firma shift

The normalizer maps `(host, path)` to a canonical action class. Cedar
evaluates the action class, not the host. Two endpoints on the same host
produce two different decisions because they describe two different things
the agent is doing.

```cedar
permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
);
// Everything else: default deny.
```

| Action       | Path       | Canonical action class | With Firma |
| ------------ | ---------- | ---------------------- | ---------- |
| Read usage   | `/usage`   | `filesystem.read`      | ALLOW      |
| Read billing | `/billing` | `credential.read`      | DENY       |

Same host. Same TLS. Same agent. Two action classes. Two decisions.

## Closing line

Same host, same service, two endpoints — and the enforcement decision is
different, because the decision is made on what the agent is doing, not on
where the packet is going. Path-level and intent-level enforcement is not
something you can retrofit onto a network proxy.
