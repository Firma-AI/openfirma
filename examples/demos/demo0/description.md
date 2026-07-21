# Demo 0 — The system surface is messy

With Firma, agent governance is centralized.

## The point

Without Firma, the surface where "what the agent can do" gets defined is
fragmented across three disconnected layers:

1. **OAuth scopes** — what the third-party identity provider lets the token do.
2. **Token permissions** — what the issued credential is entitled to do at the
   provider's API.
3. **Network allowlists** — what destinations the agent's network is permitted
   to reach.

None of these layers share a model of what the agent is actually doing. The rule
the developer wants ("read, never write or destroy") has to be encoded three
different ways in three different artifacts, and the gap between them is where
the breach happens.

## The agent

A developer assistant that operates against three providers:

- **GitHub** — to read pull requests.
- **Gmail** — to send notifications.
- **An internal service** — to read and modify user state.

The rule, in plain language: _"The agent can read data, but cannot perform
write or destructive actions."_

## Three surfaces, three configurations

| Surface           | File                                   | What it controls                                     | What it cannot see                                                                     |
| ----------------- | -------------------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------- |
| OAuth scopes      | `before/oauth-scopes.json`             | Which Gmail API methods the token can call.          | The taxonomy used by the other two surfaces.                                           |
| Token permissions | `before/github-token-permissions.yaml` | Which GitHub API verbs the PAT can issue.            | Whether the call is consistent with the agent's intent at the other providers.         |
| Network allowlist | `before/network-allowlist.yaml`        | Which destination hosts the agent process can reach. | The HTTP method or path — once the host is on the list, every call to it goes through. |

Three artifacts. Three vocabularies. Zero shared representation of "what the
agent is doing".

## What goes wrong

| Action               | Canonical action class        | What stops it today                                                            |
| -------------------- | ----------------------------- | ------------------------------------------------------------------------------ |
| Read GitHub PR       | `code.review.read`            | GitHub PAT has `pull_requests:read`. ALLOWED.                                  |
| Send Gmail message   | `communication.external.send` | OAuth scope is read-only. BLOCKED at provider.                                 |
| Delete internal user | `account.permission.change`   | Internal service host is on the egress allowlist. **The DELETE goes through.** |

The rule was consistent. The three surfaces were not. The internal service is
governed by a network allowlist that only knows about hosts — it cannot tell
read from write — so the destructive action passes through unchecked.

## The Firma shift

Firma replaces the three surfaces with one. Every outbound call from the agent
is normalized into a canonical action class and evaluated against a single
Cedar policy at the sidecar:

```cedar
permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"code.review.read",
    resource
);

permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
);
// Everything else: default deny.
```

The action class taxonomy is the same regardless of which provider the call
targets. `code.review.read` means the same thing whether the underlying call is
to GitHub, Gmail, or the internal service.

| Action               | Canonical action class        | With Firma |
| -------------------- | ----------------------------- | ---------- |
| Read GitHub PR       | `code.review.read`            | ALLOW      |
| Send Gmail message   | `communication.external.send` | DENY       |
| Delete internal user | `account.permission.change`   | DENY       |

One policy. One taxonomy. One enforcement point. Same rule, every provider,
every call.

## Closing line

Three surfaces, three vocabularies, no shared model of agent behavior — that is
the gap. With Firma, agent governance is centralized: the rule is expressed
once, against a canonical action class taxonomy, and enforced uniformly at the
moment of every outbound call.
