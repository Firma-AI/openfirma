# Demo 2 — The Agent That Cannot Misuse Credentials

## The point

An agent is compromised and attempts to exfiltrate data and misuse credentials.
Every action is blocked before execution, regardless of intent — because
enforcement happens per call, before execution, outside the agent.

## The setup

Agent task: review PRs on the acme/api repository.

The environment contains a GitHub token with full repo access:
read, write, merge, secrets.

The capability enforced by the sidecar:

| Permitted | Denied |
|---|---|
| `code.review.read` | `code.merge` |
| `issue.write` | `code.write` |
| | `credential.read` |
| | `communication.external.send` |

Credentials are injected by the sidecar only after ALLOW.
The agent never holds the token directly.

## What you will see

**Phase 1 — normal behavior**

| Action | Outcome |
|---|---|
| Read PR #41 | ALLOW |
| Read PR diff | ALLOW |
| Comment on PR | ALLOW |
| Create issue | ALLOW |

**Phase 2 — overreach**

| Action | Outcome |
|---|---|
| Merge PR #41 | DENY |
| Push code | DENY |
| Delete branch | DENY |

**Phase 3 — compromise (malicious dependency)**

| Action | Outcome |
|---|---|
| POST env vars to external host | DENY |
| Read GitHub secrets | DENY |

## Key insight

Even if the agent is compromised and the credentials allow everything —
nothing happens outside policy, because every call is enforced before execution.
