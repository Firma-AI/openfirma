# Demo 2 — The Compromised Agent

## The point

Even with a fully compromised agent, credentials are never exposed and
actions remain bounded by policy. The security perimeter is the call,
not the agent process — so the blast radius of a compromise is what the
policy permits, not what the token permits.

## The setup

Agent task: review PRs on the `acme/api` repository.

The agent *appears* to hold a full-access `GITHUB_TOKEN` (read, write,
merge, secrets). It does not. The real token lives in the sidecar's
`[credentials.github]` config; the agent process scrubs `GITHUB_TOKEN`
from its own environment at startup. After an ALLOW decision the sidecar
attaches the `Authorization: Bearer …` header on the way out.

The capability enforced by the sidecar:

| Permitted | Denied |
|---|---|
| `code.review.read` | `code.merge` |
| `issue.write` | `code.write` |
| | `credential.read` |
| | `communication.external.send` |

## What you will see

**Phase 1 — normal review**

| Action | Outcome |
|---|---|
| Read PR #41 | ALLOW |
| Read PR diff | ALLOW |
| Comment on PR | ALLOW |
| Create follow-up issue | ALLOW |

**Phase 2 — overreach**

| Action | Outcome |
|---|---|
| Merge PR #41 | DENY |
| Push branch | DENY |
| Delete branch | DENY |

**Phase 3 — compromised dependency**

| Action | Outcome |
|---|---|
| Read GitHub Actions secrets | DENY |
| POST scraped env to attacker host | DENY |

## Aha moment

The agent looks like it has a full-access token. It does not. The token
never enters the agent's process; it is held by the sidecar and injected
only post-approval. A compromised agent cannot leak what it never had.
Credential isolation under compromise is structural, not a matter of
careful scoping.

**The perimeter is the call, not the agent.**
