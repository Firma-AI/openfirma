# Demo 1b — The Path That Doesn't Exist

## The point

An agent calls two endpoints on the same internal service. One is allowed, one
is forbidden. The allowed path executes normally; the forbidden path is never
reached. Enforcement happens at execution time, outside the application.

## The setup

Task: "Fetch customer activity and summarize usage."

| Endpoint | Policy outcome |
|---|---|
| `api.internal/usage?user=123` | ALLOW — usage metrics |
| `api.internal/billing?user=123` | DENY — billing data |

Same host. Same protocol. Same agent behavior. Different path.

The agent has a generic fetch tool. It has no awareness of which paths are
sensitive, and it is behaving normally — not compromised and not misconfigured.

## What you will see

1. `GET api.internal/usage?user=123` passes through and returns a response.
2. `GET api.internal/billing?user=123` is intercepted and denied. No upstream
   call is made.

## Why this differs from existing approaches

| Approach | What it can enforce |
|---|---|
| API gateway / backend | Request reaches app — enforcement depends on code |
| Network allowlisting (host-level) | Cannot distinguish `/usage` from `/billing` |
| OpenAuthority | Path-level, before execution, uniform across all calls |

## Key insight

Same host. Same service. Different path.
The allowed path executes. The forbidden path is never reached.
