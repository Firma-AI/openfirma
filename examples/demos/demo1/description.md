# Demo 1 — The Path That Doesn't Exist

## The point

An agent calls two endpoints on the same host. The allowed path executes
normally. The forbidden path is never reached — enforced at execution time,
outside the application, with no backend logic involved.

## The setup

Task: "Fetch customer activity and summarize usage."

| Endpoint | Policy outcome |
|---|---|
| `httpbin.org/get` | ALLOW — usage data |
| `httpbin.org/anything/billing` | DENY — billing data (sensitive) |

Same host. Same protocol. Same agent behavior. Different path.

The agent has a generic `fetch(url)` tool. It has no awareness of which
paths are sensitive. It is behaving normally — not compromised.

## What you will see

1. `GET httpbin.org/get` → passes through, response returned
2. `GET httpbin.org/anything/billing` → intercepted, DENY, no upstream call

## Why this differs from existing approaches

| Approach | What it can enforce |
|---|---|
| API gateway / backend | Request reaches app — enforcement depends on code |
| Network allowlisting (host-level) | Cannot distinguish `/get` from `/anything/billing` |
| Firma | Path-level, before execution, uniform across all calls |

## Key insight

Same host. Same service. Different path.
The allowed path executes. The forbidden path is never reached.

---

Press any key to start the demo.
