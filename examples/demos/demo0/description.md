# Demo 0 — Same Rule, Four Systems, One Failure

Fragmentation of enforcement across tools and layers.

## The point

A developer defines a simple rule for an agent, but enforcement is split across
multiple systems. The result is inconsistent behavior and a guaranteed gap.

## The rule

> "This agent can read data, but cannot perform write or destructive actions."

## The system

The agent interacts with four external services over HTTP. Every call leaves the
agent process:

| Service | Today’s enforcement model |
|---|---|
| GitHub API | Provider permissions |
| Gmail API | OAuth scope |
| Stripe API | Backend check |
| Internal backend API | Application code paths |

Two systems enforce globally. Two systems rely on your code.

## The problem today

| Action | Canonical action class | Outcome without a single enforcement point |
|---|---|---|
| Read GitHub PR | `code.review.read` | Allowed |
| Send email | `communication.external.send` | Blocked by OAuth scope |
| Create Stripe refund | `payment.transfer` | Blocked by backend check |
| Delete user via backend API | `account.permission.change` | Executed if the backend missed the check |

The rule is consistent. The systems are not.

## The OpenAuthority shift

A single Cedar policy is evaluated by the Sidecar on every outbound call.
Every call to GitHub, Gmail, Stripe, or the backend goes through the same
policy, the same evaluation, and the same enforcement point.

| Action | Canonical action class | Outcome with OpenAuthority |
|---|---|---|
| Read GitHub PR | `code.review.read` | ALLOW |
| Send email | `communication.external.send` | DENY |
| Create Stripe refund | `payment.transfer` | DENY |
| Delete user via backend API | `account.permission.change` | DENY |

## Closing line

Today, enforcement is fragmented across systems. OpenAuthority enforces your rule once,
everywhere, at every call.
