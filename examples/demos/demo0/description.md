# Demo 0 — Same Rule, Four Systems, One Failure

## The point

A developer defines a simple rule for an agent, but enforcement is split across
four systems — resulting in inconsistent behavior and a guaranteed gap.

## The rule

> "This agent can read data, but cannot perform write or destructive actions."

## The system

The agent interacts with four external services over HTTP:

| Service | How the rule is enforced today |
|---|---|
| GitHub API | OAuth scope (provider-enforced) |
| Gmail API | OAuth scope (provider-enforced) |
| Stripe API | Backend check (app-enforced) |
| Internal backend | Code path (app-enforced) |

## What you will see

| Action | Canonical class | Expected outcome |
|---|---|---|
| Read GitHub PR | `code.review.read` | ALLOW |
| Send email via Gmail | `communication.external.send` | DENY |
| Create Stripe refund | `payment.transfer` | DENY |
| DELETE user via backend | `account.permission.change` | DENY |

With Firma: a single Cedar policy evaluated at every outbound call.
All four calls enforced uniformly — one rule, one enforcement point.

## Key insight

Without Firma: enforcement is distributed across four different models,
four configurations, four potential failure points.

With Firma: define the rule once. Apply it everywhere. At every call.

---

Press any key to start the demo.
