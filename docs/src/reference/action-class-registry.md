# Action Class Registry Reference

## Overview

The action class registry is a bounded configuration-time enum that defines the
canonical semantic actions the sidecar can classify and enforce. All 44 classes
(15 FEP v0.1 + 12 GitHub + 12 Stripe + 5 Gmail) are listed below. Per-request
(runtime) extension is not permitted; operators may extend at configuration time
per FEP §2.3.2 naming rules.

## Naming rules (FEP §2.3.2)

- Format: `<domain>.<subdomain?>.<verb>` — lowercase, period-separated
- Domain and verb are required; subdomain is optional
- NO provider names in action classes (providers live in `intent.resource`)
- NO transport names (HTTP, gRPC, etc.)
- `system.execute` is a bounded fallback — use only when no narrower class fits

## FEP v0.1 canonical classes (15)

| Action class                   | Domain        | Risk level | Notes                                                      |
| ------------------------------ | ------------- | ---------- | ---------------------------------------------------------- |
| `account.permission.change`    | Permissions   | Critical   | Change account or role permissions                         |
| `browser.purchase`             | Browser       | High       | Browser-driven purchase flow                               |
| `communication.external.send`  | Communication | High       | Outbound message / request to an external system           |
| `communication.internal.send`  | Communication | Medium     | Message to an internal recipient inside the trust boundary |
| `credential.read`              | Credentials   | Medium     | Read a secret, API key, or token                           |
| `credential.write`             | Credentials   | Critical   | Create, rotate, or store a secret                          |
| `filesystem.delete`            | Filesystem    | High       | Delete a file-like resource                                |
| `filesystem.read`              | Filesystem    | Low        | Read a file or file-like resource                          |
| `filesystem.write`             | Filesystem    | Medium     | Create or overwrite a file-like resource                   |
| `memory.cross_namespace.read`  | Memory        | Medium     | Cross-namespace agent memory read                          |
| `memory.cross_namespace.write` | Memory        | High       | Cross-namespace agent memory write                         |
| `payment.purchase`             | Payments      | High       | Purchase of goods or services via a payment rail           |
| `payment.transfer`             | Payments      | Critical   | Value transfer between accounts                            |
| `system.execute`               | System        | Critical   | Raw execution fallback; see §2.3.6 anti-convenience rule   |
| `system.install`               | System        | High       | Install a package or runtime dependency                    |

Risk levels are the Firma OSS v0.1 starting values (encoded in `registry.rs::RiskLevel`).
They drive telemetry grouping and default HITL thresholds; they do NOT drive Cedar decisions on their own.

## GitHub classes (12)

The registry appends 12 classes covering code/issue/repo/notification/security
domains so the sidecar can classify GitHub REST traffic deterministically
without encoding the provider into the action class.

| Action class          | Domain       | Risk     | Notes                                        |
| --------------------- | ------------ | -------- | -------------------------------------------- |
| `code.read`           | Code         | Low      | Read repository / code content               |
| `code.review.read`    | Code         | Low      | Read pull-request review surface             |
| `code.review.submit`  | Code         | Medium   | Submit / mutate a PR review                  |
| `code.write`          | Code         | High     | Mutate code, create or update PRs, push refs |
| `code.destructive`    | Code         | High     | Delete files or git refs                     |
| `code.merge`          | Code         | Critical | Merge a pull request into a target branch    |
| `issue.read`          | Issue        | Low      | Read issues and issue comments               |
| `issue.write`         | Issue        | Medium   | Create or mutate issues and issue comments   |
| `notification.manage` | Notification | Low      | Manage notification state / subscriptions    |
| `security.alert.read` | Security     | Medium   | Read code-scanning / secret-scanning alerts  |
| `repo.lifecycle`      | Repo         | Medium   | Create / fork repositories                   |
| `repo.admin`          | Repo         | Critical | Mutate repo settings / branch protection     |

## Stripe classes (12)

The registry appends 12 payment/customer-domain classes so the sidecar can
classify the Stripe REST surface deterministically. `payment.transfer`
(FEP §2.3.5, Critical) is reused for value-transfer endpoints.

| Action class            | Domain   | Risk     | Notes                                                    |
| ----------------------- | -------- | -------- | -------------------------------------------------------- |
| `payment.read`          | Payment  | Low      | Read balance / charge / payout / dispute / event objects |
| `payment.cancel`        | Payment  | High     | Cancel a PaymentIntent before capture                    |
| `payment.refund`        | Payment  | High     | Issue or cancel a refund on a captured charge            |
| `payment.payout`        | Payment  | Critical | Move funds out via Stripe payout or transfer reversal    |
| `payment.dispute`       | Payment  | High     | Update or close a dispute                                |
| `payment.subscription`  | Payment  | High     | Mutate subscriptions or invoices                         |
| `payment.method.setup`  | Payment  | Medium   | Create / confirm SetupIntents (off-session method save)  |
| `payment.method.manage` | Payment  | Medium   | Create / attach / detach payment methods                 |
| `payment.catalog.write` | Payment  | Medium   | Mutate products, prices, coupons, payment links          |
| `payment.tax`           | Payment  | Medium   | Tax calculations, transactions, and rate management      |
| `customer.read`         | Customer | Low      | Read customer records and saved methods                  |
| `customer.write`        | Customer | Medium   | Create / mutate / delete customer records                |

## Gmail classes (5)

The registry appends 5 communication-domain classes so the sidecar can
distinguish read / draft / manage / delete / filter operations on the Gmail
REST surface. `communication.external.send` (FEP §2.3.5, High) is reused
for the actual send verbs; settings that change deliverability boundaries
map to `account.permission.change`.

| Action class                    | Domain        | Risk     | Notes                                                |
| ------------------------------- | ------------- | -------- | ---------------------------------------------------- |
| `communication.external.read`   | Communication | Low      | Read messages, threads, drafts, labels, history      |
| `communication.external.draft`  | Communication | Medium   | Create / mutate / delete drafts (no send)            |
| `communication.external.manage` | Communication | Medium   | Modify / move / label messages and threads           |
| `communication.external.delete` | Communication | High     | Permanently delete messages or threads               |
| `communication.external.filter` | Communication | Critical | Create / delete server-side mail filters             |

Reserved for a future minor revision (MUST NOT appear in v0.1 policies):
`memory.read`, `memory.write`, `browser.navigate`.

## Provider attachment rule

Provider is attached to `intent.resource` only on exact host match:

- `api.github.com` / `github.com` → `provider="github"`
- `api.stripe.com` → `provider="stripe"`
- `gmail.googleapis.com` → `provider="gmail"`

Exact match is deliberate: typo-squat hostnames MUST NOT earn the tag.
Provider NEVER appears in `intent.action_class`.

## Cross-transport invariants

The same semantic action maps to the same class regardless of transport. Policy
rules MUST bind to `intent.action_class` and `intent.resource` only;
`intent.raw_transport` and `intent.raw_action_ref` are observational and MUST
NOT appear in Cedar policy predicates (FEP Invariant [I-N1]).

Examples:

- `email.send` tool, CLI `gmail send`, HTTP POST to a mail microservice, and
  MCP mail tool invocation all map to `communication.external.send`.
- Shell `rm`, filesystem tool `delete`, and an HTTP DELETE against a file
  service all map to `filesystem.delete`.
- `pip install`, `npm install`, and a package manager plugin call all map to
  `system.install`.

`system.execute` is the bounded fallback for raw execution surfaces whose
business meaning cannot be deterministically elevated into a narrower class.
It MUST NOT be used as a convenience class for actions that can be classified
more specifically (FEP §2.3.6 anti-convenience rule).

## Extending the registry

Operators may add deployment-specific classes at configuration time per FEP
§2.3.2 naming rules. Per-request runtime extension is **not** allowed. See the
extension checklist in [Architecture: Action Class Registry](../architecture/action-class-registry.md).

Common reasons to extend: a deployment-specific domain
(e.g. `compliance.report.file`), or a finer split where the existing class is
too coarse for the policy surface (e.g. `payment.refund` distinct from
`payment.transfer`).

Identifiers added at configuration time are subject to the same compatibility
contract: once deployed into capability tokens, they MUST NOT be renamed or
repurposed.

## Versioning

The registry is versioned with the FEP protocol. Compatibility rules
(FEP §2.3.7):

- Existing identifiers MUST NOT be renamed in a compatible revision.
- New identifiers MAY be added in a minor revision.
- Identifiers MAY be deprecated but MUST NOT be silently repurposed.
- Removal requires a major protocol revision.
