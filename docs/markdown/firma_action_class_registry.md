# Firma Action Class Registry — v0.1 Implementation Notes

Companion to FEP §2.3 (`context/firma_fep_spec.md`). Source of truth for how the
Firma OSS Sidecar and Mini Authority bind to the Canonical Action Class Registry
defined by FEP v0.1. Gives Claude (and human reviewers) the exact identifiers,
naming rules, and provider-handling conventions to follow when touching
registry, normalizer, Cedar schema, or policy fixtures.

## Scope

- Documents the canonical action classes that MAY appear in
  `ExecutionEnvelope.intent.action_class`.
- Fixes the mapping strategy the Intent Normalizer uses to classify raw
  requests into those classes without leaking transport names into
  `action_class`.
- Fixes how provider identity (Slack, OpenAI, Stripe, GitHub, ...) is
  represented. Provider lives in `intent.resource`, never in
  `intent.action_class`.

Out of scope: Cedar policy authoring patterns, capability scope design,
the HITL escalation engine. Those reference this document as input.

## Normative registry (FEP v0.1, §2.3.5)

The v0.1 registry is a bounded configuration-time enum. Per-request
(runtime) extension is not permitted (FEP §2.3.3). The 15 canonical
identifiers below are normative for FEP v0.1; new **canonical** identifiers
are added only in a minor protocol revision.

Operators MAY extend the registry with deployment-specific classes at
configuration time, provided those classes conform to the §2.3.2 naming
rules. See §Extending the registry for the coupled sites and procedure.

Identifiers listed in alphabetical order.

| Action class                     | Domain        | Risk level | Notes                                                       |
|----------------------------------|---------------|------------|-------------------------------------------------------------|
| `account.permission.change`      | Permissions   | Critical   | Change account or role permissions                          |
| `browser.purchase`               | Browser       | High       | Browser-driven purchase flow                                |
| `communication.external.send`    | Communication | High       | Outbound message / request to an external system            |
| `communication.internal.send`    | Communication | Medium     | Message to an internal recipient inside the trust boundary  |
| `credential.read`                | Credentials   | Medium     | Read a secret, API key, or token                            |
| `credential.write`               | Credentials   | Critical   | Create, rotate, or store a secret                           |
| `filesystem.delete`              | Filesystem    | High       | Delete a file-like resource                                 |
| `filesystem.read`                | Filesystem    | Low        | Read a file or file-like resource                           |
| `filesystem.write`               | Filesystem    | Medium     | Create or overwrite a file-like resource                    |
| `memory.cross_namespace.read`    | Memory        | Medium     | Cross-namespace agent memory read                           |
| `memory.cross_namespace.write`   | Memory        | High       | Cross-namespace agent memory write                          |
| `payment.purchase`               | Payments      | High       | Purchase of goods or services via a payment rail            |
| `payment.transfer`               | Payments      | Critical   | Value transfer between accounts                             |
| `system.execute`                 | System        | Critical   | Raw execution fallback; see §2.3.6 anti-convenience rule    |
| `system.install`                 | System        | High       | Install a package or runtime dependency                     |

Risk levels above are the Firma OSS v0.1 starting values. They are an
implementation choice (encoded in `registry.rs::RiskLevel`), not part of
the FEP spec. They drive telemetry grouping and default HITL thresholds;
they do NOT drive Cedar decisions on their own.

### GitHub coverage (extended in-place)

Appends 12 classes covering code/issue/repo/notification/security
domains so the OSS Sidecar can classify GitHub REST traffic deterministically
without encoding the provider into the action class. Extension is **in-place**
on `ActionClassRegistry::v0_1()` — no registry version bump. A future FEP
revision should absorb these or mark them optional.

| Action class            | Domain        | Risk     | Notes                                                 |
|-------------------------|---------------|----------|-------------------------------------------------------|
| `code.read`             | Code          | Low      | Read repository / code content                        |
| `code.review.read`      | Code          | Low      | Read pull-request review surface                      |
| `code.review.submit`    | Code          | Medium   | Submit / mutate a PR review                           |
| `code.write`            | Code          | High     | Mutate code, create or update PRs, push refs          |
| `code.destructive`      | Code          | High     | Delete files or git refs                              |
| `code.merge`            | Code          | Critical | Merge a pull request into a target branch             |
| `issue.read`            | Issue         | Low      | Read issues and issue comments                        |
| `issue.write`           | Issue         | Medium   | Create or mutate issues and issue comments            |
| `notification.manage`   | Notification  | Low      | Manage notification state / subscriptions             |
| `security.alert.read`   | Security      | Medium   | Read code-scanning / secret-scanning alerts           |
| `repo.lifecycle`        | Repo          | Medium   | Create / fork repositories                            |
| `repo.admin`            | Repo          | Critical | Mutate repo settings / branch protection              |

Reserved for a future minor revision (MUST NOT appear in v0.1 policies):
`memory.read`, `memory.write`, `browser.navigate`.

## Naming rules (FEP §2.3.2)

Registry identifiers follow `<domain>.<subdomain>.<verb>`, lowercase ASCII,
dot-separated. Identifiers describe semantic meaning. They MUST NOT encode:

- transport (`http.*`, `grpc.*`, `exec.*`);
- provider (`gmail.*`, `slack.*`, `stripe.*`);
- connector or runtime implementation (`tool.*`, `mcp.*`).

Non-conformant examples cited by the FEP spec:

- `gmail.send` — encodes provider.
- `http.post.mail` — encodes transport.
- `exec_gmail_send` — encodes transport and provider.
- `tool.email.send` — encodes implementation layer.
- `telegram.exec` — encodes transport channel and execution method.

The Firma OSS implementation MUST reject any attempt to introduce
identifiers that violate these rules, both at registry construction time
(`ActionClassRegistry::v0_1()`) and at mapping-rule load time
(`MappingTable::from_config`).

## Provider placement: resource, not action class

The same semantic action arriving via different providers MUST normalize to
the same `action_class`. Provider identity lives in `intent.resource`. Cedar
policies discriminate on the `(action, resource)` pair.

### Resource shape

`intent.resource` is a `BTreeMap<String, String>` (not a
string). `BTreeMap` guarantees deterministic iteration / serialization so
audit output is byte-stable and hashing is reproducible.

Conventional keys:

- `host` — request host (always present for HTTP intents).
- `path` — request path (always present for HTTP intents).
- `provider` — logical provider when detectable. Currently attached only
  when the request host exact-matches a known allowlist. For v0.1 the
  allowlist is `{"api.github.com", "github.com"}` → `provider = "github"`.
  Exact match is deliberate: typo-squat hostnames (e.g.
  `api.github.com.evil.example`) MUST NOT earn the tag.

Implementations MAY add free-form keys without protocol churn. No other
keys are reserved.

Scope checks and `PolicyEvaluator::evaluate` still consume a single string
derived via `ExecutionIntent::resource_display()` = `format!("{host}{path}")`.
Structured attribute access (Cedar entity attributes keyed on
`resource.provider`, etc.) is deferred to a follow-up task.

Worked example — Slack message from an agent:

- Agent call: `slack.post_message(channel = "general", text = "hello")`.
- Interceptor captures: `POST https://slack.com/api/chat.postMessage`
  with JSON body `{"channel": "general", "text": "hello"}`.
- Normalizer rule matches `host = slack.com`,
  `path = /api/chat.postMessage` and emits:
  - `intent.action_class = "communication.external.send"`
  - `intent.resource = {"host": "slack.com", "path": "/api/chat.postMessage"}`
    (no `provider` key — slack.com is not on the v0.1 allowlist)
  - `intent.params = Http { method: POST, ... }` (structured body preserved
    in params, sensitive headers stripped).
  - `intent.raw_transport = "https"`, `intent.raw_action_ref = "POST /api/chat.postMessage"`.
- Cedar evaluates with `action = Firma::Action::"communication.external.send"`
  and `resource = Firma::Resource::"slack.com/api/chat.postMessage"`
  (the display-string derivation).

A GitHub pull-request comment, a Stripe transfer, a Telegram message, and an
email microservice all produce the same-shape resource map and differ by
`host`/`path`/`provider`. A policy that wants "allow GitHub code.read only"
matches on `action_class = "code.read"` plus `resource_display` prefix
`api.github.com/`.

## Canonical mappings (authoring guidance)

Operators supply the mapping rules via the TOML file referenced by
`mapping.rules_path` (default: `mapping-rules.toml`, see
`crates/firma-sidecar/src/enforcement/config.rs`). Each rule maps
`(host, path, method)` to one registry identifier. Rules validate against
the registry at load time; unknown identifiers fail startup.

### Shipping mapping files

The sidecar ships optional ready-made mapping files under
`crates/firma-sidecar/config/mappings/`:

| File          | Covers                                                    |
|---------------|-----------------------------------------------------------|
| `github.toml` | 44 GitHub REST endpoint → 12 action class mappings (task 017) |

Enable a shipped file in one of two ways:

```toml
# Option 1 — use the shipped file as the sole mapping source.
[mapping]
rules_path = "crates/firma-sidecar/config/mappings/github.toml"

# Option 2 — merge the shipped file on top of a local default.
[mapping]
rules_path = "config/mappings/default.toml"
rules_paths = ["crates/firma-sidecar/config/mappings/github.toml"]
```

`rules_paths` (plural) is additive. Rule lists from `rules_path` and
each entry of `rules_paths` are concatenated. The
`MappingTable::from_config` loader fails closed at startup if two merged
files collide on the same `(method, host, path)` tuple.

Authoring rules:

1. Prefer the most specific class that still matches the spec domain.
   A Stripe `POST /v1/transfers` is `payment.transfer`, not
   `communication.external.send`.
2. When unsure, leave the rule out. Fail-closed behaviour
   (`UNCLASSIFIED_INTENT`) is preferable to a mis-classified ALLOW.
3. Never introduce provider-specific or transport-specific identifiers.
   If the provider's nuance matters, encode it in `resource` patterns in
   Cedar policies.

Reference mappings operators commonly use (alphabetical by host):

| Host pattern           | Method | Path pattern                     | Action class                    |
|------------------------|--------|----------------------------------|---------------------------------|
| `api.anthropic.com`    | POST   | `/v1/messages`                   | `communication.external.send`   |
| `api.github.com`       | GET    | `/repos/*/actions/secrets/*`     | `credential.read`               |
| `api.github.com`       | PUT    | `/orgs/*/members/*`              | `account.permission.change`     |
| `api.github.com`       | PUT    | `/repos/*/actions/secrets/*`     | `credential.write`              |
| `api.openai.com`       | POST   | `/v1/chat/completions`           | `communication.external.send`   |
| `api.openai.com`       | POST   | `/v1/responses`                  | `communication.external.send`   |
| `api.stripe.com`       | POST   | `/v1/charges`                    | `payment.purchase`              |
| `api.stripe.com`       | POST   | `/v1/payment_intents`            | `payment.purchase`              |
| `api.stripe.com`       | POST   | `/v1/transfers`                  | `payment.transfer`              |
| `api.telegram.org`     | POST   | `/bot*/sendMessage`              | `communication.external.send`   |
| `hooks.slack.com`      | POST   | `/services/*`                    | `communication.external.send`   |
| `pypi.org`             | POST   | `/legacy/`                       | `system.install`                |
| `registry.npmjs.org`   | PUT    | `/*`                             | `system.install`                |
| `slack.com`            | POST   | `/api/chat.postMessage`          | `communication.external.send`   |

LLM inference API calls are classified as `communication.external.send`
in Firma OSS v0.1. FEP v0.1 does not define an `llm.*` class; LLM API
calls are outbound communication to an external system. Providers (OpenAI,
Anthropic, ...) are discriminated via `resource`, not `action_class`.

## Cross-transport invariants (enforcement-relevant subset)

Policy rules and HITL conditions MUST bind to `intent.action_class` and
`intent.resource` only. `intent.raw_transport` and `intent.raw_action_ref`
are observational and MUST NOT appear in Cedar policy predicates
(FEP Invariant [I-N1]).

The same semantic action MUST normalize to the same class across transports:

- Native tool `email.send`, CLI `gmail send`, HTTP POST to a mail
  microservice, and MCP mail tool invocation all map to
  `communication.external.send`.
- Shell `rm`, filesystem tool `delete`, and an HTTP DELETE against a
  file service all map to `filesystem.delete`.
- `pip install`, `npm install`, and a package manager plugin call all
  map to `system.install`.

`system.execute` is the bounded fallback for raw execution surfaces whose
business meaning cannot be deterministically elevated into a narrower
class. It MUST NOT be used as a convenience class for actions that can
be classified more specifically (FEP §2.3.6 anti-convenience rule).

## Implementation surface

Components that bind to the registry:

- `crates/firma-sidecar/src/enforcement/registry.rs` —
  `ActionClassRegistry::v0_1()` defines the exact set of 15 names plus
  their domain and risk level. Construction MUST fail if the set drifts
  from the FEP registry.
- `crates/firma-sidecar/src/normalizer.rs` +
  `crates/firma-sidecar/src/normalizer/mapping.rs` — mapping rules validated
  against the registry at load time.
- Operator-supplied `mapping-rules.toml` (path configured via
  `mapping.rules_path` in the Sidecar config) — rule authors MUST review
  new entries against §2.3.2 naming rules and the authoring guidance in
  this document.
- `crates/firma-authority/policies/schema.cedarschema` — declares the 15
  actions for Cedar type-checking. Identifiers MUST be byte-identical to
  the Sidecar registry.
- `crates/firma-authority/src/cedar_loader.rs` — hardcoded action
  allow-list used during policy validation MUST stay in sync with the
  registry.
- `crates/firma-authority/src/service.rs` — issuance fixtures and
  capability `action_set` values MUST draw only from the registry.

A conformance test in the Sidecar crate asserts that
`ActionClassRegistry::v0_1()` returns exactly the 15 FEP identifiers
listed above, in any order. Any drift fails CI.

## Extending the registry

Operators MAY add canonical classes beyond the v0.1 set at configuration
time, provided identifiers conform to the §2.3.2 naming rules. Typical
reasons to extend: a deployment-specific domain
(e.g. `compliance.report.file`), or a finer split where the existing class
is too coarse for the policy surface (e.g. `payment.refund` distinct from
`payment.transfer`).

Per-request (runtime) extension remains forbidden — the registry is fixed
once the Sidecar loads. Identifiers added here are still subject to the FEP
compatibility contract in §Versioning: once deployed into capability
tokens, they MUST NOT be renamed or repurposed.

### Checklist

Adding a new class touches each site listed in §Implementation surface.
Every site MUST use the byte-identical identifier.

1. Pick the identifier per §Naming rules. Reject transport, provider, and
   implementation-layer names.
2. Pick the risk level (`Low` / `Medium` / `High` / `Critical`) by blast
   radius on misuse, not by observed frequency.
3. Register in `ActionClassRegistry` (`registry.rs`): add an
   `ActionClassDefinition` entry with `name`, `domain`, `risk_level`.
4. Declare in the Cedar schema (`schema.cedarschema`): add an
   `action "<name>" appliesTo { ... }` block using the shared
   `EnforcementContext`. `EnforcementContext` shape MUST NOT change.
5. Allow in the Cedar loader (`cedar_loader.rs`): add the identifier to
   the hardcoded action allow-list used during policy validation.
6. Add a mapping rule in `mapping-rules.toml` mapping concrete
   `(host, path, method)` triples to the new class. Without a mapping
   rule, traffic for this class fails closed with `UNCLASSIFIED_INTENT`.
7. Author a Cedar policy (`default.cedar` or operator bundle) with
   `permit` / `forbid` rules referencing `Firma::Action::"<name>"`.
8. Add a conformance test asserting the new identifier is present in the
   registry and in the Cedar schema, so drift between the two fails CI.

### Worked example: `payment.refund`

Scenario: an operator needs to distinguish refunds from the generic
`payment.transfer` class because refund policies differ (for instance,
no HITL below a fixed amount).

`registry.rs`:

```rust
ActionClassDefinition {
    name: "payment.refund",
    domain: "payment",
    risk_level: RiskLevel::High,
},
```

`schema.cedarschema`:

```cedar
action "payment.refund" appliesTo {
    principal: [Agent],
    resource: [Resource],
    context: EnforcementContext
};
```

`cedar_loader.rs`: add `"payment.refund"` to the action allow-list
constant.

`mapping-rules.toml`:

```toml
[[rule]]
host = "api.stripe.com"
method = "POST"
path = "/v1/refunds"
action_class = "payment.refund"
```

Cedar policy (`default.cedar` or operator bundle):

```cedar
permit(
    principal,
    action == Firma::Action::"payment.refund",
    resource
) when {
    resource like "api.stripe.com/v1/refunds"
};
```

### What MUST NOT change

- `EnforcementContext` shape. Fields are consumed by
  `ConstraintEnforcer::build_context`; adding fields breaks the Sidecar
  and removing fields breaks operator policies.
- The `Firma::` namespace and the `Agent` / `Resource` entity types.
  Policies across all deployments bind to these names.
- Existing v0.1 identifiers. Renaming invalidates capability tokens
  already in flight.
- Reserved identifiers (`memory.read`, `memory.write`, `browser.navigate`).
  These are held for a future FEP minor revision and MUST NOT be
  introduced as operator extensions.

## Versioning

The registry is versioned with the FEP protocol. Compatibility rules
(FEP §2.3.7):

- existing identifiers MUST NOT be renamed in a compatible revision;
- new identifiers MAY be added in a minor revision;
- identifiers MAY be deprecated but MUST NOT be silently repurposed;
- removal requires a major protocol revision.

Firma OSS tracks the FEP registry version through the `ActionClassRegistry`
constructor (`v0_1`). A future `v0_2` constructor adds new classes without
removing existing ones. Callers that enumerate actions MUST read from the
registry instance; hardcoding identifier lists elsewhere is a drift hazard
and should be reviewed against this document.
