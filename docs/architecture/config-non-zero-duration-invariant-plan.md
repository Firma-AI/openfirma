# Non-Zero Configuration Durations

## Artifact metadata

- Status: Accepted
- Durable locator: `docs/architecture/config-non-zero-duration-invariant-plan.md`
- Repository revision researched:
  `352a61ffc8ef4f0927b71cd51f247727ee33d313` (the exact inspected tip of PR
  #609)
- Task or requirement source:
  [stacked implementation request](https://ampcode.com/threads/T-01a03f40-5cc8-741b-9568-f3166944abcd)
- Supersedes: Not applicable

## Goal and acceptance outcomes

- Goal: move the strictly-non-zero invariant for configuration durations whose field
  contract requires a non-zero value from duplicated runtime validation into one reusable public schema
  value type, without changing the unit-bearing TOML representation introduced
  by PR #609.
- Observable acceptance outcomes:
  - `firma_config_schema::utils::NonZeroDuration` can represent every non-zero
    `std::time::Duration`, including sub-millisecond values, but rejects zero
    through public construction and deserialization.
  - The 13 fields in `AUDIT-001` classified as operation bounds, waits, retry
    delays, backoffs, or session-lifetime controls deserialize through
    `NonZeroDuration`.
  - Equivalent Jiff-friendly zero spellings fail while existing compact
    duration strings and serialization round trips remain unchanged.
  - Converted runtime consumers receive the same effective `Duration`; their
    duplicate zero checks disappear while cross-field and representability
    checks remain.
  - The final history contains the value type first and then one distinct
    revision per converted field.

## Scope

- In scope:
  - Every `Duration` and `Option<Duration>` field exported by
    `firma-config-schema` at the researched revision.
  - Direct gateway consumers and the `firma-run` / `firma-sidecar` validated
    configuration boundaries that consume converted fields.
  - Focused schema contract, conversion, and consumer tests plus concise
    configuration-reference clarification.
- Out of scope:
  - A generic constrained-duration abstraction, TTL type, grace-period type,
    or other scalar newtypes.
  - Changing defaults, effective durations, field names, compact
    human-readable TOML syntax, protocol units, or cross-field semantics.
  - Converting internal runtime durations that do not originate in the public
    schema.
- Assumptions:
  - The parent PR's scalar representation and field inventory are stable in
    tree content even while its commit history is rewritten.
  - Jiff's unsigned friendly compact Serde helper remains the representation
    owner for schema durations.
- Open decisions: None. `AUDIT-001` resolves the only semantic classification
  question using field documentation and terminal consumers.
- Cohesion and split assessment: one value type owns one invariant. Each field
  adoption is independently reviewable and will be committed separately as
  required, but splitting 13 child plans would duplicate the same ownership
  decision without creating independent design boundaries.
- Deferred child plans: Not applicable.

## Routing

- Mode: Full
- Trigger evidence: this changes a published Rust API, a stable configuration
  validation contract, and the owner of a non-zero invariant across schema and
  runtime crate boundaries.
- Higher-mode triggers checked: stable configuration/public API and invariant
  ownership both require Full planning.
- Downgrade evidence and reason: Not applicable.

## Current behavior and problem

- Owners and entry points:
  - `firma-config-schema` owns public Serde shapes but currently exposes raw
    `Duration` values.
  - Jiff field attributes parse compact unsigned duration strings.
  - `firma-run` and `firma-sidecar` reject zero after deserialization for most
    timeout-like values; the secret-gateway client consumes two timeout values
    directly and currently accepts zero.
- Current success and failure outcomes:
  - Non-zero checks are repeated in component conversion code and error enums.
  - Programmatic schema construction can bypass the intended non-zero
    contract, and gateway zero values reach Tokio timeout calls directly.
  - Zero rejection happens later than representation validation and is not
    uniform across schema consumers.
- Evidence:
  - `crates/firma-config-schema/src/run.rs: CapabilityLeasePatch,
    CommandMediatorPatch`
  - `crates/firma-config-schema/src/gateway.rs: GatewayClientConfig`
  - `crates/firma-config-schema/src/sidecar/{authority,connector,enforcement,
    interceptor,local_exec}.rs`
  - `crates/firma-run/src/config.rs: ResolvedProfile::validate`
  - `crates/firma-sidecar/src/config/{authority,connector}.rs`
  - `crates/firma-sidecar/src/config/mod.rs: InterceptorConfig::try_from,
    ConnectRelayConfig::try_from, LocalExecConfig::try_from`

## Key decisions and tradeoffs

### `DEC-001`: Use one predicate-specific `NonZeroDuration` newtype

- Choice: add public `firma_config_schema::utils::NonZeroDuration(Duration)` with a
  private field, a validating constructor and `TryFrom<Duration>`, copied inner
  access, `From<NonZeroDuration> for Duration`, a dedicated public zero-value error,
  manual Serde, and the useful value traits supported by `Duration`. Define a
  checked crate-private `from_static` constructor for compile-evaluated shipped
  defaults, so sibling schema modules have an infallible, lint-compliant path
  without exposing unchecked public construction.
- Rationale and evidence: all included fields share exactly one invariant and
  one representation. A private field plus validating public construction
  closes programmatic and Serde construction paths without a generic
  constrained-value framework.
- Consequences and rejected alternatives:
  - Reject a generic constrained-value or policy-parameter type: there is one
    needed predicate and no second constraint family.
  - Reject `Deref`: explicit copied inner access makes the schema-to-runtime
    boundary visible and does not pretend `NonZeroDuration` is interchangeable in
    every semantic role.
  - Reject an unchecked default constructor: `from_static` asserts the same
    predicate while its field-local constant callers force evaluation during
    compilation. It is crate-private and does not expand the public API.
  - Keep validated runtime fields as `Duration` where that is their established
    internal contract; convert once after schema deserialization.

### `DEC-002`: Preserve Jiff's exact duration representation

- Choice: manually deserialize a `Duration` with
  `jiff::fmt::serde::unsigned_duration::friendly::compact::required`, then call
  the invariant-owning constructor and map its zero error through Serde.
  Serialize the inner `Duration` with the matching Jiff helper.
- Rationale and evidence: delegating syntax to the same helper preserves every
  accepted non-zero spelling and emitted format from PR #609. Validation after
  parsing rejects all syntax-equivalent zero values rather than matching
  strings.
- Consequences and rejected alternatives: no custom duration parser, aliases,
  numeric compatibility form, or schema syntax migration is introduced.

### `DEC-003`: Include by operational role, not merely by non-zero validation

- Choice: adopt `NonZeroDuration` in this change for fields whose established
  contract requires a non-zero operation bound, deadline, wait/retry interval,
  backoff, or session lifetime. Keep TTLs, cache retention, clock-skew
  tolerance, and refresh/readiness grace values as `Duration`, including when
  their zero validity depends on runtime context.
- Rationale and evidence: the type communicates only the reusable non-zero
  invariant; field names and documentation communicate operational roles. This
  migration follows demonstrated field contracts instead of converting every
  `Duration` mechanically. `AUDIT-001` traces all 20 fields to their consumers.
- Consequences and rejected alternatives:
  - `capability.grace`, `cert_ttl`, and `token_ttl` keep their existing
    downstream non-zero checks because their contracts are distinct from the controls migrated here.
  - `clock_skew_tolerance` and `revocation_readiness_grace` retain meaningful
    strict/immediate zero behavior.
  - `reconnect_*_backoff` and `retry_after` are included because they are
    explicit retry waits; `session_max` is included because it is a hard
    session-lifetime deadline.

### `DEC-004`: Move only the owned predicate

- Choice: remove each converted field's downstream `is_zero` check and
  zero-specific error variant/test. Preserve host/rate checks, reconnect
  ordering, minimum wire-unit and range checks, endpoint/path checks, and every
  other cross-field condition.
- Rationale and evidence: a duplicate check is unreachable after construction,
  but stronger or relational predicates are not implied by `NonZeroDuration`.
- Consequences and rejected alternatives: deserialized zero now fails at the
  field boundary with a Serde error identifying the field and the reusable
  non-zero message. No validation is weakened.

## Architecture and invariant ownership

- Architecture shape:

```diagram
┌────────────────────┐  Jiff parse   ┌──────────────────────────────┐
│ compact TOML value │──────────────▶│ NonZeroDuration::deserialize │
└────────────────────┘               │ Duration → TryFrom           │
                                     └──────────────┬───────────────┘
                                                  │ non-zero only
                                                  ▼
                                     ┌──────────────────────────┐
                                     │ public schema field      │
                                     └────────────┬─────────────┘
                                                  │ duration()
                                                  ▼
                                     ┌──────────────────────────┐
                                     │ existing runtime consumer│
                                     └──────────────────────────┘
```

### `INV-001`: Public `NonZeroDuration` values are strictly non-zero

- Semantic predicate: for every publicly constructible or deserializable
  `t: NonZeroDuration`, `t.duration() != Duration::ZERO`.
- Primary owner: `firma_config_schema::utils::NonZeroDuration` field privacy,
  constructor/`TryFrom`, and manual `Deserialize`.
- Detailed proof: `CW-001`, `TRACE-NON-ZERO-DURATION-PARSE`, and `PROOF-001`.

### `INV-002`: Included fields preserve duration meaning and representation

- Semantic predicate: every previously accepted non-zero compact duration for
  an included field yields the same terminal `Duration`, and serialization
  remains Jiff-friendly compact; only zero changes from accepted-or-late-error
  to field-boundary rejection.
- Primary owner: each schema field type and its schema-to-runtime conversion or
  direct consumer.
- Detailed proof: `AUDIT-001`, `TRACE-FIELD-ADOPTION`, and `PROOF-002`.

- Compatibility, migration, and failure semantics: `DEC-002` through
  `DEC-004`. This tightens validation but does not migrate syntax. Zero is an
  intentional newly uniform parse-time error for included fields.
- Durable documentation owner: this audit and `docs/configuration.md`; Rust API
  semantics live on `utils::NonZeroDuration`.

## Implementation slices

### Slice 1: Add the reusable invariant owner

- Production, types, tests, and docs/config: add public `utils`, `NonZeroDuration`, its
  error/conversions/accessor/manual Serde and Rust docs; add integration tests
  for friendly values, equivalent zero spellings, sub-millisecond values,
  constructor/`TryFrom`, and serialization round trip. Refine the crate-level
  documentation to state that schema value types own intrinsic constructibility
  invariants while components retain cross-field, lifecycle, environment, and
  representability validation. Commit this plan and its review log with the
  type implementation.
- Affected decisions and traces: `DEC-001`, `DEC-002`,
  `TRACE-NON-ZERO-DURATION-PARSE`.
- Proof obligations: `INV-001`, `PROOF-001`.
- Focused verification: `cargo nextest run -p firma-config-schema` and
  `cargo test -p firma-config-schema --doc`.
- Dependencies: exact PR #609 tree.
- Intentionally unsupported: no schema field is converted in this revision.

### Slices 2–14: Adopt one field per revision

- Production, types, tests, and docs/config: in this exact order, convert one
  field and its default, runtime boundary/consumer, duplicate validation, and
  focused tests per revision:
  1. `sidecar.secret_gateway.connection_timeout`
  2. `sidecar.secret_gateway.operation_timeout`
  3. `run.*.sidecar_local_exec.timeout`
  4. `run.*.sidecar_local_exec.hitl_max_wait`
  5. `sidecar.authority.connect_timeout`
  6. `sidecar.authority.reconnect_min_backoff`
  7. `sidecar.authority.reconnect_max_backoff`
  8. `sidecar.interceptor.drain_timeout`
  9. `sidecar.interceptor.connect_relay.setup_timeout`
  10. `sidecar.interceptor.connect_relay.session_max`
  11. `sidecar.connector.default_timeout`
  12. `sidecar.connector.hosts[].timeout`
  13. `sidecar.local_exec.retry_after`
- Affected decisions and traces: `DEC-003`, `DEC-004`,
  `TRACE-FIELD-ADOPTION`.
- Proof obligations: `INV-002`, `PROOF-002`; each revision proves the same
  obligation for only its named field.
- Focused verification: config-schema tests plus the directly affected gateway,
  Run, or Sidecar crate tests and targeted Clippy in every field revision. For
  `retry_after`, retain explicit below-1ms and overflow conversion tests.
- Dependencies: Slice 1, then the preceding field revision.
- Intentionally unsupported: fields listed as excluded in `AUDIT-001`.

### Slice 15: Document the complete classification

- Production, types, tests, and docs/config: update `docs/configuration.md`, the
  human-facing
  `docs-site/src/content/docs/guides/run-the-sidecar.md` guidance, and
  `docs-site/public/llms.txt` with the concise inclusion/exclusion rule and
  earlier field-boundary failure. Keep existing field tables/examples and
  compact syntax unchanged. Do not convert fields here.
- Affected decisions and traces: `DEC-003`, `AUDIT-001`.
- Proof obligations: audit completeness only.
- Focused verification: dprint checks for all three documentation owners and
  repository searches proving all 20 fields remain accounted for.
- Dependencies: all field slices.
- Intentionally unsupported: field conversion or behavior changes.

## Risks and gaps

- Existing risks: public struct literals and tests must adapt to the field type
  changes; direct gateway consumers have no intermediate validation layer.
- Planned mitigations: copied inner access, per-field commits and targeted
  tests, repository-wide constructor search, final workspace build/lint/test,
  and fresh independent implemented-change review.
- Explicit evidence gaps: external Rust consumers cannot be inspected. The PR
  will call out the public type change while preserving TOML syntax.
- Least-confident decisions: excluding `capability.grace` despite its current
  non-zero check. It is a refresh lead-time margin with existing
  component-owned validation, outside this migration's selected operation,
  wait, retry, backoff, and session-lifetime controls.

## Plan-review findings and dispositions

The fresh independent reviewer inspected the exact researched revision. Its
records are preserved verbatim below; each is followed by the planner's
disposition.

### PLAN-001 — Converted field defaults lack a constructible, lint-compliant design

- **Severity:** Medium
- **Category:** Implementability / invariant ownership
- **Classification:** Confirmed conflict
- **Evidence:**
  - The plan specifies only:
    - `NonZeroDuration::new(Duration) -> Result<NonZeroDuration, ZeroDurationError>`
    - `TryFrom<Duration>`
    - a private tuple field.
  - Existing converted fields use infallible default functions returning raw
    `Duration`, including:
    - `crates/firma-config-schema/src/gateway.rs:19-29,33-48`
    - `crates/firma-config-schema/src/sidecar/authority.rs:44-60,93-126`
    - `crates/firma-config-schema/src/sidecar/interceptor.rs:67-71,116-126`
    - `crates/firma-config-schema/src/sidecar/connector.rs:19-31`
    - `crates/firma-config-schema/src/sidecar/local_exec.rs:42-53`
  - Serde `default = "..."` functions must return the field type directly.
  - Repository lint policy denies `unwrap`, `expect`, and `panic`; therefore a
    default in a sibling module cannot turn a known-valid
    `Result<NonZeroDuration, _>` into `NonZeroDuration` using the usual unreachable-error
    patterns.
  - Slice 1 explicitly leaves all fields unconverted, while Slices 2–14 say
    each field's default is converted, but neither `DEC-001` nor the type sketch
    defines constants or another infallible validated construction path.
- **Reachability:** During any field-adoption slice with a default, changing the
  field to `NonZeroDuration` requires its Serde/default constructor to return `NonZeroDuration`.
  The planned public API provides only fallible construction and hides the
  tuple field from the field-owning module. Implementation either fails to
  compile, violates workspace lints, or introduces an unplanned bypass/constant
  API.
- **Invariant owner:** `firma_config_schema::utils::NonZeroDuration`, specifically the
  claim that all construction remains owned by its validating boundary.
- **Practical impact:** The prescribed per-field commits cannot each remain
  independently buildable without making an additional public or crate-private
  API decision. An improvised unchecked constructor could also weaken the
  stated single-owner design.
- **Correction:** Amend `DEC-001`, the signature sketch, and Slice 1 to define
  the infallible path before field conversion. Prefer validated public
  associated constants for shipped defaults, or explicitly specify a narrowly
  scoped crate-private construction mechanism and explain why it preserves
  `INV-001`. Add proof that every intermediate per-field revision builds under
  the repository lint policy.
- **Confidence:** High
- **Assumptions:** No existing stable Rust facility used by this workspace can
  infallibly extract `Ok` from this specific `Result` in const/default code
  without an additional API or a denied panic path.

Disposition:

- Status: Corrected
- Rationale: `DEC-001` and the type sketch now define a checked crate-private
  `from_static` constructor used only by compile-evaluated field-local
  constants. Every shipped default can return one directly without fallible
  extraction, unchecked construction, or public API expansion. Per-field
  focused verification includes build and lint viability.
- Incorporated at: `DEC-001`, Slice 1, and Types and signatures
- Decided by: Planner

### PLAN-002 — The plan leaves the schema crate's canonical validation boundary documentation false

- **Severity:** Medium
- **Category:** Architecture documentation / ownership
- **Classification:** Confirmed conflict
- **Evidence:**
  - `crates/firma-config-schema/src/lib.rs:1-16` declares the crate
    “behavior-free,” says it contains “representation only,” “deliberately
    holds no validation,” and places validation inside consuming components.
  - `crates/firma-config-schema/src/gateway.rs:1-4` similarly states that the
    schema type carries no behavior.
  - The proposed `NonZeroDuration` deliberately moves non-zero validation into this
    crate and removes corresponding component validation.
  - Slice 1 mentions Rust documentation on `utils::NonZeroDuration`, but the file-tree
    diff and implementation slices do not update these crate/module-level
    ownership statements.
- **Reachability:** A maintainer or external API consumer reading the crate's
  canonical documentation after implementation will be told that validation
  is downstream even though zero rejection is now owned by schema
  construction/deserialization. This directly contradicts `DEC-001`,
  `DEC-004`, and `INV-001`.
- **Invariant owner:** The schema/runtime validation boundary documented by
  `firma-config-schema`.
- **Practical impact:** Future fields or consumers may reintroduce duplicate
  checks or avoid the validated type based on stale architectural guidance;
  generated crate documentation will misdescribe the public API's operational
  contract.
- **Correction:** Add `crates/firma-config-schema/src/lib.rs` and affected
  representation-only module documentation to Slice 1/field slices. Define the
  refined boundary explicitly: the schema crate may own intrinsic scalar
  constructibility invariants, while consuming components continue to own
  cross-field, environment, lifecycle, and representability validation.
- **Confidence:** High
- **Assumptions:** The existing crate-level documentation remains the canonical
  statement of this boundary.

Disposition:

- Status: Corrected
- Rationale: Slice 1 now updates the canonical crate-level boundary. Each field
  slice will also correct affected module prose when it currently claims the
  type has no behavior or that downstream code owns the moved predicate.
- Incorporated at: Slice 1 and Slices 2–14
- Decided by: Planner

### PLAN-003 — Required user-facing configuration documentation is conditional and omits the docs-site owner

- **Severity:** Low
- **Category:** Documentation / compatibility communication
- **Classification:** Confirmed conflict
- **Evidence:**
  - The change intentionally makes zero fail earlier and uniformly for 13
    stable configuration fields.
  - Repository guidance requires docs-site updates for major configuration or
    public API changes.
  - Slice 15 updates only `docs/configuration.md`, and only “if needed.”
  - Existing user-facing coverage is split across:
    - `docs/configuration.md` entries for the adopted fields, including current
      greater-than-zero statements.
    - `docs-site/src/content/docs/guides/secret-gateway.md`, which exposes
      secret-gateway timeout configuration.
    - `docs-site/src/content/docs/guides/deploy-a-genai-webapp.md`, which exposes
      Authority backoffs.
    - `docs-site/public/llms.txt`, which summarizes unit-bearing duration
      syntax.
- **Reachability:** Users supplying a zero spelling reach schema deserialization
  rather than the previous component-specific validation path. Without a
  planned docs-site update, the externally observable validation contract is
  changed while the principal integration documentation remains silent.
- **Invariant owner:** Stable `firma.toml` configuration contract and its
  user-facing documentation.
- **Practical impact:** Users may see a new parse-time failure without
  documentation explaining that timeout/deadline/wait controls are strictly
  non-zero while TTL, skew, and readiness/grace fields intentionally retain
  distinct zero semantics.
- **Correction:** Make documentation non-conditional. Identify the specific
  canonical docs-site page that will state the inclusion rule and changed
  failure boundary, update relevant field tables/examples where necessary, and
  assess whether `docs-site/public/llms.txt` needs the concise semantic
  distinction. Keep `docs/configuration.md` synchronized rather than treating
  it as the only owner.
- **Confidence:** High
- **Assumptions:** This stable configuration-validation change qualifies as a
  major configuration/public API change under repository guidance.

Disposition:

- Status: Corrected
- Rationale: Slice 15 is now required and names all documentation layers:
  `docs/configuration.md`, a human-facing docs-site guide, and discovery text.
  It documents the complete semantic rule and earlier failure boundary while
  preserving syntax and examples.
- Incorporated at: Slice 15
- Decided by: Planner

## Final verification

- Focused checks: per-slice config-schema and directly affected consumer tests.
- Workspace checks: formatting, build, lint, unnecessary-public-API check,
  full nextest suite, doctests, and final `just check`/repository verification
  as directed by the verification skill.
- Post-implementation independent review: fresh adversarial review of the
  exact base-to-head diff, including Rust-specific review, with every finding
  disposition recorded before push.

## Technical evidence

### Applicability assessment

| Section                     | Applicability  | Reason or evidence                                     |
| --------------------------- | -------------- | ------------------------------------------------------ |
| Vocabulary                  | Applicable     | The type must name only its non-zero predicate.        |
| Alternatives                | Applicable     | Predicate and policy-based boundaries were viable.     |
| File-tree diff              | Applicable     | A new public schema module is added.                   |
| Type and signature sketches | Applicable     | Public construction establishes the invariant.         |
| Semantic call traces        | Applicable     | Values cross schema and runtime crate boundaries.      |
| Trust analysis              | Not applicable | This is input validation, not an authority transition. |
| Detailed proof obligations  | Applicable     | Type and representation claims need executable proof.  |

### Vocabulary

| Canonical term    | Meaning                                              | Owner/context            | Terms to avoid                    |
| ----------------- | ---------------------------------------------------- | ------------------------ | --------------------------------- |
| Non-zero duration | A duration whose field contract strictly excludes 0. | `utils::NonZeroDuration` | Timeout when the role is broader. |
| Timeout           | A bound on completing an operation.                  | Field names and docs     | Non-zero duration as a role name. |
| TTL               | Lifetime/freshness of an issued or cached artifact.  | Existing schema fields   | Timeout.                          |
| Grace             | Margin/window around a lifecycle transition.         | Existing schema fields   | Timeout unless it bounds a wait.  |

### Alternatives

- **Selected: predicate-specific `NonZeroDuration`.** Owns exactly the
  duplicated predicate, accurately covers timeouts, waits, retries, backoffs,
  and session lifetimes, and keeps call-site conversion explicit.
- **Rejected: policy-parameterized constrained duration.** Adds traits or
  policy parameters for one predicate and one concrete value type.
- **Rejected: keep raw `Duration` plus custom field deserializers.** Repeats the
  predicate and leaves programmatic construction able to bypass it.
- **Rejected: convert every duration mechanically.** Several TTL and
  refresh-grace fields retain distinct or contextual validation, while skew and
  readiness settings have meaningful zero values.

### File-tree diff

```diff
crates/firma-config-schema/src
~├── lib.rs                 # export public utils module
+├── utils.rs               # NonZeroDuration invariant and Serde owner
~├── gateway.rs             # two adopted fields
~├── run.rs                 # two adopted fields
~└── sidecar
~    ├── authority.rs       # three adopted fields
~    ├── connector.rs       # two adopted fields
~    ├── interceptor.rs     # three adopted fields
~    └── local_exec.rs      # one adopted field
+crates/firma-config-schema/tests/schema.rs
~crates/firma-run/src/config.rs
~crates/firma-secret-provider/src/gateway/client/mod.rs
~crates/firma-sidecar/src/config/{authority,connector}.rs
~crates/firma-sidecar/src/config/mod.rs
~docs/configuration.md
~docs-site/src/content/docs/guides/run-the-sidecar.md
~docs-site/public/llms.txt
```

### Types and signatures

```rust
pub struct NonZeroDuration(Duration);

impl NonZeroDuration {
    pub const fn new(duration: Duration) -> Result<Self, ZeroDurationError>;
    pub const fn duration(self) -> Duration;
    pub(crate) const fn from_static(duration: Duration) -> Self;
}

impl TryFrom<Duration> for NonZeroDuration;
impl From<NonZeroDuration> for Duration;
impl Serialize for NonZeroDuration;
impl<'de> Deserialize<'de> for NonZeroDuration;
```

`CW-001` constructibility attack:

```rust,compile_fail
use firma_config_schema::utils::NonZeroDuration;
use std::time::Duration;

let direct = NonZeroDuration(Duration::ZERO); // private tuple field
let constructed = NonZeroDuration::new(Duration::ZERO)?; // returns Err
let converted = NonZeroDuration::try_from(Duration::ZERO)?; // returns Err
let parsed: NonZeroDuration = toml::from_str("0ms")?; // returns a Serde error
```

The type proves value cardinality only: its wrapped duration is non-zero. It
does not prove semantic provenance, field role, ordering between min/max
backoffs, millisecond representability, or runtime scheduling.

### Semantic call traces

| Trace ID                        | State    | Entry and path                                                                                                               | Invariant / outcome                                                                                             |
| ------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `TRACE-NON-ZERO-DURATION-PARSE` | Proposed | TOML/JSON scalar → Jiff required compact deserializer → `Duration` → `NonZeroDuration::try_from`                             | Non-zero yields `NonZeroDuration`; zero yields a clear Serde field error.                                       |
| `TRACE-FIELD-ADOPTION`          | Proposed | included schema field → component `TryFrom` or gateway consumer → `NonZeroDuration::duration()` → existing runtime operation | Existing non-zero values and syntax retain the same terminal `Duration`; zero cannot cross the schema boundary. |

### Detailed duration-field audit

`AUDIT-001` is complete for all 20 duration-valued fields under
`crates/firma-config-schema/src` at the researched revision.

| Schema field                                         | Classification            | Decision and rationale                                                                          |
| ---------------------------------------------------- | ------------------------- | ----------------------------------------------------------------------------------------------- |
| `authority.max_ttl`                                  | Token TTL                 | Exclude: artifact lifetime, not a timeout; zero currently means immediate expiry.               |
| `authority.bundle_ttl`                               | Bundle freshness TTL      | Exclude: advertised artifact freshness lifetime; zero currently means immediately stale.        |
| `sidecar.secret_gateway.connection_timeout`          | Connect deadline          | Include: directly bounds connection establishment; zero currently reaches Tokio.                |
| `sidecar.secret_gateway.operation_timeout`           | Operation deadline        | Include: directly bounds write/read exchange; zero currently reaches Tokio.                     |
| `run.*.capability.grace`                             | Refresh lead-time grace   | Exclude: non-zero today but semantically a renewal margin rather than a timeout or retry delay. |
| `run.*.sidecar_local_exec.timeout`                   | RPC timeout               | Include: directly bounds mediation request I/O.                                                 |
| `run.*.sidecar_local_exec.hitl_max_wait`             | Approval deadline         | Include: directly bounds total fail-closed approval wait.                                       |
| `sidecar.authority.connect_timeout`                  | Connect timeout           | Include: directly bounds tonic connection establishment.                                        |
| `sidecar.authority.reconnect_min_backoff`            | Retry wait floor          | Include: bounds retry sleep; retain `max >= min`.                                               |
| `sidecar.authority.reconnect_max_backoff`            | Retry wait ceiling        | Include: bounds retry sleep; retain `max >= min`.                                               |
| `sidecar.authority.revocation_readiness_grace`       | Readiness grace           | Exclude: zero intentionally makes readiness immediate.                                          |
| `sidecar.interceptor.drain_timeout`                  | Shutdown drain wait       | Include: directly bounds in-flight shutdown wait.                                               |
| `sidecar.interceptor.connect_relay.setup_timeout`    | Setup timeout             | Include: bounds CONNECT/TLS setup operations.                                                   |
| `sidecar.interceptor.connect_relay.session_max`      | Session lifetime deadline | Include: hard deadline for a live relay session.                                                |
| `sidecar.interceptor.https_mitm.cert_ttl`            | Certificate/cache TTL     | Exclude: cached artifact retention; zero is conditionally valid while MITM is inactive.         |
| `sidecar.connector.default_timeout`                  | Dispatch timeout          | Include: bounds fallback HTTP dispatch.                                                         |
| `sidecar.connector.hosts[].timeout`                  | Dispatch timeout          | Include: bounds per-host HTTP dispatch.                                                         |
| `sidecar.capability_validation.clock_skew_tolerance` | Expiry tolerance          | Exclude: zero explicitly means strict expiry.                                                   |
| `sidecar.local_exec.token_ttl`                       | Approval-token TTL        | Exclude: issued artifact lifetime, not a timeout.                                               |
| `sidecar.local_exec.retry_after`                     | Retry wait                | Include: retry delay; retain the stronger ≥1ms and wire-range checks.                           |

### Detailed proof obligations

| ID          | Invariant | Kind / boundary                  | Stimulus and observable effects                                                                                                                                                   | Status / slice        |
| ----------- | --------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| `PROOF-001` | `INV-001` | Type + Serde integration tests   | Friendly non-zero and sub-ms values construct/parse; constructor, `TryFrom`, and equivalent friendly zero spellings fail; serialization round trips.                              | Planned / Slice 1     |
| `PROOF-002` | `INV-002` | Schema and consumer config tests | Each included field accepts its existing default/example, rejects zero at deserialization, converts to the exact prior runtime `Duration`, and retains relational/range failures. | Planned / Slices 2–14 |
