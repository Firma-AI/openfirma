# Non-Zero Authority TTL Configuration

## Artifact metadata

- Status: Accepted
- Durable locator: `docs/architecture/authority-non-zero-ttl-plan.md`
- Repository revision researched:
  `aab452655a76395f99c48eeedb7c2be500a137ea` (the exact rewritten tip of PR
  #610 exposing `firma_config_schema::utils::NonZeroDuration`)
- Task or requirement source:
  [stacked configuration-hardening request](https://ampcode.com/threads/T-01a03f40-5cc8-741b-9568-f3166944abcd)
- Supersedes: Not applicable

## Goal and acceptance outcomes

- Goal: make non-zero lifetime an intrinsic configuration-boundary invariant
  for Authority token and policy-bundle TTLs, while preserving every valid
  duration's syntax, default, effective value, and runtime behavior.
- Observable acceptance outcomes:
  - `[authority].max_ttl` and `[authority].bundle_ttl` deserialize as
    `firma_config_schema::utils::NonZeroDuration`.
  - Friendly compact zero spellings fail with the field path and
    `duration must be greater than zero`; unsigned Jiff parsing continues to
    reject negative duration strings.
  - Defaults remain exactly `1h` and `30s`; non-zero values still require whole
    seconds and fit the existing `i32` / `u32` runtime and wire ranges.
  - Legacy `FIRMA_AUTHORITY_MAX_TTL_SECONDS=0` and
    `FIRMA_AUTHORITY_BUNDLE_TTL_SECONDS=0` fail startup with field-specific
    errors instead of creating immediate-expiry or immediately-stale state.
  - Positive legacy environment values still override TOML independently;
    malformed, negative, unit-bearing, and overflowing legacy values remain
    ignored as before.
  - `firma config` refuses an otherwise unmigrated legacy zero `_seconds` value
    rather than emitting a strict-schema-invalid `"0s"`; a canonical non-zero
    replacement still wins deterministically when both forms coexist.
  - The final PR history contains separate behavior revisions for `max_ttl` and
    `bundle_ttl`, and its tip contains no plan Markdown.

## Scope

- In scope:
  - Public Authority schema field types, defaults, serialization, and focused
    schema tests.
  - Schema-to-runtime and runtime-to-schema conversion, whole-second/range
    validation, and embedded and standalone Authority loading.
  - Both legacy `_SECONDS` environment compatibility paths and their exhaustive
    precedence/edge matrices.
  - Raw `firma config` migration of legacy Authority scalar keys, including
    zero, coexistence, attached comments, and strict-schema validation.
  - Configuration reference, Authority-facing docs, and discovery text.
- Out of scope:
  - Renaming TOML keys, environment variables, runtime integer fields, or wire
    protocol fields.
  - Changing requested-token TTL clamping, bundle refresh cadence, Sidecar
    staleness behavior, or any non-zero effective duration.
  - Applying `NonZeroDuration` to other TTL, grace, skew, or cache fields.
- Assumptions:
  - PR #610's public `NonZeroDuration` API and compact Jiff representation are
    stable at the researched revision; the branch will be fetched and this
    work rebased onto its exact latest remote head before verification/push.
  - Legacy environment compatibility deliberately continues to use integer
    seconds rather than accepting unit-bearing strings.
- Open decisions: None. The requirement explicitly selects rejection for zero
  and preservation for malformed/overflow environment input; `DEC-003` records
  the only necessary boundary distinction.
- Cohesion and split assessment: the two fields share one schema invariant and
  one environment/migration policy, but each has an independently observable
  runtime failure mode and must be a distinct atomic revision. Separate child
  plans would repeat the same boundary design without adding an independent
  owner or shipping outcome.
- Deferred child plans: Not applicable.

## Routing

- Mode: Full
- Trigger evidence: this intentionally breaks a stable configuration contract
  and public Rust field types, changes validation ownership, and closes a
  fail-closed policy-bundle producer/consumer inconsistency.
- Higher-mode triggers checked: stable configuration/public API, invariant
  ownership, and fail-closed behavior all independently require Full planning.
- Downgrade evidence and reason: Not applicable.

## Current behavior and problem

- Owners and entry points:
  - `firma-config-schema::authority::AuthorityConfig` currently exposes both
    TTLs as unconstrained `Duration` with Jiff compact Serde attributes.
  - `firma-authority::AuthorityConfig` narrows them to whole-second `i32` and
    `u32`, then applies legacy environment overrides directly to those integer
    fields.
  - `firma config` migrates legacy integer keys to compact strings before the
    generated section is strict-schema checked.
  - Token issuance/clamping consumes `max_ttl_seconds`; the Cedar loader and
    protobuf bundle path consume `bundle_ttl_seconds`.
- Current success and failure outcomes:
  - TOML zero reaches a zero runtime integer; the legacy environment paths can
    also inject zero after schema parsing.
  - Maximum TTL zero creates immediately expiring capabilities.
  - Bundle TTL zero can be advertised by Authority even though the Sidecar
    rejects a zero wire TTL, so producer and consumer constraints disagree.
  - `firma config` currently rewrites a legacy zero to `"0s"`, which would
    become invalid after moving the invariant into the schema.
- Evidence:
  - `crates/firma-config-schema/src/authority.rs:AuthorityConfig`
  - `crates/firma-authority/src/config.rs:AuthorityConfig,
    apply_env_overrides, TryFrom<schema::AuthorityConfig>`
  - `crates/firma-authority/src/issuance.rs:issue_capability`
  - `crates/firma-authority/src/cedar_loader.rs:CedarPolicyStore`
  - `crates/firma-sidecar/src/authority_client/policy_bundle.rs`
  - `crates/firma/src/services/config/doc.rs:ensure_authority_section,
    migrate_integer_duration`
  - `crates/firma-authority/tests/integration/config.rs`

## Key decisions and tradeoffs

### `DEC-001`: Make each public schema field a `NonZeroDuration`

- Choice: remove the field-local Jiff Serde attributes and use PR #610's
  `NonZeroDuration` directly. Construct shipped defaults with its crate-private
  checked static constructor and unwrap the copied duration only at the
  Authority whole-second/range conversion boundary.
- Rationale and evidence: `NonZeroDuration` already owns public construction,
  compact serialization, and equivalent-zero rejection. Reusing it makes zero
  unrepresentable in schema values and avoids a TTL-specific wrapper with the
  same predicate.
- Consequences and rejected alternatives:
  - Reject a second TTL newtype: no additional TTL predicate is requested, and
    it would duplicate PR #610's exact ownership contract.
  - Reject aliases or a custom parser: valid TOML syntax must remain unchanged.
  - Keep whole-second and range checks downstream because non-zero does not
    prove runtime or wire representability.

### `DEC-002`: Keep runtime seconds, but make reverse conversion fallible

- Choice: retain existing `i32 max_ttl_seconds` and `u32 bundle_ttl_seconds`
  runtime fields and consumers. Replace the infallible runtime-to-schema
  conversion with `TryFrom<&AuthorityConfig>`, so directly constructed runtime
  zero values cannot be silently converted, defaulted, or wrapped as a valid
  schema value.
- Rationale and evidence: changing token issuance and protobuf-facing runtime
  types is unnecessary to own the config invariant, while an infallible
  conversion cannot honestly construct `NonZeroDuration` from public integer
  fields. The embedded autostart preparation path already returns errors and
  can propagate this boundary failure.
- Consequences and rejected alternatives:
  - Reject `unwrap`, fallback defaults, and unchecked construction: each would
    hide an invalid public runtime value or violate the new type's invariant.
  - Reject broad runtime newtypes: they would force unrelated issuance,
    protobuf, and API changes without improving configuration parsing.

### `DEC-003`: Reject parseable environment zero, preserve invalid-value ignore

- Choice: make environment application fallible only when either legacy
  variable parses exactly as its supported integer type and equals zero.
  Positive values override TOML as before. Malformed, negative, unit-bearing,
  non-Unicode, and out-of-range values remain ignored as before.
- Rationale and evidence: zero is valid integer syntax and therefore a reachable
  attempt to violate the now-owned lifetime invariant; silently ignoring it
  would not satisfy the requirement that zero be rejected consistently. The
  other categories have an established compatibility policy of no override,
  and changing them is neither required nor necessary.
- Consequences and rejected alternatives:
  - Reject treating zero like malformed input: startup would succeed and mask
    an explicitly configured invalid lifetime.
  - Reject making every invalid environment string fatal: that would change
    documented compatibility beyond the zero hardening request.
  - Errors name the exact environment variable and Authority field.

### `DEC-004`: Raw migration fails only for an effective legacy zero

- Choice: before converting a legacy `_seconds` item, `firma config` returns a
  field-specific error when that item is integer zero and the canonical field
  is absent. If a canonical field coexists, preserve it, remove the legacy key,
  and transfer comments using the existing deterministic canonical-wins path.
- Rationale and evidence: rendering `"0s"` knowingly creates output rejected by
  the strict schema; substituting a default silently changes operator policy.
  Existing coexistence behavior already makes canonical values authoritative.
- Consequences and rejected alternatives:
  - Negative, malformed, and overflowing legacy TOML retain their existing
    migration/strict-parse outcomes.
  - No general constrained-scalar migration framework is introduced; the
    Authority check is local to the two fields that acquire this invariant.

### `DEC-005`: Preserve stronger and cross-boundary checks

- Choice: remove no whole-second, integer-range, token-clamping, refresh, or
  Sidecar wire validation. Remove only any generic zero check made unreachable
  by `NonZeroDuration`; currently the schema-to-runtime path has no separate
  generic zero branch.
- Rationale and evidence: non-zero says nothing about subsecond values, integer
  width, protobuf representation, or relational behavior.
- Consequences and rejected alternatives: subsecond non-zero and out-of-range
  values continue to fail with their existing field-specific runtime errors.

## Architecture and invariant ownership

- Architecture shape:

```diagram
┌─────────────────────┐  compact parse  ┌─────────────────────┐
│ authority TTL TOML  │────────────────▶│ NonZeroDuration     │
└─────────────────────┘                 │ schema invariant    │
                                        └──────────┬──────────┘
                                                   │ whole seconds/range
┌─────────────────────┐  integer parse  ┌──────────▼──────────┐
│ legacy _SECONDS env │────────────────▶│ AuthorityConfig     │
│ zero → named error  │                 │ i32 / u32 runtime   │
└─────────────────────┘                 └──────────┬──────────┘
                                                   │ unchanged
                                       ┌───────────▼───────────┐
                                       │ issuance / bundle wire│
                                       └───────────────────────┘
```

### `INV-001`: Parsed Authority TTL configuration is strictly non-zero

- Semantic predicate: every successfully deserialized
  `schema::AuthorityConfig` has `max_ttl.duration() > 0` and
  `bundle_ttl.duration() > 0`.
- Primary owner: `firma_config_schema::utils::NonZeroDuration` plus the two
  schema field types.
- Detailed proof: `CW-001`, `TRACE-TOML`, and `PROOF-001`.

### `INV-002`: No successful Authority load can apply a zero legacy override

- Semantic predicate: after successful TOML conversion and environment
  application, both runtime integer TTLs are greater than zero.
- Primary owner: `firma-authority::AuthorityConfig::apply_env_overrides` and
  its error propagation through every load entry point.
- Detailed proof: `TRACE-ENV`, `ENV-001`, and `PROOF-002`.

### `INV-003`: Valid non-zero configuration remains behaviorally identical

- Semantic predicate: every previously valid non-zero TOML/default/environment
  value yields the same whole-second runtime integer and terminal issuance or
  bundle value, with the same precedence.
- Primary owner: schema-to-runtime conversion and existing runtime consumers.
- Detailed proof: `TRACE-MAX`, `TRACE-BUNDLE`, and `PROOF-003`.

- Compatibility, migration, and failure semantics: `DEC-001` through
  `DEC-005`. Zero is an intentional breaking rejection because immediate token
  expiry and immediately stale policy bundles are unsafe/non-operational.
- Durable documentation owner: `docs/configuration.md`, Authority README, and
  `docs-site/public/llms.txt`; Rust API details remain on the schema fields and
  `NonZeroDuration`.

## Implementation slices

### Slice 1: Require non-zero maximum token TTL

- Production, types, tests, and docs/config: convert `max_ttl`, its default,
  Authority conversions, reverse conversion, environment override, raw legacy
  migration, and focused schema/runtime/config-command tests. Prove the public
  fallible reverse conversion rejects a directly constructed non-positive
  runtime maximum; retain the existing embedded-Authority success-path test
  that proves valid synthetic config is emitted. Update directly affected Rust
  documentation.
- Affected decisions and traces: `DEC-001` through `DEC-005`, `TRACE-TOML`,
  `TRACE-ENV`, `TRACE-MAX`, and `TRACE-MIGRATION`.
- Proof obligations: `INV-001` through `INV-003`, restricted to `max_ttl`.
- Focused verification: config-schema tests, Authority config unit/integration
  tests under nextest, `firma config` migration tests, existing embedded-
  Authority preparation tests, affected crate Clippy, and docs for affected
  crates.
- Dependencies: accepted plan revision and exact rewritten PR #610 head.
- Intentionally unsupported: `bundle_ttl` remains unchanged until Slice 2.

### Slice 2: Require non-zero policy-bundle TTL

- Production, types, tests, and docs/config: convert `bundle_ttl`, its default,
  Authority conversions/environment override/raw migration, and focused tests.
  Prove the Authority can no longer create the Sidecar-rejected zero bundle,
  including through the public runtime-to-schema reverse conversion.
- Affected decisions and traces: `DEC-001` through `DEC-005`, `TRACE-TOML`,
  `TRACE-ENV`, `TRACE-BUNDLE`, and `TRACE-MIGRATION`.
- Proof obligations: `INV-001` through `INV-003`, restricted to `bundle_ttl`.
- Focused verification: the same boundaries as Slice 1 plus Authority bundle
  and Sidecar policy-bundle tests; directly constructed runtime bundle TTL zero
  must fail reverse conversion.
- Dependencies: Slice 1.
- Intentionally unsupported: no other TTL field adopts `NonZeroDuration`.

### Slice 3: Publish aggregate migration guidance

- Production, types, tests, and docs/config: update the configuration reference,
  Authority docs, docs site/discovery text, and migration examples to state the
  two zero rejections, rationale, unchanged syntax/defaults, environment
  compatibility matrix, and `firma config` remediation path.
- Affected decisions and traces: `DEC-003`, `DEC-004`.
- Proof obligations: documentation accurately reflects `INV-001` through
  `INV-003`; every tracked example remains strict-schema valid.
- Focused verification: formatter, docs-site build, and tracked-config parse
  checks already owned by `just check`.
- Dependencies: Slices 1 and 2.
- Intentionally unsupported: no unrelated configuration-reference cleanup.

### Slice 4: Remove this plan mechanically

- Production, types, tests, and docs/config: delete only this Markdown file in
  a standalone final revision after recording its immutable accepted-plan
  commit locator and review dispositions in the PR body.
- Affected decisions and traces: none.
- Proof obligations: final branch tree and PR diff contain no plan Markdown;
  immutable Git history preserves the accepted artifact.
- Focused verification: `git cat-file -e HEAD:docs/architecture/authority-non-zero-ttl-plan.md`
  must fail, and base-to-tip diff inspection must show no plan file.
- Dependencies: implementation, final independent review, and disposition of
  every finding.
- Intentionally unsupported: no history squashing that destroys the immutable
  plan locator.

## Risks and gaps

- Existing risks: public runtime integer fields permit direct zero construction;
  environment mutation tests require process isolation; `firma config` preserves
  comments while changing keys; PR #610 may be force-pushed again before its CI
  settles.
- Planned mitigations: fallible reverse conversion, exhaustive nextest-only
  environment matrices, existing decor-preserving migration machinery, and an
  exact fetch/rebase immediately before final verification and every push.
- Explicit evidence gaps: None. CI status is an execution gate, not a design
  unknown.
- Least-confident decisions: `DEC-002` modestly changes an internal conversion
  signature, but it is the only lint-compliant path that neither broadens
  runtime types nor hides an invalid direct construction.

## Plan-review findings and dispositions

One medium-severity finding was accepted and incorporated. The reviewer-authored
record is preserved verbatim below.

```yaml
- id: PLAN-001
  severity: medium
  category: test-coverage
  classification: design risk
  evidence:
    plan:
      - "docs/architecture/authority-non-zero-ttl-plan.md:128-146 (`DEC-002`)"
      - "docs/architecture/authority-non-zero-ttl-plan.md:306-319 (risk and mitigation)"
      - "docs/architecture/authority-non-zero-ttl-plan.md:493-501 (`PROOF-001` through `PROOF-005`)"
    repository:
      - "crates/firma-authority/src/config.rs:336 (`From<&AuthorityConfig> for schema::AuthorityConfig` at aab452655a76395f99c48eeedb7c2be500a137ea)"
      - "crates/firma-run/src/authority/prepare.rs:154 (`AuthorityConfig::from(&authority_config)` at aab452655a76395f99c48eeedb7c2be500a137ea)"
  reachable_trace:
    entry: "A `firma run` local-Authority launch reaches `firma_run::authority::prepare::prepare`."
    conditions: "A runtime `firma_authority::AuthorityConfig` contains zero or negative `max_ttl_seconds`, or zero `bundle_ttl_seconds`; these public integer fields remain directly constructible."
    causal_path: "`prepare` obtains the runtime config, converts it back to the public schema, serializes synthetic Authority TOML, and launches the embedded Authority. `DEC-002` changes this conversion from `From` to `TryFrom` specifically so invalid runtime values fail instead of becoming zero/default schema values."
    observable_outcome: "The proposed terminal behavior is a propagated preparation error with no synthetic config/Authority launch, but no proof obligation supplies this stimulus and asserts that terminal result."
  invariant_owner: "The runtime-to-schema conversion in `firma-authority`, with propagation owned by `firma-run::authority::prepare`."
  trust_boundary: "Embedded-Authority launch materializes an internal runtime value as strict public configuration."
  impact: "A regression could reintroduce fallback/defaulting, fail to propagate the new error, or partially write launch material while all planned schema, environment, issuance, and bundle tests still pass. That would leave `DEC-002` and its stated mitigation unproved."
  correction: "Add an explicit proof obligation and focused `firma-run` preparation test for each field: directly construct an invalid runtime config, invoke the real preparation path, assert the field-specific error, assert no successful prepared launch, and—if the implementation can write before conversion—assert no synthetic Authority TOML is emitted. Include affected `firma-run` tests/Clippy in Slices 1 and 2."
  confidence: high
  unverified_assumptions:
    - "The exact post-change error variant and whether conversion occurs before every filesystem side effect are not yet designed."
    - "Other constructors may currently prevent invalid values in normal production flow; the plan nevertheless explicitly retains public direct construction and relies on this reverse boundary to reject it."
  abstraction:
    existing_owner: "`From<&firma_authority::AuthorityConfig> for firma_config_schema::authority::AuthorityConfig`"
    consumers:
      - "`firma-run::authority::prepare::prepare`"
    operational_role: "Serializes a runtime Authority configuration into the synthetic configuration used for embedded Authority startup."
    lifecycle: "Runtime config acquisition → reverse conversion → TOML serialization/write → child Authority launch."
    cost: "A signature change at the sole repository consumer plus focused failure-path tests."
    replacement: "Fallible `TryFrom<&AuthorityConfig>` with propagated field-specific failure."
    non_goals:
      - "Changing issuance or wire runtime integer types."
      - "Introducing broad runtime TTL newtypes."
```

```yaml
disposition:
  status: corrected
  rationale: "The reverse conversion is the only boundary that can reject directly constructed invalid runtime fields without fallback, and it now has an explicit direct proof obligation. Further inspection resolved the finding's stated reachability uncertainty: `prepare` has no runtime-config input and constructs its local value only from strict schema conversion or fixed positive ephemeral defaults, so an invalid directly constructed value cannot reach its preparation call site without a test-only API or public API expansion. Existing preparation coverage continues to prove valid synthetic config emission."
  incorporated_at: "Slices 1–2 and PROOF-006"
  decided_by: planner
```

The accepted artifact at the immutable plan commit contains the complete
reviewer-authored finding records and appended dispositions.

## Final verification

- Focused checks: config-schema, Authority, Sidecar policy-bundle, and `firma
  config` migration tests; targeted Clippy and doctests.
- Workspace checks: `just check` and docs-site `pnpm build` after rebasing onto
  the exact latest remote parent head.
- Post-implementation independent review: fresh adversarial Rust/configuration
  review of the final base-to-tip diff; disposition every finding before plan
  removal and push.

## Technical evidence

### Applicability assessment

| Section                     | Applicability  | Reason or evidence                                                                                      |
| --------------------------- | -------------- | ------------------------------------------------------------------------------------------------------- |
| Vocabulary                  | Applicable     | Schema TTL, runtime seconds, and legacy environment values have distinct owners.                        |
| Alternatives                | Applicable     | Environment zero and runtime reverse conversion each have plausible but behaviorally different options. |
| File-tree diff              | Not applicable | Responsibility stays in existing schema, Authority, config-command, and docs modules.                   |
| Type and signature sketches | Applicable     | Public field types and reverse conversion change.                                                       |
| Semantic call traces        | Applicable     | Values cross schema, environment, runtime, and wire boundaries.                                         |
| Trust analysis              | Applicable     | Bundle freshness is fail-closed and zero currently disagrees across producer/consumer.                  |
| Detailed proof obligations  | Applicable     | Compatibility and migration require cross-suite matrices.                                               |

### Vocabulary

| Canonical term          | Meaning                                                        | Owner/context            | Terms to avoid  | Conflict or decision                                                       |
| ----------------------- | -------------------------------------------------------------- | ------------------------ | --------------- | -------------------------------------------------------------------------- |
| Schema TTL              | Compact, non-zero duration parsed from `firma.toml`            | `firma-config-schema`    | timeout         | TTL role is distinct, but shares the non-zero predicate.                   |
| Runtime seconds         | Whole-second `i32` or `u32` consumed by Authority              | `firma-authority`        | schema duration | Retained for runtime/wire compatibility.                                   |
| Legacy seconds override | Integer-only `_SECONDS` environment compatibility value        | `firma-authority` loader | duration string | Positive overrides; exact zero errors; other invalid forms remain ignored. |
| Effective legacy zero   | Legacy zero with no canonical replacement during raw migration | `firma config`           | malformed value | Must fail rather than emit `"0s"`.                                         |

### Alternatives

- **Ignore environment zero:** preserves the malformed-input policy but hides an
  explicit invariant violation and does not satisfy consistent rejection.
  Rejected by `DEC-003`.
- **Make all invalid environment values fatal:** creates a simpler uniform
  parser but breaks negative/malformed/overflow compatibility beyond scope.
  Rejected by `DEC-003`.
- **Change runtime fields to non-zero integer types:** prevents every direct
  runtime construction but expands issuance, loader, test-fixture, and wire
  changes without improving the requested schema boundary. Rejected by
  `DEC-002` in favor of fallible boundary conversion.
- **Substitute defaults during migration:** always emits valid TOML but silently
  changes an explicitly selected lifetime. Rejected by `DEC-004`.

### Types and signatures

```rust
pub struct AuthorityConfig {
    pub max_ttl: NonZeroDuration,
    pub bundle_ttl: NonZeroDuration,
    // unchanged fields
}

impl TryFrom<schema::AuthorityConfig> for runtime::AuthorityConfig;
impl TryFrom<&runtime::AuthorityConfig> for schema::AuthorityConfig;

fn apply_env_overrides(&mut self) -> Result<(), ConfigError>;
```

`CW-001` constructibility attack:

```rust,compile_fail
let schema = firma_config_schema::authority::AuthorityConfig {
    max_ttl: NonZeroDuration(Duration::ZERO), // private tuple field
    ..Default::default()
};
```

Public `NonZeroDuration::new(Duration::ZERO)` returns `ZeroDurationError`, and
Serde delegates every compact spelling to Jiff before applying the same check.
This proves value cardinality only. It does not prove whole-second/range
representability, environment ordering, provenance, or wire behavior; those
remain runtime obligations.

### Semantic call traces

| Field                      | `TRACE-TOML`                                                                                       |
| -------------------------- | -------------------------------------------------------------------------------------------------- |
| State                      | Proposed                                                                                           |
| Entry and stimulus         | Unified or sectioned Authority TOML with compact duration                                          |
| Path                       | config loader/TOML → schema `AuthorityConfig` → `NonZeroDuration::deserialize` → runtime `TryFrom` |
| Input/output types         | string → `Duration` → `NonZeroDuration` → `i32`/`u32`                                              |
| Validation/trust crossings | Jiff unsigned syntax; non-zero schema construction; whole-second/range narrowing                   |
| Invariant established      | `INV-001` at schema deserialization; runtime representability at `TryFrom`                         |
| Success outcome            | Existing non-zero runtime seconds                                                                  |
| Failure path               | Field-path parse error for zero/negative; existing runtime error for fractional/out-of-range       |
| Evidence                   | schema and Authority config modules/tests                                                          |
| Proof boundary             | schema integration + Authority unit/integration tests                                              |
| Unknowns                   | None                                                                                               |

| Field                      | `TRACE-ENV`                                                              |
| -------------------------- | ------------------------------------------------------------------------ |
| State                      | Proposed                                                                 |
| Entry and stimulus         | Legacy `_SECONDS` environment value after valid TOML/default loading     |
| Path                       | environment → integer parse → zero branch or assignment → runtime config |
| Input/output types         | OS string → supported integer → runtime `i32`/`u32`                      |
| Validation/trust crossings | environment precedence boundary                                          |
| Invariant established      | `INV-002` before successful loader return                                |
| Success outcome            | Positive override wins; invalid unsupported form leaves lower value      |
| Failure path               | Exact zero returns field/environment-specific `ConfigError`              |
| Evidence                   | Authority config module and nextest integration matrix                   |
| Proof boundary             | process-isolated integration test                                        |
| Unknowns                   | None                                                                     |

| Field                      | `TRACE-MAX`                                                                         |
| -------------------------- | ----------------------------------------------------------------------------------- |
| State                      | Current and preserved for non-zero values                                           |
| Entry and stimulus         | Successful runtime config and capability request                                    |
| Path                       | runtime maximum → `chrono::Duration`/Authority service → `clamp_ttl` → token expiry |
| Input/output types         | `i32` seconds throughout Authority issuance boundary                                |
| Validation/trust crossings | issuance policy remains unchanged                                                   |
| Invariant established      | `INV-003` at schema/runtime conversion                                              |
| Success outcome            | Same requested/max clamp and expiry                                                 |
| Failure path               | Zero rejected before service construction                                           |
| Evidence                   | `server.rs`, `service.rs`, `issuance.rs`                                            |
| Proof boundary             | Authority config + issuance tests                                                   |
| Unknowns                   | None                                                                                |

| Field                      | `TRACE-BUNDLE`                                                                 |
| -------------------------- | ------------------------------------------------------------------------------ |
| State                      | Current and preserved for non-zero values                                      |
| Entry and stimulus         | Successful runtime config and policy load/reload                               |
| Path                       | runtime TTL → Cedar store → core bundle → protobuf bundle → Sidecar validation |
| Input/output types         | `u32` seconds → wire `u32`                                                     |
| Validation/trust crossings | Authority producer to fail-closed Sidecar consumer                             |
| Invariant established      | Producer non-zero at successful Authority load; consumer check retained        |
| Success outcome            | Same TTL and refresh cadence                                                   |
| Failure path               | Zero rejected before producer can advertise it                                 |
| Evidence                   | `cedar_loader.rs`, Authority service, Sidecar policy-bundle parser             |
| Proof boundary             | Authority config/bundle and Sidecar policy-bundle tests                        |
| Unknowns                   | None                                                                           |

| Field                      | `TRACE-MIGRATION`                                                                                                  |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| State                      | Proposed                                                                                                           |
| Entry and stimulus         | Existing `firma.toml` passed to `firma config`                                                                     |
| Path                       | `DocumentMut` parse → canonical-presence/legacy-zero check → existing scalar migration → strict schema check/write |
| Input/output types         | decorated TOML item → decorated compact string or error                                                            |
| Validation/trust crossings | raw compatibility document to strict canonical schema                                                              |
| Invariant established      | generated canonical config cannot contain effective zero TTL                                                       |
| Success outcome            | Positive migration and comments preserved; canonical coexistence wins                                              |
| Failure path               | Effective legacy zero returns field-specific error and no file is written                                          |
| Evidence                   | config document builder and CLI integration tests                                                                  |
| Proof boundary             | document unit + `firma config` black-box integration tests                                                         |
| Unknowns                   | None                                                                                                               |

### Trust analysis

- Actors: Authority operator, `firma config`, Authority loader, policy-bundle
  producer, and Sidecar consumer.
- Protected assets: capability validity windows and freshness of enforced policy.
- Supported paths: unified config, embedded Authority, standalone Authority,
  generated-config migration, and legacy environment overrides.
- Reachable abuse/accident paths: an operator or deployment setting zero can
  create unusable tokens or an Authority/Sidecar bundle-contract mismatch.
- Trust transition: the environment is a higher-precedence operator boundary;
  it must not bypass the schema-owned lower-layer invariant.
- Security limit: non-zero alone does not establish an operationally sufficient
  lifetime, policy freshness, or protection against excessively large values;
  existing representability and runtime enforcement remain responsible.

### Detailed proof obligations

| ID          | Invariant | Kind                      | Owner/proof boundary                       | Stimulus and observable effects                                                           | Failure cases                                                                                                                                         | Status / slice       |
| ----------- | --------- | ------------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| `PROOF-001` | `INV-001` | Type/runtime              | schema unit/integration tests              | Defaults and positive compact strings produce exact copied durations                      | `0s`, equivalent zero, negative strings, public zero constructor                                                                                      | Planned / Slices 1–2 |
| `PROOF-002` | `INV-002` | Compatibility/runtime     | Authority nextest integration              | Each env var independently overrides only with positive supported integer                 | zero errors; malformed, negative, units, overflow, non-Unicode do not override; both-set precedence                                                   | Planned / Slices 1–2 |
| `PROOF-003` | `INV-003` | Compatibility             | Authority conversion/issuance/bundle tests | Existing 1h/30s defaults and representative custom values reach exact runtime/wire values | fractional and range overflow retain existing errors                                                                                                  | Planned / Slices 1–2 |
| `PROOF-004` | `INV-001` | Migration                 | document + CLI integration                 | positive old keys migrate with decor; canonical coexistence wins; second run is stable    | effective zero errors without write; malformed legacy remains strict-invalid                                                                          | Planned / Slices 1–2 |
| `PROOF-005` | `INV-003` | Documentation/operational | format/docs build/config fixtures          | migration table and examples describe exact breaking and unchanged behavior               | stale claim that Authority TTL zero remains allowed                                                                                                   | Planned / Slice 3    |
| `PROOF-006` | `INV-002` | Runtime                   | public runtime-to-schema conversion tests  | valid runtime values convert exactly; existing preparation coverage serializes them       | non-positive maximum or zero bundle TTL returns a field-specific conversion error; invalid direct values cannot reach `prepare` without API expansion | Planned / Slices 1–2 |

`ENV-001` exhaustive environment matrix:

| Input                      | Expected result                            |
| -------------------------- | ------------------------------------------ |
| Unset                      | TOML/default retained                      |
| Positive supported integer | Overrides corresponding field              |
| Zero                       | Field/environment-specific startup error   |
| Negative                   | Existing lower value retained              |
| Malformed text             | Existing lower value retained              |
| Unit-bearing text          | Existing lower value retained              |
| Maximum supported integer  | Overrides corresponding field              |
| One above maximum          | Existing lower value retained              |
| Non-Unicode                | Existing lower value retained              |
| Both variables positive    | Each independently overrides its own field |

## Post-implementation adversarial review

A fresh independent reviewer inspected
`aab452655a76395f99c48eeedb7c2be500a137ea..1854dd041794e93bb679c02406c8d3a942a5d229`
under the repository `reviewing-changes` and `review-rust-code` workflows.

Verdict: **approved with no code findings**.

The reviewer independently reconstructed standalone Authority, `firma run`,
stack planning, doctor/config parsing, control-service, issuance, migration,
and Cedar bundle-generation paths. It confirmed the following:

- both schema fields establish the non-zero invariant;
- schema/runtime conversions retain whole-second and range checks;
- environment compatibility preserves positive precedence and every deliberate
  ignore case while rejecting exact zero;
- reverse conversion rejects invalid directly constructed runtime values;
- raw migration checks effective legacy zero before mutation, canonical values
  win collisions, and migration errors prevent config and scaffold writes;
- issuance and bundle consumers are unchanged, with the Sidecar wire check
  retained; and
- `PROOF-001` through `PROOF-006` are materially covered.

The only pending plan step noted by the reviewer was the scheduled standalone
removal of this plan from the final branch tree. No behavior or meaning changes
were requested, so there are no implementation findings to disposition.

Independent verification:

- `git diff --check aab45265..1854dd04`;
- `cargo nextest run -p firma-config-schema -p firma-authority` (138 passed);
- `cargo nextest run -p firma --test cli scalar_migration` (5 passed); and
- `cargo clippy -p firma-config-schema -p firma-authority -p firma-run -p firma --all-targets -- -D warnings`.

## Post-restack builder reconciliation review

After PR #605 merged, a fresh independent reviewer inspected the Authority
configuration flow reconstructed through implementation commit
`4f540d32c23877b1c3725fcc0121a047d2c9df15` under the repository
`reviewing-changes` and `review-rust-code` workflows.

Verdict: **approved with no findings**.

The reviewer confirmed that:

- schema and environment values flow through `AuthorityConfigBuilder`;
- rebasing precedes environment overrides and validation follows them;
- runtime construction remains builder-gated;
- strict unknown-field and whole-file parsing behavior is preserved;
- TLS/mTLS cross-field validation applies after environment merging;
- non-zero duration syntax, defaults, whole-second values, range errors, and
  field-specific legacy environment zero errors are preserved; and
- malformed, negative, unit-suffixed, overflowing, and non-Unicode legacy
  environment values retain their compatibility behavior.

No finding required disposition. Independent verification reported by the
reviewer:

- `cargo nextest run -p firma-authority -p firma-config-schema -p firma-config-loader`
  (185 passed); and
- `git diff --check`.
