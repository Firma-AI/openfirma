# Non-Zero Authority Runtime TTL Integers

## Artifact metadata

- Status: Accepted
- Durable locator:
  `docs/architecture/authority-non-zero-runtime-ttl-plan.md`
- Repository revision researched:
  `4523167d39b1f67b86dc483739be90cdb94696e3` (the reconstructed tip of PR
  #614)
- Task or requirement source:
  [configuration-stack restack request](https://ampcode.com/threads/T-01a03f40-5cc8-741b-9568-f3166944abcd)
- Supersedes: Not applicable

## Goal and acceptance outcomes

- Goal: encode the Authority's validated, whole-second, non-zero TTL invariant
  in its private runtime field types while preserving every configuration,
  environment, wire, default, error, and runtime outcome.
- Observable acceptance outcomes:
  - `AuthorityConfig::max_ttl_seconds` and
    `AuthorityConfig::bundle_ttl_seconds` are both `NonZeroU32`.
  - The fields keep their whole-second names because the Authority's downstream
    interfaces consume exact integer seconds rather than human durations.
  - The schema remains the sole owner of compact human-readable duration
    parsing through `NonZeroDuration`.
  - Only `AuthorityConfigBuilder` can construct validated runtime state. It
    checks whole-second/range constraints once, then constructs the standard
    non-zero integer fields.
  - The signed protobuf request remains unchanged. Its `<= 0` maximum-TTL
    sentinel is normalized once at the issuance adapter, and internal
    configuration, service state, clamping, and effective TTLs stay unsigned
    and non-zero.
  - Downstream code unwraps with `.get()` only where an integer/library/wire
    interface requires `u32` or `i64`; exact expiry and wire values remain
    unchanged.
  - The final PR tip and base-to-tip diff contain no plan Markdown.

## Scope

- In scope:
  - The private Authority runtime TTL fields and their read accessors.
  - Schema-to-runtime and runtime-to-schema conversion owned by
    `AuthorityConfigBuilder` / `AuthorityConfig`.
  - Authority server, revocation, issuance, PASETO, Cedar policy-bundle, CLI,
    and test consumers of the validated values, including the signed request
    compatibility adapter.
  - Focused tests proving default, TOML, environment, range, round-trip, and
    terminal integer values remain identical.
- Out of scope:
  - Any TOML key/type/syntax, environment name/precedence/error, protobuf field,
    external `firma-protobuf` dependency, default, integer range, or
    user-facing migration change.
  - Replacing whole-second downstream interfaces with duration types.
  - Changing the signed request TTL type, its observable sentinel/clamping
    behavior, policy-bundle storage, or public protocol types. Removing that
    protocol sentinel is deferred to a separate follow-up PR.
- Assumptions: PRs #611 and #614 continue to guarantee non-zero schema values
  and private builder-only runtime construction at the researched revision.
- Open decisions: None.
- Cohesion and split assessment: the two fields share a construction boundary
  but terminate in different consumers, so each receives a separate vertical
  implementation revision. The maximum-TTL revision also owns the issuance
  adapter that currently isolates the signed protobuf request. A child plan
  would duplicate the same ownership decision without an independently
  shippable contract.
- Deferred child plans: Not applicable.

## Routing

- Mode: Full
- Trigger evidence: the change moves the proof boundary for a runtime invariant
  from builder validation plus private primitive fields into builder validation
  plus private standard non-zero integer fields (`planning-changes` Full trigger
  3).
- Higher-mode triggers checked: no stable user configuration, wire, persisted
  format, trust boundary, concurrency, or distributed behavior changes. The
  owner/proof-boundary trigger alone requires Full planning.
- Downgrade evidence and reason: Not applicable.

## Current behavior and problem

- Owners and entry points:
  - `schema::AuthorityConfig` owns human duration parsing and guarantees each
    TTL is a `NonZeroDuration`.
  - `AuthorityConfigBuilder::build` calls `AuthorityConfig::from_schema`, which
    validates whole seconds and the existing `i32::MAX` / `u32::MAX` ranges
    before storing primitive integers in private runtime fields.
  - `AuthorityConfig::to_schema` fallibly reconstructs the maximum schema
    duration because the signed primitive runtime field does not encode
    positivity.
  - Server and CLI consumers pass those primitives into Chrono, token issuance,
    Cedar policy stores, and protobuf-producing code.
- Current success and failure outcomes: public construction is already gated by
  the builder, so zero is unreachable through supported APIs. The remaining
  primitive field shape does not state that invariant and forces reverse
  conversion to re-check it.
- Evidence:
  - `crates/firma-authority/src/config.rs:AuthorityConfig,from_schema,to_schema`
  - `crates/firma-authority/src/server.rs:load_authority_service`
  - `crates/firma-authority/src/service.rs:AuthorityServiceImpl`
  - `crates/firma-authority/src/issuance.rs:issue_capability`
  - `crates/firma-authority/src/cedar_loader.rs:CedarPolicyStore`
  - `crates/firma/src/services/authority.rs`

## Key decisions and tradeoffs

### `DEC-001`: Keep human durations in schema and unsigned whole-second integers at runtime

- Choice: use `NonZeroU32` for both maximum token TTL and bundle TTL in the
  validated runtime config. Keep the explicit `_seconds` names and the existing
  `i32::MAX` upper bound for maximum TTL while the signed request protocol
  remains.
- Rationale and evidence: the schema boundary parses compact durations, while
  Chrono, PASETO expiry, request clamping, policy bundles, and protobuf paths
  consume positive whole-second values. The signed protobuf request is a legacy
  input shape, not a reason to distort validated runtime configuration.
- Consequences and rejected alternatives: `NonZeroDuration` is rejected for
  runtime storage because it loses the downstream width contract and would
  require repeated integer narrowing. Custom TTL newtypes are rejected because
  standard non-zero integers encode the requested cardinality with fewer APIs.

### `DEC-002`: Builder conversion remains the positive/range proof boundary

- Choice: extract each `NonZeroDuration` and reject fractional seconds. Convert
  the proven non-zero whole-second count to `NonZeroU64`, preserve the existing
  `i32::MAX` check for maximum TTL, then use the standard checked
  `TryFrom<NonZeroU64>` implementation to construct `NonZeroU32` with the
  existing `DurationOutOfRange` mapping. Do not first narrow to a primitive and
  then call a second target `new`. Supported runtime construction always
  traverses the builder/schema boundary.
- Rationale and evidence: unsigned non-zero fields encode positivity directly;
  the builder remains the owner of whole-second and role-specific upper bounds,
  while field privacy prevents bypass.
- Consequences and rejected alternatives: obtaining `NonZeroU64` still uses its
  checked standard constructor because Rust has no direct conversion from
  `Duration`; `None` is unreachable after the schema non-zero and whole-second
  checks and maps to the existing range error. There is no unchecked cast,
  fallback, unsafe constructor, second target reconstruction, or new public
  constructor. Existing whole-second/range errors remain the only reachable
  builder conversion failures. `to_schema` retains its existing `Result` API
  while using the canonical infallible `NonZeroU64` to `NonZeroDuration`
  conversion for builder-produced state.

### `DEC-003`: Expose non-zero values until the actual primitive boundary

- Choice: both accessors return `NonZeroU32`. Authority service state and
  issuance clamping also retain `NonZeroU32`; consumers call `.get()` only at
  Chrono, Cedar, policy-bundle, or protocol/library integer boundaries.
- Rationale and evidence: returning primitives from accessors would erase the
  invariant immediately; propagating non-zero types through request and wire
  implementations would broaden the refactor without changing their contracts.
- Consequences and rejected alternatives: test assertions use `.get()` when
  proving exact integer outcomes. No `.get()` is introduced merely to store the
  value in another intermediate config representation.

### `DEC-004`: Isolate the signed request at one issuance adapter

- Choice: `clamp_ttl` accepts the unchanged signed protobuf request and a
  configured `NonZeroU32`, returning `NonZeroU32`. A request `<= 0` returns the
  configured maximum; a positive request is checked into `NonZeroU32` once and
  clamped against the maximum.
- Rationale and evidence: this preserves the existing sentinel and expiry
  behavior without converting validated configuration back to `i32` merely to
  fit the old clamp signature. Service state and all post-normalization issuance
  logic remain unsigned and non-zero.
- Consequences and rejected alternatives: changing the protobuf field or
  external dependency is deferred. A custom adapter type or generic clamp DSL
  would add names without removing complexity.

## Architecture and invariant ownership

```diagram
┌──────────────────────────┐
│ TOML / legacy env        │
└────────────┬─────────────┘
             ▼
┌──────────────────────────┐   parse/non-zero
│ schema::NonZeroDuration  │
└────────────┬─────────────┘
             ▼ whole-second + checked width, once
┌──────────────────────────┐
│ AuthorityConfigBuilder   │
└────────────┬─────────────┘
             ▼
┌──────────────────────────┐
│ NonZeroU32 / NonZeroU32  │
└────────────┬─────────────┘
             ▼ typed issuance state; `.get()` at terminal boundary
┌──────────────────────────┐
│ request adapter / wire   │
└──────────────────────────┘
```

### `INV-001`: Supported runtime Authority configs contain positive whole-second TTLs

- Semantic predicate: every `AuthorityConfig` obtainable through public APIs
  has `max_ttl_seconds.get() ∈ 1..=i32::MAX` and
  `bundle_ttl_seconds.get() ∈ 1..=u32::MAX`.
- Primary owner: `AuthorityConfigBuilder::build` plus private `AuthorityConfig`
  fields typed as `NonZeroU32`.
- Detailed proof: `CW-001`, `TRACE-001`, and `PROOF-001`.

### `INV-002`: Existing terminal integer values are unchanged

- Semantic predicate: for every previously accepted schema/default/environment
  input, all Chrono, issuance, policy-bundle, and wire boundaries receive the
  same positive whole-second values as before; signed requests `<= 0`, positive
  requests within the maximum, and over-maximum requests retain their existing
  expiry outcomes.
- Primary owner: accessor return types and `.get()` placement at existing
  primitive boundaries.
- Detailed proof: `TRACE-002` and `PROOF-002`.

- Compatibility, migration, and failure semantics: `DEC-001` through
  `DEC-004`; no user or wire migration exists.
- Durable documentation owner: Rust field/accessor documentation in
  `firma-authority`; user configuration docs remain unchanged because their
  contract does not change.

## Implementation slices

### Slice 1: Encode maximum token TTL as `NonZeroU32`

- Production, types, tests, and docs/config: change the private field/accessor,
  construct it in `from_schema` while preserving the `i32::MAX` bound, make
  reverse construction infallible while retaining the current `Result` API,
  propagate `NonZeroU32` through service state and issuance, and normalize the
  unchanged signed request once in `clamp_ttl`. Update focused
  default/TOML/env/range/round-trip, negative/zero/positive/over-maximum request,
  and exact-expiry tests.
- Affected decisions and traces: `DEC-001` through `DEC-004`, `TRACE-001`,
  `TRACE-002`.
- Proof obligations: `INV-001` and `INV-002` for maximum TTL.
- Focused verification: Authority config and issuance tests, Firma Authority
  command tests, affected crate build/Clippy/docs.
- Dependencies: accepted plan and reconstructed #614 tip.
- Intentionally unsupported: bundle runtime field remains `u32` until Slice 2;
  the protobuf request remains `i32` for a separate follow-up.

### Slice 2: Encode bundle TTL as `NonZeroU32`

- Production, types, tests, and docs/config: change the private field/accessor,
  construct it in `from_schema`, update reverse conversion, and unwrap only at
  Cedar/policy-bundle integer consumers. Update owning Rust docs and focused
  default/TOML/env/range/round-trip/reload tests.
- Affected decisions and traces: `DEC-001` through `DEC-004`, `TRACE-001`,
  `TRACE-002`.
- Proof obligations: `INV-001` and `INV-002` for bundle TTL.
- Focused verification: Authority config, Cedar loader, policy-bundle, Firma
  Authority command tests, affected crate build/Clippy/docs.
- Dependencies: Slice 1.
- Intentionally unsupported: downstream request/wire field types remain their
  exact existing primitives; changing `firma-protobuf` is deferred.

### Slice 3: Record review and remove this plan mechanically

- Production, types, tests, and docs/config: append independent implementation
  review findings/dispositions to this artifact, then delete only this file in
  a standalone closing revision.
- Affected decisions and traces: none.
- Proof obligations: final tip and base-to-tip diff contain no plan Markdown;
  immutable plan/review commits retain durable locators.
- Focused verification: Git tree/diff inspection.
- Dependencies: Slices 1–2, full verification, and independent review.
- Intentionally unsupported: squashing away the immutable locators.

## Risks and gaps

- Existing risks: accidentally widening maximum TTL beyond `i32::MAX`, changing
  the signed request sentinel while refactoring clamping, moving `.get()` too
  early, or obscuring behavior changes during mechanical restacking.
- Planned mitigations: retain the builder's existing maximum bound, keep fields
  private, isolate `i32` normalization in one clamp function, test all request
  classes and exact expiry, audit every consumer, and range-diff each ancestor.
- Explicit evidence gaps: None.
- Least-confident decisions: `DEC-004`, because the signed protocol sentinel is
  intentionally retained temporarily. Explicit adapter tests and a separately
  scoped protocol follow-up bound that risk.

## Plan-review findings and dispositions

One medium-severity design risk was accepted against the original signed-field
design. The reviewer-authored finding is preserved below; the revised unsigned
design resolves it structurally and will receive a fresh independent plan
review before implementation.

```yaml
id: PLAN-001
severity: medium
category: constructibility
classification: design risk
evidence:
  - "docs/architecture/authority-non-zero-runtime-ttl-plan.md:109-120 (`DEC-002`)"
  - "docs/architecture/authority-non-zero-runtime-ttl-plan.md:329-335 (`TRACE-001`)"
  - "crates/firma-authority/src/config.rs:167-205 at e535b73ba0bd49cfb3a15f9f785014fb15360830 (`AuthorityConfig::from_schema`)"
reachable_entry: "Any valid default, TOML, or environment TTL converted by `AuthorityConfigBuilder::build`."
conditions: "The plan instructs the implementation to narrow to `i32`/`u32` and then construct `NonZeroI32`/`NonZeroU32`, but does not specify a single fallible conversion or how the logically impossible zero result is handled."
causal_path: "`NonZeroDuration` -> whole-second check -> primitive `try_from` -> separate `NonZeroI*::new` reconstruction."
observable_outcome: "An implementer must invent an error mapping, unchecked constructor, or duplicate fallible validation; those choices can violate the requested preservation of exact errors or the prohibition on unchecked casts and duplicate fallible reconstruction."
invariant_owner: "`AuthorityConfigBuilder` / `AuthorityConfig::from_schema`, which owns positivity, whole-second validation, and width narrowing."
trust_boundary: "Schema-to-validated-runtime conversion boundary."
impact: "The central construction algorithm remains under-specified despite being the highest-risk proof boundary, particularly because `NonZeroI32` itself admits negative values."
correction: "Specify one checked conversion per field directly from `Duration::as_secs()` to the target non-zero integer, with existing `DurationOutOfRange` mapping and no second `new`/revalidation step; explicitly record why zero cannot occur after the schema non-zero and whole-second checks. Keep the checked `NonZeroI32::get()` to `u64` conversion in `to_schema` as the separate positivity defense."
confidence: high
unverified_assumptions:
  - "The selected Rust toolchain provides the intended checked `TryFrom` conversion into `NonZeroI32` and `NonZeroU32`; otherwise the plan must name an equally explicit checked construction sequence and error mapping."
material_abstraction:
  existing_owner: "`schema::NonZeroDuration` plus `AuthorityConfig::from_schema`"
  consumers: "Authority server, CLI issuance/revocation, Cedar policy stores, policy-bundle protobuf production, and reverse schema serialization"
  operational_role: "Convert accepted human durations into exact whole-second runtime integers"
  lifecycle: "Constructed once by the builder, projected with `.get()` at primitive boundaries, optionally serialized back to schema"
  cost: "No new abstraction is required"
  replacement_or_non_goals: "Replace only primitive runtime storage; do not replace schema durations or downstream integer contracts"
```

```yaml
disposition:
  status: corrected
  rationale: "The product decision now uses `NonZeroU32` for both runtime fields. DEC-002 retains the explicit safe sequence supported by std: after the existing whole-second check, construct `NonZeroU64`, preserve the maximum field's existing `i32::MAX` bound, then use the single target `TryFrom<NonZeroU64>` width conversion. Reverse construction is infallible while the existing Result API remains. There is no target `new`, unchecked cast, fallback, signed runtime state, or new abstraction."
  incorporated_at: "DEC-001 through DEC-004, TRACE-001, and Slices 1-2"
  decided_by: planner
```

The original reviewer found the routing, vertical slices, consumer-boundary
audit, compatibility proof, and plan-removal lifecycle adequate. The revised
plan extends those obligations to the signed request adapter and preserves the
existing maximum bound.

A fresh independent review of the revised unsigned design reported one medium
finding:

```yaml
id: PLAN-002
severity: medium
category: reverse schema conversion
evidence:
  - "Slice 1 originally required making reverse conversion infallible"
  - "AuthorityConfig::to_schema currently returns Result<schema::AuthorityConfig, ConfigError>"
impact: "The plan left an implementation choice between changing an internal API/error shape and retaining an unexplained Result."
correction: "Retain the current Result signature, remove only signed positivity reconstruction, and specify infallible conversion from the typed runtime value."
confidence: high
```

```yaml
disposition:
  status: corrected
  rationale: "DEC-002 and Slice 1 now retain the current Result API while using the canonical infallible NonZeroU64-to-NonZeroDuration conversion. Existing builder parse/range errors remain unchanged; no fallback or duplicate validation is introduced."
  incorporated_at: "DEC-002 and Slice 1"
  decided_by: planner
```

The reviewer found no other issues and approved the unsigned invariant
ownership, `i32::MAX` preservation, signed-request normalization, exact-expiry
coverage, consumer placement, atomic slices, and plan-removal lifecycle.

## Final verification

- Focused checks: Authority config/env/issuance/Cedar tests, Firma Authority
  command tests, schema round-trip tests, and relevant doctests/Clippy.
- Workspace checks: repository `verify` stack workflow, `just check`, and docs
  site build at the final latest-parent tip.
- Post-implementation independent review: fresh adversarial Rust review against
  this accepted plan; disposition every finding before the mechanical deletion.

## Technical evidence

### Applicability assessment

| Section                     | Applicability  | Reason or evidence                                        |
| --------------------------- | -------------- | --------------------------------------------------------- |
| Vocabulary                  | Not applicable | Existing schema/runtime terms remain canonical.           |
| Alternatives                | Applicable     | Runtime duration/custom/integer types were plausible.     |
| File-tree diff              | Not applicable | Responsibility remains in existing files/modules.         |
| Type and signature sketches | Applicable     | Construction and illegal states drive the change.         |
| Semantic call traces        | Applicable     | Values cross schema, builder, library, and wire shapes.   |
| Trust analysis              | Not applicable | This is an internal guardrail, not a trust-boundary move. |
| Detailed proof obligations  | Applicable     | Type and compatibility claims need executable evidence.   |

### Alternatives

- Keep primitive runtime fields: smallest diff, but leaves the validated
  invariant implicit and keeps duplicate reverse checks. Rejected by the task.
- Store `NonZeroDuration`: preserves non-zero but erases exact downstream
  integer widths and repeats narrowing. Rejected by `DEC-001`.
- Add role-specific TTL newtypes: can encode positivity and role, but adds
  constructors and APIs when standard types plus private builder ownership
  establish the requested invariant. Rejected by `DEC-001` / `DEC-002`.

### Types and signatures

```rust
pub struct AuthorityConfig {
    max_ttl_seconds: NonZeroU32,
    bundle_ttl_seconds: NonZeroU32,
    // unchanged fields
}

impl AuthorityConfig {
    pub fn max_ttl_seconds(&self) -> NonZeroU32;
    pub fn bundle_ttl_seconds(&self) -> NonZeroU32;
}

fn clamp_ttl(requested: i32, max: NonZeroU32) -> NonZeroU32;
```

`CW-001` constructibility attack:

```rust,compile_fail
let config = AuthorityConfig {
    max_ttl_seconds: NonZeroU32::new(1).unwrap(),
    bundle_ttl_seconds: NonZeroU32::new(1).unwrap(),
    // fields are private outside firma-authority
};
```

The full public construction attempt fails on field privacy and the absence of
a public runtime constructor/default. `AuthorityConfigBuilder` starts from
unsigned `NonZeroDuration`, preserves the existing role-specific bounds, then
performs checked narrowing. Supported construction therefore proves positivity,
non-zero cardinality, and integer width. It does not prove a semantic
relationship between the two TTL roles; none is required.

### Semantic call traces

| Field                      | `TRACE-001`                                                                                   |
| -------------------------- | --------------------------------------------------------------------------------------------- |
| State                      | Implemented                                                                                   |
| Entry and stimulus         | Valid Authority schema/default/env value                                                      |
| Path                       | `NonZeroDuration → AuthorityConfigBuilder::build → AuthorityConfig::from_schema → NonZeroU32` |
| Input/output types         | Human duration → `Duration` → `NonZeroU64` → checked target non-zero integer                  |
| Validation/trust crossings | Non-zero parse, whole-second check, checked target integer width, private construction        |
| Invariant established      | `INV-001` at successful builder return                                                        |
| Invariant assumed          | Schema duration is unsigned/non-zero                                                          |
| Success outcome            | Private validated config with identical seconds                                               |
| Failure path               | Existing fractional/range error; existing schema/env zero errors                              |
| Evidence                   | Config schema and Authority config modules/tests                                              |
| Proof boundary             | Type checking plus Authority config unit/integration suites                                   |
| Unknowns                   | None                                                                                          |

| Field                      | `TRACE-002`                                                                        |
| -------------------------- | ---------------------------------------------------------------------------------- |
| State                      | Implemented                                                                        |
| Entry and stimulus         | Validated Authority config reaches runtime consumer                                |
| Path                       | accessor/private field → typed service/clamp → `.get()` → Chrono/Cedar/wire        |
| Input/output types         | `NonZeroU32`; signed request normalized once into `NonZeroU32`                     |
| Validation/trust crossings | Signed request compatibility adapter; terminal invariant-preserving projection     |
| Invariant established      | `INV-002` at each existing primitive boundary                                      |
| Invariant assumed          | Config came from the builder                                                       |
| Success outcome            | Same expiry, clamp, revocation retention, bundle TTL, reload TTL, and wire integer |
| Failure path               | None introduced; request `<= 0` still selects maximum                              |
| Evidence                   | Server/service/issuance/Cedar/Firma command modules and tests                      |
| Proof boundary             | Focused unit/integration tests plus workspace build/type check                     |
| Unknowns                   | None                                                                               |

### Proof obligations

| Invariant | Kind          | Owner/proof boundary        | Stimulus                        | Observable effects                                 | Status   | Slice |
| --------- | ------------- | --------------------------- | ------------------------------- | -------------------------------------------------- | -------- | ----- |
| `INV-001` | Type/runtime  | Builder + private fields    | Defaults, TOML, env, max ranges | Accessors return typed positive exact seconds      | Verified | 1–2   |
| `INV-002` | Compatibility | Runtime consumer boundaries | Representative accepted values  | Exact positive terminal values are unchanged       | Verified | 1–2   |
| `INV-002` | Compatibility | Reverse schema conversion   | Built config round-trip         | Same friendly durations and rebuilt integer values | Verified | 1–2   |

Limits: type evidence does not prove consumer placement; focused tests and the
base-to-tip consumer audit prove that projection separately.

## Post-implementation adversarial review

A fresh independent reviewer inspected the exact behavior diff
`4523167d39b1f67b86dc483739be90cdb94696e3..de35d6298abf4fd5ba688c7df760369ed8181cf6`
under the repository `reviewing-changes` and `review-rust-code` workflows. The
reviewed production tree is identical to implementation tip `7295f062`; the
only intervening change mechanically removed this plan.

Verdict: **approved with no findings**.

The reviewer confirmed that:

- both private runtime fields and their accessors use `NonZeroU32`;
- builder conversion preserves fractional-second rejection, the existing
  `i32::MAX` maximum-token-TTL bound, and checked narrowing;
- the unchanged signed protobuf request is normalized once, with `<= 0`
  selecting the configured maximum and positive requests clamped without
  narrowing the configured maximum to `i32`;
- `.get()` projections occur only at Chrono, Cedar, policy-bundle, and
  wire/library integer boundaries;
- default, TOML, environment, range, round-trip, request-class, and exact-expiry
  behavior is covered; and
- this plan is absent from the reviewed final tree and base-to-tip diff.

No finding required disposition. Independent verification reported by the
reviewer:

- `cargo nextest run -p firma-authority -p firma-config-schema` (150 passed);
- `cargo nextest run -p firma authority` (37 selected tests passed);
- `cargo test -p firma-authority -p firma-config-schema --doc`;
- `cargo clippy -p firma-authority -p firma-config-schema -p firma --all-targets -- -D warnings`;
  and
- `git diff --check`.
