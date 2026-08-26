# Unified `firma.toml` Schema Hardening

## Artifact metadata

- Status: Accepted
- Durable locator: `docs/architecture/config-schema-hardening-plan.md`
- Repository revision researched:
  `b4daea63ba9515f6ed9476f699371387d5456071` (the exact tip of PR #605)
- Task or requirement source: PR #605 plus the requested three-PR schema
  hardening stack
- Supersedes: Not applicable

## Goal and acceptance outcomes

- Goal: make the user-facing `firma.toml` contract honest, strict, and
  consistent without moving runtime behavior into the behavior-free schema
  crate.
- Observable acceptance outcomes:
  - Configuration no longer advertises controls that have no runtime effect.
  - A misspelled or removed key fails deserialization in `[authority]`,
    `[sidecar]`, `[run.defaults]`, every `[run.profiles.*]` profile, and every
    nested schema object or tagged variant.
  - Every profile's backend is validated while the whole file is parsed,
    whether or not the profile is selected.
  - Byte limits accept human-readable byte-size strings, and durations accept
    human-readable strings such as `"500ms"` and `"30s"` under keys without
    encoded units.
  - Filesystem values use `PathBuf`; config-relative resource paths resolve
    against the containing `firma.toml`, while runtime/state paths and endpoint
    URLs retain their established semantics.
  - Generated config, examples, docs, tests, and `docs-site/public/llms.txt`
    describe the exact breaking migrations.
  - The three changes ship as an ordered GitHub PR stack rooted at PR #605,
    with each PR independently reviewable and green.

## Scope

- In scope:
  - The local Authority's `[authority]` representation, even though it has not
    yet moved into `firma-config-schema` at the researched revision.
  - Every type currently exported by `firma-config-schema`, including the
    `[sidecar]`, secret-gateway, secret-matcher, and PR #605 `[run]` schemas.
  - The unified document's top-level section vocabulary and stale documented
    `[project].agent` / `[project].provider` fields.
  - Runtime conversions, config generation, migration documentation, examples,
    and tests directly coupled to those contracts.
- Out of scope:
  - Changing policy, enforcement, protocol, rate-limit, cache-capacity, or
    profile merge semantics.
  - Removing live expert tuning or one-variant fields.
  - Renaming protocol fields such as `retry_after_ms`, CLI flags, or Authority
    environment variables merely because the corresponding TOML key changes.
  - Changing URL/endpoint strings, JSONPath expressions, HTTP paths, IDs, or
    map keys into filesystem paths.
- Assumptions:
  - This is an intentionally breaking config migration; old TOML duration,
    byte-count, and renamed keys fail rather than being silently accepted.
  - Existing documented state/runtime path exclusions remain exclusions.
- Open decisions: None. Repository evidence determines dead fields and path
  ownership; the task explicitly selects strict parsing and scalar migration.
- Cohesion and split assessment: the work is deliberately split into three
  vertical PRs. Dead-surface removal establishes the honest vocabulary;
  strictness makes stale vocabulary fail; scalar/path normalization then makes
  one explicit migration over that strict contract.
- Deferred child plans: Not applicable.

## Routing

- Mode: Full
- Trigger evidence: the work changes stable configuration syntax, defaults,
  validation failures, path resolution, and migration behavior across multiple
  crates.
- Higher-mode triggers checked: stable config/migration contract and multiple
  crate boundaries both require Full planning.
- Downgrade evidence and reason: Not applicable.

## Current behavior and problem

- Owners and entry points:
  - `firma-config-loader::FirmaConfig::{section, optional_section}` extracts a
    TOML subtree and deserializes each component independently.
  - `firma-authority::config::AuthorityConfig::from_resolved_section` owns the
    current `[authority]` representation, environment overrides, and rebasing.
  - `firma_config_schema::sidecar::SidecarConfig` is converted by
    `firma_sidecar::config::SidecarConfig::try_from` and then rebased by the
    CLI's unified-config startup path.
  - `firma_config_schema::run::FileConfig` is parsed in
    `firma_run::config::{read_config, read_configured_profile}`, then merged and
    validated only for the selected effective profile.
- Current success and failure outcomes:
  - Unknown keys are silently discarded at all three section boundaries and
    inside nested/tagged values.
  - Sidecar schema flattening combines the three enforcement tables with the
    direct Sidecar fields. Authority flattening combines TLS keys with direct
    Authority fields. Serde does not support `deny_unknown_fields` together
    with `flatten`, so attributes on the current aggregates cannot establish
    strictness.
  - PR #605 represents `backend` as `Option<String>`, so invalid values in an
    unselected profile or overridden defaults survive full-file parsing.
  - Numeric durations mix `_ms`, `_secs`, and `_seconds`; three byte limits are
    raw integers; mapping/session paths are strings; several resource paths are
    not rebased despite the documented config-relative contract.
- Evidence:
  - `crates/firma-config-loader/src/schema.rs: FirmaConfig`
  - `crates/firma-authority/src/config.rs: AuthorityConfig`
  - `crates/firma-config-schema/src/sidecar/mod.rs: SidecarConfig`
  - `crates/firma-sidecar/src/config/mod.rs: SidecarConfig::try_from`
  - `crates/firma-config-schema/src/run.rs: FileConfig, ProfilePatch`
  - `crates/firma-run/src/config.rs: read_config, resolve_profile_with_layout`
  - `docs/configuration.md: Config-Relative Resource Resolution`

## Key decisions and tradeoffs

### `DEC-001`: Remove only terminally dead or fake controls

- Choice: remove the exact surface proven dead by `TRACE-DEAD-FIELDS`:
  `[project].agent`, `[project].provider`, `[authority].log_level`, all of
  `[sidecar.log]`, Sidecar
  `constraint_enforcement.bundle_ttl_seconds` and
  `constraint_enforcement.enforcement_timeout_ms`, every Run
  `allowed_domains`, and `seccomp_policy.verify_checksum`.
- Rationale and evidence: each dead field is accepted, defaulted, and sometimes
  copied into another config type but has no terminal runtime read.
  `verify_checksum=false` is rejected while both seccomp materialization paths
  always verify checksums, so the boolean presents a choice that does not
  exist.
- Consequences and rejected alternatives:
  - Remove `[sidecar.log]` rather than leave an empty section.
  - Remove the stale `[project]` example and references; the current generator
    no longer emits that table and no runtime component consumes it.
  - Document checksum verification as unconditional behavior.
  - Keep live controls such as Authority `bundle_ttl_seconds`, Sidecar
    `authority.agent_id`, all counts/capacities, and one-variant tenancy.
  - Do not wire dead controls to new behavior; that would be a different
    product change.

### `DEC-002`: Make strictness structural rather than fighting `flatten`

- Choice:
  - Reject top-level keys other than `authority`, `sidecar`, and `run` when
    `firma-config-loader` parses a unified document.
  - Give schema structs and tagged enums `deny_unknown_fields` recursively.
  - Replace the schema-only flattened Sidecar `enforcement` member with direct
    `mapping`, `capability_validation`, and `constraint_enforcement` fields;
    construct the runtime's grouped `EnforcementConfig` during conversion.
  - Add a behavior-free `firma_config_schema::authority::AuthorityConfig` with
    TLS keys represented directly at the existing flat TOML level; convert it
    into the Authority runtime config that retains its grouped TLS type.
- Rationale and evidence: this preserves the public TOML table layout while
  eliminating both flatten interactions that prevent reliable unknown-key
  ownership.
- Consequences and rejected alternatives:
  - Reject a custom map-inspecting deserializer: an explicit wire structure is
    smaller, format-independent, and lets Serde report nested field paths.
  - Dynamic labels/profile names remain valid map keys, but their mapped values
    are strict.
  - Top-level strictness is owned by the loader because components deserialize
    separate subtrees. This makes removed `[project]` and arbitrary tables fail
    before section extraction.

### `DEC-003`: Keep only named compatibility forms

- Choice: preserve Run's documented legacy capability `kind`/`path` input and
  `codex_cli`, but type the legacy `kind` as a finite schema enum so unknown
  values fail. Add a behavior-free schema backend enum and map it explicitly to
  `firma_run::BackendKind`.
- Rationale and evidence: these are intentional compatibility inputs. A raw
  string for either field would defeat full-file validation.
- Consequences and rejected alternatives: do not add aliases for removed dead
  fields or pre-migration scalar keys. Stale `[sidecar.preflight]` is rejected.

### `DEC-004`: Use one representation convention per scalar category

- Choice:
  - User-facing byte limits use `bytesize::ByteSize`.
  - User-facing durations use `std::time::Duration` with Jiff's unsigned,
    friendly, compact Serde helper.
  - Unit-bearing key suffixes are removed according to the migration matrix in
    `TRACE-SCALAR-MIGRATION`.
  - Counts, cache capacities, rates, ratios, IDs, and protocol/URL values keep
    their existing representations.
- Rationale and evidence: `GatewayClientConfig` already establishes these byte
  and duration representations in the schema crate.
- Consequences and rejected alternatives: old numeric values and old keys are
  rejected. Runtime types use `Duration` where practical and perform checked
  integer conversion only at an existing protocol or library boundary. The
  existing `FIRMA_AUTHORITY_MAX_TTL_SECONDS` and
  `FIRMA_AUTHORITY_BUNDLE_TTL_SECONDS` environment variables intentionally
  remain bare integer seconds: valid nonnegative/in-range values replace the
  schema duration after rebasing, while malformed, negative, or overflowing
  values continue to leave the prior value unchanged. Zero remains accepted as
  it is today. Schema durations that cannot fit the downstream `i32`/`u32`
  second boundaries fail checked runtime conversion.

### `DEC-005`: Type and resolve filesystem paths according to ownership

- Choice:
  - Convert mapping paths, persistent session-state path, Run executable
    allowlists, and home-mask paths to `PathBuf`-based representations.
  - Rebase config-declared resource inputs against the containing
    `firma.toml`: Sidecar explicit MITM CA files, Authority mTLS client files,
    credential secret files, and Run mount sources, seccomp resources, and
    capability files/keys, in addition to the already-rebased fields.
  - In `firma-run`, normalize paths on the parsed `FileConfig` (both defaults
    and every profile) before selecting or merging a profile with built-in and
    CLI patches. This preserves provenance without adding provenance types:
    file paths are anchored once; equivalent CLI values remain verbatim.
  - Keep sandbox mount targets absolute, executable allowlist entries absolute
    and canonical, and endpoint-embedded Unix socket paths absolute.
  - Do not rebase state/runtime-owned `ca.dir`, Authority `revocation_file`,
    persistent session state, audit WAL, or socket paths.
- Rationale and evidence: this matches the ownership rule in
  `docs/configuration.md` without reclassifying identifiers, URLs, JSONPath,
  HTTP paths, or sandbox destinations as host resources.
- Consequences and rejected alternatives: validation continues to fail closed
  on empty or invalid paths. Environment-supplied Authority paths remain
  verbatim because environment overrides are not relative to a config file.

## Architecture and invariant ownership

- Architecture shape:

```diagram
┌──────────────────────┐   deserialize   ┌────────────────────────┐
│ firma.toml section   │────────────────▶│ behavior-free schema   │
│ authority/sidecar/run│  strict + typed │ representation         │
└──────────────────────┘                 └───────────┬────────────┘
                                                    │ convert / merge
                                                    ▼
                                        ┌────────────────────────┐
                                        │ component runtime config│
                                        │ validation + rebasing   │
                                        └───────────┬────────────┘
                                                    │ consume
                                                    ▼
                                        ┌────────────────────────┐
                                        │ startup / hot-path owner│
                                        └────────────────────────┘
```

### `INV-001`: Accepted user fields have a terminal owner

- Semantic predicate: every accepted non-compatibility config field changes a
  runtime input, and every accepted compatibility field is explicitly named
  and validated.
- Primary owner: component schema-to-runtime conversion plus terminal startup
  consumers.
- Detailed proof: `TRACE-DEAD-FIELDS` and `TRACE-LIVE-SURFACE`.

### `INV-002`: Known sections are recursively typo-intolerant

- Semantic predicate: adding an unknown top-level section or an unrecognized
  key in any schema object below `[authority]`, `[sidecar]`, or `[run]` makes
  parsing fail before component startup, including unselected Run profiles.
- Primary owner: `firma-config-loader` for top-level section names;
  `firma-config-schema` and the Authority's use of its new representation for
  section contents.
- Detailed proof: `TRACE-STRICT-PARSE`.

### `INV-003`: Scalar meaning is represented in the parsed type

- Semantic predicate: parsed byte quantities are `ByteSize`, parsed durations
  are `Duration`, and parsed filesystem paths are `PathBuf`; unit conversion
  cannot be accidentally repeated by a consumer.
- Primary owner: `firma-config-schema`.
- Detailed proof: `TRACE-SCALAR-MIGRATION`.

### `INV-004`: Resource paths have one stable anchor

- Semantic predicate: a relative config-declared host resource resolves once
  against the parent of the `firma.toml` that declared it; state/runtime paths,
  sandbox targets, endpoints, and environment overrides are not re-anchored.
- Primary owner: component runtime config resolution.
- Detailed proof: `TRACE-PATH-RESOLUTION`.

- Compatibility, migration, and failure semantics: `DEC-001` through
  `DEC-005`. All three PRs are breaking configuration changes and must list
  exact migrations. Parsing failures remain fail-closed startup failures.
- Durable documentation owner: `docs/configuration.md`; task-focused docs-site
  guides and `docs-site/public/llms.txt` mirror discovery-critical changes.

## Implementation slices

### Slice 1: Remove dead and fake config controls

- Production, types, tests, and docs/config:
  - Remove the fields in `DEC-001` from schema/runtime structs, merge/default
    code, config generation, examples, fixtures, and docs.
  - Remove stale `[project]` documentation and examples.
  - Remove the complete Sidecar log schema/runtime section.
  - Keep unconditional seccomp checksum verification and replace the rejected
    false-choice test with invariant-focused checksum coverage.
  - Commit this plan and its independent findings at the durable locator.
- Affected decisions and traces: `DEC-001`, `TRACE-DEAD-FIELDS`.
- Proof obligations: `INV-001`.
- Focused verification: config-schema, Authority config, Sidecar config,
  firma-run config/seccomp, config-generator, and affected integration tests;
  formatting, lint, build, and full repository verification before PR update.
- Dependencies: exact PR #605 tip.
- Intentionally unsupported: no new logging, TTL, or timeout behavior.

### Slice 2: Reject unknown fields and validate all backend values

- Production, types, tests, and docs/config:
  - Implement `DEC-002` and `DEC-003` recursively across all schema modules.
  - Reject unknown top-level sections in the unified loader.
  - Move Authority wire representation into `firma-config-schema` while
    preserving runtime validation, environment, and path behavior.
  - Test direct, nested, tagged-variant, dynamic-map-value, stale
    `[sidecar.preflight]`, removed `[project]`, arbitrary top-level tables,
    Authority TLS, Run defaults, selected profile, and unselected profile
    typos.
  - Test invalid backend values in unselected profiles and overridden defaults.
- Affected decisions and traces: `DEC-002`, `DEC-003`, `TRACE-STRICT-PARSE`.
- Proof obligations: `INV-002` and the compatibility part of `INV-001`.
- Focused verification: schema, loader, Authority, Sidecar, firma-run, and CLI
  config parsing suites; formatting, lint, build, and full repository
  verification.
- Dependencies: Slice 1 branch.
- Intentionally unsupported: no catch-all extension map and no silent aliases
  for stale fields.

### Slice 3: Normalize scalar and path conventions

- Production, types, tests, and docs/config:
  - Apply `DEC-004`, `DEC-005`, and the exact matrices below.
  - Update runtime consumers and checked wire/library conversions.
  - Rebase Run file patches before built-in/CLI merge and prove equivalent CLI
    paths remain untouched.
  - Preserve and test the two integer-seconds Authority environment overrides;
    emit the new friendly TOML duration keys in generated config.
  - Update generated templates, examples, docs, migration tables, config
    rebasing tests, schema representation tests, and docs-site discovery text.
- Affected decisions and traces: `DEC-004`, `DEC-005`,
  `TRACE-SCALAR-MIGRATION`, `TRACE-PATH-RESOLUTION`.
- Proof obligations: `INV-003`, `INV-004`.
- Focused verification: schema Serde tests; every component config/conversion
  suite; generator and config-relative integration tests; representative
  startup tests; formatting, lint, build, and full repository verification.
- Dependencies: Slice 2 branch.
- Intentionally unsupported: changing counts/capacities or protocol field
  units, and rebasing state/runtime paths.

## Risks and gaps

- Existing risks: strict parsing and renamed scalar keys intentionally reject
  existing files; scattered examples can otherwise preserve stale syntax.
- Planned mitigations: repository-wide old-key searches, generated-config
  assertions, explicit migration tables, per-slice full verification, and
  independent implemented-change review.
- Explicit evidence gaps: external configurations cannot be inspected; the
  migration is therefore documented rather than auto-rewritten.
- Least-confident decisions: whether every historically unre-based resource
  was intentional. `DEC-005` limits changes to paths covered by the existing
  resource-anchor contract and preserves explicit state/runtime exclusions.

## Plan-review findings and dispositions

The independent reviewer inspected the exact researched revision. Its records
are preserved verbatim below; each is followed by the planner's disposition.

```yaml
findings:
  - id: PLAN-001
    severity: high
    category: path-resolution
    classification: design risk
    evidence:
      - "docs/architecture/config-schema-hardening-plan.md:181-199 (`DEC-005`) requires Run resource paths to be config-relative while CLI paths remain outside that rule."
      - "crates/firma-run/src/config.rs:420-436 (`resolve_profile_with_layout`) merges built-in, file, and CLI `ProfilePatch` values before paths are consumed."
      - "crates/firma-run/src/config.rs:487-495 moves merged mount paths directly into `MountSpec` without retaining their source."
      - "crates/firma-run/src/config.rs:640-647 constructs CLI capability paths in the same `ProfilePatch` type used for file configuration."
      - "crates/firma-run/src/config.rs:686-735 consumes capability and seccomp paths after provenance has been erased."
    reachable_trace:
      entry: "Run invocation with both `firma.toml` resource paths and CLI overrides."
      conditions:
        - "A relative mount source, seccomp resource, capability file, or capability public key originates in `firma.toml`."
        - "A path-bearing CLI override may also be present."
      causal_path:
        - "`read_config` returns a `ProfilePatch`."
        - "The file patch is merged with built-in and CLI patches."
        - "The merged patch no longer records which paths came from the config file."
        - "A later generic rebase either misses config paths or also rebases CLI paths."
      observable_outcome: "Config-declared resources can continue resolving against the process working directory, or CLI paths can be incorrectly anchored to the config directory."
    invariant_owner: "`firma-run` profile loading and merge boundary; proposed `INV-004`."
    practical_impact: "Slice 3 cannot implement the promised one-anchor rule correctly from the proposed architecture without making an unplanned provenance/ordering decision."
    correction: "Specify and sketch a file-only normalization boundary: rebase each `FileConfig`/selected file patch against `ResolvedConfig::config_dir()` before merging built-in or CLI patches. Define handling for defaults and selected profiles, and add positive and negative controls proving file paths rebase exactly once while equivalent CLI paths remain verbatim."
    confidence: high
    unverified_assumptions:
      - "No separate path-provenance wrapper is intended."
      - "CLI path values are not intended to become config-relative."

  - id: PLAN-002
    severity: medium
    category: scope-completeness
    classification: confirmed conflict
    evidence:
      - "docs/architecture/config-schema-hardening-plan.md:114-130 defines the exact dead-field removal inventory."
      - "docs/architecture/config-schema-hardening-plan.md:439-453 claims a repository-wide inventory found no other terminally dead schema field."
      - "docs/configuration.md:19-27 presents `[project].agent` and `[project].provider` as part of the scaffolded user-facing `firma.toml`."
      - "crates/firma-config-loader/src/schema.rs:11-30 parses the document as a generic top-level TOML table."
      - "crates/firma-config-loader/src/schema.rs:45-83 deserializes only named component subtrees; no `[project]` consumer is present."
      - "Repository search at revision `b4daea63ba9515f6ed9476f699371387d5456071` found no runtime read of these two `[project]` keys."
    reachable_trace:
      entry: "An operator follows the configuration reference and supplies `[project].agent` or `[project].provider`."
      conditions:
        - "Authority, Sidecar, or Run loads its own section through `FirmaConfig::section` or `optional_section`."
      causal_path:
        - "The top-level TOML parser accepts `[project]`."
        - "Component extraction ignores that table."
        - "Neither field reaches a runtime owner."
      observable_outcome: "Two documented controls remain accepted-looking no-ops despite the requirement to remove every proven-dead user-facing field."
    invariant_owner: "User-facing unified-config documentation and proposed `INV-001`."
    practical_impact: "PR 1 would not establish an honest user-facing vocabulary, and `TRACE-DEAD-FIELDS` would falsely certify completeness."
    correction: "Add `[project].agent` and `[project].provider` to the dead-surface inventory and remove their documentation/examples, or identify and cite a terminal runtime consumer. Clarify that component-level strictness intentionally cannot reject arbitrary top-level sections."
    confidence: high
    unverified_assumptions:
      - "No external contract outside the repository gives `[project]` semantics."
      - "The task's phrase “every proven-dead user-facing config field” includes documented top-level fields even though component schemas are section-scoped."

  - id: PLAN-003
    severity: medium
    category: compatibility-migration
    classification: design risk
    evidence:
      - "docs/architecture/config-schema-hardening-plan.md:165-179 changes user-facing duration types and says integer conversion remains only at protocol or library boundaries."
      - "docs/architecture/config-schema-hardening-plan.md:483-486 renames Authority TOML TTL keys to `max_ttl` and `bundle_ttl` with `Duration` values."
      - "crates/firma-authority/src/config.rs:132-146 independently parses `FIRMA_AUTHORITY_MAX_TTL_SECONDS` as `i32` and `FIRMA_AUTHORITY_BUNDLE_TTL_SECONDS` as `u32`."
      - "docs/architecture/config-schema-hardening-plan.md:198-199 preserves Authority environment override semantics only for paths; it does not decide TTL environment syntax or conversion."
      - "crates/firma/src/services/config/doc.rs:155-165 currently emits the old integer TOML TTL keys, demonstrating another migration consumer requiring exact output changes."
    reachable_trace:
      entry: "Authority startup with either legacy TTL environment variable set after Slice 3."
      conditions:
        - "The runtime Authority fields become `Duration`, as preferred by `DEC-004`."
      causal_path:
        - "Environment overrides are applied after schema conversion."
        - "Current overrides parse bare integer seconds."
        - "The plan neither preserves that contract explicitly nor defines friendly-duration parsing for environment values."
      observable_outcome: "Implementation must silently choose between breaking established environment syntax, retaining an undocumented integer-seconds compatibility boundary, or accepting inconsistent TOML and environment representations."
    invariant_owner: "Authority schema-to-runtime conversion and environment override boundary; proposed `INV-003`."
    practical_impact: "Slice 3 contains a hidden public compatibility decision and lacks tests or migration documentation for a reachable Authority launch path."
    correction: "Decide explicitly that the existing `_SECONDS` environment variables remain bare integer seconds or replace them with named duration variables. Add the conversion signature, precedence behavior, migration documentation, and tests for valid, malformed, zero, and overflow values. Assign generated-config emission of `max_ttl = \"1h\"` and `bundle_ttl = \"30s\"` explicitly."
    confidence: high
    unverified_assumptions:
      - "The existing Authority environment variables are user-facing compatibility surfaces."
      - "No separate environment migration requirement supersedes their current names."

required_plan_repairs:
  - sections:
      - "`DEC-001`"
      - "`TRACE-DEAD-FIELDS`"
      - "`TRACE-LIVE-SURFACE`"
      - "Slice 1"
    repair: "Resolve the omitted documented `[project]` fields and remove the unsupported claim that no other dead user-facing field exists."
  - sections:
      - "`DEC-005`"
      - "Architecture and invariant ownership"
      - "Types and signatures"
      - "`TRACE-PATH-RESOLUTION`"
      - "Slice 3"
    repair: "Define the Run file-only rebasing boundary and preserve source provenance by rebasing before built-in/CLI merge. Extend `INV-004` evidence with config-versus-CLI negative controls and defaults/profile coverage."
  - sections:
      - "`DEC-004`"
      - "`TRACE-SCALAR-MIGRATION`"
      - "Slice 3"
      - "Detailed proof obligations for `INV-003`"
    repair: "Specify Authority TTL environment compatibility, checked conversion behavior, malformed/overflow outcomes, and generated-config output."
  - sections:
      - "Detailed proof obligations for `INV-001`"
    repair: "Replace the non-executable statement “every removed field has no terminal read” with a repository inventory or explicit per-field terminal trace, including documented top-level user-facing fields."

review_status: "Changes required before implementation."
review_basis: "Independent inspection of repository revision b4daea63ba9515f6ed9476f699371387d5456071; plan citations were treated only as leads."
files_modified: []
```

```yaml
disposition:
  finding: PLAN-001
  status: corrected
  rationale: The accepted plan rebases every FileConfig defaults/profile patch before selection and before built-in/CLI merge, with explicit negative controls for CLI provenance.
  incorporated_at: DEC-005, Slice 3, TRACE-PATH-RESOLUTION, INV-004 proof obligation
  decided_by: planner
```

```yaml
disposition:
  finding: PLAN-002
  status: corrected
  rationale: The documented but unconsumed project fields join the dead inventory. The loader now owns a strict top-level authority/sidecar/run section vocabulary so stale project tables fail after removal.
  incorporated_at: Scope, DEC-001, DEC-002, Slice 1, Slice 2, TRACE-DEAD-FIELDS, TRACE-STRICT-PARSE
  decided_by: planner
```

```yaml
disposition:
  finding: PLAN-003
  status: corrected
  rationale: Existing Authority _SECONDS environment variables remain explicit integer-seconds compatibility boundaries with unchanged precedence and ignored invalid input; schema-to-protocol range conversion and generated TOML output are now specified and tested.
  incorporated_at: DEC-004, Slice 3, TRACE-SCALAR-MIGRATION, INV-003 proof obligation
  decided_by: planner
```

## Final verification

- Focused checks: crate/unit/integration suites named per slice.
- Workspace checks: repository formatting, build, lint, test, API-visibility,
  and final `just check` as routed by repository skills.
- Post-implementation independent review: required for each stack diff, with
  Rust-specific review added by the review router.

## Technical evidence

### Applicability assessment

| Section                     | Applicability | Reason or evidence                                      |
| --------------------------- | ------------- | ------------------------------------------------------- |
| Vocabulary                  | Applicable    | Scalar/path terms and compatibility keys are normalized |
| Alternatives                | Applicable    | Flatten strictness and compatibility had alternatives   |
| File-tree diff              | Applicable    | Authority representation gains a schema module          |
| Type and signature sketches | Applicable    | Schema/runtime ownership and typed backend matter       |
| Semantic call traces        | Applicable    | Validation and consumption cross crates                 |
| Trust analysis              | Applicable    | Typos can silently weaken fail-closed configuration     |
| Detailed proof obligations  | Applicable    | Migration and recursive strictness require cross-suites |

### Vocabulary

| Canonical term        | Meaning                                               | Owner/context           | Terms to avoid                       |
| --------------------- | ----------------------------------------------------- | ----------------------- | ------------------------------------ |
| schema representation | Behavior-free Serde shape of a `firma.toml` section   | firma-config-schema     | validated config                     |
| runtime config        | Validated/defaulted/rebased component input           | consuming component     | wire schema                          |
| resource path         | Host file/directory input declared by a config file   | component resolver      | state path, endpoint, sandbox target |
| state/runtime path    | Component-owned mutable location                      | runtime-state/component | config-relative resource             |
| compatibility key     | Intentionally retained older input with strict values | schema representation   | arbitrary ignored key                |

### Alternatives

- Strict flattened maps via a custom deserializer:
  - Benefit: preserves Rust grouping in the schema aggregate.
  - Cost: duplicates key inventories and nested error behavior outside normal
    derives.
  - Rejected in favor of explicit schema fields plus runtime grouping.
- Preserve old scalar keys with aliases:
  - Benefit: softer rollout.
  - Cost: creates two conventions, obscures generated output, and conflicts
    with the requested explicit breaking migration.
  - Rejected; only named compatibility inputs in `DEC-003` remain.
- Keep runtime integer duration fields after parsing `Duration`:
  - Benefit: smaller internal diff.
  - Cost: repeats unit conversion and lets internal names preserve obsolete
    units.
  - Use only where an existing protocol/library boundary requires an integer;
    otherwise carry `Duration`.

### File-tree diff

```diff
 crates/firma-config-schema/src
+├── authority.rs          # NEW — strict behavior-free [authority] shape
~├── run.rs                # MODIFIED — strict types/backend/scalars/paths
~├── gateway.rs            # MODIFIED — recursive strictness
~├── secret_matcher.rs     # MODIFIED — recursive tagged-variant strictness
~└── sidecar/              # MODIFIED — no flatten; strict/scalar/path shapes
~crates/firma-authority/   # MODIFIED — schema conversion and durations
~crates/firma-sidecar/     # MODIFIED — conversion, rebasing, typed scalars
~crates/firma-run/         # MODIFIED — merge mapping, rebasing, typed scalars
~crates/firma/             # MODIFIED — generated config and integration tests
~docs/, docs-site/, examples/ # MODIFIED — exact contract and migrations
```

### Types and signatures

```rust
// Behavior-free vocabulary; no host/platform behavior.
enum Backend { Bwrap, Vz, Wsl2, Firecracker }
enum LegacyCapabilityKind { Disabled, File }

struct SidecarConfig {
    // direct section fields ...
    mapping: MappingConfig,
    capability_validation: CapabilityValidationConfig,
    constraint_enforcement: ConstraintEnforcementConfig,
}

struct AuthorityConfig {
    // direct fields, including the existing flat TLS key names
}

impl From<schema::Backend> for firma_run::BackendKind;
impl TryFrom<schema::SidecarConfig> for firma_sidecar::config::SidecarConfig;
impl From<schema::AuthorityConfig> for firma_authority::config::AuthorityConfig;

// firma-run-owned behavior, applied only to parsed file input.
fn rebase_file_config(config: &mut schema::run::FileConfig, config_dir: &Path);
```

`CW-001`: a finite schema enum makes this construction fail during full-file
deserialization rather than selected-profile resolution:

```rust
// TOML witness in an unselected profile:
// [run.profiles.unselected]
// backend = "bworp"
```

This proves backend vocabulary cardinality at the parse boundary. It does not
prove host support; `firma-run` remains the owner of that runtime validation.

### Semantic call traces

#### `TRACE-DEAD-FIELDS`

| Candidate                     | Accepted/copied path                         | Terminal evidence                                             | Decision                           |
| ----------------------------- | -------------------------------------------- | ------------------------------------------------------------- | ---------------------------------- |
| `[project].agent`             | documentation/top-level TOML only            | generator does not emit it; no component reads it             | remove documentation               |
| `[project].provider`          | documentation/top-level TOML only            | generator does not emit it; no component reads it             | remove documentation               |
| Authority `log_level`         | Authority Serde/default/env override         | no read by logging initialization or server startup           | remove                             |
| Sidecar `log.level`           | schema → validation-only runtime `LogConfig` | tracing initializes before config; no later read              | remove whole table                 |
| Sidecar constraint bundle TTL | schema → runtime config                      | pipeline builds the enforcer without it                       | remove                             |
| Sidecar enforcement timeout   | schema → runtime config                      | pipeline builds the enforcer without it                       | remove                             |
| Run `allowed_domains`         | patch merge → `ResolvedProfile`              | network startup consumes `profile.network`, never this vector | remove                             |
| seccomp `verify_checksum`     | omitted → true; false rejected               | both materialization modes always verify digest               | remove fake choice; keep invariant |

Repository-wide inventories covered every field declared by the Authority,
Sidecar, gateway, secret-matcher, and Run schema structs, plus every field in
the documented top-level `[project]` table. No other field lacked a terminal
owner. Sidecar `authority.agent_id` is consumed by `firma-run` identity/config
synthesis, and Sidecar `policy.dir` participates in startup bundle-version
calculation; neither is dead.

#### `TRACE-LIVE-SURFACE`

- Authority fields terminate in listener binding, policy/issuance store load,
  schema/key/TLS/mTLS file reads, revocation storage, token TTL clamping, or
  bundle construction.
- Sidecar fields terminate in interceptor/connector/Authority client startup,
  mapping and token verification, session/revocation stores, credential/secret
  providers, audit sinks, local-exec governance, or `firma-run` identity
  synthesis.
- Run fields terminate in backend launch, mounts/environment, network policy,
  capability acquisition/refresh, executable launch policy, command mediation,
  CA trust, or sandbox identity.

#### `TRACE-STRICT-PARSE`

| Entry and stimulus                               | Proposed path                               | Observable failure                   |
| ------------------------------------------------ | ------------------------------------------- | ------------------------------------ |
| `[project]` or arbitrary top-level table         | loader top-level section allowlist          | parse error before section access    |
| typo in `[authority]` or flat TLS key            | loader section → schema AuthorityConfig     | parse error before Authority startup |
| `[sidecar.preflight]`                            | loader section → direct-field SidecarConfig | unknown field parse error            |
| typo under a Sidecar nested/tagged value         | strict nested derive                        | parse error at nested key            |
| typo in Run defaults/any profile                 | whole `FileConfig` parse                    | parse error before profile selection |
| invalid backend in overridden/unselected profile | schema Backend enum                         | unknown variant parse error          |
| extra key on tagged capability/secret variant    | strict enum representation                  | parse error rather than discard      |

#### `TRACE-SCALAR-MIGRATION`

Durations use friendly compact strings and `Duration` after migration:

| Old TOML key/value                                       | New TOML key/value                     |
| -------------------------------------------------------- | -------------------------------------- |
| `authority.max_ttl_seconds = 3600`                       | `authority.max_ttl = "1h"`             |
| `authority.bundle_ttl_seconds = 30`                      | `authority.bundle_ttl = "30s"`         |
| `interceptor.drain_timeout_secs = 30`                    | `interceptor.drain_timeout = "30s"`    |
| `interceptor.connect_relay.setup_timeout_secs = 10`      | `setup_timeout = "10s"`                |
| `interceptor.connect_relay.session_max_secs = 600`       | `session_max = "10m"`                  |
| `interceptor.https_mitm.cert_ttl_secs = 86400`           | `cert_ttl = "1d"`                      |
| `sidecar.authority.connect_timeout_secs = 10`            | `connect_timeout = "10s"`              |
| `reconnect_min_backoff_ms = 250`                         | `reconnect_min_backoff = "250ms"`      |
| `reconnect_max_backoff_secs = 30`                        | `reconnect_max_backoff = "30s"`        |
| `revocation_readiness_grace_ms = 500`                    | `revocation_readiness_grace = "500ms"` |
| `capability_validation.clock_skew_tolerance_seconds = 5` | `clock_skew_tolerance = "5s"`          |
| `connector.default_timeout_ms = 30000`                   | `connector.default_timeout = "30s"`    |
| `connector.hosts[].timeout_ms = 5000`                    | `connector.hosts[].timeout = "5s"`     |
| `local_exec.token_ttl_secs = 300`                        | `local_exec.token_ttl = "5m"`          |
| `local_exec.retry_after_ms = 500`                        | `local_exec.retry_after = "500ms"`     |
| `run.*.capability.grace_seconds = 30`                    | `grace = "30s"`                        |
| `run.*.sidecar_local_exec.timeout_ms = 500`              | `timeout = "500ms"`                    |
| `hitl_max_wait_ms = 300000`                              | `hitl_max_wait = "5m"`                 |

Byte quantities use `ByteSize`:

| Old TOML key/value                               | New TOML key/value                |
| ------------------------------------------------ | --------------------------------- |
| `interceptor.max_request_body_bytes = 4194304`   | `max_request_body_size = "4 MiB"` |
| `interceptor.total_body_budget_bytes = 67108864` | `total_body_budget = "64 MiB"`    |
| `audit.wal_max_bytes = 104857600`                | `audit.wal_max_size = "100 MiB"`  |

Existing `max_decompressed_body_size` and secret-gateway `max_buffer_size`
already use `ByteSize`; secret-gateway timeouts already use `Duration` and keep
their keys. Counts/capacities/rates are intentionally absent from this table.

Authority environment compatibility is deliberately asymmetric with TOML:
`FIRMA_AUTHORITY_MAX_TTL_SECONDS` remains a bare nonnegative `i32` number of
seconds and `FIRMA_AUTHORITY_BUNDLE_TTL_SECONDS` remains a bare `u32` number of
seconds. They override parsed TOML after path rebasing. Malformed, negative, or
overflowing input is ignored; zero is retained. Tests cover each case and
checked rejection of TOML durations outside the downstream integer ranges.
`firma config` emits `max_ttl = "1h"` and `bundle_ttl = "30s"`.

#### `TRACE-PATH-RESOLUTION`

- Current: the Sidecar rebases policy, mapping, Authority public key/CA,
  Authority pre-shared key, audit file/signing key, and capability-seed paths.
  Authority rebases policy/issuance/schema/key and TLS/mTLS resources except its
  state-managed revocation file.
- Proposed additions:
  - Sidecar explicit HTTPS MITM CA certificate/key, Authority mTLS client
    certificate/key, and credential secret files.
  - Run mount sources, seccomp policy/artifact resources, capability file, and
    capability public key.
- Run ordering: parse the complete `FileConfig`, rebase path-bearing fields in
  `defaults` and every `profiles` value against `path.parent()`, then select and
  merge the file layers over built-ins; merge the CLI patch last without
  rebasing it. Tests cover a defaults path, a selected-profile path, an
  unselected profile (normalized without consumption), an absolute file path,
  and an equivalent relative CLI path that remains verbatim.
- Typed but intentionally not config-relative:
  - state/runtime: `ca.dir`, revocation file, audit WAL, persistent session
    state, sockets;
  - sandbox/execution boundary: mount target, canonical executable allowlist;
  - endpoint/identifier/expression values remain their non-path types.

### Trust analysis

- Actor: an operator authors `firma.toml`; accidental typos and stale examples
  are the primary hostile input model for this schema boundary.
- Protected assets: fail-closed network/local-exec policy, credentials, signing
  material, and runtime availability.
- Trust transition: TOML text becomes typed schema only after recursive strict
  deserialization; validated runtime conversion then establishes component
  constraints.
- Reachable abuse today: a typo can silently select a default or leave a dead
  control appearing active. Strictness changes that path to a startup error.
- This does not make operator-controlled config untrusted in a cryptographic
  sense; it prevents accidental policy weakening and stale no-op controls.

### Detailed proof obligations

| Invariant | Kind                  | Owner/proof boundary                                  | Stimulus and observable effect                                                                                                        | Status/slice      |
| --------- | --------------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| `INV-001` | Runtime/compatibility | per-field inventory + component startup suites        | every declared/documented field has a cited terminal read or removal; retained compatibility values validate                          | Planned/Slice 1–2 |
| `INV-002` | Runtime/trust         | schema Serde plus component parse suites              | unknown direct/nested/tagged keys and stale tables fail, including unselected profiles                                                | Planned/Slice 2   |
| `INV-003` | Type/migration        | schema representation + Authority env/generator tests | friendly TOML parses to exact `ByteSize`/`Duration`; numeric/old keys fail; integer-seconds env compatibility and checked bounds hold | Planned/Slice 3   |
| `INV-004` | Runtime/migration     | component rebasing and startup tests                  | defaults/profile resources resolve under config parent exactly once; CLI and state/runtime paths remain unchanged                     | Planned/Slice 3   |
