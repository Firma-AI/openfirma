# Remove Obsolete Run Configuration Forms

## Artifact metadata

- Status: Accepted
- Durable locator: this path in PR #614's first implementation-owned commit;
  the immutable commit URL is recorded in the PR body before the file's final
  mechanical deletion.
- Repository revision researched:
  `5820d57f37c7d0a136b09e544647d82de2c358b7`
- Task or requirement source:
  <https://github.com/Firma-AI/openfirma/pull/614>
- Supersedes: the broader artifact formerly published at this path; this plan
  narrows PR #614 to obsolete Run forms only.

## Goal and acceptance outcomes

- Goal: expose one canonical Run configuration shape by removing flat
  `capability.kind` / `capability.path` and `codex_cli` from every parsing and
  generation path.
- Observable acceptance outcomes:
  - direct runtime parsing accepts tagged `capability.source` and
    `executable_policies.codex` only;
  - `firma config` rejects removed forms before any write, including forms in
    defaults and every named profile;
  - removed forms are neither migrated nor silently ignored;
  - canonical configuration keeps its existing merge, path-rebasing, generated
    defaults, CLI precedence, and runtime behavior;
  - public docs and generated comments describe only canonical current syntax;
    and
  - no plan Markdown remains at the final branch tip or in the PR diff.

## Scope

- In scope: Run schema and runtime patch handling, form-specific regression
  coverage through the existing whole-file `firma config` validation boundary,
  generated configuration, focused CLI/schema/runtime tests, current-product
  docs, and deletion of code or dependencies owned only by the removed forms.
- Out of scope: Run profile merge semantics established by PR #613; Sidecar
  template shape; global config discovery; Authority client identity;
  capability-file handoff or filesystem confinement; protocol behavior.
- Assumptions: the branch is stacked on PR #615, whose Authority-only aggregate
  patch is independent from Run configuration.
- Open decisions: none.
- Cohesion and split assessment: the two removed fields have distinct atomic
  implementation commits but share one existing strict scaffold boundary and
  one public Run contract. All other legacy surfaces are split into child PRs.
- Deferred child plans: canonical config discovery, sectioned Sidecar
  templates, canonical Authority client identity, canonical capability-file
  handoff, and capability-seed confinement each have separate plans and proof
  boundaries.

## Routing

- Mode: Full
- Trigger evidence: this deliberately breaks externally observable TOML and
  CLI scaffolding behavior and changes a strict fail-closed configuration
  boundary across three crates.
- Higher-mode triggers checked: configuration contract, trust-boundary
  validation, multiple-crate consumers, and no-write failure behavior all
  require Full planning.
- Downgrade evidence and reason: Not applicable.

## Current behavior and problem

- Owners and entry points:
  `firma_config_schema::run::{CapabilityLeasePatch,ProfilePatch}` own accepted
  TOML shape; `firma_run::config` merges, rebases, and resolves those patches;
  `firma config` in `crates/firma/src/services/config` reads and renders
  existing configuration.
- Current success and failure outcomes: the schema and runtime still accept
  flat capability fields and `codex_cli`. Scaffold rendering already validates
  both source and rendered complete configuration through the owning schemas
  before directory creation or writes; form-specific black-box cases are still
  required to prove the removed fields reach that boundary in defaults and
  every named profile.
- Evidence: `crates/firma-config-schema/src/run.rs`,
  `crates/firma-run/src/config.rs`, `crates/firma-run/src/profile.rs`, and
  `crates/firma/src/services/config/{doc.rs,mod.rs}` at the researched revision.

## Key decisions and tradeoffs

### `DEC-001`: Reject removed forms at every public configuration entry

- Choice: delete legacy schema fields and runtime fallback branches. Do not add
  aliases, untagged compatibility variants, or raw migration.
- Rationale and evidence: OpenFirma is alpha and the product contract is the
  canonical shape. Retaining migration in `firma config` would make that
  command a bypass around strict runtime parsing.
- Consequences and rejected alternatives: old files fail with path-bearing
  unknown-field diagnostics and remain byte-identical. Automatic rewriting and
  precedence between old and current forms are intentionally unsupported.

### `DEC-002`: Reuse the existing strict scaffold boundary

- Choice: leave complete source/rendered typed validation and the existing
  render-all-before-write sequence unchanged. Extend its black-box matrix in
  each field-removal commit.
- Rationale and evidence:
  `services/config/doc.rs::render_firma_toml` already validates before and after
  reconciliation, while `services/config/mod.rs::run` generates all files
  before directory creation or writes.
- Consequences and rejected alternatives: this PR adds no redundant raw scan or
  scaffold architecture churn. Existing renderer-level tests and canonical
  generated-output parsing remain the evidence for post-render validation;
  black-box removed-form tests prove the reachable source-rejection path only.

### `DEC-003`: Preserve canonical Run semantics

- Choice: remove only compatibility-owned fields, branches, fixtures, and
  prose. Keep PR #613's absent/present scalar, nested, list, and map merge
  behavior unchanged.
- Rationale and evidence: canonical values already have explicit owners and
  exhaustive layering tests.
- Consequences and rejected alternatives: no merge redesign or new defaults are
  included in this PR.

## Architecture and invariant ownership

- Architecture shape: one strict schema is consumed by runtime loading and by
  scaffold pre-write validation; canonical runtime conversion no longer sees
  a legacy representation.

### `INV-001`: Removed Run forms never reach runtime conversion

- Semantic predicate: for defaults and every named profile, any flat
  `capability.kind` / `capability.path` or `codex_cli` key causes strict parse
  failure before resolution or process launch.
- Primary owner: `firma-config-schema::run` recursive
  `#[serde(deny_unknown_fields)]` boundaries.
- Detailed proof: `PROOF-001` in the technical evidence.

### `INV-002`: Scaffold rejection is non-mutating

- Semantic predicate: if source or rendered configuration is strict-invalid,
  `firma config` returns failure before its first filesystem write and existing
  files remain byte-identical.
- Primary owner: `firma::services::config` generation/write boundary.
- Detailed proof: `PROOF-002`.

- Compatibility, migration, and failure semantics: `DEC-001` deliberately
  provides no compatibility or migration path; diagnostics identify the
  rejected profile/field without modifying files.
- Durable documentation owner: `docs/configuration.md`, the docs-site Run and
  initialization guides, and `docs-site/public/llms.txt` when discovery syntax
  is summarized there.

## Existing prerequisite evidence

- `services/config/doc.rs::render_firma_toml` validates source and rendered
  complete configuration through Authority, Sidecar, and Run schemas.
- `services/config/mod.rs::run` generates and validates all output before
  directory creation or writes.
- `firma_config::invalid_existing_sections_fail_without_writing` already proves
  strict rejection, unchanged configuration and neighboring files, and no
  state-directory creation. Each removal slice extends that matrix with its own
  forms.

## Implementation slices

### Slice 1: Remove flat capability fields

- Production, types, tests, and docs/config: remove schema fields, merge and
  path-rebase grouping, legacy final conversion, enums/helpers, fixtures, and
  old syntax documentation; add strict rejection through runtime and scaffold
  entries.
- Affected decisions and traces: `DEC-001`, `DEC-003`, `TRACE-RUNTIME`.
- Proof obligations: `INV-001`, `INV-002`.
- Focused verification: config-schema and firma-run integration tests plus
  black-box scaffold rejection/no-write tests.
- Dependencies: accepted plan and the existing `DEC-002` boundary.
- Intentionally unsupported: converting flat forms to tagged forms.

### Slice 2: Remove `codex_cli`

- Production, types, tests, and docs/config: remove schema, merge, profile,
  final-resolution, fixtures, and prose for the alias; add the same strict
  rejection proof while preserving keyed policy merge semantics.
- Affected decisions and traces: `DEC-001`, `DEC-003`, `TRACE-RUNTIME`.
- Proof obligations: `INV-001`, `INV-002`.
- Focused verification: executable-policy merge tests and scaffold
  rejection/no-write matrix.
- Dependencies: accepted plan and the existing `DEC-002` boundary; independent
  of Slice 1's implementation.
- Intentionally unsupported: alias precedence or migration.

## Risks and gaps

- Existing risks: unselected profiles can be missed by selected-profile-only
  tests.
- Planned mitigations: extend the existing complete-file typed validation
  matrix with defaults, selected-profile, and unselected-profile fixtures.
- Explicit evidence gaps: third-party TOML diagnostic formatting is not an
  OpenFirma-owned stable contract; tests assert field/profile context and
  no-write effects instead.
- Least-confident decisions: none.

## Plan-review findings and dispositions

### `PLAN-001` — High — Plan durability / review handoff — Confirmed conflict

- **Evidence:** The plan names
  `docs/architecture/remove-legacy-run-config-plan.md` as its sole durable
  locator (metadata lines 5–7), but acceptance requires that “no plan Markdown
  remains at the final branch tip or in the PR diff” (lines 27–28). The review
  section is still “Pending independent review” (line 212). In the worktree,
  the plan is untracked and therefore not available at base revision
  `5820d57f…`.
- **Path/outcome:** If implementation follows the plan, the accepted design and
  immutable review findings disappear from the only named team-accessible
  location before implementation review and PR handoff.
- **Owner/invariant:** Planning artifact and review-disposition durability.
- **Impact:** Implementers and post-implementation reviewers cannot reliably
  recover the accepted decisions, findings, or dispositions from PR #614.
- **Correction:** Name a durable repository path or external URL that will
  retain the accepted plan and unchanged findings. Repeat that locator in
  implementation commits/PR handoff. If the PR diff must omit planning
  Markdown, publish it durably outside that diff before deleting the working
  copy.
- **Confidence:** High. No alternate durable locator is stated.

Disposition: accepted and repaired. The durable locator now explicitly means
this path at the immutable first PR-owned commit. The final PR body records that
commit URL, which remains available after the immediate closing deletion.

### `PLAN-002` — High — Base-state accuracy / atomic implementation — Confirmed conflict

- **Evidence:** Slice 1 proposes adding complete pre/post-render typed
  validation and no-write tests (lines 140–151), but this boundary already
  exists at the exact researched base:
  - `crates/firma/src/services/config/doc.rs:95–102` validates both source and
    rendered `firma.toml`.
  - `doc.rs:137–144` deserializes the Authority, Sidecar, and complete Run
    schemas.
  - `crates/firma/src/services/config/mod.rs:160–176` generates and validates all
    output before directory creation or writes.
  - `crates/firma/tests/integration/firma_config.rs:939–1029` already proves
    strict invalid-input failure, unchanged `firma.toml`, unchanged neighboring
    files, and no state-directory creation.
  - `doc.rs:751–776` already tests rejection before mode-driven reconciliation.
- **Path/outcome:** Treating Slice 1 as new production work invites a redundant
  scaffold commit or unnecessary redesign. It also conflicts with the requested
  atomic per-form history: the actual implementation boundary is already
  established, leaving the flat capability and `codex_cli` removals as the two
  behavior commits.
- **Owner/invariant:** `firma::services::config::doc::render_firma_toml` already
  owns `INV-002`.
- **Impact:** Review scope and commit structure become misleading, and unrelated
  scaffold churn could enter narrowly scoped PR #614.
- **Correction:** Recast Slice 1 as **existing prerequisite evidence**, not an
  implementation slice. Add only form-specific regression cases to the
  relevant capability and `codex_cli` commits. Preserve the existing validation
  architecture unless a separately evidenced gap is found.
- **Confidence:** High.

Disposition: accepted and repaired. `DEC-002` and the prerequisite section now
record the existing owner; implementation has only one commit per removed form.

### `PLAN-003` — Medium — Proof design — Design risk

- **Evidence:** Slice 1 calls for black-box coverage of “invalid rendered
  output” (lines 146–149), while `PROOF-002` defines only removed or malformed
  source keys (lines 267–269). The production renderer validates generated
  output internally at `doc.rs:99–102`, but no external CLI stimulus in the
  plan explains how valid source plus normal CLI inputs can force generation of
  strict-invalid output.
- **Path/outcome:** A CLI test may only re-prove invalid-source rejection and be
  credited incorrectly as evidence that post-render validation catches a
  renderer defect.
- **Owner/invariant:** Post-render validation in `render_firma_toml`.
- **Impact:** The proof matrix can claim a negative control it does not actually
  exercise.
- **Correction:** Specify an internal renderer-level test that constructs or
  injects an invalid rendered candidate, or explicitly classify post-render
  validation as structural defensive evidence covered by canonical
  generated-output parsing. Do not claim a black-box test proves this path
  unless a reachable stimulus is identified.
- **Confidence:** Medium-high; no renderer injection seam or reachable
  invalid-output input is identified.

Disposition: accepted and repaired. `DEC-002` limits black-box claims to the
reachable source path. Existing renderer tests and generated-output parsing
remain the separate evidence for the post-render guard.

## Final verification

- Focused checks: affected config-schema, firma-run, and `firma config`
  integration suites; tracked generated examples; `git diff --check`.
- Workspace checks: `just check` and `just docs-build` at the final PR tip.
- Post-implementation independent review: fresh review of the exact cumulative
  base-to-tip diff, followed immediately by the review record and mechanical
  plan removal.

## Technical evidence

### Applicability assessment

| Section                     | Applicability  | Reason or evidence                                                       |
| --------------------------- | -------------- | ------------------------------------------------------------------------ |
| Vocabulary                  | Not applicable | Existing canonical terms are retained.                                   |
| Alternatives                | Applicable     | Typed validation versus ad hoc raw scans affects drift and bypass risk.  |
| File-tree diff              | Applicable     | Compatibility-only ownership is deleted across schema, runtime, and CLI. |
| Type and signature sketches | Not applicable | The change deletes fields; it introduces no architecture-shaping type.   |
| Semantic call traces        | Applicable     | Runtime and scaffold are distinct public entries.                        |
| Trust analysis              | Applicable     | Operator-controlled configuration must fail before launch or mutation.   |
| Detailed proof obligations  | Applicable     | Strict rejection and no-write effects cross crate boundaries.            |

### Alternatives

- Raw key scans in `firma config` would be locally smaller but duplicate the
  schema and can miss inline, defaults, or unselected-profile shapes. Rejected
  in favor of complete typed validation.
- Keeping aliases and warning would preserve obsolete inputs and contradict
  `DEC-001`. Rejected.

### File-tree diff

```diff
crates/firma-config-schema/src/run.rs
crates/firma-run/src/config.rs
crates/firma-run/src/profile.rs
crates/firma/src/services/config/doc.rs
crates/firma/src/services/config/mod.rs
crates/*/tests/integration/*.rs
docs/configuration.md
docs-site/src/content/docs/guides/{firma-run,initialize-a-project}.md
docs-site/public/llms.txt
```

### Semantic call traces

| Trace ID         | State    | Entry and stimulus                                   | Path                                                        | Outcome and proof boundary                                                 |
| ---------------- | -------- | ---------------------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------- |
| `TRACE-RUNTIME`  | Proposed | Runtime loads a profile containing a removed key     | TOML → strict Run schema → failure                          | No patch resolution or launch; schema and Run integration suites prove it. |
| `TRACE-SCAFFOLD` | Proposed | `firma config` reads a file containing a removed key | file bytes → complete typed validation → failure → no write | Existing bytes remain identical; CLI subprocess tests prove it.            |

### Trust analysis

- Actor and authority: an operator supplies local TOML and may invoke runtime or
  scaffold commands.
- Protected assets: launched process policy and existing configuration bytes.
- Reachable abuse/error path: a permissive mutable-document path could accept
  or rewrite input rejected by runtime.
- Boundary: complete typed validation before runtime conversion and before the
  scaffold write phase.

### Detailed proof obligations

| ID          | Invariant | Kind                           | Owner/proof boundary                   | Stimulus and observable effects                                                                           | Status                  |
| ----------- | --------- | ------------------------------ | -------------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------- |
| `PROOF-001` | `INV-001` | Runtime/configuration          | schema and Run integration suites      | Removed key in defaults and named profiles produces strict failure; canonical control resolves unchanged. | Planned                 |
| `PROOF-002` | `INV-002` | Configuration/mutation         | compiled `firma` CLI integration suite | Removed key exits non-zero and every pre-existing scaffold file remains byte-identical.                   | Existing plus extension |
| `PROOF-003` | `DEC-003` | Compatibility/current contract | PR #613 layering suite                 | Canonical profile merge matrix remains green and generated current configuration parses.                  | Existing plus rerun     |
