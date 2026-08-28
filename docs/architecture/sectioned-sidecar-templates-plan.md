# Sectioned Sidecar Templates

## Artifact metadata

- Status: Accepted
- Durable locator: this path in the first implementation-owned commit of the
  sectioned Sidecar templates PR; the immutable accepted-plan and review-record
  commit locators will be recorded in the PR body before final deletion.
- Repository revision researched:
  `7fc9cbbe38e34c1cb18581bf0fd8536eea3d3d88`
- Task or requirement source: the authorized configuration-stack restructuring
  above PR #619 in <https://github.com/Firma-AI/openfirma>.
- Supersedes: the Sidecar-template portion of the deleted broad PR #614 plan.

## Goal and acceptance outcomes

- Goal: make the unified `[sidecar.*]` schema the only accepted operator
  template shape for a Sidecar autostarted by `firma run`.
- Observable acceptance outcomes:
  - every selected explicit, environment, or discovered template is parsed as
    a unified `firma.toml` and strictly validated as `SidecarConfig`;
  - a flat Sidecar document or an unknown/superseded Sidecar field fails closed
    with the selected path and schema error;
  - rejected templates create no synthesized output or marker directory;
  - valid sectioned templates retain source precedence, relative-path rebasing,
    runtime overrides, and synthesized output behavior;
  - no-template autostart still synthesizes a minimal `[sidecar]` document; and
  - public guidance describes only sectioned templates and no plan Markdown
    remains at the final branch tip or PR diff.

## Scope

- In scope: local-autostart template selection, parsing, strict Sidecar-section
  validation, pre-marker validation, minimal synthesis, directly owned Run
  integration tests, and concise current-product template documentation.
- Out of scope: the global file-selection model owned by PR #619, direct
  `firma sidecar` selection, Run profile layering, Authority client identity,
  capability-file parsing, seed confinement, or protobuf behavior.
- Assumptions: all operator configuration uses the one current sectioned
  schema, and local Sidecar preparation remains Unix-only.
- Open decisions: none.
- Cohesion and split assessment: template shape and pre-side-effect validation
  share one parser and one observable launch boundary. Later identity and
  capability changes have independent invariant owners and remain separate
  PRs.

## Routing

- Mode: Full
- Trigger evidence: this removes an externally observable configuration form
  and moves fail-closed validation ahead of filesystem side effects.
- Higher-mode triggers checked: the stable configuration and fail-closed
  triggers apply; no protocol, concurrency, or distributed-state redesign is
  included.
- Downgrade evidence and reason: Not applicable.

## Current behavior and problem

- Owners and entry points: `firma run` resolves local autostart template inputs
  in `crates/firma-run/src/routing.rs`; the component orchestrator creates its
  runtime directory and can start an owned Authority; `sidecar::prepare::prepare`
  creates the run marker directory; `sidecar::config::synthesize` selects and
  parses a template, wraps a flat root under `[sidecar]`, applies runtime
  overrides, and writes the synthesized document.
- Current success and failure outcomes: an existing flat Sidecar document is
  silently converted into the unified shape. The generic TOML parse does not
  reject unknown Sidecar fields, and template errors are discovered only after
  marker creation.
- Evidence: `crates/firma-run/src/sidecar/{config,prepare}.rs` and
  `crates/firma-run/tests/integration/{sidecar_config_merge,sidecar_prepare}.rs`
  at the researched revision.

## Key decisions and tradeoffs

### `DEC-001`: Validate the selected unified document through canonical owners

- Choice: parse the selected text with `firma_config_loader::FirmaConfig`, then
  extract `sidecar` as `firma_config_schema::sidecar::SidecarConfig`. Retain the
  original TOML value for path rebasing, runtime overrides, and synthesis.
- Rationale and evidence: `FirmaConfig` owns strict top-level keys and section
  extraction; the schema type owns recursive Sidecar field validation. Using
  both avoids a second schema or local unknown-key list.
- Consequences and rejected alternatives: remove flat-root normalization and
  do not retain an alias or migration path. Parsing only as `toml::Value` is
  rejected because it cannot prove schema validity.

### `DEC-002`: Resolve and validate one template snapshot before side effects

- Choice: introduce a private resolved-template value containing its source,
  TOML value, and source directory. `prepare_run_components` resolves this value
  before invoking the component orchestrator and passes the same snapshot into
  Sidecar preparation and synthesis. Direct synthesis tests use the same
  resolver.
- Rationale and evidence: merely parsing once before marker creation and again
  during synthesis permits the selected file to change between reads. Carrying
  one private value proves that the validated bytes are the bytes transformed.
- Consequences and rejected alternatives: no public API or persisted format is
  added. Validation is not duplicated, and selection order remains explicit
  path, environment path, working-directory path, then minimal.

### `DEC-003`: Minimal synthesis starts with an explicit Sidecar table

- Choice: when no existing template is selected, construct a root table that
  already contains `sidecar = {}`.
- Rationale and evidence: all synthesis helpers operate below `[sidecar]`; an
  explicit table removes the former flat-normalization dependency.
- Consequences and rejected alternatives: no-template defaults and runtime
  overrides remain unchanged.

## Architecture and invariant ownership

### `INV-001`: Selected operator templates are canonical and validated

- Semantic predicate: the bytes transformed by synthesis have passed both the
  unified top-level contract and strict `SidecarConfig` deserialization; flat,
  missing-Sidecar, and unknown-field documents cannot reach override or write
  operations.
- Primary owner: the private template resolver in
  `crates/firma-run/src/sidecar/config.rs`.
- Detailed proof: `PROOF-001` and `PROOF-002`.

### `INV-002`: Template rejection precedes local launch artifacts

- Semantic predicate: if selected-template resolution or schema validation
  fails, no component orchestration, owned Authority startup, capability mint,
  run marker, log alias, or synthesized Sidecar configuration occurs.
- Primary owner: `routing::prepare_run_components` ordering, consuming the
  resolved template snapshot before `spawn_stack_from_plan`.
- Detailed proof: `PROOF-003`.

- Compatibility and failure semantics: accepted sectioned documents preserve
  precedence, path anchoring, overrides, and output. Rejected current-invalid
  forms return the existing path-bearing `RunError::ConfigParse` and do not
  fall through to a lower-priority source.
- Durable documentation owner: `docs/cli.md`, with concise aligned guidance in
  the docs-site Run guide. The global selected-file model stays owned by
  `docs/configuration.md#configuration-resolution`.

## Implementation slice

- Observable capability: one canonical, strictly validated Sidecar-template
  boundary with no pre-validation marker writes.
- Expected files:
  `crates/firma-run/src/{routing,sidecar/config,sidecar/prepare}.rs`,
  `crates/firma-run/tests/integration/{capability_routing,sidecar_config_merge,sidecar_prepare}.rs`,
  `docs/cli.md`, and
  `docs-site/src/content/docs/guides/firma-run.md`.
- Affected decisions and traces: `DEC-001`–`DEC-003`, `TRACE-DIRECT`, and
  `TRACE-PREPARE`.
- Proof obligations: `INV-001` and `INV-002`.
- Focused verification: affected `firma-run` integration tests, config-loader
  and schema parsing through those tests, changed-file dprint, and docs build.
- Dependencies: PR #619's exact tip for accurate global-selection docs.
- Intentionally unsupported: flat templates, unknown/superseded fields, and
  missing `[sidecar]` sections.

## Risks and gaps

- Existing risk: synthesis applies runtime overrides after schema validation;
  existing downstream startup validation remains the owner for combinations
  created by those overrides.
- Planned mitigation: preserve current override behavior and tests; this PR
  validates operator input rather than introducing a second post-override
  runtime schema owner.
- Explicit evidence gap: Windows cannot exercise local preparation because
  that path is Unix-only. Shared synthesis tests remain portable while the
  pre-marker resolver entry is `#[cfg(unix)]`.
- Least-confident decision: none after tracing the existing source and write
  order.

## Plan-review findings and dispositions

### `PLAN-001` — High — Lifecycle ordering — Confirmed conflict

- **Evidence:** The candidate placed resolution in
  `sidecar::prepare::prepare` and limited expected production changes to
  `sidecar/{config,prepare}.rs`.
- **Reachable path:** Unix `firma run` local autostart enters
  `prepare_run_components`. Before Sidecar `prepare` runs,
  `spawn_stack_from_plan` creates and locks `<marker>/orchestrator`; when
  Authority is also owned, it prepares and starts Authority first; Sidecar
  planning may mint a capability seed; and `create_log_alias` creates the run
  marker directory and `sidecar.log` symlink.
- **Observable outcome:** An invalid selected template can create
  marker/orchestrator files, create capability output, and potentially start an
  Authority before rejection. A `sidecar_prepare`-only test can pass while the
  actual `firma run` invariant fails.
- **Invariant owner / trust boundary:** `INV-002`; the production local-component
  orchestration boundary in `routing::prepare_run_components`, not solely
  `sidecar::prepare::prepare`.
- **Impact:** Violates the requirement that flat, missing, or unknown template
  forms be rejected before marker/output side effects. It also makes
  `TRACE-PREPARE` incomplete and `PROOF-003` a proxy rather than proof of the
  production outcome.
- **Required correction:** Resolve and validate the selected template snapshot
  in `prepare_run_components` before `spawn_stack_from_plan`, capability
  minting, log aliases, or any owned Authority startup. Pass that same owned
  snapshot through to Sidecar preparation/synthesis. Add `routing.rs` to the
  implementation files and add a production-boundary integration test that
  exercises local autostart with an invalid selected template and asserts
  absence of the complete run marker/output tree. Retain direct-synthesis tests
  for source selection and schema errors.
- **Material abstraction assessment:** Existing owners are `sidecar::config`
  for selection/transformation and `routing::prepare_run_components` for
  component lifecycle and side-effect ordering. The proposed snapshot remains
  appropriate, but its operational lifecycle must begin before orchestration
  and be consumed once by Sidecar synthesis; it need not become public or
  replace global config discovery.
- **Confidence:** High.
- **Unverified assumptions:** The exact test seam needed to prove that an owned
  Authority was not started may require additional harness support, but
  filesystem side effects are directly demonstrable from the cited path.

Disposition: accepted and repaired in `DEC-002`, `INV-002`, the implementation
file inventory, `TRACE-PREPARE`, and `PROOF-003`. Resolution now precedes the
orchestrator itself, and the production `prepare_network_runtime` integration
boundary must prove the complete marker tree absent. An owned-Authority process
probe is unnecessary because reaching `spawn_stack_from_plan` is structurally
after the now-fallible resolver call; the test supplies the negative filesystem
outcome while code review proves this ordering.

## Final verification

- Focused checks: affected `firma-run` integration tests and public-doc search.
- Workspace checks: `just check` and `just docs-build` at the final PR tip.
- Post-implementation independent review: fresh review of the exact
  base-to-candidate diff, followed immediately by a durable review record and
  mechanical plan deletion.

## Technical evidence

### Applicability assessment

| Section                     | Applicability  | Reason or evidence                                                     |
| --------------------------- | -------------- | ---------------------------------------------------------------------- |
| Vocabulary                  | Not applicable | Existing template and section terminology is sufficient.               |
| Alternatives                | Applicable     | Parse ownership and pre-side-effect handoff materially affect proof.   |
| File-tree diff              | Applicable     | Runtime, tests, and current-product docs change.                       |
| Type and signature sketches | Applicable     | A private validated snapshot closes the read/validate gap.             |
| Semantic call traces        | Applicable     | Direct synthesis and prepared local launch are separate entry paths.   |
| Trust analysis              | Applicable     | Operator input controls a policy-enforcement component configuration.  |
| Detailed proof obligations  | Applicable     | Strict rejection and no-write outcomes need executable negative proof. |

### Alternatives

- Validate and then reread during synthesis: rejected because it does not prove
  that the validated bytes are the transformed bytes.
- Teach the local synthesizer every accepted field: rejected because it
  duplicates canonical schema ownership.
- Validate only the synthesized output: rejected because marker and helper
  artifacts may already exist and runtime overrides obscure whether the
  operator input itself was canonical.

### Type and signature sketch

```rust
struct ResolvedTemplate {
    source: TemplateSource,
    value: toml::Value,
    template_dir: Option<PathBuf>,
}

fn resolve_template(/* source paths */) -> Result<ResolvedTemplate, RunError>;
fn synthesize_resolved(
    request: SynthesizeRequest<'_>,
    template: ResolvedTemplate,
) -> Result<TemplateSource, RunError>;
```

The type proves only that one resolver produced one owned snapshot. It does not
claim semantic provenance beyond its private constructor; callers cannot
construct or mutate it outside the module.

### Semantic call traces

| Trace ID        | State    | Entry and stimulus                   | Path                                                                  | Outcome and proof boundary                                             |
| --------------- | -------- | ------------------------------------ | --------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `TRACE-DIRECT`  | Proposed | direct synthesis with selected input | source selection → canonical parse → schema parse → overrides → write | Invalid input returns `ConfigParse`; synthesis integration tests.      |
| `TRACE-PREPARE` | Proposed | local Sidecar preparation            | source selection/validation → component orchestration → synthesis     | Invalid input creates no run artifacts; routing integration test.      |
| `TRACE-MINIMAL` | Proposed | no existing template source          | explicit `[sidecar]` value → runtime overrides → atomic write         | Existing minimal output behavior remains; synthesis integration tests. |

### Trust analysis

- Actor and authority: the operator supplies a Sidecar template; the wrapped
  process must not influence it before launch.
- Protected assets: enforcement configuration and predictable fail-closed
  launch behavior.
- Reachable error path: a flat or misspelled document is currently normalized
  or retained, then transformed and written as runtime configuration.
- Boundary: selected-template resolution before any per-run marker output.

### Detailed proof obligations

| ID          | Invariant | Kind                 | Owner/proof boundary                       | Stimulus and observable effects                                                                                 | Status  |
| ----------- | --------- | -------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------- |
| `PROOF-001` | `INV-001` | Strict configuration | synthesis integration tests                | Flat input through explicit, environment, and CWD sources returns path-bearing unknown-top-level-key failures.  | Planned |
| `PROOF-002` | `INV-001` | Recursive schema     | synthesis integration tests                | Sectioned input with an unknown Sidecar field returns a path-bearing schema failure and writes no config.       | Planned |
| `PROOF-003` | `INV-002` | Lifecycle/filesystem | `prepare_network_runtime` integration test | Invalid selected input returns before orchestration; the complete run marker/output tree does not exist.        | Planned |
| `PROOF-004` | both      | Positive controls    | existing synthesis and preparation suites  | Sectioned explicit input, precedence, resource rebasing, overrides, and minimal synthesis retain exact outputs. | Planned |
