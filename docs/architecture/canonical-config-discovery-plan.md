# Canonical Configuration Discovery

## Artifact metadata

- Status: Accepted
- Durable locator: this path in the first implementation-owned commit of the
  canonical configuration discovery PR; the immutable commit URL will be
  recorded in the PR body before the file's final mechanical deletion.
- Repository revision researched:
  `549016a47c887b03b3e9a96151f9597898b3d882`
- Task or requirement source: the authorized configuration-stack restructuring
  above PR #614 in <https://github.com/Firma-AI/openfirma>.
- Supersedes: the config-discovery portion of the broader, deleted PR #614 plan;
  this artifact owns only file selection, command consistency, and the concise
  global resolution documentation.

## Goal and acceptance outcomes

- Goal: expose one current configuration-file selection contract across
  `firma doctor`, `firma control`, and `firma monitor`, and document the global
  model without implying that configuration files or non-Run sections inherit.
- Observable acceptance outcomes:
  - each command selects an explicit `--config`, otherwise `FIRMA_CONFIG`,
    otherwise the nearest `.firma/firma.toml`;
  - `FIRMA_STACK_CONFIG` has no effect and does not appear in public help or
    current-product documentation;
  - subprocess tests prove canonical environment selection, explicit flag
    precedence, ignored unrelated environment input, and project discovery for
    all three commands;
  - one concise canonical section states file selection, schema defaults,
    Authority and Sidecar overlays, and Run-only profile inheritance;
  - Run shape behavior is expressed once as general rules plus only the
    security-relevant sharp edges; and
  - no plan Markdown remains at the final branch tip or in the PR diff.

## Scope

- In scope: the three command argument contracts, compiled CLI behavior tests,
  help-surface checks as secondary evidence, and consolidation of current
  configuration resolution and Run layering documentation, including the
  machine-oriented `docs-site/public/llms.txt` summary.
- Out of scope: changing the shared resolver, command-specific state-directory
  behavior, Sidecar template structure or selection, Authority client identity,
  capability-file parsing, seed confinement, Run merge implementation, or
  protobuf behavior.
- Assumptions: the PR is stacked on rebuilt PR #614 and all configuration files
  use the one current sectioned schema.
- Open decisions: none.
- Cohesion and split assessment: the three commands expose the same file
  selection input and are proved by one subprocess matrix. The docs describe
  that shared model. Sidecar templates and capability boundaries have separate
  owners and remain in child PRs.
- Deferred child plans: sectioned Sidecar templates, canonical Authority client
  identity, canonical capability-file handoff, and capability-seed confinement.

## Routing

- Mode: Full
- Trigger evidence: the change removes an externally observable CLI/environment
  configuration contract and changes fail-closed file selection for three
  commands.
- Higher-mode triggers checked: stable CLI/configuration surface and
  multi-command failure behavior require Full planning; there is no protocol,
  concurrency, or lifecycle redesign.
- Downgrade evidence and reason: Not applicable.

## Current behavior and problem

- Owners and entry points: Clap fields in
  `crates/firma/src/args/{doctor,control,monitor}.rs` bind `--config` to
  `FIRMA_STACK_CONFIG`; each service then passes the resulting optional path to
  `firma_config_loader::ConfigResolver`.
- Current success and failure outcomes: the resolver already implements exact
  file selection and fail-closed selected-file loading, but these three Clap
  boundaries inject a separate environment name before the resolver sees the
  input. Public docs also repeat Run inheritance details and can obscure that
  only one file is selected.
- Evidence: `crates/firma-config-loader/src/resolver.rs`,
  `crates/firma/src/services/{doctor,control,monitor}.rs`,
  `crates/firma-run/src/config.rs`, and `docs/configuration.md` at the researched
  revision.

## Key decisions and tradeoffs

### `DEC-001`: Bind every general config input to `FIRMA_CONFIG`

- Choice: change the three Clap environment bindings to `FIRMA_CONFIG` and do
  not retain an alias or translation layer.
- Rationale and evidence: the shared resolver and all other general config
  consumers already define one canonical environment input. Binding at Clap is
  sufficient because explicit arguments outrank environment-derived values.
- Consequences and rejected alternatives: no compatibility alias, warning, or
  fallback is added. Explicit `--config` semantics and command-specific
  `--state-dir` behavior remain unchanged.

### `DEC-002`: Prove selection through subprocess outcomes

- Choice: select deliberately invalid files at each precedence tier and assert
  that path-bearing failures identify only the chosen file. For doctor, inspect
  its structured report because diagnostics are reported rather than returned
  as startup errors.
- Rationale and evidence: help output proves discoverability, not command
  behavior. Path-specific failures exercise Clap environment binding, resolver
  selection, and service consumption without depending on long-running success
  paths.
- Consequences and rejected alternatives: help checks remain secondary. Tests
  do not assert internal `ConfigSource` provenance because Clap intentionally
  materializes environment values as argument values.

### `DEC-003`: Give the global model one documentation owner

- Choice: make `docs/configuration.md#configuration-resolution` the canonical
  explanation and link docs-site guides to its public GitHub URL. State one
  selected file, schema defaults, section-specific overlays, and Run-only
  inheritance once. Keep `docs-site/public/llms.txt` as a concise aligned
  machine-readable summary rather than a second detailed specification.
- Rationale and evidence: repeated per-field prose is harder to keep accurate
  and has implied broader inheritance than production provides.
- Consequences and rejected alternatives: concise links replace duplicate
  prose. Field-specific text remains only when semantics differ or matter for
  security. Sidecar template selection details stay with the dedicated child
  PR rather than being designed here.

## Architecture and invariant ownership

- Architecture shape: Clap maps one explicit flag/environment source into an
  optional path; the existing resolver selects at most one file; each command
  consumes only the section or runtime paths it owns.

### `INV-001`: General config selection is exclusive and canonical

- Semantic predicate: for doctor, control, and monitor, the selected file is
  exactly explicit `--config` when present, otherwise `FIRMA_CONFIG` when
  present, otherwise the nearest project file; no other environment input can
  affect this choice and no files are field-merged.
- Primary owner: each command's Clap `Args::config` field plus
  `firma_config_loader::ConfigResolver`.
- Detailed proof: `PROOF-001` in the technical evidence.

### `INV-002`: Documentation does not generalize Run inheritance

- Semantic predicate: current-product documentation distinguishes selected-file
  schema defaults and explicit Authority/Sidecar overlays from Run's four-layer
  profile inheritance.
- Primary owner: `docs/configuration.md#configuration-resolution`.
- Detailed proof: `PROOF-002`.

- Compatibility, migration, and failure semantics: `DEC-001` removes the
  alternate environment input. Any selected unreadable or invalid file fails
  closed through existing command behavior rather than falling through.
- Durable documentation owner: `docs/configuration.md`, with links from
  `docs/cli.md` and the relevant docs-site guides, plus a concise derivative
  summary in `docs-site/public/llms.txt`.

## Implementation slices

### Slice 1: Canonical command selection

- Production, types, tests, and docs/config: update the three Clap bindings and
  current help text; add doctor and shared control/monitor subprocess coverage;
  correct the doctor option table.
- Affected decisions and traces: `DEC-001`, `DEC-002`, `TRACE-COMMAND`.
- Proof obligations: `INV-001`.
- Focused verification: compiled `firma` integration tests for doctor and the
  shared config-selection matrix, plus argument/help tests.
- Dependencies: existing shared resolver behavior.
- Intentionally unsupported: aliases or migration diagnostics for removed
  inputs.

### Slice 2: Concise global resolution documentation

- Production, types, tests, and docs/config: consolidate file selection and Run
  shape rules in `docs/configuration.md`; replace duplicate CLI and docs-site
  prose with public GitHub links; align `docs-site/public/llms.txt`; retain only
  current security sharp edges.
- Affected decisions and traces: `DEC-003`, `TRACE-DOCS`.
- Proof obligations: `INV-002`.
- Focused verification: dprint and docs-site build; verify docs-site links have
  valid public targets; search every public surface, including `llms.txt`, for
  contradictory file-merging or removed-input guidance.
- Dependencies: Slice 1 supplies the exact command contract being documented.
- Intentionally unsupported: documenting child-PR behavior before it exists.

## Risks and gaps

- Existing risks: control and monitor have state-directory paths that can avoid
  config loading; a happy-path test could therefore pass without exercising
  selection.
- Planned mitigations: use invalid selected files and assert exact path-bearing
  failure diagnostics.
- Explicit evidence gaps: subprocess tests do not inspect private resolver
  provenance and docs checks cannot mechanically prove every prose implication;
  independent review must compare text with owning call paths.
- Least-confident decisions: the exact amount of duplicated docs-site prose to
  retain while keeping each guide understandable.

## Plan-review findings and dispositions

### `PLAN-001` — High — Documentation architecture / proof completeness — Design risk

- **Evidence:** The candidate made `docs/configuration.md#configuration-resolution`
  the canonical public owner and proposed links from docs-site guides, but
  `docs/configuration.md` is outside Astro's `docs-site/src/content/docs/`
  content tree. Existing repository-relative links do not establish a generated
  docs-site route. The candidate's file inventory also omitted
  `docs-site/public/llms.txt`, which independently summarizes discovery and Run
  layering.
- **Reachable path and outcome:** A docs-site reader could receive a link with no
  public route, while machine-oriented readers could receive a divergent second
  model even though the docs build remained green.
- **Invariant owner / boundary:** `INV-002`; the publication boundary between
  repository Markdown, Astro content, and `llms.txt`.
- **Impact:** The PR could satisfy formatting without delivering one reachable,
  non-contradictory current-product model.
- **Correction:** Specify a valid public target for docs-site links, include
  `llms.txt` in the consumer inventory, and extend `PROOF-002` to verify link
  targets and all public surfaces.
- **Confidence:** High.
- **Unverified assumptions:** no deploy-time rewrite mechanism for
  repository-relative Markdown links was executed during review.

Disposition: accepted and repaired. Docs-site guides will use the explicit
public GitHub URL for the canonical repository section. `llms.txt` is now an
in-scope derivative summary, and Slice 2 / `PROOF-002` require target and
cross-surface verification rather than treating a docs build as sufficient.

## Final verification

- Focused checks: affected `firma` compiled integration tests, Clap/help tests,
  and public-doc searches.
- Workspace checks: `just check` and `just docs-build` at the final PR tip.
- Post-implementation independent review: fresh review of the exact
  base-to-candidate diff, followed immediately by a durable review record and
  mechanical plan deletion.

## Technical evidence

### Applicability assessment

| Section                     | Applicability  | Reason or evidence                                                   |
| --------------------------- | -------------- | -------------------------------------------------------------------- |
| Vocabulary                  | Not applicable | Existing configuration terms remain sufficient.                      |
| Alternatives                | Applicable     | Alias/fallback and proof-boundary choices materially affect scope.   |
| File-tree diff              | Applicable     | Command, integration-test, and canonical-doc owners change.          |
| Type and signature sketches | Not applicable | Existing argument and resolver types remain unchanged.               |
| Semantic call traces        | Applicable     | Selection crosses Clap, resolver, loader, and command services.      |
| Trust analysis              | Applicable     | Operator-selected configuration controls runtime and must fail shut. |
| Detailed proof obligations  | Applicable     | Precedence and documentation accuracy need cross-boundary evidence.  |

### Alternatives

- Keep `FIRMA_STACK_CONFIG` as a lower-precedence alias: rejected because it
  preserves two general configuration-selection contracts and requires new
  precedence rules.
- Move environment handling into every service: rejected because Clap already
  owns explicit flag/environment precedence and the resolver owns file
  discovery.
- Assert only help output: rejected because it cannot prove which path is
  loaded.

### File-tree diff

```diff
crates/firma/src/args/{doctor,control,monitor}.rs
crates/firma/tests/integration/{doctor,config_selection,main}.rs
docs/configuration.md
docs/cli.md
docs-site/public/llms.txt
docs-site/src/content/docs/guides/{firma-doctor,firma-run,manage-the-stack}.md
```

### Semantic call traces

| Trace ID        | State    | Entry and stimulus                          | Path                                                                  | Outcome and proof boundary                                                    |
| --------------- | -------- | ------------------------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `TRACE-COMMAND` | Proposed | command with flag/env/discovered candidates | Clap `Args::config` → `ConfigResolver` → command-specific load/report | Exactly one selected path reaches a path-bearing failure; subprocess tests.   |
| `TRACE-DOCS`    | Proposed | operator reads configuration guidance       | canonical resolution section → linked command and Run guides          | File selection and section/profile layering have one non-contradictory model. |

### Trust analysis

- Actor and authority: an operator chooses a configuration file through CLI,
  environment, or project layout.
- Protected assets: runtime policy and the operator's ability to predict which
  configuration controls a command.
- Reachable error path: a separate environment binding can select an unexpected
  file before the shared resolver runs.
- Boundary: Clap input binding followed by fail-closed selected-file loading.

### Detailed proof obligations

| ID          | Invariant | Kind                      | Owner/proof boundary                                                    | Stimulus and observable effects                                                                                                                    | Status  |
| ----------- | --------- | ------------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `PROOF-001` | `INV-001` | CLI/configuration         | compiled `firma` integration suite                                      | Explicit, canonical env, removed env, and discovered invalid paths; exact selected path appears in the outcome.                                    | Planned |
| `PROOF-002` | `INV-002` | Documentation/current API | docs build, public-link and surface audit, independent call-path review | Canonical section states exclusive file selection and only Run profile inheritance; docs-site links resolve publicly and `llms.txt` stays aligned. | Planned |

## Post-implementation independent review

The final exact implementation candidate reviewed was:
`549016a47c887b03b3e9a96151f9597898b3d882..d7dbe425`.

### `IMPL-001` — Medium — Doctor project discovery lacked command-boundary proof

- **Evidence:** The first candidate's control/monitor matrix covered project
  discovery, while Doctor covered canonical environment, explicit flag, and no
  selected config but did not create and select `.firma/firma.toml`.
- **Impact:** a Doctor-specific regression in the third selection tier could
  pass despite the accepted compiled subprocess proof obligation.
- **Correction:** add a Doctor subprocess case with only an invalid discovered
  project file and assert its exact path in the structured failure.

Disposition: accepted and repaired in the atomic CLI implementation commit.
Doctor now proves all three tiers and proves the removed environment input was
not selected.

### `IMPL-002` — Low — Canonical docs overstated section ownership

- **Evidence:** The first candidate said every command reads only its own
  section and every missing section is a hard error. Doctor inspects Sidecar and
  Authority sections, while Control can continue without optional Authority
  policy configuration.
- **Impact:** the canonical model could imply a stricter and more uniform
  section requirement than production implements.
- **Correction:** state that commands consume the sections they need, required
  section extraction fails closed, and diagnostic/optional consumers can
  inspect several sections or continue without an optional one.

Disposition: accepted and repaired in the atomic docs implementation commit.

### `IMPL-003` — Low — Doctor and Monitor help named XDG as config discovery

- **Evidence:** the second candidate's public Clap help described fallback as
  `FIRMA_CONFIG / XDG`, while the resolver searches ancestor
  `.firma/firma.toml` files.
- **Impact:** operators could look in the wrong location when neither the flag
  nor canonical environment input is set.
- **Correction:** name the nearest `.firma/firma.toml` fallback in both command
  descriptions.

Disposition: accepted and repaired in the atomic CLI implementation commit.

### Final re-review outcome

The fresh reviewer found no actionable findings in exact candidate `d7dbe425`:

- no Rust correctness, robustness, lint-policy, or compatibility findings;
- compiled subprocess coverage proves all three commands' precedence, ignored
  `FIRMA_STACK_CONFIG`, and nearest-project discovery;
- changed public guidance consistently describes selected-file defaults,
  Authority overlays, Sidecar overlays, and Run-only layering; and
- no security, resolver, Run-merge, Sidecar-template, Authority-identity,
  capability, or protocol regressions were found.

After the prior no-findings review, full clippy identified only that the Doctor
test function exceeded the repository's line limit. The assertions were moved
unchanged behind a shared JSON extraction helper. A final fresh reviewer
inspected the complete new candidate and confirmed that each invocation still
parses its own output and proves status, selected path or reason, project
discovery, and ignored `FIRMA_STACK_CONFIG`; it reported no actionable
findings.

This review record is committed independently. Its immediate child commit
mechanically deletes the plan. The accepted plan, plan-review finding, all
implementation-review findings and dispositions remain available at the
immutable review-record commit, which the PR body records.

### Verification evidence

- Focused compiled CLI selection tests: 3 passed.
- `just check`: 2,585 tests passed, 34 skipped; clippy, doctests, build, audit,
  dependency policy, formatting, and release-script checks passed. An earlier
  run hit one unrelated endpoint-readiness timing failure; its exact isolated
  rerun passed before the full green rerun.
- `just docs-build`: 311 pages built.
- `git diff --check` and changed-file dprint checks passed.
