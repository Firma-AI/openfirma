# Capability Seed Filesystem Confinement

## Artifact metadata

- Status: Accepted
- Durable locator:
  `docs/architecture/capability-seed-confinement-plan.md`
- Repository revision researched:
  `fe70ae95754a531e955535c7a0816e739fb49d27`
- Task or requirement source:
  <https://ampcode.com/threads/T-01a042e7-9125-736f-9bdc-ce404c78d707>
- Supersedes: the confinement slice from the deleted broad #614 plan; this
  artifact owns the independently split trust-boundary change.

## Goal and acceptance outcomes

- Goal: ensure the Sidecar reads and watches capability seeds only through
  physical paths contained by its canonical runtime capabilities directory.
- Observable acceptance outcomes:
  - Startup accepts an existing canonical seed whose resolved path and
    configured path's canonical parent are under the resolved runtime
    capabilities directory.
  - A disjoint path, `..` traversal, or file symlink that resolves outside that
    directory fails startup before any seed content is read.
  - Hot-reload setup rejects the same escape paths before registering any
    external directory, watches only parents of resolved contained seeds, and
    re-resolves containment before every reload read.
  - Errors identify the configured path, resolved path when available, and
    canonical directory without including seed contents.
  - Current CLI flows, docs, and examples place Sidecar-loaded seeds beneath the
    selected runtime state's `capabilities/` directory.

## Scope

- In scope: Sidecar initial seed loading, hot-reload registration and reads,
  runtime-layout threading, traversal and platform-specific symlink regression
  coverage, one CLI startup proof, and current-product docs/examples that
  configure explicit Sidecar seed paths.
- Out of scope: Run's canonical seed parsing and environment handoff (owned by
  the direct parent PR), PASETO verification or claim matching, seed issuance,
  automatic refresh, external-Sidecar configuration ownership, runtime
  directory permissions, and descriptor-relative defenses against a trusted
  host operator racing filesystem mutation after validation.
- Assumptions:
  - The wrapped process cannot mutate the host runtime root; existing sandbox
    sealing owns that boundary. An operator with host/runtime write access is a
    trusted actor.
  - Every configured seed must exist at startup, as required by the current
    initial read contract. An empty seed list remains valid even when the
    capabilities directory has not been created.
  - Relative configuration paths retain existing config-file rebasing before
    the runtime containment boundary.
- Open decisions: None.
- Cohesion and split assessment: initial load and watcher registration consume
  the same seed list and must share one physical-resolution contract. Splitting
  them would leave an intermediate tip that could read safely but register an
  external watcher. Tests and current docs/examples are direct proofs of that
  one boundary.
- Deferred child plans: Not applicable.

## Routing

- Mode: Full.
- Trigger evidence: this change establishes a filesystem trust boundary and
  fail-closed startup/reload behavior across Unix and Windows.
- Higher-mode triggers checked: the security/trust-boundary trigger requires
  Full planning even though one Sidecar module owns the central check.
- Downgrade evidence and reason: Not applicable.

## Current behavior and problem

- Owners and entry points:
  - `startup::pipeline::build_pipeline_runtime` loads the initial map through
    `startup::capability::load_capability_map`.
  - `firma::services::sidecar::spawn_capability_reload` starts
    `CapabilityReloader`, which registers each configured path's lexical parent
    and calls the same loader on events.
  - `SidecarConfig::rebase_paths` resolves configuration-relative seed paths;
    `RuntimeLayout::capabilities_dir` owns the selected runtime boundary.
- Current success and failure outcomes: every readable configured path is
  accepted regardless of location. Initial loading reads it directly; watcher
  setup registers its lexical parent. `..` and symlink paths can therefore read
  or watch outside the runtime capabilities directory.
- Evidence: `crates/firma-sidecar/src/startup/capability.rs:load_capability_map`,
  `CapabilityReloader::spawn`,
  `crates/firma-sidecar/src/startup/pipeline.rs:build_pipeline_runtime`, and
  `crates/firma/src/services/sidecar.rs:spawn_capability_reload`.

## Key decisions and tradeoffs

### `DEC-001`: Establish containment from canonical existing paths

- Choice: when the seed list is non-empty, canonicalize the runtime capabilities
  directory, every configured existing seed, and every configured seed's parent.
  Accept a seed only when both its resolved path and canonical configured parent
  start with the resolved directory by path component. Apply the same rule with
  or without hot reload so watcher configuration cannot change seed validity.
- Rationale and evidence: canonicalization resolves `..` and platform-supported
  symlinks before the containment check. The current startup contract already
  requires every configured seed to exist, so this adds no missing-file state.
- Consequences and rejected alternatives: lexical `Path::starts_with` on raw
  configured values is rejected because it is bypassable. Rejecting all
  symlinks is unnecessary: a symlink located under the canonical runtime
  capabilities directory whose resolved target remains contained satisfies the
  boundary. A symlink configured from an external parent is rejected even when
  it targets a contained seed because watching its retarget events would require
  an external registration. Descriptor-relative/open-handle confinement is not
  selected because the wrapped process cannot mutate the host runtime root and
  a cross-platform safe Rust implementation would defend against a trusted
  host actor outside the stated threat model.

### `DEC-002`: Use resolved contained paths for every Sidecar filesystem effect

- Choice: one private resolution function returns configured/resolved path
  pairs. Initial reads use only the resolved path. Watcher setup resolves all
  paths before creating registrations and watches each resolved path's parent
  plus the canonical, contained parent of each configured path. Watching both
  parents preserves notifications when a contained seed symlink is retargeted;
  duplicate directories are registered once. Event-driven reload calls the same
  loader and repeats resolution before reading.
- Rationale and evidence: checking one path but reading or watching another
  would not establish confinement. Reusing one boundary prevents drift between
  initial loading and reload.
- Consequences and rejected alternatives: the configured path remains available
  only for diagnostics and missing-file classification. Caching a resolution
  forever is rejected because a later symlink retarget must fail the next
  reload rather than read the new target.

### `DEC-003`: Preserve current empty, path, and failure contracts

- Choice: return an empty map without requiring the runtime capabilities
  directory when no paths are configured. Preserve config-relative rebasing,
  map retention after reload failure, and the original configured path in
  diagnostics. Add the resolved path and canonical boundary when available.
- Rationale and evidence: default Sidecars have no seed directory, while
  current reload failures intentionally retain the previous verified map until
  its tokens expire.
- Consequences and rejected alternatives: creating the directory in the loader
  is rejected because startup validation must not mutate runtime state. Parser
  and token errors remain secret-safe and never include seed contents.

### `DEC-004`: Document the selected Sidecar runtime boundary once

- Choice: describe `[sidecar.capability_seed].paths` as existing canonical seed
  TOML beneath `<state-dir>/capabilities/`. Update executable examples to select
  the same state directory they use for seed placement. Describe the local
  `--capability-file` requirement without implying that Run configures a
  pre-managed external Sidecar.
- Rationale and evidence: the boundary would otherwise make current shipped
  examples and the documented Authority → Run → local Sidecar flow fail at
  startup.
- Consequences and rejected alternatives: no migration guidance, old path
  examples, or aliases remain. Removing explicit seed files is rejected because
  the parent PR establishes them as a current canonical workflow.

## Architecture and invariant ownership

- Architecture shape: configuration rebasing determines each configured path;
  the Sidecar capability loader establishes physical containment against the
  runtime layout before reading. The reloader applies the same resolution gate
  before watcher registration and delegates every reload read back to the
  loader.

### `INV-001`: Initial seed reads are physically contained

- Semantic predicate: if initial loading reads a configured seed, both the
  runtime directory and seed were canonicalized successfully and the exact path
  passed to `read_to_string` is component-contained by the canonical runtime
  capabilities directory.
- Primary owner: `firma_sidecar::startup::capability::load_capability_map`.
- Detailed proof: `TRACE-STARTUP` and `PROOF-001` through `PROOF-003`.

### `INV-002`: Watch and reload effects are physically contained

- Semantic predicate: every registered seed watcher directory is the parent of
  a resolved seed satisfying `INV-001` or the canonical contained parent of its
  configured path; each reload read re-establishes `INV-001`, and a failed
  resolution preserves the previous map.
- Primary owner: `firma_sidecar::startup::capability::CapabilityReloader`.
- Detailed proof: `TRACE-WATCH` and `PROOF-002` through `PROOF-004`.

### `INV-003`: Canonical seed workflows remain coherent

- Semantic predicate: standalone Sidecar and locally autostarted Run examples
  select a runtime state whose `capabilities/` directory contains every
  Sidecar-configured seed; token verification, claim matching, and external
  Sidecar ownership are unchanged.
- Primary owner: CLI integration fixtures and current user documentation.
- Detailed proof: `TRACE-WORKFLOW` and `PROOF-005`.

- Compatibility, migration, and failure semantics: this is an intentional
  breaking location constraint. Seeds whose resolved target or canonical
  configured parent is outside the physical runtime capability directory fail
  closed without a migration or alias. `DEC-003` preserves empty defaults and
  reload map retention.
- Durable documentation owner: `docs/configuration.md`, `docs/cli.md`, the
  docs-site Run/capability guides, `docs-site/public/llms.txt`, and executable
  examples.

## Implementation slices

### Slice 1: Confine Sidecar seed reads and watchers

- Production, types, tests, and docs/config:
  - add one private configured/resolved path resolver;
  - thread the runtime capabilities directory into initial loading and reloader
    setup;
  - read only resolved contained paths, watch both validated contained parents,
    and repeat resolution on reload;
  - update all unit/integration helpers for the explicit boundary;
  - add disjoint, traversal, `#[cfg(unix)]` symlink, and `#[cfg(windows)]`
    symlink controls for initial load and watcher setup, including contained
    symlink retarget notification and map retention;
  - prove real CLI startup accepts a contained Authority-issued seed and rejects
    an external one;
  - update current docs and executable examples to select matching runtime
    state and `capabilities/` paths.
- Affected decisions and traces: `DEC-001` through `DEC-004`, `TRACE-STARTUP`,
  `TRACE-WATCH`, and `TRACE-WORKFLOW`.
- Proof obligations: `INV-001` through `INV-003`.
- Focused verification: Sidecar capability unit/reload tests; Firma Sidecar-seed
  CLI E2E; affected Run mint/routing tests; Unix traversal/symlink execution;
  Windows all-target compile with Windows symlink execution delegated to CI;
  shell syntax and example smoke checks; current-doc searches.
- Dependencies: canonical capability-file handoff tip
  `fe70ae95754a531e955535c7a0816e739fb49d27`.
- Intentionally unsupported: missing configured seeds, outside-directory static
  seeds, migration, operator path aliases, Run-side cryptographic verification,
  external-Sidecar mutation, or concurrent mutation by a trusted host writer.

## Risks and gaps

- Existing risks: lexical traversal or symlinks can redirect initial reads and
  watcher registration outside the intended runtime state.
- Planned mitigations: resolve before every effect, test both initial-load and
  watcher boundaries with traversal and supported-platform symlinks, and keep
  configured/resolved/boundary context in errors.
- Explicit evidence gaps: this Linux orb cannot execute Windows symlink behavior;
  Windows compilation and CI own that platform proof. Notification backends may
  coalesce events, so tests prove registration/rejection and existing successful
  reload behavior rather than exact event counts.
- Least-confident decisions: retaining contained symlinks. Physical containment
  makes them safe for the stated boundary, and blanket rejection would narrow
  current filesystem syntax without a security benefit under the trusted-host
  assumption.

## Plan-review findings and dispositions

### `PLAN-001` — High · Review lifecycle · Confirmed conflict

- **Evidence:** `capability-seed-confinement-plan.md:415,423-430`
- **Path/outcome:** The plan reviews the implementation candidate, commits review evidence into the plan, then deletes the plan in a subsequent revision. That deletion creates a new final PR tip without a durable review record tied to its exact SHA.
- **Invariant owner:** Exact-tip review and durable review-record lifecycle.
- **Impact:** The proposed sequence does not satisfy the requirement for a durable exact-tip review record at the final PR tip.
- **Correction:** Define a durable external/team-accessible review record tied explicitly to the final post-deletion commit SHA, and require the mechanical deletion diff to be included in that exact-tip review. Preserve immutable plan findings and dispositions at a durable locator before deletion.
- **Confidence:** High. Assumes “exact-tip” means the final commit after plan removal.

**Prior findings:** None recorded; the plan still says review is pending.

**Evidence gaps:** Windows symlink behavior cannot be executed in this Linux orb; the plan appropriately delegates runtime proof to Windows CI. Post-implementation behavior remains unreviewed.

**Verdict:** **Changes required.** Otherwise, the plan adequately reconstructs startup, runtime layout, config rebasing, watcher/reload, platform, documentation/example, and test paths while preserving Sidecar ownership and the parent `CapabilitySeed` handoff. Pre-implementation approval would not replace implementation review.

#### Disposition

- Status: Corrected.
- Rationale: the lifecycle now includes two independent review gates: an
  implementation-candidate review whose immutable record is committed into the
  plan before deletion, followed by a final exact-tip review that includes the
  mechanical deletion and proves plan absence. The final review record is tied
  to the post-deletion SHA in the PR body, a durable team-accessible locator
  that does not alter the reviewed tree. A behavior-changing final-tip finding
  restarts the plan/review/deletion sequence rather than being fixed after the
  closing commit.
- Incorporated at: Final verification, `PROOF-007`, and Atomic revision and
  review lifecycle.
- Decided by: planner.

> **Focused follow-up verdict: Corrected — no findings.** `PLAN-001`
> reviewer-authored text remains preserved; the appended disposition is
> coherent. The lifecycle now records exact implementation-candidate review in
> the plan, mechanically deletes the plan, reviews the exact post-deletion SHA
> including deletion and plan absence, records that review against the SHA in
> the durable PR body, and restarts the lifecycle for a behavior-changing
> finding. No new actionable incoherence was introduced. Pre-implementation
> review does not replace post-implementation review.

## Final verification

- Implementation candidate: `0dc3ab7f620435971ac3b1036ab5cff6f5c2392a`.
- Focused checks:
  - `cargo check -p firma-sidecar -p firma-run -p firma --all-targets` passed.
  - Sidecar capability-reload integration selection passed 7 tests, including
    traversal and Unix symlink controls; the Windows symlink control is
    `#[cfg(windows)]` and remains delegated to Windows CI.
  - Run's real-Authority compatible-seed test passed.
  - Firma's real Sidecar-seed CLI E2E selection passed 3 tests, including
    contained acceptance and external-path rejection.
  - `bash -n` passed for every changed shell example.
- Workspace checks:
  - `just check` passed at the exact implementation candidate: dprint, clippy,
    2,605 nextest tests, doctests, all-feature/all-target build, audit, deny,
    and release validation.
  - `just docs-build` passed and generated all 311 pages.
- Example smoke evidence:
  - Policy-control issued all five canonical seeds beneath its selected runtime
    capabilities directory before its pre-existing Authority revocation-path
    lookup prevented the detached stack from starting.
  - `just demo-ci` passed the ALLOW and DENY round trips with a temporary
    `socat`-backed `nc -z` shim because this orb has no `nc` executable. The
    exact checked-in demo selected its direct Sidecar runtime through the
    supported `FIRMA_STATE_DIR` contract. Generated keys, seeds, logs, and
    temporary build outputs were removed.
- Post-implementation independent review: implementation-candidate review
  complete with no findings; final post-deletion exact-tip review remains
  pending.

### Implementation-candidate review — `ba4501c6`

#### Scope / baseline inspected

- **Exact revision:** `ba4501c66309e3e47d7f6cf32ce246e93094a63c`
- **Baseline:** `02ee445cefc0008600072a4079bff5f8abd31f41`
- Reviewed the complete `02ee445c..ba4501c6` diff and surrounding production
  Rust, integration tests, configuration schema, runtime threading,
  documentation, examples, Unix/Windows conditional paths, and accepted
  plan/proof obligations.
- No files or history modified.

#### Findings

**No actionable findings.**

The implementation canonicalizes non-empty seed configurations before reads or
watcher registration, uses resolved contained paths for filesystem effects,
repeats resolution on reload, preserves the prior map on failure, and preserves
empty-list behavior without requiring the capabilities directory. Documentation
and examples consistently select contained runtime state, while external
Sidecar ownership remains independent.

#### Unknowns / evidence gaps

- Windows symlink behavior could not be executed in this Linux orb; the
  Windows-specific test is present behind `#[cfg(windows)]`.
- `cargo nextest run -p firma-sidecar --test integration capability_reload`
  passed: **7/7 tests**.
- The reviewer's Firma CLI `sidecar_seed_e2e` verification could not complete
  because its checkout ran out of disk while compiling `cedar-policy`; the
  author's exact-candidate focused run and full `just check` above passed all
  three selected CLI tests and all 2,605 nextest tests.
- `git diff --check 02ee445c ba4501c6` passed.

#### Verdict

**Approved — no findings** for exact revision
`ba4501c66309e3e47d7f6cf32ce246e93094a63c`. Residual verification risk is
limited to unexecuted Windows runtime behavior.

#### Disposition

- Accepted. No implementation or documentation change was required after the
  independent review.

### Post-CI corrective review — `0dc3ab7f`

#### Trigger and correction

- GitHub's demo workflow exposed that the release demo passed unsupported
  `--state-dir` syntax to direct `firma sidecar` serving, so the process exited
  before readiness. The demo now selects that direct Sidecar's runtime through
  canonical `FIRMA_STATE_DIR` and retains the same runtime boundary and seed
  placement.
- The behavior correction is isolated in
  `0dc3ab7f620435971ac3b1036ab5cff6f5c2392a`; no production Rust, schema,
  configuration, or public contract changed.

#### Findings and proof status

**No actionable findings.** The independent reviewer inspected exact revision
`0dc3ab7f620435971ac3b1036ab5cff6f5c2392a` against direct base
`7b88d17d07048b8daf7ebdb5ed721e65822ad29d`, reconstructed the filesystem
boundary and current Authority → Run → Sidecar workflow, and found `INV-001`
through `INV-003` satisfied. `PROOF-001` through `PROOF-005` passed on Linux;
Windows symlink execution and final plan deletion remain CI/lifecycle-owned.

Reviewer-run evidence:

- Sidecar capability-reload selection: **7/7 passed**.
- Firma Sidecar-seed CLI E2E selection: **3/3 passed**.
- Empty-seed unit behavior: passed.
- `bash -n` on every changed shell example and `git diff --check`: passed.

Author-run corrective evidence:

- `just demo-ci`: passed exact ALLOW and DENY round trips after direct Sidecar
  startup through `FIRMA_STATE_DIR`.

#### Disposition

- Accepted. No further implementation or documentation change was required.

### `FINAL-001` — Medium · Watch coverage · Confirmed gap

- **Evidence:** `crates/firma-sidecar/src/startup/capability.rs:246-256` at
  reviewed final revision `4dcf24b6`.
- **Path/outcome:** The reloader accepts contained seed symlinks but registered
  only the resolved target's parent. Replacing or retargeting a configured
  symlink changes its configured parent, so no observed event was guaranteed
  and the previous map could remain active until expiry without executing the
  intended per-reload containment check.
- **Invariant owner:** `INV-002`, watcher registration and reload signaling.
- **Impact:** A valid contained symlink retarget might not hot-reload or exercise
  fail-closed map retention promptly.
- **Correction:** Register both the resolved target parent and the canonical,
  contained configured parent, deduplicated. Add Unix and Windows regressions
  that retarget a contained seed symlink and prove reload notification plus
  previous-map retention when the new target escapes.
- **Confidence:** Medium. Filesystem notification delivery may vary, but the
  missing configured-parent registration is deterministic.

#### Disposition

- Status: Accepted for correction.
- Rationale: contained symlinks are an accepted current representation under
  `DEC-001`; rejecting them would contradict the settled physical-containment
  contract. Canonicalizing and containment-checking the configured parent before
  registration closes the notification gap without authorizing an external
  watch. The existing event path then re-runs `INV-001` and retains the previous
  verified map on an escaping retarget.
- Incorporated at: `DEC-002`, `INV-002`, Slice 1, `TRACE-WATCH`, `PROOF-003`,
  and `PROOF-004`.
- Decided by: planner, following exact-tip independent review.

### Watcher-amendment `PLAN-001` — High · Contract coherence · Confirmed conflict

- **Evidence:** At revision `531db544`, `DEC-001` accepted any configured seed
  whose resolved target was beneath the canonical capabilities directory, while
  amended `DEC-002`, `INV-002`, and `TRACE-WATCH` additionally required the
  configured path's canonical parent to be contained.
- **Path/outcome:** An external symlink such as
  `/outside/seed.toml -> <state>/capabilities/seed.toml` could pass initial
  resolution, but watcher setup could neither register `/outside` without
  violating confinement nor preserve the amendment's stated acceptance rule.
- **Invariant owner:** `INV-001` and `INV-002`; Sidecar read and watcher
  registration boundaries.
- **Impact:** Hot reload would otherwise change seed validity or force an
  undocumented choice between an external watch and the `FINAL-001` gap.
- **Correction:** Require both the resolved seed and canonical configured parent
  to be contained for every load, independently of hot reload. Update the
  acceptance outcomes, `DEC-001`, failure contract, resolver sketch, traces, and
  proof controls. Add Unix and Windows rejection controls for an externally
  located symlink targeting a contained seed.
- **Classification:** Confirmed conflict.
- **Confidence:** High.

#### Disposition

- Status: Corrected in plan.
- Rationale: one resolver establishes both path predicates before any load or
  watcher registration. This gives direct startup and hot-reloaded startup one
  validity contract, rejects every required external filesystem effect, and
  retains contained symlink support.
- Incorporated at: acceptance outcomes, `DEC-001`, compatibility/failure
  semantics, type sketch, `TRACE-STARTUP`, `TRACE-WATCH`, and `PROOF-001` through
  `PROOF-004`.
- Decided by: planner following independent amendment review.

## Technical evidence

### Applicability assessment

| Section                     | Applicability | Reason or evidence                                              |
| --------------------------- | ------------- | --------------------------------------------------------------- |
| Vocabulary                  | Applicable    | Configured and resolved paths have distinct trust roles.        |
| Alternatives                | Applicable    | Lexical, canonical, and handle-relative designs differ.         |
| File-tree diff              | Applicable    | Runtime layout crosses loader/reloader and CLI boundaries.      |
| Type and signature sketches | Applicable    | Function inputs must expose the containment boundary.           |
| Semantic call traces        | Applicable    | Startup and watcher paths cross filesystem trust boundaries.    |
| Trust analysis              | Applicable    | Operator paths select seed reads and watcher registrations.     |
| Detailed proof obligations  | Applicable    | Platform and lifecycle controls are required for the invariant. |

### Vocabulary

| Canonical term                 | Meaning                                              | Owner/context       |
| ------------------------------ | ---------------------------------------------------- | ------------------- |
| Configured seed path           | Rebased path supplied by Sidecar configuration       | `SidecarConfig`     |
| Resolved seed path             | Canonical existing filesystem target                 | capability loader   |
| Runtime capabilities directory | Canonical `<state-dir>/capabilities/` trust boundary | `RuntimeLayout`     |
| Contained seed                 | Resolved seed component-contained by that directory  | startup/reload gate |

### Alternatives

- Selected: canonicalize existing directory and seed paths, then use only the
  resolved contained path. This meets the specified cross-platform boundary
  with safe standard-library APIs.
- Rejected: lexical prefix checking. It accepts `..` and symlink escapes.
- Rejected: string-prefix comparison. It also confuses sibling names such as
  `capabilities-other` and platform path normalization.
- Rejected: reject every symlink. It is stricter than physical containment and
  does not improve the accepted target invariant.
- Deferred outside the threat model: descriptor-relative opening plus identity
  checks between validation and use. It would require platform-specific APIs or
  unsafe/dependency work to defend against a trusted host writer racing the
  runtime filesystem.

### File-tree diff

```diff
~ crates/firma-sidecar/src/startup/capability.rs       # resolution/read/watch owner
~ crates/firma-sidecar/src/startup/pipeline.rs         # runtime boundary threading
~ crates/firma/src/services/sidecar.rs                 # reloader boundary threading
~ crates/firma-sidecar/tests/integration/capability_reload.rs
~ crates/firma-run/tests/integration/capability_mint.rs
~ crates/firma/tests/integration/sidecar_seed_e2e.rs   # real startup proof
~ crates/firma-config-schema/src/sidecar/capability_seed.rs
~ crates/firma-sidecar/src/config/capability_seed.rs
~ docs/configuration.md
~ docs/cli.md
~ docs-site/src/content/docs/concepts/capabilities.md
~ docs-site/src/content/docs/guides/firma-run.md
~ docs-site/src/content/docs/guides/secure-a-coding-agent.md
~ docs-site/public/llms.txt
~ examples/demo/*
~ examples/firma-git-demo/*
~ examples/firma-run/local/*
~ examples/policy-control/*
```

### Type and signature sketches

```rust
struct ResolvedSeedPath {
    configured_path: PathBuf,
    resolved_path: PathBuf,
    configured_parent: PathBuf,
}

fn resolve_seed_paths(
    seed: &CapabilitySeedConfig,
    capabilities_dir: &Path,
) -> anyhow::Result<Vec<ResolvedSeedPath>>;

pub fn load_capability_map(
    seed: &CapabilitySeedConfig,
    verifier: &dyn TokenVerifier,
    capabilities_dir: &Path,
) -> anyhow::Result<CapabilityMap>;

pub fn CapabilityReloader::spawn(
    runtime_layout: &RuntimeLayout,
    config: &CapabilitySeedConfig,
    token_verifier: Arc<dyn TokenVerifier + Send + Sync>,
    capability_handle: CapabilityMapHandle,
    cancel: CancellationToken,
) -> anyhow::Result<Self>;
```

No type makes provenance unrepresentable: configured, resolved, and parent
values are all `PathBuf` and can be swapped in compile-valid code (`CW-001`). The
private resolver and tests own their semantic roles; callers receive no public
constructor or reusable unchecked value.

`CW-001`:

```rust
let configured = canonical_path.clone();
let resolved = user_path.clone();
let configured_parent = external_path.clone();
let value = ResolvedSeedPath {
    configured_path: configured,
    resolved_path: resolved,
    configured_parent,
}; // compiles, but violates semantic roles
```

The design therefore claims runtime validation and private ownership, not type
proof of path provenance.

### Semantic call traces

#### `TRACE-STARTUP`

| Field                      | Content                                                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| State                      | Proposed                                                                                                                                         |
| Entry and stimulus         | `firma sidecar` starts with non-empty `[sidecar.capability_seed].paths`.                                                                         |
| Path                       | config rebasing → `build_pipeline_runtime` → `load_capability_map` → resolve directory/seeds/configured parents → containment check → read/parse |
| Input/output types         | configured `PathBuf` + runtime `Path` → resolved contained paths and parents → verified `CapabilityMap`                                          |
| Validation/trust crossings | Canonical containment precedes filesystem read; token/claim verification remains downstream.                                                     |
| Invariant established      | `INV-001` immediately before each read.                                                                                                          |
| Success outcome            | Contained seeds populate Stage 1.                                                                                                                |
| Failure path               | Resolution/containment/read/parse/verification error aborts startup before readiness.                                                            |
| Proof boundary             | capability unit/integration and Firma CLI E2E.                                                                                                   |

#### `TRACE-WATCH`

| Field                      | Content                                                                                                                                            |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| State                      | Proposed                                                                                                                                           |
| Entry and stimulus         | Hot reload starts or a watched contained directory emits an event.                                                                                 |
| Path                       | `CapabilityReloader::spawn` → resolve/check all seeds and configured parents → watch both contained parents; event → loader → resolve/check → read |
| Input/output types         | configured paths + runtime layout → contained directories; event → replacement map or retained prior map                                           |
| Validation/trust crossings | No registration precedes resolution; every event read repeats `INV-001`.                                                                           |
| Invariant established      | `INV-002` at each registration and reload read.                                                                                                    |
| Success outcome            | Valid contained rewrite atomically replaces the map.                                                                                               |
| Failure path               | Escaped/missing/invalid reload logs a secret-safe error and retains the previous map.                                                              |
| Proof boundary             | real notify integration tests plus platform-specific escape controls.                                                                              |

#### `TRACE-WORKFLOW`

| Field                      | Content                                                                                                                           |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| State                      | Proposed                                                                                                                          |
| Entry and stimulus         | Authority issues canonical TOML beneath selected state capabilities; Sidecar or local Run starts with that state.                 |
| Path                       | Authority file output → Run pre-launch parse/token-path split → local Sidecar config → `TRACE-STARTUP`; external Sidecar separate |
| Validation/trust crossings | Run validates structure; Sidecar establishes path containment and verifies token/claims.                                          |
| Invariant established      | `INV-003` without moving cryptographic ownership.                                                                                 |
| Success outcome            | Current contained seed reaches Stage 1; external topology remains independently configured.                                       |
| Failure path               | Outside local seed fails Sidecar startup; malformed seed fails Run or Sidecar before authorization.                               |
| Proof boundary             | Firma CLI E2E, Run integration tests, executable examples, and current docs.                                                      |

### Trust analysis

- Actors and authority: the operator selects configuration and runtime state;
  the Sidecar owns seed reads and Stage 1 state; the wrapped process is untrusted
  but cannot write host runtime state.
- Protected assets: arbitrary host-file contents and external directory watcher
  registrations, plus integrity of the capability map.
- Hostile input: configured paths containing traversal or symlinks and files
  that fail canonical parsing or token verification.
- Trust transitions: configured paths gain filesystem authority only after
  canonical containment; seed claims gain authorization authority only after
  existing PASETO and claim-equality verification.
- Reachable abuse addressed: a lexically contained path can no longer resolve
  to and read/watch an external host location.
- Unchanged limits: a trusted host writer can race path mutation; directory
  permissions and sandbox runtime masking remain separate owners.

### Detailed proof obligations

| ID          | Invariant | Required evidence                                                                                                                                                                                                                             |
| ----------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PROOF-001` | `INV-001` | Contained ordinary path loads; disjoint existing and missing configured paths fail with useful context and no content; hot reload does not alter validity.                                                                                    |
| `PROOF-002` | `INV-001` | `..` traversal, platform file symlinks resolving outside, and external-parent symlinks targeting inside fail initial loading with configured/resolved/parent/boundary context.                                                                |
| `PROOF-003` | `INV-002` | The same traversal and `#[cfg(unix)]`/`#[cfg(windows)]` symlink cases fail watcher setup before registration; a contained symlink retarget emits through its validated configured parent.                                                     |
| `PROOF-004` | `INV-002` | Existing valid atomic rewrite or contained-symlink retarget hot-swaps the map; missing, escaped, structurally invalid, or unverifiable reload retains the previous map.                                                                       |
| `PROOF-005` | `INV-003` | Real CLI startup accepts an Authority-issued contained seed, rejects an external seed, and current examples/docs select matching state.                                                                                                       |
| `PROOF-006` | all       | Focused tests, platform compile/CI, full `just check`, docs build, example checks, and exact-tip independent review pass.                                                                                                                     |
| `PROOF-007` | lifecycle | Accepted reviewed plan is first PR commit; implementation review record directly precedes mechanical plan deletion; final exact-tip review includes that deletion, is recorded against the final SHA in the PR body, and proves plan absence. |

## Atomic revision and review lifecycle

1. Commit this accepted, independently reviewed Full plan as the first PR-owned
   revision.
2. Add coherent implementation revisions containing the boundary, runtime
   threading, platform regressions, real CLI proof, and current docs/examples.
3. Run focused and full verification and obtain fresh independent review of the
   exact implementation candidate.
4. Record review evidence and every disposition in this plan in one revision.
5. Mechanically delete exactly this plan in the immediately following closing
   revision.
6. Obtain a fresh independent review of the exact post-deletion tip, including
   the mechanical deletion and plan-absence proof, and record that review in the
   PR body against the exact final SHA. If it identifies a behavior-changing
   issue, restore/amend the plan and repeat implementation review, recording,
   and deletion; do not add a behavior commit after the closing deletion.

The final branch tip and PR diff contain no plan Markdown. Immutable commit
locators retain the accepted plan, plan review, implementation review, and
dispositions after deletion; the PR body retains the final exact-tip review
without changing the reviewed tree.
