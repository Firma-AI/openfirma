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
  duplicate directories are registered once. Event-driven reload repeats
  resolution, builds a complete replacement watcher, then loads the candidate
  map from that exact resolution while both watchers are active. A successful
  load publishes the map before the old watcher is dropped. Resolution or
  watcher-build failure retains both the previous verified map and watcher. A
  contained but invalid seed retains the previous map while adopting its newly
  validated watcher so a correction in a newly selected target directory can
  trigger recovery. The public startup loader resolves once and delegates to a
  private loader over `&[ResolvedSeedPath]`; reload passes that same slice to
  watcher construction and candidate loading, so a concurrent retarget cannot
  split their targets.
- Rationale and evidence: checking one path but reading or watching another
  would not establish confinement. Reusing one boundary prevents drift between
  initial loading and reload.
- Consequences and rejected alternatives: the configured path remains available
  only for diagnostics and watcher ownership. Caching a resolution or resolved
  parent forever is rejected because a later symlink retarget must fail the next
  reload rather than read the new target, while a valid cross-directory retarget
  must move subsequent hot-reload coverage to its new target parent. Incremental
  watch mutation is rejected because partial add/remove failures make actual
  coverage ambiguous; constructing the replacement before reading and before
  dropping the old watcher provides an auditable handoff and queues concurrent
  writes for another reload.

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
  configured path; each reload read re-establishes `INV-001`, and a successful
  retarget registers the complete replacement watcher before reading and
  publishes the new map before dropping the old watcher. A failed resolution or
  watcher rebuild preserves the previous map and watcher; a failed candidate
  load preserves the previous map and its fully validated replacement watcher.
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
    and replace the complete validated watcher set on each resolved reload;
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

- Implementation candidate: `a9c58c899da4987dd2281f45a173919f43f20998`.
- Focused checks:
  - Sidecar capability-reload integration selection passed 9 tests, including
    traversal, Unix symlink controls, cross-directory retarget, invalid-content
    map retention, replacement-watcher recovery, and escape rejection; the
    Windows symlink controls remain delegated to Windows CI.
  - Run's real-Authority compatible-seed test passed.
  - Firma's real Sidecar-seed CLI E2E selection passed 3 tests, including
    contained acceptance and external-path rejection.
  - `bash -n` passed for every changed shell example.
- Workspace checks:
  - `just check` passed at the exact implementation candidate: dprint, clippy,
    2,607 nextest tests, doctests, all-feature/all-target build, audit, deny,
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
  - `just git-demo-ci` reached its documented credential gate and skipped because
    this orb has no `FIRMA_GIT_DEMO_GITHUB_TOKEN`; exact script syntax and the
    shared supported direct-Sidecar launch pattern were reviewed, while the live
    GitHub round trip remains CI-owned.
- Post-implementation independent review: implementation-candidate review
  complete with one corrected demo finding; fresh exact-candidate re-review at
  `a9c58c89` reported no actionable findings. Final post-deletion exact-tip
  review remains pending.

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

### `FINAL-002` — Medium · Watch lifecycle · Confirmed gap

- **Evidence:** `CapabilityReloader::spawn` at reviewed revision `dd64b30c`
  registered resolved parents only during startup; reloads re-resolved and
  replaced the map without reconciling registrations.
- **Path/outcome:** A contained configured symlink could move from
  `capabilities/a/seed.toml` to `capabilities/b/seed.toml`. Its configured-parent
  event loaded the target in `b`, but later atomic rewrites in `b` emitted no
  event because the watcher still covered `a` and the configured parent.
- **Invariant owner:** `INV-002`, watcher coverage after successful retarget.
- **Impact:** Hot reload could silently stop for a newly selected valid target.
- **Correction:** Build a complete replacement watcher from each newly resolved
  contained path set before loading from that exact resolution. Publish a valid
  candidate map before dropping the old watcher. On contained seed load failure,
  retain the old map but keep the replacement watcher so a correction in the
  new target parent can trigger recovery. Strengthen Unix and Windows regressions
  to retarget across two contained directories and atomically rewrite the new
  target afterward.
- **Confidence:** Medium; the stale registration set is deterministic even
  though event delivery timing varies by backend.

#### Disposition

- Status: Accepted for correction.
- Rationale: whole-watcher replacement avoids ambiguous partial add/remove
  outcomes and preserves continuous coverage because the new contained watcher
  is fully registered before the candidate read and before the old one is
  dropped. Resolution and watcher-build failures cannot influence active
  ownership. A parse or verification failure occurs only after containment and
  watcher validation, so retaining that replacement watcher preserves fail-closed
  map state while allowing a corrected file in the new target parent to recover.
- Incorporated at: `DEC-002`, `INV-002`, Slice 1, `TRACE-WATCH`, and
  `PROOF-003` through `PROOF-004`.
- Decided by: planner following exact-candidate independent review.

### Watcher-replacement `PLAN-001` — High · Watch handoff ordering · Confirmed conflict

- **Evidence:** The accepted plan mandates
  `resolve → load candidate → build replacement watcher → publish map` at
  `docs/architecture/capability-seed-confinement-plan.md:119-122,646`.
  `PROOF-004` nevertheless claims a subsequent atomic rewrite in the new target
  parent reloads (`:691`). Firma's normal refresher performs atomic rename
  writes (`crates/firma-run/src/capability/refresh.rs:124-132`;
  `crates/firma-run/src/capability/issue.rs:301-305`).
- **Path/outcome:** After a symlink retarget from contained directory `a` to `b`,
  reload reads candidate B while only the old watcher covers `a` and the
  configured parent. An atomic rewrite in `b` after that read but before
  replacement watcher registration emits no covered event. The stale candidate
  is then published and no later reload is guaranteed.
- **Owner/boundary:** `INV-002`; `CapabilityReloader`.
- **Impact:** Violates the required reliable reload after a valid
  cross-directory retarget and subsequent atomic rewrite.
- **Correction:** Change the transaction to
  `resolve/check → fully build replacement watcher → load candidate using the same resolution result → publish map → install/drop watcher`,
  retaining the old map/watcher on either build or load failure. Ensure events
  received by the candidate watcher during loading remain queued for another
  reload. Add a deterministic coordination test that rewrites the new target
  after its watch registration but before candidate publication, then asserts
  the later token becomes live.
- **Confidence:** High. No hostile host race is assumed; the repository's
  ordinary background refresher is a reachable concurrent writer.

#### Disposition

- Status: Corrected in plan.
- Rationale: watcher construction now precedes the candidate read, and both old
  and replacement watchers feed the same bounded signal channel until map
  publication finishes. Therefore a write after replacement registration is
  either observed by the candidate read or remains queued for a subsequent
  reload. The correction refines the suggested load-failure handling: once
  resolution and watcher construction succeed, the replacement watcher is safe
  to retain with the old map, which preserves recovery when the newly selected
  contained seed is corrected.
- Incorporated at: `DEC-002`, `INV-002`, Slice 1, `FINAL-002`,
  `TRACE-WATCH`, and `PROOF-003` through `PROOF-004`.
- Decided by: planner following independent amendment review.

### Watcher-replacement `PLAN-002` — Medium · Watcher ownership/lifecycle · Design risk

- **Evidence:** Current `CapabilityReloader` separately owns `_watcher` and the
  spawned task (`crates/firma-sidecar/src/startup/capability.rs` at the reviewed
  parent: `234-244,314-361`). The plan adds only
  `build_seed_watcher(...) -> RecommendedWatcher`
  (`docs/architecture/capability-seed-confinement-plan.md:583-586`) and says the
  event-driven task replaces the watcher (`:646`), without specifying how the
  task gains exclusive ownership or atomically updates the watcher retained by
  `CapabilityReloader`.
- **Path/outcome:** Implementers must invent a synchronization/ownership design.
  A naïve move into the task changes drop semantics; shared mutable ownership
  introduces locking and cancellation ordering; leaving the original field
  unchanged cannot replace registrations.
- **Owner/boundary:** `CapabilityReloader` lifecycle and `INV-002`.
- **Impact:** Hidden design work can produce leaked/stale watchers or shutdown
  races, undermining "retain previous watcher" semantics.
- **Correction:** Amend the type/lifecycle sketch so one explicit
  owner—preferably the reload task—holds and swaps the active watcher. Define
  spawn handoff, cancellation, task termination, and `Drop` behavior, and
  require a lifecycle test proving dropping/cancelling the reloader drops the
  currently active replacement watcher.
- **Confidence:** High on the ownership gap; exact implementation consequences
  remain design-dependent.

#### Disposition

- Status: Corrected in plan.
- Rationale: the spawned reload task is the sole owner of the active watcher and
  replacement operations use ordinary local ownership without locks. The task
  drops the active watcher when cancellation exits its loop; dropping the guard
  requests task abort, so Tokio drops that same future-owned watcher when the
  task terminates. Neither path claims synchronous cessation of already-running
  non-async reload work. The single-owner type shape plus task termination prove
  resource release without a test-only watcher abstraction.
- Incorporated at: type sketch, `TRACE-WATCH`, and `PROOF-004`.
- Decided by: planner following independent amendment review.

### Watcher-replacement follow-up `PLAN-001` — High · Handoff coherence · Confirmed conflict

- **Evidence:** At revision `76befab4`, `DEC-002` requires the replacement
  watcher and candidate load to use the _same_ resolution result
  (`docs/architecture/capability-seed-confinement-plan.md:119-126`).
  `TRACE-WATCH` repeats this requirement (`:739-744`). However, the type sketch
  exposes only:
  - `resolve_seed_paths(...) -> Vec<ResolvedSeedPath>` (`:667-670`), and
  - `load_capability_map(seed, verifier, capabilities_dir)` (`:681-685`).

  Production `load_capability_map` independently calls `resolve_seed_paths`
  again (`crates/firma-sidecar/src/startup/capability.rs:111-120`).
- **Reachable path/outcome:** A reload can resolve target `b`, register a
  replacement watcher for `b`, and then call the existing loader, which
  re-resolves a retargeted configured symlink to contained target `c`. It can
  publish `c` while installing a watcher covering `b`. Later atomic rewrites in
  `c` are unobserved, recreating the stale-map/stale-registration failure the
  disposition claims to close.
- **Invariant owner:** `INV-002`; `CapabilityReloader`.
- **Impact:** The handoff ordering and candidate-event queue are insufficient
  unless the candidate read is structurally tied to the exact paths used to
  build its watcher.
- **Correction:** Add a concrete private boundary such as:
  `load_capability_map_from_resolved(&[ResolvedSeedPath], verifier)`.
  Require reload to resolve once, build the watcher from that value, and load
  exclusively from that same value. Keep the public startup loader as
  resolve-then-delegate. Add a coordinated test that retargets between watcher
  registration and candidate reading and proves watcher/map correspondence
  afterward.
- **Classification:** Confirmed conflict.
- **Confidence:** High. The plan's signatures currently cannot directly
  implement its stated transaction without an unspecified helper.

#### Disposition

- Status: Corrected in plan.
- Rationale: the private slice-based loader makes one `ResolvedSeedPath` value
  the shared input to replacement registration and candidate reading. The
  public startup loader resolves and immediately delegates. Public reloader
  controls retarget across contained directories and then rewrite the new target;
  code inspection proves both operations consume one slice. Deterministic
  suspension between two private synchronous calls would require a test-only
  production hook, which the repository's Rust test guidance rejects.
- Incorporated at: `DEC-002`, type sketch, `TRACE-WATCH`, and `PROOF-003`
  through `PROOF-004`.
- Decided by: planner following independent follow-up review.

### Watcher-replacement follow-up `PLAN-002` — Medium · Cancellation/lifecycle proof · Design risk

- **Evidence:** The disposition assigns sole watcher ownership to the spawned
  task and says cancellation or guard drop stops effects
  (`docs/architecture/capability-seed-confinement-plan.md:586-594`;
  `TRACE-WATCH` at `:739-745`). `PROOF-004` requires that “cancellation/drop
  stops effects,” but its proposed regression only rewrites after
  cancellation/drop and observes no later map effect.

  Existing reload work is synchronous after event selection: drain signals,
  read/verify files, and store the map without an await
  (`crates/firma-sidecar/src/startup/capability.rs:314-350`). Existing `Drop`
  merely calls `JoinHandle::abort()` (`:241-244`).
- **Reachable path/outcome:** Cancellation or `Drop` can occur after the task
  selects an event but while synchronous candidate loading is underway. Tokio
  abort cannot interrupt that work before the next await, so the task may still
  publish a map after the reloader guard has been dropped. Separately, “no map
  effect after a rewrite” does not prove that the watcher itself was dropped: a
  leaked watcher sending into an unconsumed channel has the same observation.
- **Invariant owner:** `CapabilityReloader` lifecycle and `INV-002`.
- **Impact:** Shutdown ordering remains under-specified, and the planned test
  cannot establish watcher resource termination or exclude an in-flight
  post-drop publication.
- **Correction:** Define the intended terminal guarantee explicitly:
  - If post-cancellation publication is forbidden, add a cancellation check
    immediately before `capability_handle.store`, prioritize cancellation in
    the select loop, and provide an async shutdown/join path that confirms task
    termination.
  - If `Drop` is only eventually aborting, document that weaker contract and
    avoid claiming synchronous cessation.

  Coordinate a test with the task paused after candidate load but before
  publication, then cancel/drop and assert the selected terminal behavior.
  Treat sole future ownership as the proof that watcher resources are dropped
  once task termination is confirmed; do not use map inactivity as a proxy for
  watcher destruction.
- **Classification:** Design risk.
- **Confidence:** High on the proof gap; whether post-drop publication is
  unacceptable requires the plan to settle the lifecycle contract.

#### Disposition

- Status: Corrected in plan by selecting the weaker existing contract.
- Rationale: this guard has no synchronous shutdown API today. `Drop` requests
  task abort but does not wait, so already-running synchronous reload work may
  complete before Tokio observes cancellation. The task remains the sole watcher
  owner; task completion, whether by the external cancellation branch or abort,
  destroys its active watcher. The implementation and docs will state this
  eventual terminal contract and will not claim synchronous cessation or use
  map inactivity as a watcher-destruction proxy. A joinable shutdown API and
  test coordination hook would add machinery outside the confinement fix.
- Incorporated at: type sketch, `TRACE-WATCH`, and `PROOF-004`.
- Decided by: planner following independent follow-up review.

### `FINAL-003` — Medium · Executable example · Confirmed failure

- **Evidence:** `examples/firma-git-demo/run.sh` at reviewed revision
  `6d123c1c` invoked direct `firma sidecar` with `--state-dir`, but
  `crates/firma/src/args/sidecar.rs` exposes that option only for the nested
  `sidecar start` and `sidecar stop` commands.
- **Path/outcome:** The Git demo's Sidecar exited during CLI parsing, readiness
  polling failed, and the newly relocated seed beneath `$STATE_DIR/capabilities`
  was never loaded.
- **Invariant owner:** `INV-003`, executable current workflow coherence.
- **Impact:** The Authority → Sidecar → Git demonstration could not start.
- **Correction:** Set `FIRMA_STATE_DIR="$STATE_DIR"` on the direct Sidecar process
  and remove the unsupported argument, matching the working primary demo.
- **Confidence:** High; Clap rejects the argument before Sidecar startup.

#### Disposition

- Status: Corrected in implementation revision
  `a9c58c899da4987dd2281f45a173919f43f20998`.
- Rationale: the canonical runtime-state environment boundary is supported by
  direct `firma sidecar`, preserves the demo's selected state and seed path, and
  requires no alternate CLI representation.
- Verification: `bash -n` passed; `just check` passed 2,607 tests and all
  workspace gates. The credentialed GitHub round trip remains CI-owned because
  this orb has no `FIRMA_GIT_DEMO_GITHUB_TOKEN`.
- Decided by: implementer following exact-candidate independent review.

### Exact implementation-candidate review — `a9c58c89`

- **Exact revision:** `a9c58c899da4987dd2281f45a173919f43f20998`.
- **Baseline:** `7b88d17d07048b8daf7ebdb5ed721e65822ad29d`.
- **Scope:** complete PR diff, production startup/reload and platform paths,
  accepted plan conformance, current-product docs, secret-safe errors, async
  watcher ownership and map handoff, tests, and executable examples.
- **Findings:** No actionable findings after `FINAL-003` was corrected.
- **Reviewer-run evidence:** Sidecar capability-reload integration selection
  passed 9/9, including traversal, Unix symlink escape, cross-directory
  retarget/rewrite recovery, invalid-content retention, and secret-safe errors;
  changed executable examples passed `bash -n`.
- **Residual uncertainty:** Windows symlink behavior remains CI-owned in this
  Linux orb. Descriptor-relative protection against trusted-host filesystem
  races remains outside the accepted threat model.
- **Disposition:** Accepted. No further implementation or documentation change
  was required.

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

fn build_seed_watcher(
    paths: &[ResolvedSeedPath],
    signal: tokio::sync::mpsc::Sender<()>,
) -> anyhow::Result<notify::RecommendedWatcher>;

fn load_capability_map_from_resolved(
    paths: &[ResolvedSeedPath],
    verifier: &dyn TokenVerifier,
) -> anyhow::Result<CapabilityMap>;

pub struct CapabilityReloader {
    task: tokio::task::JoinHandle<()>,
}

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

| Field                      | Content                                                                                                                                                                                                                                                                                            |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| State                      | Proposed                                                                                                                                                                                                                                                                                           |
| Entry and stimulus         | Hot reload starts or a watched contained directory emits an event.                                                                                                                                                                                                                                 |
| Path                       | `CapabilityReloader::spawn` → resolve/check all seeds and configured parents → task owns active watcher; event → resolve once → build complete replacement watcher on shared signal channel → load candidate from the same resolved slice → publish valid map or retain old map → drop old watcher |
| Input/output types         | configured paths + runtime layout → contained directories; event → replacement map or retained prior map                                                                                                                                                                                           |
| Validation/trust crossings | No registration precedes resolution; every event read repeats `INV-001`.                                                                                                                                                                                                                           |
| Invariant established      | `INV-002` at each registration and reload read.                                                                                                                                                                                                                                                    |
| Success outcome            | Valid contained rewrite replaces the watcher set and atomically publishes the map; events concurrent with the candidate read remain queued.                                                                                                                                                        |
| Failure path               | Resolution or watcher-build failure retains the previous watcher and map. Invalid contained content retains the map and validated replacement watcher for recovery. Cancellation or task abort drops the task-owned watcher when the task terminates; in-flight synchronous work may finish first. |
| Proof boundary             | Real notify integration tests, replacement lifecycle controls, and platform-specific escape controls.                                                                                                                                                                                              |

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

| ID          | Invariant | Required evidence                                                                                                                                                                                                                                                                                                                   |
| ----------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PROOF-001` | `INV-001` | Contained ordinary path loads; disjoint existing and missing configured paths fail with useful context and no content; hot reload does not alter validity.                                                                                                                                                                          |
| `PROOF-002` | `INV-001` | `..` traversal, platform file symlinks resolving outside, and external-parent symlinks targeting inside fail initial loading with configured/resolved/parent/boundary context.                                                                                                                                                      |
| `PROOF-003` | `INV-002` | The same traversal and `#[cfg(unix)]`/`#[cfg(windows)]` symlink cases fail watcher setup before registration; public cross-directory retarget controls plus code inspection prove replacement registration and candidate reading use one resolved slice.                                                                            |
| `PROOF-004` | `INV-002` | Existing valid atomic rewrite, contained-symlink retarget, a queued concurrent rewrite, and a later rewrite in the new target parent hot-swap the map; resolution/watcher failure retains old state and invalid content retains the validated new watcher. Task-only watcher ownership proves resource release at task termination. |
| `PROOF-005` | `INV-003` | Real CLI startup accepts an Authority-issued contained seed, rejects an external seed, and current examples/docs select matching state.                                                                                                                                                                                             |
| `PROOF-006` | all       | Focused tests, platform compile/CI, full `just check`, docs build, example checks, and exact-tip independent review pass.                                                                                                                                                                                                           |
| `PROOF-007` | lifecycle | Accepted reviewed plan is first PR commit; implementation review record directly precedes mechanical plan deletion; final exact-tip review includes that deletion, is recorded against the final SHA in the PR body, and proves plan absence.                                                                                       |

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
