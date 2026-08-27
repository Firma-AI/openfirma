# Deterministic Run Profile Patch Merging

## Artifact metadata

- Status: Accepted
- Durable locator: `docs/architecture/run-profile-patch-merge-plan.md`
- Repository revision researched:
  `dc82f6d655ffa6421c25bc91a77e9f24e35ba8d1` (PR #1 stack head)
- Required base: PR #611 branch `amp/authority-non-zero-ttl`
- Task source: stacked breaking-configuration request in
  <https://ampcode.com/threads/T-01a03f40-5cc8-741b-9568-f3166944abcd>
- Supersedes: not applicable

## Goal and acceptance outcomes

Make `[run]` profile patch merging distinguish omission from an explicit value
for every field, with one documented rule for each shape. Resolution must be
deterministic across these four ordered layers:

1. selected built-in profile;
2. `[run.defaults]`;
3. `[run.profiles.<selected>]`; and
4. supplied CLI overrides.

Observable outcomes:

- explicit `use_http_proxy_sidecar = false` and
  `allow_non_structural = false` override inherited `true`;
- an absent collection inherits; present lists replace, present maps merge by
  key, and any present empty collection clears its lower value;
- independently configurable nested structures merge field-by-field;
- executable-policy entries merge by executable name, then field-by-field;
- CLI values retain highest precedence, while unsupplied enable-only CLI flags
  do not manufacture `false` overrides;
- `FIRMA_SIDECAR_ENDPOINT` remains a fallback only when no profile layer sets
  an endpoint, and `FIRMA_RUN_ALLOW_NON_STRUCTURAL` remains a separate
  enable-only runtime override after profile resolution;
- effective-config output exposes the final resolved values without adding a
  patch DSL or generic merge framework; and
- the final branch tip and PR diff contain no plan Markdown.

## Scope

In scope:

- every field and variant payload in `ProfilePatch`, `MountPatch`,
  `NetworkPolicyPatch`, `SeccompPolicyPatch`, `CapabilityLeasePatch`,
  `CapabilitySourcePatch`, `CommandMediatorPatch`, and
  `ExecutableLaunchPolicyPatch`;
- schema representation, built-in profile construction, path rebasing, merge
  behavior, final runtime conversion/validation, tests, and Run documentation;
- explicit migration guidance for old OR/additive/non-empty-only/whole-nested
  behavior; and
- a table-driven contract suite covering all four ordered layers.

Out of scope:

- removal or migration of legacy capability `kind` / `path` or `codex_cli`;
  PR #3 owns those breaking removals;
- changing profile selection, config discovery, backend support fallback,
  Sidecar selection, runtime environment override semantics, or generated
  profile contents;
- adding deletion sentinels for individual map keys or a generic patch DSL;
- adding CLI flags for fields that do not currently have CLI overrides; and
- unrelated stale Run documentation or schema cleanup.

Assumptions and open decisions:

- The requested absent/present contract intentionally changes existing
  ambiguous additive list behavior. Operators must repeat lower list elements
  they want to keep in a higher present list.
- There is no material product decision left open. The request explicitly
  permits deliberate map or field-wise behavior; `DEC-002` and `DEC-003`
  record the selected key-merge rule and value-shape distinction.

## Routing

- Mode: Full
- Trigger evidence: this changes a stable public Rust schema and externally
  observable configuration contract, including fail-closed backend opt-in and
  sandbox environment/mount behavior.
- Higher-mode triggers: stable configuration/public API, trust-sensitive
  `allow_non_structural`, and merge-order behavior each independently require
  Full planning.
- Split assessment: one plan remains cohesive because all slices establish one
  patch algebra at the same owner (`firma-run::config::Merge`) and must compose
  into one four-layer proof. Separate plans would obscure interactions among
  nested and collection fields.

## Current behavior and ownership

Observed at the researched revision:

- `firma-config-schema/src/run.rs::ProfilePatch` mixes optional scalars with
  defaulted booleans and collections, erasing absent/present information during
  deserialization.
- `firma-run/src/profile.rs::built_in_profile` returns a concrete patch for the
  selected known profile.
- `firma-run/src/config.rs::read_config` merges
  `FileConfig.defaults.merge(selected_profile)`, then
  `resolve_profile_with_layout` merges that result over the built-in and the
  CLI patch over the file result.
- scalar `Option<T>` fields use `higher.or(lower)`; capability fields merge
  mostly field-by-field.
- `use_http_proxy_sidecar` and `allow_non_structural` use logical OR, so
  explicit higher `false` cannot override lower `true`.
- `env_passthrough` is appended and `env_set` overlays map keys;
  `mounts` replaces only when higher is non-empty; no explicit empty value can
  clear any of them.
- `network`, `seccomp_policy`, `sidecar_local_exec`, and `codex_cli` replace the
  whole lower nested patch. `executable_policies` overlays executable names but
  replaces each matching nested policy wholesale.
- capability `requested_actions = []` survives merge but is converted back to
  the all-action default during final resolution.
- `mask_home_paths: Option<Vec<_>>` already has correct absent/present-empty
  replacement cardinality.
- `FIRMA_SIDECAR_ENDPOINT` is consulted after patch merge only when
  `sidecar_endpoint` is absent. Explicit `--sidecar` selection is resolved
  afterward and wins.
- `FIRMA_RUN_ALLOW_NON_STRUCTURAL` is OR'd with the resolved profile only in
  `runtime::execute_run`; it is not one of the four patch layers.

Primary owners and consumers:

- representation: `firma-config-schema/src/run.rs`;
- built-in lower layer: `firma-run/src/profile.rs`;
- ordering and merge: `firma-run/src/config.rs::{Merge, read_config,
  resolve_profile_with_layout, cli_profile_patch}`;
- final consumers: `ResolvedProfile` plus backend preparation, runtime
  environment/mount assembly, Sidecar routing, capability issuance/refresh,
  seccomp, command mediation, and executable wrapper argument injection;
- CLI construction: `firma/src/args/run.rs` and `firma/src/services/run.rs`;
- current tests: `firma-run/src/config.rs` plus integration tests under
  `crates/firma-run/tests/integration`.

## Key decisions

### `DEC-001`: Preserve absence with `Option<T>` at the patch boundary

Every top-level boolean and collection that participates in layered merge uses
`Option<T>`. `None` means the layer did not configure the field. `Some(value)`
means the layer explicitly configured it, including `Some(false)` and
`Some(empty)`.

Built-in profiles set every built-in-owned value with `Some`. The CLI patch
sets `Some` only for values actually supplied. In particular, the current
enable-only `--allow-non-structural` flag maps `true` to `Some(true)` and
unsupplied `false` to `None`, preserving lower config.

Rejected alternatives:

- custom deserializers that track presence outside the type: duplicate Serde's
  `Option` model and obscure public schema cardinality;
- a generic `Patch<T>` wrapper or DSL: no additional operation beyond
  absent/present is needed; and
- changing resolved runtime types to optional: optionality ends at resolution.

### `DEC-002`: Replace lists as a whole; merge maps by key

All collection fields distinguish absence from presence. Lists use one rule:
absent inherits; present replaces; present empty clears. This applies to:

- `env_passthrough`;
- `mounts`;
- capability `requested_actions`;
- command-mediator `allowed_executables`; and
- existing `mask_home_paths`.

Maps use a key-oriented rule: absent inherits the lower map; present empty
clears it; present non-empty merges keys, with each higher key overriding or
recursively merging the matching lower key according to its value shape. This
applies to:

- `env_set`, whose string values replace by key;
- executable-policy `config_overrides`, whose string values replace by key;
  and
- `executable_policies`, whose nested values merge under `DEC-004`.

The final resolved type still uses concrete empty/default collections. Removing
the current empty-`requested_actions` fallback is intentional: explicit empty
means an empty requested action set, not the built-in all-actions set. When
per-session Authority issuance is active, that empty set is sent unchanged to
`IssueCapability`. The Authority deterministically returns `DENY` with
`NO_ACTIONS`; `firma run` maps that response to `CapabilityDenied` and fails
before agent launch, so it never mints or refreshes an empty-action token. When
the profile uses disabled or pre-staged capability material instead, requested
actions are not used for issuance and the existing source behavior is
unchanged.

Consequences:

- a higher non-empty `env_passthrough` no longer appends;
- `mounts = []` can remove the built-in workspace mount; and
- explicit empty `env_set` can remove every built-in environment value,
  including security-relevant bwrap and proxy controls, but adding or replacing
  one map key does not remove unrelated safeguards.

Rejected alternatives:

- whole-map replacement for `env_set`: a narrow environment customization
  would silently remove unrelated built-in rootfs, home-mask, and proxy-bypass
  controls;
- list append plus an empty-clear special case: a present non-empty list would
  still be unable to remove individual inherited entries; and
- per-key deletion sentinels: selective map deletion is not required and would
  introduce a patch DSL.

### `DEC-003`: Map values follow their own semantic shape

All maps follow the outer presence/key rule in `DEC-002`. Their values differ:

- string values in `env_set` and `config_overrides` replace by key; and
- a matching `executable_policies.<name>` patch merges field-by-field under
  `DEC-004` because its settings are independently overridable.

No per-key deletion sentinel is added. A present empty map can clear every
inherited entry, but selectively deleting one inherited map key while retaining
others is explicitly unsupported. A single TOML layer cannot express both an
empty clear and rebuilt entries for the same field; documentation must not
promise that workflow.

### `DEC-004`: Merge independently overridable nested patches field-by-field

When both lower and higher nested patches exist, merge their fields recursively
for:

- `network`;
- `seccomp_policy`;
- `capability` (retaining the current canonical-vs-legacy source grouping until
  PR #3);
- `sidecar_local_exec`;
- each `executable_policies.<name>` entry; and
- legacy `codex_cli` while it remains accepted.

`SeccompPolicyPatch.source_policy_path` and `artifact_dir` become optional at
the patch level so a profile can override `runtime_mode` without restating the
lower paths. Final resolution remains strict: if a merged explicit seccomp
patch lacks either required path, return a field-specific configuration error.

Tagged `capability.source` remains one atomic scalar choice, not a fieldwise
merge inside variants. A higher canonical source clears lower legacy source
fields; a higher legacy source field clears the canonical source, preserving
the existing deterministic compatibility contract until PR #3.

### `DEC-005`: Keep resolution defaults and external precedence boundaries

After all patch layers merge, final conversion supplies existing defaults only
for fields still absent:

- false for unresolved profile booleans;
- empty for unresolved collections/maps;
- existing network, capability, mediator, seccomp, CA, and identity defaults.

CLI backend, capability file, identity mode/host-user preservation, Sidecar
selection, and `--allow-non-structural` remain highest precedence. Existing
environment behavior is unchanged and documented separately from the four
patch layers.

## Invariants

### `INV-001`: Higher explicit scalar values win

For every scalar/enum/boolean patch leaf and layers `L < H`, if `H.field` is
present, `merge(L,H).field == H.field`, including `false`; otherwise it equals
`L.field`.

Owner: schema `Option` representation plus `firma-run::config::Merge`.

### `INV-002`: Collection presence selects the documented shape operation

For every `DEC-002` collection and layers `L < H`, absent `H.field` inherits
`L.field`. A present list is the complete result. A present empty map clears;
a present non-empty map merges keys with higher values winning or recursively
merging under `DEC-003`.

Owner: patch field types and merge implementations.

### `INV-003`: Nested siblings survive partial overrides

For every `DEC-004` nested patch, a higher present child changes only that
child; absent higher siblings retain lower values. Final required-field
validation occurs after all four layers.

Owner: nested `Merge` implementations and final converters.

### `INV-004`: Layer order is total and CLI remains terminal

For selected profile `P`, resolution is exactly:

```text
merge(merge(merge(built_in(P), run.defaults), run.profiles[P]), cli)
```

Environment fallbacks and explicit Sidecar selection retain their existing
post-merge roles and are not silently inserted into this algebra.

Owner: `read_config`, `resolve_profile_with_layout`, and `cli_profile_patch`.

## Program design

Key type changes:

```rust
pub struct ProfilePatch {
    pub env_passthrough: Option<Vec<String>>,
    pub env_set: Option<BTreeMap<String, String>>,
    pub mounts: Option<Vec<MountPatch>>,
    pub executable_policies: Option<BTreeMap<String, ExecutableLaunchPolicyPatch>>,
    pub use_http_proxy_sidecar: Option<bool>,
    pub allow_non_structural: Option<bool>,
    // existing optional scalar/nested fields
}

pub struct SeccompPolicyPatch {
    pub source_policy_path: Option<PathBuf>,
    pub artifact_dir: Option<PathBuf>,
    pub runtime_mode: Option<SeccompRuntimeMode>,
}

pub struct CommandMediatorPatch {
    // existing optional scalars
    pub allowed_executables: Option<Vec<PathBuf>>,
}

pub struct ExecutableLaunchPolicyPatch {
    // existing optional scalars
    pub config_overrides: Option<BTreeMap<String, String>>,
}
```

Small dedicated `Merge` implementations remain in `firma-run/src/config.rs`.
No new public helper, trait, module, or generic abstraction is introduced.

Constructibility checks:

- `Option<bool>` admits exactly absent, explicit false, and explicit true; this
  proves cardinality, not layer order, which remains a runtime proof.
- `Option<Vec<_>>` and `Option<BTreeMap<_,_>>` distinguish absent from empty;
  they do not encode replace-vs-merge semantics, so tests must prove `DEC-002`
  and `DEC-003`.
- optional seccomp paths permit incomplete intermediate patches by design; only
  the merged boundary can establish final completeness.

Semantic trace:

```diagram
┌──────────────────┐
│ built-in profile │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ [run.defaults]   │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ selected profile │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ supplied CLI     │
└────────┬─────────┘
         ▼
┌──────────────────┐    post-merge fallback/enable
│ merged patch     │◀─── environment boundaries
└────────┬─────────┘
         ▼
┌──────────────────┐
│ ResolvedProfile  │───▶ validation and runtime consumers
└──────────────────┘
```

## Implementation slices and atomic revisions

### Slice 1: Explicit boolean overrides

- Change both profile booleans to `Option<bool>`, update built-ins, CLI patch,
  final defaults, exhaustive false/true/absence tests, and direct docs.
- Proves `INV-001` for booleans and CLI enable-only behavior.
- Verification: schema tests, focused `firma-run` config/runtime tests, affected
  Clippy, formatter.

### Slice 2: Presence-aware top-level collections

- Change environment collections and mounts to optional collections; preserve
  path rebasing only for present mounts; update built-ins/final conversion and
  tests/docs. Lists replace; non-empty `env_set` merges by key; explicit empty
  maps/lists clear. Prove an `env_set` clear's terminal runtime and bwrap
  hardening inputs so the security effect is explicit.
- Proves `INV-002` for top-level lists/maps and records the deliberate
  broad-clear behavior.
- Verification: schema/path/config tests, runtime environment and bwrap/profile
  tests, affected Clippy.

### Slice 3: Fieldwise network and seccomp patches

- Add nested merges; make seccomp paths optional until final conversion; retain
  path rebasing and stronger backend/path validation; add partial-override and
  incomplete-final-patch tests/docs.
- Proves `INV-003` for backend policy structures.
- Verification: focused config/seccomp/backend tests and affected Clippy.

### Slice 4: Capability collection semantics

- Retain fieldwise capability merge and source compatibility, but preserve an
  explicit empty requested-actions list through final resolution. Prove that
  automatic issuance sends the empty set, receives Authority `NO_ACTIONS`,
  surfaces `CapabilityDenied`, and creates no seed or agent/refresh lifecycle;
  retain a neighboring non-empty narrowing control.
- Proves `INV-002` for capability actions and re-proves source precedence.
- Verification: capability config/mint/Authority/refresh tests and affected
  Clippy.

### Slice 5: Fieldwise command-mediator patch

- Merge every mediator scalar field, make its allowlist optional/replacing,
  preserve final defaults/canonicalization/cross-field checks, and add
  partial/false/empty tests/docs.
- Proves `INV-001` through `INV-003` for local command governance.
- Verification: local-exec config/runtime tests and affected Clippy.

### Slice 6: Executable policy map and nested merge

- Give the outer structural map presence, merge executable entries
  field-by-field, give `config_overrides` the same absent/empty/key-merge map
  rule, apply the nested rule to legacy `codex_cli`, and update
  built-ins/runtime/tests/docs. Prove that empty TOML tables deserialize as
  present empty maps and clear the lower map; document selective deletion as
  unsupported.
- Proves `INV-001` through `INV-003` for executable wrapper policy.
- Verification: Codex/profile/runtime tests and affected Clippy.

### Slice 7: Aggregate four-layer contract and migration guidance

- Add one table-driven suite that exercises built-in → defaults → profile → CLI
  ordering and inventories every field/variant in all eight patch element
  types, including atomic mount elements and tagged capability-source variants;
  add effective-config examples and the complete migration table to config
  docs, docs site, and `llms.txt`.
- Proves `INV-004` and cross-slice composition.
- Verification: focused suite, `just check`, and docs-site build.

### Slice 8: Review and remove this plan

- Record fresh independent post-implementation review and all dispositions in
  this artifact, then delete only this file in a standalone final revision.
- Proof: immutable plan/review commits remain linkable; tip and base-to-tip diff
  contain no plan Markdown.

## Compatibility and migration matrix

| Shape / field                                | Previous behavior                       | New behavior                                                 |
| -------------------------------------------- | --------------------------------------- | ------------------------------------------------------------ |
| scalar / enum `Option<T>`                    | higher present wins                     | unchanged                                                    |
| profile booleans                             | logical OR                              | absent inherits; explicit false/true replaces                |
| `env_passthrough`                            | append                                  | absent inherits; present list replaces; empty clears         |
| `env_set`                                    | key overlay, empty indistinguishable    | absent inherit; empty clear; non-empty higher keys win       |
| `mounts`                                     | non-empty higher replaces               | absent inherits; any present list replaces; empty clears     |
| `mask_home_paths`                            | absent inherits; present replaces       | unchanged                                                    |
| capability `requested_actions`               | empty becomes all-action default        | empty reaches issuance and fails `NO_ACTIONS` before launch  |
| mediator `allowed_executables`               | whole parent replacement; empty default | parent fieldwise; present allowlist replaces/clears          |
| executable-policy `config_overrides`         | whole policy replacement                | parent fieldwise; empty clear; non-empty higher keys win     |
| `network`, `seccomp`, mediator, policy patch | whole higher nested patch replaces      | nested siblings merge field-by-field                         |
| `executable_policies` outer map              | key overlay, matching entry replacement | absent inherit; empty clear; non-empty key + fieldwise merge |
| CLI supplied value                           | highest                                 | unchanged                                                    |
| CLI unsupplied enable-only bool              | represented as false, neutral via OR    | represented as absent, therefore inherits                    |

Migration guidance will tell operators to:

- repeat inherited list members they still need when configuring a higher
  non-empty list;
- use an explicit empty list/map to clear a lower collection;
- treat empty `env_set` as an explicit broad opt-out from built-in bwrap
  rootfs/home masking and proxy-bypass controls, and prefer key overrides for
  narrow customization;
- understand that selective inherited map-key deletion is unsupported;
- rely on partial nested tables only for independently overridable siblings;
  and
- inspect `firma run --print-effective-config` before launching.

## Proof obligations

| ID          | Invariant | Stimulus / assertion                                                                                       |
| ----------- | --------- | ---------------------------------------------------------------------------------------------------------- |
| `PROOF-001` | `INV-001` | each optional scalar inherits when absent and replaces with explicit false/true/value                      |
| `PROOF-002` | `INV-002` | each list inherits/replaces/clears; each map inherits/key-merges/clears                                    |
| `PROOF-003` | `INV-003` | every nested patch retains lower siblings during one-field higher override                                 |
| `PROOF-004` | `INV-003` | incomplete final seccomp patch fails with the exact missing field after all layers merge                   |
| `PROOF-005` | `INV-004` | table-driven built-in/default/profile/CLI cases establish total ordering and CLI precedence                |
| `PROOF-006` | `INV-004` | environment endpoint fallback and runtime allow override retain their documented post-merge behavior       |
| `PROOF-007` | all       | representative `--print-effective-config` JSON exposes false, empty, nested partial, and CLI final values  |
| `PROOF-008` | all       | all built-in profiles resolve with unchanged effective values when no higher configuration is present      |
| `PROOF-009` | `INV-002` | empty requested actions produce Authority `NO_ACTIONS`, no seed, no agent launch, and no refresh lifecycle |
| `PROOF-010` | `INV-002` | empty `env_set` removes named bwrap/proxy controls at effective and terminal runtime boundaries            |

The field inventory in `PROOF-001` through `PROOF-003` must name every field in
all eight patch/element types, including `MountPatch` and every
`CapabilitySourcePatch` variant payload. Atomic mount entries replace only as
whole list elements; their `source` rebasing, `target`, `read_only`, and final
backend consumption receive explicit assertions. A new field or variant must
make the table-driven inventory fail to compile or require an explicit contract
update.

## Risks and mitigations

- Clearing built-in environment/mount values is powerful and can weaken a
  profile. Non-empty environment maps retain unrelated controls; an empty map
  is the explicit broad clear. Docs name every affected control, and tests prove
  both effective and terminal runtime consequences.
- Empty capability actions deterministically fail automatic issuance with
  Authority `NO_ACTIONS` before launch. Tests cover the request, mapped error,
  and absence of seed/agent/refresh lifecycle.
- Optional seccomp paths move completeness validation later. Mitigation:
  field-specific final errors plus partial and missing-field tests.
- Legacy `codex_cli` complicates one nested merge until PR #3. Mitigation:
  apply the same fieldwise rule and retain canonical same-name precedence;
  removal/migration remains isolated in PR #3.
- Cross-platform backend defaults can make resolved tests platform-dependent.
  Mitigation: patch-level contract tests are platform-neutral and existing
  runtime tests cover supported platform behavior.

Least-confident decision: map-wide empty clear combined with non-empty key
merging cannot selectively delete one inherited key. This is explicit and
testable without introducing deletion syntax; future selective deletion would
require a separate product contract.

## Plan-review findings and dispositions

A fresh independent reviewer did not approve the candidate. Its complete
reviewer-authored finding record is preserved verbatim below.

```text
# Plan review: `run-profile-patch-merge-plan.md`

**Verdict: NOT APPROVED.** The proposed layer algebra is generally coherent, but the plan leaves security-sensitive `env_set` replacement insufficiently decided, does not prove the terminal behavior of empty requested actions, describes an unrepresentable structural-map workflow, and omits nested patch elements from its claimed exhaustive inventory.

## PLAN-001 — High — Security / configuration semantics — Design risk

**Finding:** Whole-map replacement for `env_set` can silently remove built-in sandbox and proxy safeguards, but the plan treats this as a settled collection-shape decision rather than an explicit security-posture decision.

**Evidence:**

- `docs/architecture/run-profile-patch-merge-plan.md:160-185` assigns `env_set` whole-map replacement semantics.
- `docs/architecture/run-profile-patch-merge-plan.md:488-492` acknowledges generic environment/mount risk without identifying the concrete controls removed.
- Built-in `env_set` contains security-relevant values:
  - `FIRMA_RUN_BWRAP_ROOTFS_MODE=readonly`: `crates/firma-run/src/profile.rs:34-41`
  - `FIRMA_RUN_BWRAP_MASK_HOME_PATHS`: `crates/firma-run/src/profile.rs:42-49`
  - empty `NO_PROXY` and `no_proxy` to prevent proxy bypass: `crates/firma-run/src/profile.rs:50-54`
  - `FIRMA_RUN_BWRAP_RUNTIME_HOME`: `crates/firma-run/src/profile.rs:30-33`
- These values feed the sandbox environment at `crates/firma-run/src/runtime/mod.rs:560-566`; bwrap consumes the rootfs and mask controls in `crates/firma-run/src/backend/linux_bwrap/mount.rs:21-55`.
- The plan’s migration advice merely tells operators to repeat inherited entries (`run-profile-patch-merge-plan.md:441-448`), although several entries are generated built-in implementation details and profile-specific values.

**Reachable trace:**

1. Operator selects a built-in profile.
2. Built-in profile supplies proxy-clearing and bwrap-hardening entries.
3. Operator adds any non-empty `[run.defaults.env_set]` or selected-profile `env_set`.
4. `DEC-002` replaces the entire built-in map.
5. Final runtime environment lacks unspecified safeguards.
6. Depending on backend and host environment, the agent may regain proxy bypass paths, lose sensitive-home masking, or receive a weaker rootfs posture.

**Invariant owner / trust boundary:** `firma-run::profile` owns built-in security posture; `firma-run::config::Merge` and runtime environment assembly cross the operator-config-to-sandbox trust boundary.

**Practical impact:** A seemingly narrow environment customization becomes a broad security override. Effective-config inspection is useful but does not make that consequence obvious or preserve safe defaults.

**Required correction:** Obtain and record an explicit product/security decision for `env_set`:

- either retain whole replacement and document the exact security controls that must be repeated, with migration examples and negative tests proving the resulting effective and runtime environment; or
- separate framework-owned control variables from operator leaf-map replacement so user `env_set` cannot erase invariant-owned controls; or
- deliberately use key merge plus a narrowly scoped clear/removal representation if selective removal is required.

At minimum, add proof cases for clearing/replacing each security-relevant built-in variable and assert the terminal bwrap/proxy configuration, not only effective JSON.

**Confidence:** High.

**Assumptions:** Operator configuration is trusted to opt into weaker behavior, but accidental weakening remains materially different from an explicit, named opt-out.

---

## PLAN-002 — High — Proof obligation / capability behavior — Design risk

**Finding:** The plan preserves explicit empty `requested_actions` but proves only merge and issuance input, not its terminal authorization behavior.

**Evidence:**

- The plan changes empty from “all actions” to an empty set: `docs/architecture/run-profile-patch-merge-plan.md:165-172`.
- Slice 4 proposes “issuance-input tests”: `docs/architecture/run-profile-patch-merge-plan.md:381-387`.
- The risks section says issuance “may” fail: `docs/architecture/run-profile-patch-merge-plan.md:493-495`, leaving the observable result unresolved.
- Current resolution converts empty to all actions at `crates/firma-run/src/config.rs:701-709`.
- The resolved vector reaches the gRPC request unchanged at `crates/firma-run/src/capability/issue.rs:174-179`.
- Authority policy evaluation receives the empty slice at `crates/firma-authority/src/issuance.rs:63-76`; if allowed, it can construct claims from the returned grant at `crates/firma-authority/src/issuance.rs:80-99`.
- Minting and refresh reuse this request path, so launch-time and refresh-time outcomes both matter.

**Reachable trace:**

1. Higher layer sets `requested_actions = []`.
2. Resolution preserves the empty vector.
3. `firma run` requests an empty action set from Authority.
4. Behavior depends on Cedar evaluation and Authority response: startup denial, an issued empty-action token, or another response.
5. The resulting launch and refresh behavior is not specified or tested by the plan.

**Invariant owner / trust boundary:** Authority issuance policy owns grants; Firma Run owns interpretation of profile configuration and fail-closed conversion at the run↔Authority boundary.

**Practical impact:** Operators cannot know whether clear means “launch with a capability that denies every protected action” or “fail before launch.” Refresh could also behave differently from initial issuance if only the request payload is tested.

**Required correction:** Choose and document the terminal contract, then add an end-to-end proof from TOML through resolution, issuance, verified claims, and enforcement—or through the exact startup denial. Cover initial mint and refresh. Include positive and negative controls showing that a neighboring non-empty request grants only the expected intersection and that empty never broadens to all actions.

**Confidence:** High.

**Assumptions:** Existing Cedar policy behavior may reject empty requests or permit an empty grant; repository inspection did not establish one universal outcome across policy bundles.

---

## PLAN-003 — Medium — Structural-map semantics / representability — Confirmed conflict

**Finding:** The plan recommends a clear-then-rebuild workflow for `executable_policies` that cannot be expressed in one TOML layer under its own merge rules.

**Evidence:**

- `DEC-003` defines:
  - empty map clears;
  - non-empty map key-merges: `docs/architecture/run-profile-patch-merge-plan.md:188-194`.
- It then says operators can remove selected inherited entries by providing a complete desired map “after first clearing it in the layer that owns the final configuration”: `run-profile-patch-merge-plan.md:198-203`.
- A TOML field/table has one value per layer. An empty
  `[run.profiles.<name>.executable_policies]` table cannot simultaneously contain the rebuilt entries; once entries are added, the map is non-empty and therefore key-merges with inherited keys.
- The plan itself notes that current TOML syntax provides only one value per field, but does not reconcile that fact with the proposed workflow.

**Reachable trace:**

1. Lower layer defines policies for executables `a` and `b`.
2. Higher layer wants to retain modified `a` and remove `b`.
3. Higher empty map removes both.
4. Higher non-empty `{a = ...}` merges and retains inherited `b`.
5. No single-layer TOML representation produces only `a`.

**Invariant owner / trust boundary:** `ProfilePatch.executable_policies` representation and its `Merge` implementation own the structural-map contract.

**Practical impact:** Migration guidance promises an operation the configuration language cannot perform. Operators cannot selectively remove inherited executable governance entries without a deletion operation or control of a separate later layer.

**Required correction:** Remove the impossible clear-and-rebuild guidance and explicitly state that selective inherited-key deletion is unsupported. Add TOML parsing tests proving that an explicitly empty structural map is representable and clears the lower map. If selective removal is required, obtain a product decision for replacement semantics or a narrowly typed deletion mechanism; do not introduce a generic patch DSL.

**Confidence:** High.

**Assumptions:** No CLI override supplies a second `executable_policies` value after the selected profile.

---

## PLAN-004 — Medium — Completeness / field inventory — Confirmed conflict

**Finding:** The claimed exhaustive nested-field contract omits patch elements that participate in the affected collections.

**Evidence:**

- Scope and proof inventory name six structs only: `docs/architecture/run-profile-patch-merge-plan.md:47-51` and `:471-474`.
- `ProfilePatch.mounts` contains `MountPatch`, whose fields are:
  - `source`
  - `target`
  - `read_only`
  
  at `crates/firma-config-schema/src/run.rs:121-129`.
- Capability nesting also contains `CapabilitySourcePatch::{Disabled, File { path }}` at `crates/firma-config-schema/src/run.rs:194-200`.
- Mount source rebasing is an affected transformation at `crates/firma-run/src/config.rs:1064-1067`.
- Capability source path rebasing and canonical/legacy source interaction occur at `crates/firma-run/src/config.rs:1072-1081` and `:352-369`.
- The plan mentions rebasing generally but its compile-enforced field inventory cannot detect changes to `MountPatch` or `CapabilitySourcePatch`.

**Reachable trace:**

1. TOML constructs nested mount or capability-source values.
2. File-relative paths are rebased.
3. A higher layer replaces the mount list or atomically selects a capability source.
4. Final conversion sends those values to filesystem or capability consumers.
5. A future or overlooked nested field can bypass the proposed six-struct inventory while the contract suite still claims completeness.

**Invariant owner / trust boundary:** `firma-config-schema::run` owns patch representation; `rebase_profile_paths`, merge implementations, and final converters own transformations across the file-config boundary.

**Practical impact:** The required “all `ProfilePatch` and nested fields/consumers audited” guarantee is not met, and path/read-only/source semantics could regress without forcing a contract update.

**Required correction:** Expand the canonical inventory and contract table to include `MountPatch`, `CapabilitySourcePatch`, and every nested variant payload. For atomic collection elements, explicitly record “whole element/list replacement; no per-field element merge.” Include rebasing, final conversion, and terminal consumer assertions. Ensure adding a field or variant requires an explicit contract disposition.

**Confidence:** High.

**Assumptions:** “All nested fields” includes element structs and tagged-enum payloads reachable from `ProfilePatch`, as required by the task constraints.

---

## Residual review notes

- The proposed scalar `Option<T>` model correctly represents absent, explicit false, and explicit empty collection states.
- CLI precedence ordering matches the current entry path (`built-in → file defaults/profile → CLI`) at `crates/firma-run/src/config.rs:436-444`, but the aggregate suite must distinguish genuine CLI construction from synthetic fourth-layer patch tests.
- Optional seccomp paths are implementable, but the plan should explicitly test a partial explicit seccomp table when no lower explicit table exists: generated managed defaults are currently synthesized only after patch merging (`crates/firma-run/src/config.rs:533-541`) and therefore cannot complete that partial patch.
- Slice boundaries appear potentially compilable if every schema struct literal and converter is updated in the same slice, but this must be verified per revision; the final aggregate suite cannot substitute for per-slice compilation.
```

Dispositions:

- `PLAN-001` — **corrected**. `DEC-002` now selects key merge for non-empty
  maps, so narrow `env_set` changes preserve unrelated built-in safeguards.
  Explicit empty remains the deliberate broad-clear operation. Slice 2 and
  `PROOF-010` name the concrete bwrap/proxy controls and require effective and
  terminal runtime tests.
- `PLAN-002` — **corrected**. Direct repository evidence at
  `firma-authority/src/service.rs::evaluate_cedar_policy` establishes the
  terminal contract: empty actions return `NO_ACTIONS`; the Run client maps the
  DENY to `CapabilityDenied`. `DEC-002`, Slice 4, and `PROOF-009` now require
  TOML-to-terminal proof, no seed/launch/refresh lifecycle, and a neighboring
  non-empty narrowing control.
- `PLAN-003` — **corrected**. `DEC-003` and migration guidance now state that
  selective inherited-key deletion is unsupported and no longer promise an
  impossible clear-and-rebuild workflow. Slice 6 requires a real TOML
  present-empty parse-and-clear proof.
- `PLAN-004` — **corrected**. Scope, Slice 7, and the proof inventory now include
  `MountPatch`, `CapabilitySourcePatch`, every tagged payload, path rebasing,
  atomic element replacement, final conversion, and terminal consumers.

The residual notes are also incorporated: the aggregate suite must use genuine
CLI construction, Slice 3 tests an incomplete partial seccomp table with no
lower explicit patch, and every slice receives targeted compilation/tests.

A second fresh independent reviewer checked every corrected finding against the
repository and **approved the plan with no remaining or new findings**. It
confirmed:

- `PLAN-001` is resolved by non-empty key merge, explicit broad empty clear,
  and terminal bwrap/proxy proofs;
- `PLAN-002` is resolved by the Authority `NO_ACTIONS` trace, Run
  `CapabilityDenied` mapping, and no-seed/launch/refresh proof;
- `PLAN-003` is resolved by explicitly unsupported selective deletion and real
  TOML present-empty tests;
- `PLAN-004` is resolved by the eight-type inventory, variant payloads,
  rebasing, atomic element, conversion, and terminal-consumer assertions; and
- genuine CLI construction, partial seccomp without a lower explicit table,
  per-slice compilation, full verification, and docs gates are all explicit.

## Final verification

- Targeted checks per atomic revision as listed in each slice.
- Full `just check` and docs-site `pnpm build` after rebasing onto the exact
  latest PR #1 remote head.
- Fresh independent post-implementation Rust/config review with every finding
  dispositioned before plan removal.
- Final base/head/merge-base checks, no-plan-at-tip/no-plan-in-diff proof, and
  required latest-head CI success after opening the stacked PR.

## Post-implementation review

A fresh independent reviewer inspected revision range
`dc82f6d655ffa6421c25bc91a77e9f24e35ba8d1..d8437bc3aae7e4637ab962d782b684c3d71b0d6c`
against this accepted plan. The reviewer inspected all changed files, schema
cardinality and Serde behavior, every merge implementation, four-layer
resolution, built-ins, CLI patch construction, environment fallbacks, path
rebasing, final validation and conversion, runtime consumers, capability
denial routing, tests, and migration documentation. Its targeted verification
ran 455 tests successfully with four skipped.

### REVIEW-001 — Low — Accepted cleanup/proof obligation remains incomplete

**Finding:** The final reviewed tip still contains this plan, contrary to the
accepted no-plan-at-tip obligation. The artifact also has trailing whitespace
in the preserved original plan-review transcript, so a base-to-tip
`git diff --check` fails until the artifact is removed.

**Evidence:** The no-plan-at-tip obligation and standalone deletion are stated
in Scope and Slice 8. At reviewed revision `d8437bc3`, this file remains, and
line 658 of that revision contains the trailing whitespace.

**Failure trace:** Merge the reviewed tip, and the plan remains in the branch
diff; the no-plan proof is false and the base-to-tip whitespace check fails.

**Required correction:** Delete only this plan in the planned standalone final
revision, preserving the first plan commit as the durable historical locator.

**Disposition:** Accepted. The next and final revision deletes only this file.
The deletion simultaneously satisfies the no-plan-at-tip requirement and
removes the preserved transcript whitespace from the final PR diff. This is a
purely mechanical change, so the adversarial-review workflow does not require
another behavior review.

The reviewer reported no correctness, security, merge-algebra, path-rebasing,
runtime-consumer, compatibility-beyond-documented-breakage, or test-coverage
findings. Full local verification independently passed before this record:
`just check` ran 2,577 tests plus all workspace Clippy, doctests, builds,
dependency checks, and release-script checks; the docs site built all 35 pages.
