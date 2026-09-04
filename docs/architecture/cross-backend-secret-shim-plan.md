# Cross-Backend Secret Shim Deployment Plan

## Artifact metadata

- Status: Accepted
- Durable locator: `docs/architecture/cross-backend-secret-shim-plan.md`
- Repository revision researched: `abaf068d`
- Task or requirement source: User request in planning session, 2026-09-04
- Supersedes: Not applicable

## Goal and acceptance outcomes

- Goal: Allow CLI secret-provider shims on sandbox backends whose guest cannot invoke the host directly, while selecting a shim binary that matches the guest execution architecture and keeping shim deployment out of installer-facing UX.
- Observable acceptance outcomes: CLI `secret_providers` are accepted for bwrap and any backend that declares an isolated guest-shim deployment capability, rejected for proxy-only or host-call-capable backends, and fail before launch if no guest-compatible shim artifact is available.
- Observable acceptance outcomes: Unix and Windows installers report and install only `firma`; any copied or staged shim artifacts are internal and not described as separately installed tools.
- Observable acceptance outcomes: VZ guest launch contracts carry only guest-consumable shim deployment metadata, not host secrets, and the VZ runner/guest-init validate the broker bridge, materialize the correct shim, and place provider shim entries before the command starts.

## Scope

- In scope: `firma-run` backend capability modeling, secret-shim planning, installer messaging/copy behavior, release artifact packaging assumptions, installer smoke CI updates, VZ guest contract/schema validation, VZ runner directory-share planning, VZ guest-init materialization, VZ guest broker reachability, and focused tests.
- Out of scope: Firecracker implementation beyond preserving the future capability hook, WSL2 structural isolation, new user-facing config for selecting shim paths, and changing HTTP secret-provider behavior.
- Assumptions: Release artifacts can contain private data files or bundled binaries alongside `firma`; if cargo-dist cannot express the desired private layout, a release-packaging child plan is required before implementation.
- Open decisions: Whether the private shim store should live beside `firma` as `libexec/openfirma/secret-shims/<target>/...` or be embedded in `firma` and extracted per run.
- Cohesion and split assessment: One parent plan is cohesive because backend eligibility, artifact selection, and contract materialization all enforce the same secret-boundary invariant. Release packaging may split if cargo-dist constraints force a separate workflow redesign.
- Deferred child plans: Conditional release-packaging child plan if cargo-dist cannot include non-user-facing companion artifacts without installer exposure.

## Routing

- Mode: Full
- Trigger evidence: The change touches the secret path and fail-closed behavior in `crates/firma-run/src/runtime/secret_shims.rs:1`, `crates/firma/src/bin/firma-secret-shim.rs:10`, and `crates/firma-run/src/config.rs:694`.
- Trigger evidence: The change crosses backend and guest contracts in `crates/firma-run/src/backend/mod.rs:346`, `crates/firma-run/src/backend/macos_vz.rs:367`, `crates/firma-vz-runner/src/contract/mod.rs:27`, and `crates/firma-vz-guest-init/src/linux/contract.rs:18`.
- Higher-mode triggers checked: Security/trust boundary, stable installer behavior, stable guest launch contract, and multiple architectural boundaries all apply.
- Downgrade evidence and reason: Not applicable.

## Current behavior and problem

- Owners and entry points: `config::resolve_profile` rejects CLI secret providers unless `backend == bwrap`; `runtime::run` starts secret services and calls `secret_shims::prepare`; `SandboxBackend::start_agent` consumes `LaunchSpec` and backend mounts.
- Current success and failure outcomes: bwrap locates a sibling `firma-secret-shim`, bind-mounts it over each provider executable, injects `FIRMA_BROKER_ADDR`, and strips vault credential env vars. Non-bwrap backends reject CLI providers at config resolution. Installers require, move, chmod, and report a standalone shim binary.
- Evidence: `crates/firma-run/src/config.rs:694`, `crates/firma-run/src/runtime/mod.rs:244`, `crates/firma-run/src/runtime/secret_shims.rs:238`, `crates/firma-run/src/runtime/secret_shims.rs:326`, `install.sh:310`, `install.ps1:212`.

## Key decisions and tradeoffs

### `DEC-001`: Model shim eligibility as a backend capability

- Choice: Add a backend-owned capability query, not hard-coded backend-name checks, that returns whether CLI shim mediation is supported, unsupported because the backend can call the host, or unsupported because guest artifact deployment is not implemented.
- Rationale and evidence: Current `backend == bwrap` gating is explicit in `config.rs:703`, while VZ has structural guest and sandbox-exec modes with different isolation guarantees in `macos_vz.rs:100`. A capability avoids accidentally allowing shims in VZ compatibility or WSL2 proxy-only modes.
- Consequences and rejected alternatives: Reject “allow all non-bwrap” because WSL2 is proxy-only (`windows_wsl2.rs:98`) and macOS VZ compatibility is proxy-only (`macos_vz.rs:232`). Reject user config switches because this is a trust boundary, not a preference.

### `DEC-002`: Select shim artifacts by guest target triple

- Choice: Introduce a runtime shim artifact resolver that maps backend guest execution targets to bundled shim artifacts and fails closed on missing, non-executable, or wrong-platform artifacts.
- Rationale and evidence: The current locator only finds a host-platform sibling via `std::env::consts::EXE_SUFFIX` in `secret_shims.rs:326`. VZ guest commands run inside Linux guest init (`firma-vz-guest-init/src/linux/command.rs:81`), so a macOS host binary cannot be used as the guest shim.
- Consequences and rejected alternatives: Reject relying on the install script to install a visible shim because the user requirement says the shim is private. Reject compiling at run time because deterministic launch and offline operation should not depend on toolchains.

### `DEC-003`: Keep bwrap bind-over behavior, add contract-backed guest deployment

- Choice: Preserve bwrap’s direct read-only bind mounts. For VZ guest mode, serialize a bounded internal `secret_shims` contract section that identifies guest target paths and a selected shim artifact share, then let guest-init bind or copy the shim before spawning the command.
- Rationale and evidence: bwrap already consumes `SandboxMount` directly (`linux_bwrap/mod.rs:211`). VZ runner currently exposes only directory shares and rejects file mount sources (`firma-vz-runner/src/vm/plan.rs:76`), while guest-init bind-mounts contract shares by index (`firma-vz-guest-init/src/linux/mount.rs:112`).
- Consequences and rejected alternatives: Reject adding file-backed mounts to the existing VZ `mounts` list because runner validation currently requires directories and operator/framework mounts have broader semantics than internal shim artifacts.

### `DEC-004`: Remove shim from installer-facing UX but keep private packaging

- Choice: Installer scripts should install/report only `firma`. If release artifacts still contain shim files, scripts may copy an internal private directory without naming it in normal output.
- Rationale and evidence: `install.sh` currently locates, moves, chmods, and logs `firma-secret-shim` (`install.sh:310`); `install.ps1` does the same (`install.ps1:217`). This makes the shim appear as a public installed command.
- Consequences and rejected alternatives: Reject dropping shim artifacts from releases entirely because cross-guest support requires prebuilt guest binaries. Reject putting guest-shim paths in user config unless a later packaging constraint proves unavoidable.

### `DEC-005`: Bridge only the redaction-only broker into isolated guests

- Choice: Add an explicit VZ guest broker bridge using the existing guest VSOCK service pattern: `firma-run` allocates a guest broker endpoint and serializes it in the internal shim contract, `firma-vz-runner` validates/plans the VSOCK device or service, and guest-init exposes a guest-local `FIRMA_BROKER_ADDR` that forwards only to the host broker.
- Rationale and evidence: Current secret services bind the broker as `unix://...` on Unix hosts in `secret_shims.rs:344`, and VZ guest networking currently provisions HTTP proxy and DNS only in `macos_vz.rs:621` and `firma-vz-guest-init/src/linux/network.rs:46`. A deployed Linux shim cannot reach a macOS host Unix socket without a bridge.
- Consequences and rejected alternatives: Reject exposing the plaintext gateway or broad host runtime share to the guest. Reject assuming virtiofs can carry host Unix socket semantics. Missing broker bridge remains a fail-before-command-spawn error.

### `DEC-006`: Intercept guest provider lookup with a private shim directory

- Choice: For isolated guests, do not reuse host `PATH` resolution. Guest-init creates a private guest shim directory containing provider-name symlinks or copies to the selected shim binary, prepends that directory to the command environment `PATH`, and validates that each configured provider name is represented exactly once.
- Rationale and evidence: The current resolver is host-only (`secret_shims.rs:312`), while VZ guest commands spawn inside a separate Linux filesystem (`firma-vz-guest-init/src/linux/command.rs:93`). Host paths may not exist in the guest or may refer to the wrong executable.
- Consequences and rejected alternatives: Reject binding over host-resolved paths for guests. Reject discovering and overwriting arbitrary guest filesystem binaries because it is image-dependent and can miss shell lookup behavior. This narrows `INV-001` to command lookup through the supplied environment; absolute provider invocations remain unsupported unless a later provider spec requires them and defines guest-path metadata.

## Architecture and invariant ownership

- Architecture shape: `config` asks backend capability for CLI provider eligibility; `runtime::secret_shims` resolves provider binaries for host-bind backends and provider names plus guest-target shim artifacts for isolated guests; bwrap receives ordinary framework mounts; VZ guest receives an internal contract section validated by `firma-vz-runner` and materialized by `firma-vz-guest-init`; guest-init prepends a private shim directory and injects a guest-local broker address; installers copy only `firma` plus private implementation artifacts.

### `INV-001`: CLI provider commands never run unmediated after CLI providers resolve

- Semantic predicate: If a resolved profile contains CLI secret providers, every configured provider lookup performed through the launch environment resolves to the shim, and startup fails before launching the command if mediation cannot be installed. Absolute guest provider paths are intentionally unsupported until provider specs carry validated guest-path metadata.
- Primary owner: `firma-run::runtime::secret_shims`, with backend-specific proof at the backend launch boundary.
- Detailed proof: `PO-001`.

### `INV-002`: Shim executable architecture matches the guest execution environment

- Semantic predicate: The shim artifact deployed into a backend is executable by the guest process that will invoke the shimmed provider path.
- Primary owner: backend capability plus shim artifact resolver in `firma-run`.
- Detailed proof: `PO-002`.

### `INV-003`: Plaintext secret custody remains host-side only

- Semantic predicate: The guest-visible shim and broker channel never receive vault credential env vars or plaintext secret-store access; only the redacted broker output enters the guest.
- Primary owner: `SecretServices` and `secret_shims::prepare`.
- Detailed proof: `PO-003`.

- Compatibility, migration, and failure semantics: `DEC-001` and `DEC-004` preserve existing bwrap behavior, change non-bwrap CLI-provider rejection only for proven isolated guest modes, and keep missing artifacts, missing broker bridges, or invalid guest shim directories fail-closed.
- Durable documentation owner: implementation must update `docs-site/src/content/docs/guides/secret-gateway.md` only to describe supported backends, not private shim file names.

## Implementation slices

### Slice 1: Backend capability gate and private artifact resolver

- Production, types, tests, and docs/config: Add a `SecretShimSupport` or equivalent backend capability in `backend/mod.rs`; replace `config.rs` bwrap-only validation with capability validation; add an artifact resolver in `runtime/secret_shims.rs` that can resolve current-host and guest-target shims from a private bundle path; update installer scripts and `.github/workflows/installer-smoke.yml` to stop reporting or asserting shim installation as a user command.
- Affected decisions and traces: `DEC-001`, `DEC-002`, `DEC-004`, `TRACE-CURRENT-BWRAP`, `TRACE-PROPOSED-BWRAP`, `TRACE-INSTALLER-PRIVATE`.
- Proof obligations: `INV-001`, `INV-002`, `INV-003`.
- Focused verification: `cargo test -p firma-run config::tests::cli_secret_providers_on_non_bwrap_backend_are_rejected`; new tests for VZ compatibility/WSL2 rejection, bwrap acceptance, missing artifact failure, installer dry-run output excluding shim names, and installer-smoke checks asserting private artifacts are not installed on PATH.
- Dependencies: None.
- Intentionally unsupported: VZ guest materialization until Slice 2; Firecracker stays unsupported.

### Slice 2: VZ guest broker bridge and private shim directory

- Production, types, tests, and docs/config: Extend `VzGuestLaunchContract`, `firma-vz-runner` contract validation, VM share planning, and `firma-vz-guest-init` contract/mount/network/command setup with an internal `secret_shims` section; deploy selected Linux guest shim into a read-only share or guest-private runtime path; create a private guest shim directory with provider-name entries; prepend it to `PATH`; expose a guest-local broker address over a redaction-only VSOCK bridge; ensure command spawn happens after broker and shim placement are both ready.
- Affected decisions and traces: `DEC-001`, `DEC-002`, `DEC-003`, `DEC-005`, `DEC-006`, `TRACE-PROPOSED-VZ-GUEST`.
- Proof obligations: `INV-001`, `INV-002`, `INV-003`.
- Focused verification: `cargo test -p firma-run macos_vz`, `cargo test -p firma-vz-runner`, `cargo test -p firma-vz-guest-init`, plus contract fixture tests proving secret env exclusion, guest-target shim metadata validation, broker bridge validation, and guest `PATH` precedence for provider names that differ from host `PATH` resolution.
- Dependencies: Slice 1 capability and artifact resolver.
- Intentionally unsupported: VZ sandbox-exec compatibility mode and WSL2 unless a later backend proves guest cannot call host and can materialize artifacts.

## Risks and gaps

- Existing risks: VZ guest contract version is currently `1`; adding a required section is a stable contract change between `firma-run`, `firma-vz-runner`, and guest-init. Existing installer smoke CI asserts visible shim installation.
- Planned mitigations: Bump contract version or add a strictly validated optional section only when CLI providers are configured; ensure all three components change atomically in one slice; update installer smoke CI with installer edits in Slice 1.
- Explicit evidence gaps: cargo-dist private artifact layout has not been proven; release CI may need a child plan.
- Least-confident decisions: private artifact layout beside `firma` versus embedded extraction.

## Plan-review findings and dispositions

```yaml
id: PLAN-001
severity: high
category: trust-boundary
classification: confirmed conflict
claim: VZ guest shims cannot reach the current host broker transport, but the candidate plan assumed end-to-end shim mediation.
evidence:
  - docs/architecture/cross-backend-secret-shim-plan.md:214-216
  - crates/firma-run/src/runtime/secret_shims.rs:102-105
  - crates/firma-run/src/runtime/secret_shims.rs:344-349
  - crates/firma-run/src/backend/macos_vz.rs:621-649
  - crates/firma-vz-guest-init/src/linux/network.rs:46-63
reachability: macOS VZ guest run with CLI providers deploys a Linux shim, then the shim reads FIRMA_BROKER_ADDR but has no guest-to-host broker transport.
invariant_or_boundary: INV-001 and INV-003; host broker redaction boundary.
impact: VZ guest mediation cannot work or may tempt an unsafe host runtime/socket exposure.
correction: Add explicit broker bridge fields, validation, runner VSOCK planning, guest-init proxy/env injection, and tests.
disposition: Accepted. Added DEC-005, expanded architecture shape, Slice 2, TRACE-PROPOSED-VZ-GUEST, trust analysis, and proof obligations so VZ guest support requires a redaction-only broker bridge and fails before command spawn without it.
```

```yaml
id: PLAN-002
severity: high
category: correctness
classification: design risk
claim: The candidate plan did not define who discovers guest provider paths and relied on current host PATH resolution evidence.
evidence:
  - docs/architecture/cross-backend-secret-shim-plan.md:57
  - docs/architecture/cross-backend-secret-shim-plan.md:105
  - crates/firma-run/src/runtime/secret_shims.rs:270-272
  - crates/firma-run/src/runtime/secret_shims.rs:312-324
  - crates/firma-vz-guest-init/src/linux/mount.rs:112-127
  - crates/firma-vz-guest-init/src/linux/command.rs:93-124
reachability: Host and guest PATH differ, so host-resolved paths may not overlay guest provider executables.
invariant_or_boundary: INV-001; VZ guest-init materialization boundary.
impact: Provider commands may fail closed unexpectedly or run unmediated if a real guest provider remains earlier on PATH.
correction: Define one guest lookup interception mechanism and test guest PATH differences.
disposition: Accepted. Added DEC-006, narrowed INV-001 to launch-environment lookup, marked absolute guest provider paths unsupported, and updated Slice 2 verification for guest PATH precedence.
```

```yaml
id: PLAN-003
severity: medium
category: verification
classification: confirmed conflict
claim: Installer smoke CI asserts visible shim installation and was omitted from plan scope.
evidence:
  - docs/architecture/cross-backend-secret-shim-plan.md:96-99
  - docs/architecture/cross-backend-secret-shim-plan.md:169-170
  - .github/workflows/installer-smoke.yml:39
  - .github/workflows/installer-smoke.yml:85
reachability: Removing installer-facing shim output or location makes current smoke jobs fail, or keeping it violates the private implementation detail requirement.
invariant_or_boundary: DEC-004; installer UX/release verification boundary.
impact: Plan acceptance outcomes would conflict with CI.
correction: Include installer smoke workflow updates and assertions that private artifacts are not on PATH or reported as installed tools.
disposition: Accepted. Added installer smoke CI to scope, file-tree diff, Slice 1 production scope, and focused verification.
```

## Final verification

- Focused checks: affected crate unit/integration tests listed per slice.
- Workspace checks: `just fmt`, `just lint`, `just test` after implementation; `just check` before PR if platform tools are available.
- Post-implementation independent review: required via `adversarial-review` for the final diff.

## Technical evidence

### Applicability assessment

| Section                     | Applicability | Reason or evidence                                                                                      |
| --------------------------- | ------------- | ------------------------------------------------------------------------------------------------------- |
| Vocabulary                  | Applicable    | “backend”, “guest”, “shim”, and “isolated” currently overlap across bwrap, VZ, and WSL2.                |
| Alternatives                | Applicable    | Sibling shim, private bundle, embedded extraction, and installer-visible copy are materially different. |
| File-tree diff              | Applicable    | Responsibility changes across run, runner, guest-init, installers, and docs.                            |
| Type and signature sketches | Applicable    | Backend capability and artifact resolver shape invalid-state handling.                                  |
| Semantic call traces        | Applicable    | Behavior crosses config, runtime, backend launch, runner, and guest-init boundaries.                    |
| Trust analysis              | Applicable    | Secret custody and fail-closed behavior are central.                                                    |
| Detailed proof obligations  | Applicable    | Runtime and contract invariants require tests across crates.                                            |

### Vocabulary

| Canonical term            | Meaning                                                                                                         | Owner/context                             | Synonyms or terms to avoid | Conflict or decision                             |
| ------------------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------- | -------------------------- | ------------------------------------------------ |
| CLI secret shim           | Guest-executed binary that proxies a configured CLI provider call to the host broker.                           | `firma-run::runtime::secret_shims`        | Avoid “installed command”. | Private implementation detail.                   |
| Host-call-capable backend | Backend where the wrapped process can directly execute or reach host tooling outside a stronger guest boundary. | `SandboxBackend` capability.              | Avoid “non-bwrap”.         | Must not allow CLI shims solely by backend name. |
| Guest target              | OS/architecture ABI of the process that invokes shimmed provider paths.                                         | Backend capability and artifact resolver. | Avoid host target.         | Drives shim artifact choice.                     |

### Alternatives

- Selected: Private bundled shim artifacts resolved by guest target. Benefit: deterministic, installer-private, supports cross-architecture guests. Cost: release packaging complexity.
- Rejected: Visible sibling `firma-secret-shim` installed on PATH-adjacent location. Benefit: current simple bwrap behavior. Cost: user-visible implementation detail and wrong architecture for guests.
- Rejected: Runtime compilation. Benefit: flexible targets. Cost: non-deterministic, requires guest toolchains, poor fail-closed startup.
- Deferred: Embed shim bytes into `firma`. Benefit: simplest installer UX. Cost: larger binary and multi-target embedding/release complexity; decide after cargo-dist evidence.

### File-tree diff

```diff
crates/firma-run/src/backend/mod.rs              # MODIFIED - backend shim capability contract
crates/firma-run/src/backend/linux_bwrap/mod.rs  # MODIFIED - declares host-target bind-over support
crates/firma-run/src/backend/macos_vz.rs         # MODIFIED - declares VZ guest support only in guest mode; emits contract section
crates/firma-run/src/backend/windows_wsl2.rs     # MODIFIED - explicitly declares unsupported/proxy-only support
crates/firma-run/src/runtime/secret_shims.rs     # MODIFIED - private artifact resolver and backend-neutral shim plan
crates/firma-vz-runner/src/contract/*.rs         # MODIFIED - validates internal shim contract metadata
crates/firma-vz-runner/src/vm/plan.rs            # MODIFIED - adds private shim artifact directory share
crates/firma-vz-guest-init/src/linux/*.rs        # MODIFIED - materializes guest shim before command spawn
install.sh                                       # MODIFIED - install/report only firma; copy private artifacts silently if needed
install.ps1                                      # MODIFIED - install/report only firma; copy private artifacts silently if needed
.github/workflows/installer-smoke.yml            # MODIFIED - no visible shim command assertion
docs-site/src/content/docs/guides/secret-gateway.md # MODIFIED - backend support notes without private file names
```

### Type and signature sketches

```rust
pub enum SecretShimSupport {
    Unsupported {
        reason: SecretShimUnsupportedReason,
    },
    HostBindMount {
        guest_target: ShimTarget,
    },
    IsolatedGuest {
        guest_target: ShimTarget,
        broker_bridge: BrokerBridgeKind,
    },
}

pub struct ShimTarget {
    triple: &'static str,
    exe_suffix: &'static str,
}

pub trait SandboxBackend {
    fn secret_shim_support(&self) -> SecretShimSupport;
}
```

- `CW-001`: A caller can still construct `ShimTarget { triple: "x86_64-unknown-linux-musl", exe_suffix: "" }` for an aarch64 guest if fields are public. Therefore `ShimTarget` must be constructed by backend-owned constants or private constructors, and runtime tests must verify each backend mode returns the expected target.
- `CW-002`: A caller can pass a host-target artifact path for an `IsolatedGuest` support value if artifact path and target are independent same-typed values. Therefore artifact resolution should accept `ShimTarget` and return an `ResolvedShimArtifact { target, path }`, and contract emission should consume that paired value.
- `CW-003`: A caller can construct `IsolatedGuest { guest_target, broker_bridge }` without checking that the runner and guest-init implement the bridge. Therefore `SecretShimSupport::IsolatedGuest` must only be returned by backend modes whose start path serializes and validates broker bridge metadata, and tests must assert VZ compatibility mode returns `Unsupported`.

### Semantic call traces

| Field                      | Content                                                                                                                                                                                                   |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Trace ID                   | `TRACE-CURRENT-BWRAP`                                                                                                                                                                                     |
| State                      | Current                                                                                                                                                                                                   |
| Entry and stimulus         | `firma run` with `secret_providers = ["bws"]` and `backend = "bwrap"`.                                                                                                                                    |
| Path                       | `resolve_profile` backend-name allow -> `SecretServices::start` -> `secret_shims::prepare` -> `BwrapMountPlan::build` -> `bwrap --bind shim real-bin` -> guest invokes shim -> broker runs host provider. |
| Validation/trust crossings | Config validation, host PATH resolution, mount planning, broker socket boundary.                                                                                                                          |
| Success outcome            | Provider command is mediated and credentials are stripped from launch env.                                                                                                                                |
| Failure path               | Missing real binary or missing shim sibling errors before launch.                                                                                                                                         |
| Evidence                   | `config.rs:694`, `secret_shims.rs:238`, `linux_bwrap/mod.rs:211`.                                                                                                                                         |

| Field                      | Content                                                                                                                                                                                                                                                                                                                                                         |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Trace ID                   | `TRACE-PROPOSED-VZ-GUEST`                                                                                                                                                                                                                                                                                                                                       |
| State                      | Proposed                                                                                                                                                                                                                                                                                                                                                        |
| Entry and stimulus         | `firma run` with CLI providers, `backend = "vz"`, and `FIRMA_RUN_VZ_GUEST=1`.                                                                                                                                                                                                                                                                                   |
| Path                       | capability allow -> artifact resolver selects Linux guest shim -> VZ launch contract includes shim deployment and broker bridge -> runner validates and shares artifact directory plus VSOCK broker bridge -> guest-init creates private provider shim directory and guest-local broker endpoint -> command starts with updated `PATH` and `FIRMA_BROKER_ADDR`. |
| Validation/trust crossings | Backend mode selection, private artifact lookup, contract custody/validation, virtiofs share planning, VSOCK broker bridge validation, guest-init mount/copy/env mutation.                                                                                                                                                                                      |
| Success outcome            | Guest provider lookup through `PATH` executes a guest-architecture shim that can reach only the redaction-only broker bridge.                                                                                                                                                                                                                                   |
| Failure path               | Missing artifact, unsupported target, invalid contract, absent broker bridge, or failed shim directory materialization exits before command spawn.                                                                                                                                                                                                              |
| Evidence                   | `macos_vz.rs:367`, `firma-vz-runner/src/contract/mod.rs:86`, `firma-vz-guest-init/src/linux/mount.rs:112`, `firma-vz-guest-init/src/linux/command.rs:81`.                                                                                                                                                                                                       |

| Field                      | Content                                                                                                                                                                     |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Trace ID                   | `TRACE-INSTALLER-PRIVATE`                                                                                                                                                   |
| State                      | Proposed                                                                                                                                                                    |
| Entry and stimulus         | `install.sh` or `install.ps1` installs a release archive containing `firma` and private shim artifacts.                                                                     |
| Path                       | installer downloads/checksums archive -> extracts `firma` -> copies private implementation artifacts outside user PATH or embeds no separate files -> reports only `firma`. |
| Validation/trust crossings | Release archive integrity check and install-dir PATH behavior.                                                                                                              |
| Success outcome            | `firma --version` and `firma help config` work; `firma-secret-shim` is not advertised or installed as a user command.                                                       |
| Failure path               | Missing required private artifacts fails only when `firma run` needs CLI shims, not during basic CLI install.                                                               |
| Evidence                   | `install.sh:304`, `install.ps1:212`, `.github/workflows/installer-smoke.yml:39`, `.github/workflows/installer-smoke.yml:85`.                                                |

### Trust analysis

- Actors: host `firma run`, host broker/gateway, sidecar, backend runner, guest-init, guest command, configured provider CLI.
- Protected assets: vault credential environment variables, plaintext `SecretStore`, host runtime control-plane directory, policy/capability material.
- Trust transitions: host config to launch plan, launch plan to backend contract, runner contract validation to VM shares, guest-init validation to guest filesystem mutation, shim to broker protocol.
- Abuse paths to block: backend accepts CLI providers without mediation; guest invokes wrong-architecture shim and falls back to real provider; contract serializes secrets; installer exposes shim as a supported command; guest can access plaintext gateway instead of redaction-only broker; guest shim cannot reach broker and implementer compensates by exposing host runtime state.

### Proof obligations

| Field                | Content                                                                                                                                                   |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Invariant            | `INV-001`                                                                                                                                                 |
| ID                   | `PO-001`                                                                                                                                                  |
| Kind                 | Runtime / Trust                                                                                                                                           |
| Owner/proof boundary | `firma-run::runtime::secret_shims` plus backend launch implementation                                                                                     |
| Suite/boundary       | `firma-run` unit/integration, VZ runner contract tests, guest-init tests                                                                                  |
| Stimulus             | CLI provider profile on bwrap, VZ guest, VZ compatibility, WSL2                                                                                           |
| Observable effects   | accept supported modes; reject unsupported modes; command never spawns on missing materialization, missing broker bridge, or invalid guest shim directory |
| Status               | Planned                                                                                                                                                   |

| Field                | Content                                                                                                                                        |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Invariant            | `INV-002`                                                                                                                                      |
| ID                   | `PO-002`                                                                                                                                       |
| Kind                 | Type / Runtime / Compatibility                                                                                                                 |
| Owner/proof boundary | backend capability and artifact resolver                                                                                                       |
| Suite/boundary       | `firma-run` resolver tests, VZ contract fixture tests, installer smoke CI                                                                      |
| Stimulus             | host macOS/aarch64 selecting Linux guest artifacts; bwrap selecting host Linux artifacts                                                       |
| Observable effects   | selected path is paired with expected `ShimTarget`; missing mismatched target fails closed; private artifacts are not exposed as user commands |
| Status               | Planned                                                                                                                                        |

| Field                | Content                                                                                                                                                           |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Invariant            | `INV-003`                                                                                                                                                         |
| ID                   | `PO-003`                                                                                                                                                          |
| Kind                 | Trust                                                                                                                                                             |
| Owner/proof boundary | `SecretServices`, env builder, VZ contract sanitizers                                                                                                             |
| Suite/boundary       | existing secret service tests plus new contract/env and VZ broker bridge tests                                                                                    |
| Stimulus             | provider credential vars in inherited env and VZ guest launch with CLI providers                                                                                  |
| Observable effects   | credential vars absent from launch env and serialized contract; gateway stays outside guest-visible runtime; guest receives only a redaction-only broker endpoint |
| Status               | Existing for bwrap gateway placement, planned for VZ contract and broker bridge extension                                                                         |
