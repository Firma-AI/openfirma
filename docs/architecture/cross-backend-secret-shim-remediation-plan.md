# Cross-Backend Secret Shim Remediation Plan

## Artifact metadata

- Status: Accepted
- Durable locator: `docs/architecture/cross-backend-secret-shim-remediation-plan.md`
- Repository revision researched: `67596405`
- Task or requirement source: Production-readiness findings requested for remediation, 2026-09-04
- Supersedes: The implementation details of `docs/architecture/cross-backend-secret-shim-plan.md`; its goals and invariants remain authoritative.

## Goal and acceptance outcomes

- Goal: Make the shipped bwrap and macOS VZ CLI secret-provider paths satisfy the existing mediation, guest-architecture, and host-only plaintext invariants.
- Observable acceptance outcomes: An installed Linux release locates and executes its private shim; a VZ guest with CLI providers receives an executable guest-architecture shim and reaches the host broker through a validated loopback-to-VSOCK bridge; VZ launches without CLI providers carry no shim contract; malformed provider names, missing artifacts, port conflicts, and unavailable bridges fail before command spawn.
- Observable acceptance outcomes: `firma-run`, `firma-vz-runner`, and guest-init agree on contract version 2, and installer smoke coverage proves the private target-qualified artifact layout without exposing the shim as a user command.

## Scope

- In scope: All eight findings reported against `6b78e4b9..67596405`, including contract compatibility, Linux lookup, release acquisition, VZ staging, VSOCK broker forwarding, architecture selection, provider-name validation, read-only share behavior, tests, and user documentation.
- Out of scope: Firecracker and WSL2 shim support, direct guest VSOCK support in `firma-secret-provider`, and changing the broker wire protocol.
- Assumptions: cargo-dist continues to publish a Linux-musl archive for each supported macOS architecture.
- Open decisions: None. If release evidence disproves the Linux archive naming assumption, implementation stops and this plan is amended rather than shipping an unverified layout.
- Cohesion and split assessment: The fixes form one atomic trust-boundary repair because advertising VZ support before artifact and transport completion recreates the current invalid state.
- Deferred child plans: Not applicable.

## Routing

- Mode: Full
- Trigger evidence: The work crosses the secret broker boundary, the VZ launch contract, guest root filesystem mutation, release packaging, and fail-closed startup.
- Higher-mode triggers checked: Security boundary, stable operational contract, lifecycle ordering, and multiple crates all apply.
- Downgrade evidence and reason: Not applicable.

## Current behavior and problem

- Owners and entry points: `firma-run::runtime::secret_shims` resolves and stages artifacts; `VzGuestLaunchContract` serializes launch state; `firma-vz-runner` validates and installs host VSOCK listeners; guest-init creates guest-local services and provider entries; installers establish the private release layout.
- Current success and failure outcomes: The implementation passes component tests but installed bwrap lookup disagrees with installer layout, every VZ contract uses the obsolete version, VZ never stages its located artifact or broker bridge, provider names are unsafe filesystem components, and guest-init mutates a read-only share.
- Evidence: `crates/firma-run/src/backend/mod.rs:63`, `crates/firma-run/src/backend/macos_vz.rs:25`, `crates/firma-run/src/runtime/secret_shims.rs:290`, `crates/firma-vz-runner/src/runner/vz/transport.rs:8`, `crates/firma-vz-guest-init/src/linux/mod.rs:140`, `install.sh:326`.

## Key decisions and tradeoffs

### `DEC-R01`: Use one target-qualified private artifact layout

- Choice: Both bwrap and VZ resolve `libexec/openfirma/secret-shims/<linux-musl-target>/firma-secret-shim`; bwrap may retain the sibling fallback for development, while isolated guests require the private target-qualified artifact and stage it into the run directory. Every selected artifact, including the development fallback, must pass complete ELF identity validation.
- Rationale and evidence: Installed Linux releases already create a target-qualified directory, while accepting a sibling on macOS could select a Darwin executable for a Linux guest.
- Consequences and rejected alternatives: Reject relying on `std::env::consts::ARCH` as a target triple and reject guest-side artifact mutation. The resolver validates file type, executable mode, ELF class, and machine architecture before launch.

### `DEC-R02`: Acquire the VZ guest artifact from existing Linux release output

- Choice: On macOS, `install.sh` downloads and checksum-verifies the matching Linux-musl release archive, extracts only `firma-secret-shim`, and stores it under the private target-qualified directory. Linux uses the shim already present in its primary archive.
- Rationale and evidence: cargo-dist builds host-target package binaries per target; the existing release matrix already emits the required Linux-musl archives.
- Consequences and rejected alternatives: Reject relabeling the Darwin shim and reject runtime compilation. This adds one install-time release download on macOS but no user-facing command.

### `DEC-R03`: Bridge the broker through a guest-local TCP endpoint

- Choice: The host contract carries the owner-only Unix broker socket path and distinct broker VSOCK port. The runner installs a VSOCK listener forwarding byte-for-byte to that Unix socket. Guest-init binds a loopback TCP listener before command spawn, forwards each connection to host CID 2 over VSOCK, and injects its `tcp://` address for the unchanged `BrokerClient`.
- Rationale and evidence: Guest-init already owns loopback-to-VSOCK services, while `firma-secret-provider` intentionally owns only portable TCP and Unix endpoints.
- Consequences and rejected alternatives: Reject adding Linux-only VSOCK to the shared broker endpoint model and reject sharing the host Unix socket through virtiofs. The broker bridge carries only already-redacted broker responses, never the plaintext gateway.

### `DEC-R04`: Make shim deployment explicit and conditional

- Choice: `secret_shims::prepare` serializes provider names as JSON, stages the selected artifact with executable permissions, and sets internal launch metadata only for non-empty CLI providers. Contract production consumes that metadata, emits schema version 2, and otherwise omits `secret_shims`.
- Rationale and evidence: Backend capability alone does not prove that a launch requested CLI mediation, and comma-delimited environment transport does not preserve names.
- Consequences and rejected alternatives: Reject unconditional optional sections and discarded resolver output. Internal metadata is removed from the guest command environment.

### `DEC-R05`: Reuse the canonical portable binary-name invariant

- Choice: `CliIntegrationSpec` validates `binary_name` with the existing broker `BinaryName` owner; runner and guest contract boundaries defensively reject names that are not one portable path component.
- Rationale and evidence: The same string becomes a broker selector and a guest symlink name, so accepting separators or traversal admits filesystem escape before the broker's later validation.
- Consequences and rejected alternatives: Existing invalid custom configuration becomes a startup error. No compatibility shim is retained because preserving it would preserve the filesystem escape.

### `DEC-R06`: Keep VZ control state outside guest-writable shares

- Choice: VZ broker sockets and staged shim artifacts live beneath the run-scoped control-plane root, not `SandboxHandle::runtime_dir`. Only the staged artifact directory is exposed through its dedicated read-only share. Before VM creation, canonical path validation rejects any configured or implicit writable share whose source contains or aliases either sensitive path. The writable runtime share remains limited to launch/result exchange that trusted guest-init consumes before the untrusted command starts.
- Rationale and evidence: VZ exposes the general runtime directory read-write, so placing broker endpoints or validated executable bytes beneath it lets the guest replace host authority or invalidate artifact validation.
- Consequences and rejected alternatives: Reject aliasing a sensitive path through both read-write and read-only shares. Bwrap retains its sandbox-visible redaction-only broker socket because that backend has no VSOCK bridge.

### `DEC-R07`: Negotiate independently supplied VZ components

- Choice: The runner exposes a hidden machine-readable supported-contract-version query. `firma-run` requires version 2 before writing or launching a contract, and guest-init accepts only version 2. The guest artifact builder records contract version, target, and checksums for the kernel, initrd, rootfs, and matching secret shim in `manifest.txt`; `firma-run` parses the manifest first, derives the guest target from it, requires all configured bundle paths to be siblings of that manifest, and validates every checksum before launch.
- Rationale and evidence: Runner and guest images are configured independently from `firma`, so source-level atomicity does not imply deployable compatibility.
- Consequences and rejected alternatives: Older runners and guest bundles fail during preflight with rebuild or upgrade guidance instead of at VM boot. Packaging the experimental runner and complete guest bundle with cargo-dist remains outside this remediation.

### `DEC-R08`: Prove broker readiness and own bridge shutdown

- Choice: Guest-init starts its loopback broker proxy, then retries a bounded protocol probe through guest TCP, VSOCK, and the intended host Unix broker until a fixed deadline before spawning the command. The runner bridge owns accepted connections, reaps completed connections during normal operation, and shuts descriptors down and joins remaining forwarding workers on VM exit or startup failure.
- Rationale and evidence: Binding either endpoint proves only local readiness, and detached forwarding threads can outlive the VM and run-scoped broker.
- Consequences and rejected alternatives: Reject lazy first-use-only connection and detached broker forwarding. The probe uses a reserved unconfigured binary name and requires the broker's normal rejected response, proving the protocol endpoint without executing a provider.

### `DEC-R09`: Complete the repository-owned Homebrew path

- Choice: Before invoking Homebrew, `install.sh` checksum-fetches and atomically installs the matching Linux guest shim under the prefix-stable, version-qualified `$(brew --prefix)/var/openfirma/secret-shims/<version>/<target>/` resource path. Homebrew then exclusively owns keg/package mutation, with no fallible installer validation afterward. Installer smoke covers this branch with a controlled Brew fixture. Direct formula installation remains documented as CLI-only until the external tap packages the resource itself.
- Rationale and evidence: The repository cannot atomically edit the separately published tap, but it owns the advertised curl installer and can make that default path complete.
- Consequences and rejected alternatives: Reject silently claiming raw `brew install` provides VZ CLI mediation and reject copying binaries between versioned kegs as rollback. A later release-packaging change may move the checksum-pinned resource into the formula.

## Architecture and invariant ownership

- Architecture shape: Profile resolution produces validated provider basenames. Runtime resolution returns a target-paired artifact, stages it outside guest-writable state, and emits internal launch metadata. VZ preflight checks runner and guest-manifest compatibility. Contract validation creates a VM plan containing optional artifact-share and broker-bridge plans. The runner installs both Sidecar and supervised broker VSOCK listeners. Guest-init binds all loopback services, proves the complete broker path, and materializes symlinks only within its private directory before command execution.

### `INV-R01`: Every enabled CLI provider reaches a ready broker through an executable matching shim

- Semantic predicate: Before command spawn, every provider name is a safe basename linked to a validated, executable artifact for the manifest-declared guest architecture, and a bounded probe has traversed the complete guest TCP to VSOCK to host Unix broker path.
- Primary owner: `firma-run::runtime::secret_shims`, with runner and guest-init boundary proofs.
- Detailed proof: `PO-R01` and `PO-R02`.

### `INV-R02`: Shim metadata is absent when CLI mediation is absent

- Semantic predicate: Profiles with no CLI providers, including empty and HTTP-only profiles, do not stage artifacts, allocate broker VSOCK metadata, add shim shares, or alter guest `PATH`.
- Primary owner: `firma-run::runtime::secret_shims` and `VzGuestLaunchContract`.
- Detailed proof: `PO-R03`.

### `INV-R03`: Guest filesystem mutation cannot escape the private shim directory

- Semantic predicate: Every provider name is a validated portable basename before guest-init joins it to the private directory; guest-init never chmods or writes the read-only artifact share.
- Primary owner: `CliIntegrationSpec` validation, defended by runner and guest-init contract validation.
- Detailed proof: `PO-R04`.

### `INV-R04`: VZ host capabilities and workers remain run-scoped

- Semantic predicate: No guest-writable path aliases the broker socket or staged shim, and dropping the VZ bridge closes listeners and active connections and joins all broker-forwarding workers before host secret services can be dropped.
- Primary owner: VZ runtime layout and runner broker-bridge handle.
- Detailed proof: `PO-R05`.

- Compatibility, migration, and failure semantics: `DEC-R01` preserves bwrap development fallback while repairing release lookup. Contract version 2 changes atomically across all producers and consumers. Invalid legacy custom binary names fail closed with a configuration error.
- Durable documentation owner: `docs-site/src/content/docs/guides/secret-gateway.md` and installer smoke workflow.

## Implementation slices

### Slice 1: Validate and deliver target-correct artifacts

- Production, types, tests, and docs/config: Add canonical binary-name validation, manifest-authoritative `ShimTarget` selection, executable/ELF artifact validation, host-only VZ staging, conditional JSON metadata, Linux/macOS installer acquisition including the Brew branch, and private-layout smoke assertions.
- Affected decisions and traces: `DEC-R01`, `DEC-R02`, `DEC-R04`, `DEC-R05`, `DEC-R06`, `DEC-R07`, `DEC-R09`, `TRACE-R-BWRAP`, `TRACE-R-INSTALL`.
- Proof obligations: `INV-R01`, `INV-R02`, `INV-R03`, `INV-R04`.
- Focused verification: `firma-secret-provider` config integration tests, `firma-run` secret-shim and VZ contract tests, runner-version and guest-manifest mismatch tests, installer lint/smoke logic including controlled Homebrew, and target-layout fixtures for x86_64 and aarch64.
- Dependencies: None.
- Intentionally unsupported: VZ command execution until Slice 2 completes; the branch must not ship between slices.

### Slice 2: Complete the VZ broker transport and contract

- Production, types, tests, and docs/config: Align contract version 2; add host broker socket, guest loopback endpoint, and collision validation; carry broker plans through `Contract` and `VmPlan`; install a supervised host VSOCK-to-Unix bridge; bind and probe the guest TCP-to-VSOCK bridge before materialization; remove guest chmod; update support documentation.
- Affected decisions and traces: `DEC-R03`, `DEC-R04`, `DEC-R06`, `DEC-R07`, `DEC-R08`, `TRACE-R-VZ`.
- Proof obligations: `INV-R01`, `INV-R02`, `INV-R03`, `INV-R04`.
- Focused verification: Runner contract and transport tests, bidirectional byte-forwarding and bounded-shutdown tests, guest network-plan, readiness, and forwarding tests, generated-contract acceptance tests, and all affected crate suites.
- Dependencies: Slice 1.
- Intentionally unsupported: Direct `vsock://` broker endpoints and non-VZ isolated guests.

## Risks and gaps

- Existing risks: macOS Virtualization.framework runtime behavior cannot be exercised on Linux CI; release archive composition is generated by cargo-dist; direct installation from the external Homebrew formula remains unable to carry the guest resource in this repository.
- Planned mitigations: Keep transport byte-forwarding platform-independent below the VZ callback, test all plans, readiness, custody, and bounded forwarding shutdown with socket pairs, assert release asset names/layout in installer tests, document raw Homebrew's limit, and retain fail-before-command behavior for missing prerequisites.
- Explicit evidence gaps: A live VZ launch remains a macOS CI/manual proof boundary.
- Least-confident decisions: Fetching the existing Linux archive during macOS installation adds latency but avoids an unproven cargo-dist archive-merging customization.

## Plan-review findings and dispositions

```yaml
id: PLAN-001
severity: critical
category: trust-boundary
classification: confirmed conflict
claim: The proposed VZ bridge leaves host broker custody and staged shim integrity reachable through the guest-writable runtime share.
evidence:
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:43
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:55
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:73-77
  - crates/firma-run/src/runtime/secret_shims.rs:109-112
  - crates/firma-run/src/backend/macos_vz.rs:440
  - crates/firma-vz-runner/src/vm/plan.rs:70-74
  - crates/firma-vz-runner/src/vm/plan.rs:89-100
reachability: A VZ run places the broker socket and proposed staged shim beneath handle.runtime_dir; VmPlan exposes that whole directory read-write as the runtime virtiofs share. The untrusted guest can therefore mutate the same host paths through /firma-shares/runtime even if a second read-only share aliases the shim. In particular, replacing broker.sock with a symlink before a later bridge connection can redirect the runner's same-user Unix connection to another host socket.
invariant_or_boundary: INV-R01 and INV-R03; host-only broker authority and guest-to-host VSOCK boundary.
impact: The guest can deny mediation, invalidate the selected executable after validation, or potentially turn the broker VSOCK port into access to an unintended same-user host Unix service.
correction: Keep the broker socket and immutable staged artifact outside every guest-writable share. Split host-only control state from a narrowly scoped guest exchange directory, make the general runtime share read-only, and provide a separate bounded writable result channel if required. Add a negative proof that guest-visible writable paths cannot alias or replace the broker endpoint or shim inode.
confidence: high
unverified_assumptions: VZ virtiofs permits unlink, symlink, or content mutation through the writable runtime alias as normal shared-directory semantics indicate.
disposition:
  status: accepted
  rationale: VZ broker and artifact state move to the existing host-only control-plane root; only the artifact receives a dedicated read-only share. The writable exchange directory contains neither capability.
  incorporated_at: DEC-R06, INV-R04, Slice 1
  decided_by: planner
```

```yaml
id: PLAN-002
severity: high
category: compatibility
classification: confirmed conflict
claim: Source-level agreement on contract version 2 cannot be deployed atomically through the current release architecture.
evidence:
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:15
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:93
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:107-113
  - dist-workspace.toml:16
  - crates/firma-run/src/backend/macos_vz.rs:21-25
  - crates/firma-run/src/backend/macos_vz.rs:356-382
  - crates/firma-vz-runner/src/contract/mod.rs:24
  - crates/firma-vz-guest-init/src/linux/contract.rs:516-520
  - scripts/macos-vz/build-guest-artifacts.sh:465-472
  - docs-site/src/content/docs/guides/firma-run.md:85-97
reachability: cargo-dist publishes only the firma package, while operators supply firma-vz-runner, kernel, initrd, and rootfs independently through environment paths. Installing a new firma can therefore pair its v2 producer with an older runner or guest image, and updating repository sources does not make those consumers atomic.
invariant_or_boundary: VZ launch contract compatibility boundary between firma-run, firma-vz-runner, and guest-init.
impact: Upgrades can fail before launch or, if compatibility remains permissive, let components assign different semantics to the optional secret_shims section.
correction: Choose and document a deployable compatibility strategy: package and version-lock the runner and guest bundle with firma, or introduce explicit capability/version negotiation and a migration window. Test supported mixed-version combinations and reject unsupported combinations before VM boot.
confidence: high
unverified_assumptions: No external distribution mechanism outside revision 67596405 already guarantees synchronized runner and guest-image installation.
disposition:
  status: accepted
  rationale: Runner capability query and guest manifest validation reject unsupported independently supplied components during preflight.
  incorporated_at: DEC-R07, Slice 1
  decided_by: planner
```

```yaml
id: PLAN-003
severity: high
category: release-packaging
classification: confirmed conflict
claim: DEC-R02 does not cover the default macOS installation path, which exits through Homebrew before install.sh downloads the Linux shim artifact.
evidence:
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:47-51
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:98-105
  - install.sh:482-490
  - install.sh:509-517
  - dist-workspace.toml:16
  - dist-workspace.toml:36-40
  - .github/workflows/installer-smoke.yml:27-39
reachability: On a macOS host with Homebrew, install.sh runs brew install and returns before tarball acquisition. The generated Homebrew publication is based on the target-local firma package and the plan provides no formula resource or post-install step for the matching Linux-musl shim. Existing smoke coverage explicitly disables Homebrew.
invariant_or_boundary: DEC-R01, DEC-R02, and INV-R01; release-to-runtime artifact availability boundary.
impact: The dominant supported macOS installer can successfully install firma while leaving every VZ CLI-provider launch unable to locate a guest shim.
correction: Include the Homebrew formula/tap contract in scope. Either package the target-qualified Linux shim as a checksum-pinned formula resource or make the installer select a complete non-Brew bundle when VZ support is claimed. Add smoke coverage for both Homebrew architectures and assert the private artifact's target, checksum, mode, and non-PATH placement.
confidence: high
unverified_assumptions: The external tap has no unpublished customization that installs Linux guest artifacts.
disposition:
  status: accepted
  rationale: The repository-owned installer completes the Brew path with the verified Linux resource and documents raw formula installation as CLI-only until the external tap is updated.
  incorporated_at: DEC-R09, Slice 1
  decided_by: planner
```

```yaml
id: PLAN-004
severity: high
category: lifecycle
classification: confirmed conflict
claim: Binding a guest-local TCP listener does not prove that the complete TCP-to-VSOCK-to-Unix broker path is ready before command spawn.
evidence:
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:14
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:55
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:77
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:109-112
  - crates/firma-vz-runner/src/runner/vz/lifecycle.rs:44-58
  - crates/firma-vz-guest-init/src/linux/mod.rs:103-110
  - crates/firma-vz-guest-init/src/linux/network.rs:424-439
reachability: VZ listeners are installed only after the asynchronous VM-start callback. Guest-init can bind its loopback listener and immediately spawn the command, while the first VSOCK connection and host Unix connection are deferred until a client request.
invariant_or_boundary: INV-R01; cross-host/guest startup ordering and broker availability boundary.
impact: A missing, late, or incorrectly installed host bridge passes startup and surfaces only as a shim failure after the command has started, contradicting the acceptance outcome and fail-before-spawn requirement.
correction: Define an explicit readiness handshake that traverses the actual guest TCP, VSOCK listener, and intended Unix broker endpoint before command execution. Specify timeout, negative response semantics, and ownership of the synchronization channel. Add a real macOS VZ proof or retain VZ support as non-release until that terminal predicate is exercised.
confidence: high
unverified_assumptions: Apple VZ does not expose a pre-boot listener-ready primitive sufficient to prove guest reachability without a guest handshake.
disposition:
  status: accepted
  rationale: Guest-init performs a bounded reserved-name broker protocol probe through the complete path before command spawn.
  incorporated_at: DEC-R08, INV-R01, Slice 2
  decided_by: planner
```

```yaml
id: PLAN-005
severity: high
category: platform-architecture
classification: design risk
claim: The plan assumes host and guest architecture equality without defining the production authority that selects and verifies that architecture.
evidence:
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:21
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:45
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:100-103
  - crates/firma-run/src/backend/mod.rs:63-81
  - crates/firma-run/src/backend/macos_vz.rs:315-328
  - scripts/macos-vz/build-guest-artifacts.sh:51-77
  - scripts/macos-vz/build-guest-artifacts.sh:443-470
reachability: The guest builder permits RUST_TARGET to differ from uname, and firma-run receives opaque kernel/initrd/rootfs paths. A process target, hardware architecture, installer target, and supplied guest bundle can therefore disagree, including under Rosetta or manually supplied artifacts. Validating only the shim's ELF machine proves consistency with the selected label, not with the actual guest bundle.
invariant_or_boundary: INV-R01; artifact-to-guest execution architecture boundary.
impact: The resolver can select and successfully validate the wrong Linux shim, causing a late guest exec or VM boot failure instead of deterministic pre-launch rejection.
correction: Establish one authoritative guest-bundle architecture value, preferably from a signed/checksummed guest artifact manifest, and validate the runner architecture, guest-init/rootfs architecture, and shim ELF machine against it. Include native Intel, native Apple Silicon, Rosetta, overridden RUST_TARGET, and mismatched-bundle controls.
confidence: high
unverified_assumptions: Apple VZ remains native-architecture-only for these Linux guests and no existing artifact manifest omitted from the cited paths supplies this value.
disposition:
  status: accepted
  rationale: The existing generated manifest becomes mandatory and authoritative for contract version, guest target, and initrd integrity; shim ELF validation uses that target rather than process architecture alone.
  incorporated_at: DEC-R07, INV-R01, Slice 1
  decided_by: planner
```

```yaml
id: PLAN-006
severity: medium
category: proof-obligation
classification: design risk
claim: The plan does not assign terminal ownership or shutdown behavior to accepted broker bridge connections.
evidence:
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:107-112
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:118-120
  - docs/architecture/cross-backend-secret-shim-remediation-plan.md:152-157
  - crates/firma-vz-runner/src/runner/vz/sidecar_bridge.rs:127-141
  - crates/firma-vz-runner/src/runner/vz/sidecar_bridge.rs:218-246
  - crates/firma-vz-runner/src/runner/vz/lifecycle.rs:50-86
reachability: The existing VZ bridge removes only the listener on drop and detaches both forwarding threads for every accepted connection. The remediation plan says to add another byte-forwarding bridge and socket-pair tests but does not state whether active forwarding tasks are cancelled, drained, joined, or allowed to outlive VM stop and SecretServices teardown.
invariant_or_boundary: Host broker capability lifecycle and run-scoped secret-service ownership.
impact: Active broker requests or host Unix connections may survive listener removal, race run teardown, retain resources, or continue a provider operation after the VM has stopped.
correction: Specify a supervised bridge handle that owns listeners and every accepted connection, with bounded cancellation/drain/join semantics on VM startup failure, normal stop, forced stop, and broker loss. Extend PO-R01 with assertions that no live VSOCK, Unix stream, forwarding worker, or provider child remains after the runner and SecretServices guards drop.
confidence: medium
unverified_assumptions: The new bridge would otherwise follow the existing detached-thread implementation pattern.
disposition:
  status: accepted
  rationale: The broker bridge owns accepted descriptors and workers, shuts descriptors down, and joins workers during bridge drop before the runner exits.
  incorporated_at: DEC-R08, INV-R04, Slice 2
  decided_by: planner
```

## Final verification

- Focused checks: Affected crate tests and installer linters after each slice.
- Workspace checks: `just fmt`, `just lint`, `just test`, then `just check` when platform tooling is available.
- Post-implementation independent review: Required via `adversarial-review` against the final diff.

## Post-implementation review amendments

The first post-implementation adversarial review reported the following findings. The user accepted all corrections on 2026-09-04; they amend the decisions and proof obligations above without changing the goal or scope.

- `IMPL-001` (high, trust boundary): Reject canonical overlap between every writable guest share and the broker socket or staged shim, including implicit working-directory and `/tmp` ancestors. Incorporated into `DEC-R06`, `INV-R04`, and `PO-R05`.
- `IMPL-002` (high, lifecycle): Reap completed broker bridge connections during normal operation so descriptors and worker handles do not accumulate. Incorporated into `DEC-R08`, `INV-R04`, and `PO-R05`.
- `IMPL-003` (high, compatibility): Make the guest manifest authoritative for target selection and verify the coherent kernel, initrd, rootfs, and shim bundle rather than only the initrd. Incorporated into `DEC-R07`, `INV-R01`, `PO-R01`, and `PO-R02`.
- `IMPL-004` (medium, startup ordering): Retry the complete broker protocol readiness probe until one bounded deadline to tolerate listener-installation races. Incorporated into `DEC-R08` and `PO-R01`.
- `IMPL-005` (medium, artifact validation): Validate ELF class, endianness, executable type, header size, and machine for private and sibling shim artifacts. Incorporated into `DEC-R01` and `PO-R02`.
- `IMPL-006` (medium, compatibility): Require v2 at the guest-init boundary and remove obsolete v1 fixtures. Incorporated into `DEC-R07` and `PO-R01`.
- `IMPL-007` (medium, proof obligation): Add a production-generated vertical contract fixture covering CLI, HTTP-only, empty, invalid-name, custody, and consumer acceptance paths. Incorporated into `PO-R01`, `PO-R03`, `PO-R04`, and `PO-R05`.

The second post-implementation adversarial review reported four remaining findings. The user accepted all corrections on 2026-09-04.

- `IMPL-008` (high, compatibility): Record the guest shim digest in the bundle manifest and require the selected private shim to match it before staging. Incorporated into `DEC-R07`, `INV-R01`, `PO-R01`, and `PO-R02`.
- `IMPL-009` (medium, installer compatibility): Detect releases that predate the shim before mutating the installation and preserve their explicitly requested CLI-only installation behavior. Incorporated into `DEC-R02`, `DEC-R09`, and `TRACE-R-INSTALL`.
- `IMPL-010` (medium, proof obligation): Exercise empty and HTTP-only omission through production profile preparation rather than direct internal environment construction. Incorporated into `IMPL-007` and `PO-R03`.
- `IMPL-011` (low, validation ordering): Reserve the broker readiness probe identity at canonical provider configuration and runner contract boundaries so it fails before VM boot. Incorporated into `DEC-R05` and `PO-R04`.

The third post-implementation adversarial review reported three installer and diagnostic findings. The user accepted all corrections on 2026-09-04.

- `IMPL-012` (medium, installer transaction): Stage and validate complete CLI/shim replacements and preserve the previous pair if any destination update fails. Incorporated into `DEC-R02`, `DEC-R09`, and `TRACE-R-INSTALL`.
- `IMPL-013` (medium, installer versioning): Preserve the originally resolved GitHub release across a failed Homebrew attempt so tarball fallback still installs the documented latest version. Incorporated into `DEC-R09` and `TRACE-R-INSTALL`.
- `IMPL-014` (low, diagnostics): Report manifest digests as expected and computed artifact digests as actual, with an exact mismatch regression. Incorporated into `DEC-R07` and `PO-R01`.

The fourth post-implementation adversarial review reported two remaining lifecycle and installer findings. The user accepted both corrections on 2026-09-04.

- `IMPL-015` (medium, launch consistency): Resolve and validate one immutable VZ guest-bundle context and thread its target, digest, and artifact paths through shim staging and contract launch without re-reading mutable inputs. Incorporated into `DEC-R07`, `INV-R01`, and `PO-R01`.
- `IMPL-016` (medium, Homebrew transaction): Do not emulate Homebrew rollback by copying files between kegs. Complete every fallible external shim acquisition and destination preflight before invoking Brew, leaving no post-Brew step that can invalidate package state. Incorporated into `DEC-R09` and `TRACE-R-INSTALL`.

The final post-implementation review confirmed all technical findings closed and reported one documentation mismatch. The user accepted the correction on 2026-09-04.

- `IMPL-017` (low, documentation): Distinguish tarball `libexec` placement from the prefix-stable, version-qualified Homebrew resource path in the quickstart. Incorporated into the durable installation documentation.

## Technical evidence

### Semantic call traces

| Field          | `TRACE-R-BWRAP`                                                     | `TRACE-R-VZ`                                                                                    | `TRACE-R-INSTALL`                                                                      |
| -------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Entry          | Linux `firma run` with CLI provider                                 | macOS VZ guest run with CLI provider                                                            | Unix installer                                                                         |
| Path           | target resolver -> executable ELF shim -> bind mount -> Unix broker | staged ELF shim -> v2 contract -> VSOCK-to-Unix listener -> guest TCP-to-VSOCK listener -> shim | primary archive plus optional matching Linux archive -> target-qualified private store |
| Failure        | Missing or invalid artifact before launch                           | Any invalid contract, collision, bind, listener, or materialization failure before command      | Missing archive/checksum/shim aborts installation                                      |
| Proof boundary | `firma-run` integration                                             | runner and guest-init integration plus macOS smoke                                              | installer smoke and release artifact CI                                                |

### Constructibility attack

- `CW-R01`: A raw `String` provider name can contain `/`, `\\`, `:`, NUL, `.` or `..`; named fields do not prevent guest path escape. `CliIntegrationSpec::new` must invoke `BinaryName::new`, and contract consumers must repeat the portable-basename predicate because deserialized contracts bypass that constructor.
- `CW-R02`: Separate target and path arguments can pair an aarch64 target with an x86_64 artifact. Runtime resolution therefore returns one `ResolvedShimArtifact` containing both validated target and path, and staging consumes that pair.
- `CW-R03`: An optional broker port without an upstream path can compile yet cannot forward. The runner's `BrokerBridgePlan` constructor consumes both a non-zero, conflict-free port and an existing absolute Unix socket path before lifecycle installation.

### Proof obligations

| ID       | Invariant | Stimulus                                                     | Observable assertion                                                                               | Failure cases                                               |
| -------- | --------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `PO-R01` | `INV-R01` | Valid x86_64/aarch64 VZ shim contract                        | Runner and guest plans contain matching bridge and artifact data; byte forwarding is bidirectional | Missing socket, wrong ELF machine, unsupported target       |
| `PO-R02` | `INV-R01` | Installed bwrap layout                                       | Resolver selects `<target>/firma-secret-shim` and verifies executable ELF                          | Architecture-only directory, non-executable file            |
| `PO-R03` | `INV-R02` | Empty and HTTP-only VZ profiles                              | Generated contract omits `secret_shims`; VM plan has no shim share or broker bridge                | Empty provider metadata                                     |
| `PO-R04` | `INV-R03` | Custom provider names with traversal and platform separators | Config and deserialized contracts reject before filesystem mutation                                | Absolute path, `..`, slash, backslash, drive separator, NUL |
| `PO-R05` | `INV-R04` | VZ artifact, broker socket, and active bridge teardown       | Writable guest sources exclude sensitive paths; bridge descriptors close and workers join          | Writable alias, startup failure, normal and forced VM stop  |
