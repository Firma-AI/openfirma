---
title: macOS structural confinement strategy
description: macOS parity strategy, ESF coverage, residual caveats, and follow-up implementation milestones.
---

This page records the strategy decision for macOS `firma run` confinement. It chooses the primary path for moving macOS from proxy-only compatibility mode toward the same runtime invariants expected from Linux structural mode, without claiming that Endpoint Security Framework (ESF) can provide Linux-equivalent network confinement by itself.

## Decision

**Primary path:** prioritize cross-OS structural parity first: turn the macOS `vz` backend into a real guest-backed structural boundary where the wrapped process runs in a confined guest and the Sidecar bridge is the only usable egress route.

**Secondary path:** treat ESF-native work as targeted host hardening, supervision, and audit. ESF can be useful for process lifecycle controls, child-process visibility, file/config protection, and detecting or blocking selected host actions, but it is not the primary mechanism for sidecar-only egress or DNS confinement.

This keeps OpenFirma's claim language simple:

- macOS remains **proxy-only compatibility mode by default** until the structural path has hardware E2E evidence for every required invariant.
- ESF-only controls must not be described as structural network confinement.
- A future ESF component may strengthen macOS operations, but it does not by itself make `vz` equivalent to Linux `bwrap`.

## Decision Record Summary

| Question | Decision |
| -------- | -------- |
| Primary macOS confinement strategy | VZ guest-backed structural parity. |
| ESF-native strategy | Secondary host hardening and audit path, not a standalone parity model. |
| Current default claim | Proxy-only compatibility mode unless an experimental structural mode is explicitly enabled. |
| Claim graduation bar | Hardware E2E evidence for sidecar-only egress, DNS confinement, fail-closed startup/runtime, direct-bypass resistance, and interactive CLI/TUI usability. |
| Implementation boundary | `firma run` owns proof metadata, preflight, routing artifacts, launch contracts, and process supervision. The VZ runner owns Virtualization.framework lifecycle and in-guest enforcement. |

## Baseline Reality Check

Current macOS default behavior is compatibility mode. The backend is named `vz`, but the default implementation launches a host process through `sandbox-exec`, injects proxy environment variables, and starts a host-side proxy bridge. It reports `structural=false` and requires explicit non-structural opt-in before launch. That provides useful ergonomics, attribution, and some filesystem masking for supported profiles, but it does not remove the agent's ability to open direct sockets, use direct DNS, or spawn a child with a clean environment.

Two experimental structural paths now exist behind explicit environment gates. `FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1` selects the intermediate sandbox-exec network-deny mode. `FIRMA_RUN_VZ_GUEST=1` selects the stronger VZ guest runner contract path, which validates configured runner and guest image artifact paths and writes a deterministic launch contract under private runtime custody. The contract path does not by itself ship Apple Virtualization.framework lifecycle code; the configured runner must own guest boot, virtio networking, guest DNS, stdio/signal/exit plumbing, and route proof inside the VM.

There is also no direct seccomp-BPF-to-ESF translation. Linux seccomp filters operate at syscall decision points; ESF exposes a different event model oriented around endpoint security events. ESF has authorization and notification events for areas such as process execution, file access, and some IPC, and it requires the Endpoint Security entitlement. It should be evaluated as its own macOS-native control plane, not as a syscall parity layer.

## Capability Matrix

Coverage key:

- **Full target:** Can satisfy the invariant as the primary enforcement mechanism once implementation and test evidence exist.
- **Partial:** Can help, but needs another control to meet the invariant.
- **No:** Does not materially satisfy the invariant.

| Required invariant | Option A: VZ structural parity path | Option B: ESF-native selected controls | Residual caveat |
| ------------------ | ----------------------------------- | -------------------------------------- | --------------- |
| Sidecar-only egress | **Full target.** Put the agent inside a guest boundary where routing/firewall policy exposes only the guest-local proxy bridge and host Sidecar bridge. | **Partial at best.** ESF can supervise process launch and selected actions, but ESF alone is not a general network namespace or mandatory egress boundary. | Default macOS `vz` is proxy-only. The experimental `sandbox-exec` mode blocks external IP egress but allows all loopback; the VZ guest path must prove strict bridge-only egress. Option B would need Network Extension, packet filter, or another network control to approach this invariant. |
| DNS confinement | **Full target.** Provide a guest-local deterministic resolver and prevent fallback to host or public resolvers. | **No/Partial.** ESF may observe or restrict processes involved in resolver setup, but it is not a DNS confinement primitive. | Default macOS `vz` does not provide DNS confinement. The experimental mode confines DNS by denying non-loopback network access, not by replacing the system resolver. DNS must be tested as a bypass channel, including direct UDP and custom resolver configuration. |
| Fail-closed startup | **Full target.** Refuse to launch the guest command unless the sidecar bridge, proxy bridge, DNS stub, and guest network rules are installed and verified. | **Partial.** ESF client startup can fail closed for ESF-protected operations, but extension load/approval is an operational dependency outside the normal CLI fast path. | Both paths need explicit preflight state and typed errors. ESF adds user/MDM approval states that must be modeled separately. |
| Fail-closed runtime | **Full target.** Sidecar loss should make the only egress path stop returning successful network results, while preserving deterministic process teardown or error behavior. | **Partial.** ESF can deny future authorized events it controls, but cannot make arbitrary established network flows fail closed unless paired with a network filter. | Mid-session sidecar loss must have deterministic test cases. ESF-only cannot claim this for all network traffic. |
| Direct-bypass resistance | **Full target.** Proxy-env-unset children, raw sockets, non-HTTP protocols, and direct DNS should remain inside the guest dead end. | **Partial.** ESF can block or log selected child exec patterns and protect config, but in-process raw socket use by an already running allowed process is outside ESF-only parity claims. | Option B is useful for reducing accidental bypass and detecting suspicious behavior, not for replacing the structural boundary. |
| Interactive CLI/TUI usability | **Partial/Full target.** Needs VZ lifecycle work to preserve stdio, signals, exit codes, terminal resizing, and startup latency. | **Partial.** ESF runs out-of-process and can preserve CLI UX once installed, but installation and approval are not frictionless. | Option A has engineering complexity in guest lifecycle and terminal plumbing. Option B has deployment friction and may be unacceptable for quick local adoption. |
| Immutable execution envelope | **Full target.** Guest launch can bind the session ID, proxy endpoint, DNS endpoint, and capability seed before process start. | **Partial.** ESF can observe exec metadata and help detect drift, but cannot replace the `firma run` launch envelope. | Both paths should continue treating the Sidecar's execution envelope as the policy/audit source of truth. |
| No network on enforcement hot path | **Full target.** Local Sidecar still makes policy decisions; the guest boundary only forces traffic to reach it. | **Partial.** ESF decisions are local, but using ESF as an extra authorization layer creates a second local decision path that must not call the Authority. | ESF policy must be cached locally and deterministic if introduced. |

## Option A: VZ Structural Parity Path

Option A implements the macOS parity direction. The target end state is that the wrapped process runs inside a guest boundary, and the host exposes only the controlled bridge needed to reach the Sidecar. The guest gets deterministic DNS and no usable ambient network path.

Expected design shape:

- Replace the current host-process compatibility implementation with a real VZ-backed execution lifecycle rather than relying on host proxy environment variables.
- Start host-side Sidecar bridge and guest-local proxy/DNS endpoints before launching the command.
- Install guest routing/firewall policy so the bridge is the only successful outbound path.
- Fail closed if any required bridge, resolver, policy, or health proof is missing.
- Preserve `firma run` UX: stdin/stdout/stderr, terminal mode, signal forwarding, exit status, and log clarity.

Why this is the primary path:

- It matches the existing Linux mental model: the agent's ability to bypass the Sidecar is removed structurally.
- It lets macOS claim boundaries use the same language as Linux structural mode after evidence exists.
- It avoids turning ESF into a syscall compatibility layer it is not designed to be.
- It keeps policy enforcement centralized in the Sidecar instead of splitting policy between Sidecar and host extension logic.

Main costs:

- Guest image lifecycle, caching, upgrades, and compatibility testing.
- More complex stdio/signal/TTY plumbing than the current host process path.
- Network proof work: raw socket, direct DNS, child process, sidecar loss, and startup failure cases must all be automated on macOS.
- Performance and developer experience tuning, especially cold start.

## Option B: ESF-Native Selected Controls

Option B builds a macOS Endpoint Security system extension and uses ESF authorization/notification events for selected host controls. This is a valid hardening path, but not a structural egress parity path by itself.

Controls ESF can plausibly help with:

- Observe and optionally authorize process execution, including child processes spawned by an agent.
- Protect selected files, configuration, and runtime sockets from modification.
- Attach host-side audit to process lineage, executable identity, code-signing metadata, and file events.
- Deny known dangerous helper launches or unapproved shell escape patterns.
- Detect drift between the `firma run` execution envelope and host process behavior.

Controls ESF cannot solve alone for parity:

- It does not provide a Linux-style network namespace.
- It should not be treated as a general seccomp replacement.
- It does not by itself make DNS deterministic or prevent custom direct resolver use.
- It does not guarantee sidecar-only egress for arbitrary in-process network libraries.
- It does not fail closed for established network flows unless paired with a network confinement primitive.

ESF lifecycle impact:

- Requires Apple Developer Program signing and the `com.apple.developer.endpoint-security.client` entitlement.
- Ships as a system extension packaged in an app bundle and installed/updated through System Extensions.
- Requires user approval or MDM-managed approval in enterprise deployment.
- Adds versioning, upgrade, rollback, uninstall, crash recovery, and health-check states to the product.
- Adds a product-health dimension: `firma run` would need to distinguish extension not installed, installed but disabled, installed but not approved, approved but unhealthy, and policy bundle stale.
- CI needs macOS runners with signing material, entitlement handling, and integration tests that can exercise extension install/approval states. Most open CI runners cannot fully validate this path.

Market-standard use of ESF is closer to EDR/DLP host supervision than application sandbox networking. That makes it valuable for enterprise hardening and audit, but a risky foundation for the primary `firma run` structural confinement claim.

## Risk and Complexity Scoring

Scores use 1 = low and 5 = high. Higher implementation risk means more engineering uncertainty; higher operational burden means more deployment and support complexity.

| Dimension | Option A: VZ structural parity path | Option B: ESF-native selected controls | Decision impact |
| --------- | ----------------------------------- | -------------------------------------- | --------------- |
| Ability to satisfy sidecar-only egress | 5 | 2 | VZ is the only option here that can become the primary parity claim without adding a separate network-control product. |
| Ability to satisfy DNS confinement | 5 | 1 | DNS must be structurally contained in the guest; ESF can observe adjacent behavior but is not a resolver boundary. |
| Fail-closed model clarity | 4 | 2 | VZ failures are mostly inside the runtime launch path; ESF adds approval and extension-health states outside normal CLI control. |
| Direct-bypass resistance | 5 | 2 | VZ can remove ambient paths. ESF can reduce or audit some bypass attempts but cannot contain arbitrary in-process networking alone. |
| Interactive CLI/TUI implementation risk | 4 | 2 | VZ needs careful stdio, TTY, signal, and exit-code plumbing. ESF is less intrusive after installation. |
| Product operational burden | 3 | 5 | VZ needs image lifecycle and hardware testing. ESF needs entitlements, app packaging, user/MDM approval, system extension updates, and health reporting. |
| CI evidence burden | 4 | 5 | Both need macOS hardware. ESF additionally needs signing/approval-capable environments that normal CI often cannot provide. |
| Over-claiming risk | 2 | 5 | VZ claim boundaries map cleanly to Linux structural language after evidence. ESF is easy to overstate as a network boundary when it is not one. |

Recommendation from scoring: pursue Option A as the primary path, keep ESF as an explicitly separate hardening track, and do not make ESF a dependency for baseline macOS structural parity.

## Operational and Testing Implications

| Area | Option A: VZ structural parity path | Option B: ESF-native selected controls |
| ---- | ----------------------------------- | -------------------------------------- |
| Local development | Needs guest image/bootstrap tooling and VZ availability checks. | Needs signed system extension and local approval; awkward for casual contributors. |
| Enterprise deployment | Manage guest image version, resource usage, and update cadence. | Manage entitlement, Developer ID, system extension approval, MDM profiles, and extension health. |
| CI | Needs macOS E2E runners capable of VZ, plus raw bypass tests. | Needs signed artifacts and approval-capable macOS environments; many tests become manual or vendor-run. |
| Failure model | Mostly under `firma run` control: bridge, guest, DNS, route proof. | Split between CLI, system extension daemon, OS approval state, and ESF event delivery. |
| Performance | Cold-start and guest lifecycle are the main risks. | Runtime overhead depends on event subscriptions and decision latency; install friction is the main adoption risk. |
| Claim boundary | Can graduate to structural after macOS E2E evidence. | Must remain selected host hardening/audit unless paired with separate network confinement. |

## Current Implementation Status

| Area | Status | Notes |
| ---- | ------ | ----- |
| Proof metadata | Implemented | `NetworkConfinement` added to `EnforcementProof`; all backends updated. |
| Intermediate macOS structural mode | Experimental | `sandbox-exec` network-deny mode via `FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1`. It blocks external IP egress but still allows host loopback. |
| VZ guest runner contract | Experimental | `FIRMA_RUN_VZ_GUEST=1` validates runner/kernel/initrd/rootfs paths, checks runner executability, emits `macos_vz_guest` proof metadata, writes `vz-guest-launch.json` in a private contract directory with capability tokens excluded from the serialized env and spawns the configured runner. |
| Host DNS refusal stub | Implemented | `HostDnsStubHandle` wired into macOS structural routing paths and exposed to the VZ guest contract. |
| Unit coverage | Implemented | Focused tests cover proof types, sandbox profile generation, guest contract generation, DNS stub behavior, and routing setup. |
| macOS E2E schema | Written | `examples/firma-run/e2e/macos-structural-assertions.md` defines the hardware validation suite. |
| VZ guest runner implementation | Started | `firma-vz-runner` now accepts `--launch-contract`, validates the v1 contract fail-closed, and confirms the selected Rust Virtualization.framework binding exposes `VZLinuxBootLoader`. VM lifecycle, guest networking, and route proof remain unimplemented; normal execution still fails closed. |
| ESF hardening | Planned | Separate enterprise hardening and audit path. |

## Recommended Milestones

### Milestone 1: Baseline Proof and Claim Boundaries

- macOS `vz` marked non-structural in runtime proof logs by default.
- Decision page in docs; `llms.txt` explicit that ESF-only is not structural parity.
- macOS E2E assertion schema defined.
- `FIRMA_RUN_VZ_STRUCTURAL_NETWORK` gate added for opt-in experimental structural mode.

### Milestone 2: Intermediate Structural Mode

- `sandbox-exec` with `deny network-outbound` policy implemented in `VzBackend`.
- Host-side proxy bridge + DNS refusal stub started before the sandbox.
- `EnforcementProof { structural: true, network_confinement: macos_sandbox_network_deny }` emitted.
- All unit tests passing on Linux CI; E2E tests require macOS hardware.
- Activation: `FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1`.
- Residual caveat: the policy is loopback-scoped, not port-scoped, so other host loopback services remain reachable.

### Milestone 3: macOS E2E Evidence (next)

- Run MACOS-001 through MACOS-009 from `examples/firma-run/e2e/macos-structural-assertions.md` on macOS 12+ Apple Silicon and Intel.
- Include raw socket, proxy-env-unset, child process, direct DNS, policy deny, startup sidecar-down, and mid-session sidecar-loss cases.
- Keep the runtime claim as non-structural (default mode) until the suite is reliable on supported macOS versions.
- Keep the central known-limits table in [the sandbox boundary](../sandbox/) current as evidence changes.

### Milestone 4: VZ Guest Runner Contract

- Add `FIRMA_RUN_VZ_GUEST=1` mode with fail-closed validation for runner and guest image artifacts.
- Emit `EnforcementProof { structural: true, network_confinement: macos_vz_guest }` only when guest mode is selected.
- Write a versioned launch contract containing command, env, cwd, mounts, sidecar proxy URL, DNS stub address, attribution headers, and required invariants.
- Spawn the configured runner with `--launch-contract <path>` so existing process supervision preserves the `firma run` wait path.
- Keep claim language experimental until the runner and guest image prove every invariant on macOS hardware.

### Milestone 5: VZ Guest Runner Implementation

- Implement the Apple Virtualization.framework runner and sign/package it for macOS deployment.
- Guest lifecycle: command launch via virtio-serial stdio, signals, exit status, terminal resize.
- Guest-local proxy bridge and deterministic DNS stub inside the guest network namespace.
- Guest routing/firewall rules: bridge-only mandatory egress.
- Emit structural proof only in experimental mode with evidence fields for bridge, DNS, and route setup.
- Network bypass tests: raw socket, proxy-env-unset, child process, direct DNS from inside the guest.

### Milestone 6: ESF Hardening Spike

- Prototype a minimal ESF system extension outside the hot path.
- Test process lineage capture, exec authorization, runtime socket/config protection, and host-side audit correlation.
- Measure operational burden: entitlement approval, signing, install/update flow, MDM path, local dev workflow, and CI feasibility.
- Decide whether ESF becomes an enterprise add-on, not a requirement for baseline macOS structural mode.

### Milestone 7: Productionization

- Promote macOS `vz` structural mode only when E2E evidence supports every required invariant.
- Keep proxy-only compatibility available behind explicit opt-in for unsupported hosts.
- Add docs for install prerequisites, resource usage, failure modes, and claim boundaries.
- If ESF continues, ship it with separate status reporting and separate claims: host hardening/audit, not network structural parity.

## Follow-Up Implementation Cards

| Suggested card | Milestone | Status | Scope |
| -------------- | --------- | ------ | ----- |
| Structural proof metadata | Baseline proof | Done | `NetworkConfinement` on `EnforcementProof`; preflight logging. |
| Intermediate macOS network-deny mode | Intermediate structural mode | Done | `sandbox-exec` network-deny structural mode + DNS stub + routing wiring. |
| VZ guest runner contract | VZ contract | Done | Fail-closed artifact validation, private launch-contract JSON, `macos_vz_guest` proof, runner spawn path. |
| VZ runner implementation | VZ runner | Started | Apple Virtualization.framework guest lifecycle with stdio, TTY, signals, terminal resize, and exit code preservation. |
| Guest image and route proof | VZ runner | Planned | Guest image lifecycle, bridge-only route setup, DNS stub wiring, and machine-readable proof fields. |
| macOS structural E2E suite | Evidence | Planned | Hardware tests for cooperative HTTP, policy deny, direct TCP/UDP, direct DNS, proxy-env-unset children, sidecar startup failure, and mid-session sidecar loss. |
| macOS performance and UX pass | Productionization | Planned | Cold-start budget, image caching, TTY behavior, signal forwarding, exit status, and diagnostics. |
| ESF hardening spike | ESF hardening | Planned | Entitlement path, signed system extension prototype, process lineage audit, runtime socket/config protection, and selected authorization decisions. |
| ESF operational readiness | ESF hardening | Planned | MDM deployment, CI constraints, update/rollback, crash recovery, health reporting, and claim language. |
| Operator docs and known-limits table | Productionization | In progress | Strategy, sandbox, runtime guide, retrieval notes, and claim boundaries updated as implementation evidence changes. |

## Definition of Done Status

| Requirement | Status |
| ----------- | ------ |
| A single recommended macOS strategy is selected | Done: VZ guest-backed structural parity is the primary path. |
| ESF coverage and limits are documented | Done: ESF is positioned as selected host hardening/audit, not standalone network confinement. |
| Capability matrix is complete and reviewable | Done: required invariants are mapped across VZ and ESF with residual caveats. |
| Entitlement/system-extension lifecycle impact is documented | Done: signing, entitlement, approval, packaging, health, and CI implications are covered. |
| Operational and CI/testing implications are documented | Done: comparison matrix and risk scoring are included. |
| Follow-up implementation scope is clear and sequenced | Done: milestones and implementation-card suggestions are split by work stream. |
| Claim language boundaries are defined | Done: default macOS remains proxy-only; experimental modes require evidence before graduation; ESF-only must not be called structural confinement. |

## References

- [Apple Endpoint Security documentation](https://developer.apple.com/documentation/endpointsecurity)
- [Apple System Extensions documentation](https://developer.apple.com/documentation/SystemExtensions)
- [Apple System Extensions overview](https://developer.apple.com/system-extensions/)
