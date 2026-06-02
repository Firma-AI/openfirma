---
title: macOS structural confinement strategy
description: FIR-112 decision memo for macOS parity, ESF coverage, residual caveats, and follow-up implementation milestones.
---

This is the FIR-112 strategy decision for macOS `firma run` confinement. It chooses the primary path for moving macOS from proxy-only compatibility mode toward the same runtime invariants expected from Linux structural mode, without claiming that Endpoint Security Framework (ESF) can provide Linux-equivalent network confinement by itself.

## Decision

**Primary path:** prioritize the FIR-72 cross-OS structural parity path first: turn the macOS `vz` backend into a real guest-backed structural boundary where the wrapped process runs in a confined guest and the Sidecar bridge is the only usable egress route.

**Secondary path:** treat ESF-native work as targeted host hardening, supervision, and audit. ESF can be useful for process lifecycle controls, child-process visibility, file/config protection, and detecting or blocking selected host actions, but it is not the primary mechanism for sidecar-only egress or DNS confinement.

This keeps OpenFirma's claim language simple:

- macOS remains **proxy-only compatibility mode** until the VZ structural path has evidence for the FIR-72 acceptance cases.
- ESF-only controls must not be described as structural network confinement.
- A future ESF component may strengthen macOS operations, but it does not by itself make `vz` equivalent to Linux `bwrap`.

## Baseline Reality Check

Current macOS behavior is compatibility mode. The backend is named `vz`, but the implementation currently launches a host process through `sandbox-exec`, injects proxy environment variables, and starts a host-side proxy bridge. It reports `structural=false` and requires explicit non-structural opt-in before launch. That provides useful ergonomics, attribution, and some filesystem masking for supported profiles, but it does not remove the agent's ability to open direct sockets, use direct DNS, or spawn a child with a clean environment.

There is also no direct seccomp-BPF-to-ESF translation. Linux seccomp filters operate at syscall decision points; ESF exposes a different event model oriented around endpoint security events. ESF has authorization and notification events for areas such as process execution, file access, and some IPC, and it requires the Endpoint Security entitlement. It should be evaluated as its own macOS-native control plane, not as a syscall parity layer.

## Capability Matrix

Coverage key:

- **Full target:** Can satisfy the invariant as the primary enforcement mechanism once implementation and test evidence exist.
- **Partial:** Can help, but needs another control to meet the invariant.
- **No:** Does not materially satisfy the invariant.

| Required invariant | Option A: VZ structural parity path | Option B: ESF-native selected controls | Residual caveat |
| ------------------ | ----------------------------------- | -------------------------------------- | --------------- |
| Sidecar-only egress | **Full target.** Put the agent inside a guest boundary where routing/firewall policy exposes only the guest-local proxy bridge and host Sidecar bridge. | **Partial at best.** ESF can supervise process launch and selected actions, but ESF alone is not a general network namespace or mandatory egress boundary. | Current macOS `vz` is proxy-only. Option A must prove that raw TCP/UDP from the guest cannot reach ambient network paths. Option B would need Network Extension, packet filter, or another network control to approach this invariant. |
| DNS confinement | **Full target.** Provide a guest-local deterministic resolver and prevent fallback to host or public resolvers. | **No/Partial.** ESF may observe or restrict processes involved in resolver setup, but it is not a DNS confinement primitive. | Current macOS `vz` does not provide DNS confinement. DNS must be tested as a bypass channel, including direct UDP and custom resolver configuration. |
| Fail-closed startup | **Full target.** Refuse to launch the guest command unless the sidecar bridge, proxy bridge, DNS stub, and guest network rules are installed and verified. | **Partial.** ESF client startup can fail closed for ESF-protected operations, but extension load/approval is an operational dependency outside the normal CLI fast path. | Both paths need explicit preflight state and typed errors. ESF adds user/MDM approval states that must be modeled separately. |
| Fail-closed runtime | **Full target.** Sidecar loss should make the only egress path stop returning successful network results, while preserving deterministic process teardown or error behavior. | **Partial.** ESF can deny future authorized events it controls, but cannot make arbitrary established network flows fail closed unless paired with a network filter. | Mid-session sidecar loss must have deterministic test cases. ESF-only cannot claim this for all network traffic. |
| Direct-bypass resistance | **Full target.** Proxy-env-unset children, raw sockets, non-HTTP protocols, and direct DNS should remain inside the guest dead end. | **Partial.** ESF can block or log selected child exec patterns and protect config, but in-process raw socket use by an already running allowed process is outside ESF-only parity claims. | Option B is useful for reducing accidental bypass and detecting suspicious behavior, not for replacing the structural boundary. |
| Interactive CLI/TUI usability | **Partial/Full target.** Needs VZ lifecycle work to preserve stdio, signals, exit codes, terminal resizing, and startup latency. | **Partial.** ESF runs out-of-process and can preserve CLI UX once installed, but installation and approval are not frictionless. | Option A has engineering complexity in guest lifecycle and terminal plumbing. Option B has deployment friction and may be unacceptable for quick local adoption. |
| Immutable execution envelope | **Full target.** Guest launch can bind the session ID, proxy endpoint, DNS endpoint, and capability seed before process start. | **Partial.** ESF can observe exec metadata and help detect drift, but cannot replace the `firma run` launch envelope. | Both paths should continue treating the Sidecar's execution envelope as the policy/audit source of truth. |
| No network on enforcement hot path | **Full target.** Local Sidecar still makes policy decisions; the guest boundary only forces traffic to reach it. | **Partial.** ESF decisions are local, but using ESF as an extra authorization layer creates a second local decision path that must not call the Authority. | ESF policy must be cached locally and deterministic if introduced. |

## Option A: VZ Structural Parity Path

Option A implements the macOS parity direction from FIR-72. The target end state is that the wrapped process runs inside a guest boundary, and the host exposes only the controlled bridge needed to reach the Sidecar. The guest gets deterministic DNS and no usable ambient network path.

Expected design shape:

- Replace the current host-process compatibility implementation with a real VZ-backed execution lifecycle rather than relying on host proxy environment variables.
- Start host-side Sidecar bridge and guest-local proxy/DNS endpoints before launching the command.
- Install guest routing/firewall policy so the bridge is the only successful outbound path.
- Fail closed if any required bridge, resolver, policy, or health proof is missing.
- Preserve `firma run` UX: stdin/stdout/stderr, terminal mode, signal forwarding, exit status, and log clarity.

Why this is the primary path:

- It matches the existing Linux mental model: the agent's ability to bypass the Sidecar is removed structurally.
- It lets macOS claim boundaries use the same language as FIR-72 after evidence exists.
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
- CI needs macOS runners with signing material, entitlement handling, and integration tests that can exercise extension install/approval states. Most open CI runners cannot fully validate this path.

Market-standard use of ESF is closer to EDR/DLP host supervision than application sandbox networking. That makes it valuable for enterprise hardening and audit, but a risky foundation for the primary `firma run` structural confinement claim.

## Operational and Testing Implications

| Area | Option A: VZ structural parity path | Option B: ESF-native selected controls |
| ---- | ----------------------------------- | -------------------------------------- |
| Local development | Needs guest image/bootstrap tooling and VZ availability checks. | Needs signed system extension and local approval; awkward for casual contributors. |
| Enterprise deployment | Manage guest image version, resource usage, and update cadence. | Manage entitlement, Developer ID, system extension approval, MDM profiles, and extension health. |
| CI | Needs macOS E2E runners capable of VZ, plus raw bypass tests. | Needs signed artifacts and approval-capable macOS environments; many tests become manual or vendor-run. |
| Failure model | Mostly under `firma run` control: bridge, guest, DNS, route proof. | Split between CLI, system extension daemon, OS approval state, and ESF event delivery. |
| Performance | Cold-start and guest lifecycle are the main risks. | Runtime overhead depends on event subscriptions and decision latency; install friction is the main adoption risk. |
| Claim boundary | Can graduate to structural after FIR-72 E2E evidence. | Must remain selected host hardening/audit unless paired with separate network confinement. |

## Implementation status

| Card | Status | Notes |
| ---- | ------ | ----- |
| FIR-112A | ✅ Implemented | `ConfinementMechanism` added to `EnforcementProof`; all backends updated. |
| FIR-112B (intermediate) | ✅ Implemented | `sandbox-exec` network-deny mode via `FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1`. Full VZ guest planned next. |
| FIR-112C | ✅ Implemented | `HostDnsStubHandle` wired into macOS structural path in `routing.rs`. |
| FIR-112D | ✅ Implemented | Unit tests for proof types, sandbox profile generation, DNS stub, and routing. E2E schema defined. |
| FIR-112E | ✅ Schema written | `examples/firma-run/e2e/macos-structural-assertions.md` — 12 test cases covering all required invariants. |
| FIR-112B (VZ guest) | Planned | Apple Virtualization.framework Linux guest; FIR-112B proper. |
| FIR-112F | ✅ Docs updated | This page, `sandbox.md`, `firma-run.md`, `llms.txt`. |
| FIR-112G | Planned | ESF hardening spike. |
| FIR-112H | Planned | ESF operational readiness review. |

## Recommended Milestones

### Milestone 1: Baseline Proof and Claim Boundaries ✅

- macOS `vz` marked non-structural in runtime proof logs by default.
- Decision page in docs; `llms.txt` explicit that ESF-only is not structural parity.
- macOS FIR-72 E2E assertion schema defined (MACOS-001 through MACOS-012).
- `FIRMA_RUN_VZ_STRUCTURAL_NETWORK` gate added for opt-in experimental structural mode.

### Milestone 2: Intermediate Structural Mode (sandbox-exec network deny) ✅

- `sandbox-exec` with `deny network-outbound` policy implemented in `VzBackend`.
- Host-side proxy bridge + DNS refusal stub started before the sandbox.
- `EnforcementProof { structural: true, confinement_mechanism: macos_sandbox_network_deny }` emitted.
- All unit tests passing on Linux CI; E2E tests require macOS hardware.
- Activation: `FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1`.

### Milestone 3: macOS E2E Evidence (next)

- Run MACOS-001 through MACOS-009 from `examples/firma-run/e2e/macos-structural-assertions.md` on macOS 12+ Apple Silicon and Intel.
- Include raw socket, proxy-env-unset, child process, direct DNS, policy deny, startup sidecar-down, and mid-session sidecar-loss cases.
- Keep the runtime claim as non-structural (default mode) until the suite is reliable on supported macOS versions.
- Publish known-limits table: sandbox-exec deprecation caveats, DNS stub port limitation, loopback-all allow scope.

### Milestone 4: VZ Guest Prototype (FIR-112B proper)

- Replace sandbox-exec with Apple Virtualization.framework Linux guest.
- Guest lifecycle: command launch via virtio-serial stdio, signals, exit status, terminal resize.
- Guest-local proxy bridge and deterministic DNS stub inside the guest network namespace.
- Guest routing/firewall rules: bridge-only mandatory egress.
- Emit structural proof only in experimental mode with evidence fields for bridge, DNS, and route setup.
- Network bypass tests: raw socket, proxy-env-unset, child process, direct DNS from inside the guest.

### Milestone 5: ESF Hardening Spike

- Prototype a minimal ESF system extension outside the hot path.
- Test process lineage capture, exec authorization, runtime socket/config protection, and host-side audit correlation.
- Measure operational burden: entitlement approval, signing, install/update flow, MDM path, local dev workflow, and CI feasibility.
- Decide whether ESF becomes an enterprise add-on, not a requirement for baseline macOS structural mode.

### Milestone 6: Productionization

- Promote macOS `vz` structural mode only when E2E evidence supports every required invariant.
- Keep proxy-only compatibility available behind explicit opt-in for unsupported hosts.
- Add docs for install prerequisites, resource usage, failure modes, and claim boundaries.
- If ESF continues, ship it with separate status reporting and separate claims: host hardening/audit, not network structural parity.

## Follow-Up Card Suggestions

| Card | Status | Scope |
| ---- | ------ | ----- |
| FIR-112A | ✅ Done | `ConfinementMechanism` on `EnforcementProof`; preflight logging. |
| FIR-112B (intermediate) | ✅ Done | `sandbox-exec` network-deny structural mode + DNS stub + routing wiring. |
| FIR-112B (VZ guest) | Planned | Apple Virtualization.framework Linux guest lifecycle (stdio, TTY, signals, exit code). |
| FIR-112C | ✅ Done | `HostDnsStubHandle` + macOS structural routing path in `prepare_network_runtime`. |
| FIR-112D | ✅ Done | Unit tests for all new code; E2E schema written. |
| FIR-112E | ✅ Done | `examples/firma-run/e2e/macos-structural-assertions.md` — 12 test cases, graduation criteria. |
| FIR-112F | ✅ Done | Operator docs updated: this page, `sandbox.md`, `firma-run.md`, `llms.txt`. |
| FIR-112G | Planned | ESF hardening spike: entitlement path, signed system extension prototype, process lineage audit, selected authorization decisions. |
| FIR-112H | Planned | ESF operational readiness review: MDM deployment, CI constraints, update/rollback, crash recovery, claim language. |
| FIR-112H | ESF operational readiness review: MDM deployment, CI constraints, update/rollback, crash recovery, and claim language. |

## References

- [Apple Endpoint Security documentation](https://developer.apple.com/documentation/endpointsecurity)
- [Apple System Extensions documentation](https://developer.apple.com/documentation/SystemExtensions)
- [Apple System Extensions overview](https://developer.apple.com/system-extensions/)
