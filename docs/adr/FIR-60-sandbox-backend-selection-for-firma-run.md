---
adr: FIR-60
title: Sandbox backend selection for Firma Run
created: 2026-04-24T00:00:00Z
status: accepted
superseded_by: null
---

# FIR-60 ADR: Sandbox backend selection for Firma Run

## Status

Accepted on 2026-04-24.

## Context and problem statement

FIR-56 surfaced a structural gap: sidecar HTTP interception does not directly govern process-forking execution (`run_shell`, browser automation, subprocess trees) unless process network egress is confined.

On 2026-04-23, the architecture direction changed:

- Do not introduce a second policy plane.
- Keep Pingora/HTTP enforcement as the single decision plane.
- Move the hard boundary to sandboxed process execution and mandatory egress routing through the sidecar.

This ADR chooses sandbox backend(s) for Firma Run so FIR-61 and FIR-62 can implement that boundary consistently across Linux, macOS, and Windows.

## Decision drivers

1. Structural interception: no trust in cooperative `HTTP_PROXY` behavior.
2. Cross-platform coverage: Linux, macOS, Windows must all have a first-class path.
3. Fast developer workflow: interactive CLI/TUI usage must remain usable.
4. Security posture: fail-closed when sidecar path is unavailable.
5. Reuse over reinvention: no custom sandbox engine.
6. Enterprise extensibility: stronger isolation profile must be possible without redesign.

## Considered options

### A. OS-specific multi-backend with common enforcement invariants (selected)

Backend family:

- Linux default: `sandbox-bwrap` (bubblewrap-class namespace isolation).
- macOS accepted target: `sandbox-vz` (Linux guest via Apple Virtualization Framework).
- Windows accepted target: `sandbox-wsl2` (Linux guest via WSL2).
- Linux enterprise additive: `sandbox-firecracker`.

This ADR records the selected backend strategy and structural target. It does not
mean every backend already has Linux-equivalent runtime guarantees in the current
implementation. Current release posture is tracked in the status table below and
in the sandbox boundary docs.

Why selected:

- Preserves one enforcement model while supporting all required host OSes.
- Allows fast Linux path now and enterprise microVM path later.
- Keeps FIR-61 pluggable and avoids lock-in to one runtime.

### B. Firecracker-first for all paths

Pros:

- Strong isolation on Linux.

Cons:

- Linux/KVM-centric; no practical universal path for macOS/Windows defaults.
- Overhead/ops complexity too high for default local developer loop.

Decision: not selected as default strategy.

### C. OCI runtime default (Docker/Podman)

Pros:

- Mature ecosystem and operational familiarity.

Cons:

- Larger runtime/daemon/networking surface than required for FIR-61 wrapper goals.
- Adds complexity without improving the chosen enforcement-plane model.

Decision: explicitly out of scope for FIR-60/FIR-61 default path.

### D. gVisor/Kata as default

Pros:

- Strong sandboxing properties in container-centric environments.

Cons:

- Better fit for orchestrated/container fleets than local universal CLI wrapping.
- Higher integration cost relative to the selected path.

Decision: not selected for v1 default; can be revisited as future backend profiles.

### E. Linux-only initial release

Pros:

- Lower immediate implementation complexity.

Cons:

- Fails explicit cross-platform requirement from this decision cycle.

Decision: rejected.

### F. Managed sandbox platforms as FIR-60 primary backend (E2B, Beam, Daytona)

Pros:

- Mature productized sandbox workflows with SDKs and orchestration features.
- Can provide strong isolation depending on platform/runtime configuration.

Cons:

- FIR-60 requirement is a local wrapper boundary (`firma run -- <agent-command>`) with deterministic sidecar routing semantics under Firma control.
- Introducing an external control plane as the default backend shifts trust and lifecycle ownership away from the local Firma Run contract.
- Licensing and deployment complexity differ significantly by platform (for example AGPL-based stacks), which is undesirable for the default OSS path.

Decision: not selected as FIR-60 default backend strategy.

### G. Build a new custom cross-platform sandbox framework

Pros:

- Maximum design freedom.

Cons:

- High security and maintenance risk for a safety-critical boundary.
- Reinvents mature OS/runtime primitives already available.

Decision: rejected.

## Decision outcome

Adopt **Option A**: an OS-specific backend matrix with a common backend contract and common security invariants.

### Backend matrix

| Host OS          | Backend               | Accepted structural target                          | Current release status                                                                                                                                                   |
| ---------------- | --------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Linux            | `sandbox-bwrap`       | Namespaces/seccomp/cgroup-style process isolation   | Current structural fast path for local and CI.                                                                                                                           |
| macOS            | `sandbox-vz`          | Linux guest VM using Apple Virtualization Framework | Default implementation is proxy-only compatibility mode. Experimental `sandbox-exec` and VZ guest contract modes exist, but parity still requires hardware E2E evidence. |
| Windows          | `sandbox-wsl2`        | Linux guest VM via WSL2                             | Current implementation is proxy-only compatibility mode.                                                                                                                 |
| Linux enterprise | `sandbox-firecracker` | KVM microVM                                         | Planned additive stronger isolation profile.                                                                                                                             |

### Structural backend invariants and current status

These invariants must hold before a backend is described as structural. They do
not all hold on proxy-only compatibility backends.

1. All agent outbound TCP egress is transparently redirected to sidecar.
2. DNS is confined; direct resolver bypass is blocked.
3. Sidecar unreachable implies fail-closed with no external network fallback from
   the agent sandbox.
4. Each execution has deterministic sandbox/session identity for policy attribution
   and audit.
5. Wrapper remains interactive-safe (`stdin/stdout/stderr` passthrough, no TUI breakage).

Current status:

- Linux `bwrap` is the current structural backend.
- macOS default `vz` and Windows `wsl2` are proxy-only compatibility backends and
  require explicit opt-in before launch.
- macOS `FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1` is experimental and loopback-scoped.
- macOS `FIRMA_RUN_VZ_GUEST=1` emits a launch contract for an external runner; the
  runner and guest image must still prove the structural invariants.
- Firecracker remains planned.

### Backend interface contract (FIR-61)

Every backend implements:

- `prepare(config) -> SandboxHandle`
- `start_sidecar(handle, sidecar_config) -> SidecarHandle`
- `enforce_network(handle, sidecar_endpoint) -> EnforcementProof`
- `start_agent(handle, command, argv, env) -> AgentHandle`
- `verify_fail_closed(handle) -> Result`
- `teardown(handle) -> Result`

The wrapper chooses backend automatically by host OS with explicit override flags.

## Technical notes by OS

### Linux (`sandbox-bwrap`)

- Use namespace isolation and mandatory egress redirection in sandbox network namespace.
- Enforce deny-by-default outbound policy except sidecar path.
- Validate host prerequisites at startup (user namespace support, required tooling).

### macOS (`sandbox-vz`)

- Accepted target: run the agent within a managed Linux guest to keep enforcement
  mechanics consistent with Linux.
- Current release: default `vz` launches a host process with proxy mediation and
  does not claim Linux-equivalent structural confinement. The VZ guest path is a
  launch-contract mode for an external runner, not the runner implementation itself.

### Windows (`sandbox-wsl2`)

- Accepted target: run the agent inside a WSL2 distro/instance dedicated to Firma
  Run profile.
- Current release: `wsl2` is proxy-only compatibility mode. Linux guest-level
  routing and DNS confinement remain target behavior, not the current guarantee.

### Linux enterprise (`sandbox-firecracker`)

- Optional hard-isolation profile for stricter environments.
- Uses same logical interface and invariants as other backends.

## External ecosystem notes (informative)

The following external discussions and tools were reviewed to pressure-test FIR-60. They are informative, not normative for the decision.

| Project family | Verified from primary sources                                                                         | FIR-60 relevance                                                                                                                                           |
| -------------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| E2B            | Linux VM sandbox model; configurable timeout/pause-resume lifecycle; managed SDK-first platform       | Useful reference for remote sandbox APIs, but not selected as FIR-60 default because FIR-60 targets local wrapper enforcement under direct runtime control |
| Beam           | Open-source platform components with AGPL core; cloud-oriented sandbox workflows                      | Valuable for cloud execution patterns, but not selected as default local backend                                                                           |
| Daytona        | AGPL platform with multi-service control/compute architecture and sandbox runners                     | Strong orchestration platform, but heavier than FIR-60 default requirements                                                                                |
| Microsandbox   | Apache-2.0 self-hosted microVM execution layer; docs indicate Linux/macOS support and Windows pending | Strong candidate for future backend experimentation, especially enterprise/high-isolation tracks                                                           |
| Dify Sandbox   | Apache-2.0 code execution sandbox; Linux/container-oriented requirements                              | Useful design reference, but not a direct FIR-60 cross-platform default fit                                                                                |

Interpretation rule used in this ADR:

- Vendor/blog performance claims are treated as directional unless corroborated by primary technical documentation and reproducible benchmarks in FIR-61.
- Reddit/community discussion is treated as qualitative signal, not as architectural proof.

## Licensing and redistribution check

Recorded licensing posture for selected ecosystem components:

- `anthropic-experimental/sandbox-runtime`: Apache-2.0
- Firecracker: Apache-2.0
- bubblewrap: LGPL-2.0-or-later
- gVisor: Apache-2.0

Implementation policy:

- Do not statically embed bubblewrap.
- Treat system-level sandbox binaries as runtime dependencies.
- Keep third-party notices current.
- Add CI license scan gate before release tagging.

## Benchmark and confirmation plan (ADR scope)

FIR-60 ships no runtime code. FIR-61 must provide benchmark and confirmation artifacts per backend profile.

Required measurements:

1. Startup:
   - `t_backend_ready`: wrapper invoke -> sandbox ready
   - `t_sidecar_ready`: sandbox ready -> sidecar healthy
   - `t_first_request`: wrapper invoke -> first mediated HTTP request
2. Overhead:
   - Direct baseline vs sidecar-routed path latency/throughput deltas
   - p50/p95/p99 by profile (`generic`, `codex`)
3. Security behavior:
   - Sidecar unavailable at startup and mid-session
   - Structural-backend assertion: zero direct external egress from sandboxed
     agent process

Artifacts:

- Machine-readable JSON under `target/benchmarks/`
- Human-readable summary in `docs/security/`

## Consequences

### Positive

- Unblocks FIR-61 and FIR-62 with concrete, implementable backend constraints.
- Keeps single HTTP enforcement-plane narrative intact.
- Supports cross-platform adoption without promising one-size-fits-all runtime internals.

### Negative / tradeoffs

- Increased test matrix and backend-specific operational code.
- macOS/Windows paths depend on guest runtime provisioning and lifecycle management.
- Firecracker remains Linux-only and non-default.

### Risks and mitigations

- Backend drift:
  - Mitigation: strict shared backend interface and invariant test suite.
- Host capability variability:
  - Mitigation: startup preflight checks with actionable diagnostics.
- Egress bypass regressions:
  - Mitigation: mandatory fail-closed integration tests in CI for every backend
    mode that claims structural confinement.

## Non-goals

- Building a custom sandbox engine.
- Introducing a second policy engine outside sidecar.
- Shipping Docker/Podman backend in FIR-60/FIR-61 default scope.
- Implementing Claude Code specialization in this ADR (FIR-62 scope).

## Rollout alignment

- FIR-60: decision and constraints (this ADR).
- FIR-61: implement backend interface + default profiles.
- FIR-62: Claude Code / `run_shell` specialization on FIR-61 foundation.

## Ownership and sign-off

- Author: Dario
- Sign-off: Derek
- External narrative alignment: Tommaso

## References (informative)

- MADR and ADR structure guidance: https://adr.github.io/madr/
- Bubblewrap project: https://github.com/containers/bubblewrap
- Anthropic sandbox runtime: https://github.com/anthropic-experimental/sandbox-runtime
- Apple Virtualization Framework docs: https://developer.apple.com/documentation/virtualization
- WSL networking model: https://learn.microsoft.com/en-us/windows/wsl/networking
- Firecracker overview and usage in Lambda/Fargate: https://aws.amazon.com/about-aws/whats-new/2018/11/firecracker-lightweight-virtualization-for-serverless-computing/
- E2B sandbox lifecycle docs: https://e2b.dev/docs/legacy/sandbox/api/timeouts
- E2B auto-resume docs: https://e2b.dev/docs/sandbox/auto-resume
- Beam sandbox docs: https://docs.beam.cloud/v2/sandbox/overview
- Daytona OSS deployment docs: https://www.daytona.io/docs/en/oss-deployment/
- Daytona architecture docs: https://www.daytona.io/docs/ja/architecture/
- Microsandbox docs: https://docs.microsandbox.dev/
- Microsandbox repository: https://github.com/zerocore-ai/microsandbox
- Dify Sandbox repository: https://github.com/langgenius/dify-sandbox
