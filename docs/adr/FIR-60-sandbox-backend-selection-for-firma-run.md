---
adr: FIR-60
title: Sandbox backend selection for Firma Run
created: 2026-04-24T00:00:00Z
status: accepted
superseded_by: null
---

# FIR-60 ADR: Sandbox backend selection for Firma Run

## Context

FIR-56 identified a hard governance gap: process-forking tools (`run_shell`, browser automation, subprocess flows) are outside the HTTP proxy interception primitive.

On April 23, 2026, the architecture direction changed from "new enforcement primitive" to "new enforcement boundary":

- Keep Pingora/HTTP as the single policy enforcement plane.
- Run the agent process inside a sandbox.
- Force all sandbox egress through the sidecar.

Under this model, shell and subprocess traffic become governable because network confinement is structural at the sandbox boundary.

This ADR selects the sandbox backend for Firma Run (implemented in FIR-61, specialized for Claude Code/run_shell in FIR-62).

## Decision

Adopt a **dual-backend strategy** with a pluggable backend interface in Firma Run:

1. **Default backend family by host OS**:
   - Linux: bubblewrap-based sandboxing (OSS runtime adapter path).
   - macOS: lightweight VM sandbox profile (Apple Virtualization Framework based).
   - Windows: WSL2-backed sandbox profile (Linux guest confinement model).
2. **Enterprise backend (additive): Firecracker microVM on Linux**, exposed as a dedicated profile, not a migration.

Decision summary:

- Default for `firma run --profile generic` and `--profile codex` is OS-specific:
  - Linux: bubblewrap-class sandboxing.
  - macOS: VM-based sandbox profile.
  - Windows: WSL2-based sandbox profile.
- Firecracker is reserved for stricter isolation deployments on Linux (enterprise profile).
- gVisor and nsjail/firejail are not selected as first-class backends in v1.
- Docker/Podman OCI backends are intentionally excluded from FIR-60 scope.

## Requirements mapping

| Requirement                                     | Selected handling                                                                              |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Structural interception (no `HTTP_PROXY` trust) | Sandbox network namespace confinement + mandatory sidecar routing                              |
| DNS confinement                                 | Resolver path confined inside sandbox and routed through the controlled network path           |
| Cross-platform support                          | OS-specific backend strategy (Linux native namespaces, macOS VM profile, Windows WSL2 profile) |
| Fast local developer UX                         | bubblewrap as default for low startup overhead and simple tool wrapping                        |
| Strong enterprise isolation option              | Firecracker profile for kernel boundary isolation                                              |
| No from-scratch sandbox engine                  | Reuse existing OSS runtimes and kernel primitives                                              |

## Option analysis (best to worst for v1)

### A. bubblewrap + OSS runtime adapter

Pros:

- Good balance of isolation and startup speed for interactive developer workflows.
- Native fit for wrapping arbitrary commands (`firma run -- <cmd>`).
- Reuses existing OSS runtime ecosystem instead of custom sandbox engineering.

Cons:

- Weaker isolation than microVMs.
- Depends on Linux namespace posture and host configuration.

Decision: **Selected as v1 default backend**.

### B. Firecracker microVM

Pros:

- Strongest isolation boundary (microVM/kernel boundary).
- Excellent fit for strict multi-tenant or regulated enterprise workloads.

Cons:

- Higher operational complexity (image lifecycle, VM orchestration, KVM constraints).
- Heavier for local dev and per-invocation CLI loops.

Decision: **Selected as secondary/enterprise backend**, not v1 default.

### C. gVisor

Pros:

- Strong syscall mediation with user-space kernel model.

Cons:

- Added operational complexity for limited near-term benefit over selected default.
- Less aligned with fast local CLI wrapping as the initial delivery priority.

Decision: **Not selected for v1**.

### D. nsjail / firejail

Pros:

- Lightweight alternatives for namespace-style confinement.

Cons:

- No clear advantage over bubblewrap path once ecosystem/runtime integration is considered.
- Would fragment backend effort early.

Decision: **Fallback options only if bubblewrap path hits a hard blocker**.

### E. Docker / Podman OCI runtime

Pros:

- Very mature ecosystem and strong operational familiarity.
- Easy reuse where teams already run OCI-based workflows.

Cons:

- Not a minimal process-sandbox primitive; adds runtime/daemon surface and networking complexity relative to FIR-61 goals.
- Less aligned with "invisible wrapper over arbitrary agent command" as the primary v1 constraint.
- Increases implementation scope while not improving the selected enforcement boundary model.

Decision: **Explicitly out of scope for FIR-60/FIR-61 default path**.

## Cross-platform backend matrix

| Host OS          | v1 backend path                             | Enforcement approach                                                                           | Notes                                                                                        |
| ---------------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Linux            | bubblewrap default (`sandbox-bwrap`)        | Native namespace/network confinement + mandatory sidecar routing                               | Primary implementation target and reference path                                             |
| macOS            | VM-backed profile (`sandbox-vz`)            | Agent runs inside managed Linux guest VM; guest egress forced through sidecar path             | Uses OS-supported virtualization primitives; avoids deprecated macOS process sandbox tooling |
| Windows          | WSL2-backed profile (`sandbox-wsl2`)        | Agent runs in WSL2 guest; egress confinement and sidecar routing enforced in guest/bridge path | Works with modern Windows developer environments without Docker dependency                   |
| Linux enterprise | Firecracker profile (`sandbox-firecracker`) | MicroVM isolation + sidecar routing                                                            | Additive hard-isolation option for regulated environments                                    |

Implementation contract for FIR-61:

- `firma run` selects backend automatically by host OS, with explicit override flags.
- Security invariants stay constant across OSes:
  - fail-closed if sidecar is unreachable,
  - no direct egress bypass,
  - deterministic identity attribution for policy and audit.
- Performance and startup SLOs are measured per backend profile (not one global number).

## Licensing and redistribution check

This ADR records licensing posture for selected candidates:

- `anthropic-experimental/sandbox-runtime`: Apache-2.0 (compatible with Firma OSS Apache-2.0 distribution model).
- Firecracker: Apache-2.0.
- bubblewrap: LGPL-2.0-or-later.
- gVisor: Apache-2.0.

Redistribution policy for FIR-61 implementation:

- Do not vendor or statically embed bubblewrap.
- Treat bubblewrap as a system/runtime dependency.
- Keep third-party notices for any bundled adapter code and transitive artifacts.
- Add CI license scanning gate before release tagging of Firma Run binaries.

## Benchmark harness decision (ADR-level scope)

No production runtime code is shipped in FIR-60, but FIR-61 must include a benchmark harness with these outputs:

1. Startup latency:
   - Time from `firma run` invocation to first successful mediated HTTP request.
   - Report p50/p95/p99 for `generic` and `codex` profiles.
2. Proxy overhead:
   - Baseline direct sandbox egress (control sample where allowed in test rig).
   - Sandboxed + sidecar-routed egress.
   - Delta latency and throughput under fixed request volumes.
3. Fail-closed behavior:
   - Sidecar unavailable at launch and mid-session.
   - Assertion: zero network egress from sandbox.

Benchmark output format:

- Machine-readable JSON artifacts committed under `target/benchmarks/` in CI jobs.
- Human-readable summary in `docs/security/` for launch narrative and partner review.

## Consequences

Positive:

- Unblocks FIR-61 and FIR-62 with a clear backend contract.
- Preserves single enforcement-plane message (HTTP/Pingora) while expanding practical coverage through sandbox confinement.
- Avoids overcommitting to microVM overhead for all use cases.

Tradeoffs:

- Two backends increase abstraction and test matrix surface.
- v1 default isolation is namespace-level, not microVM-level.

Risks and mitigations:

- Host kernel/user-namespace variance: detect capabilities at startup and fail with actionable diagnostics.
- Routing bypass risk: enforce no-default-route/no-direct-egress invariants in integration tests.
- Complexity creep: keep Firecracker as additive profile behind the same backend trait.

## Non-goals

- Building a custom sandbox engine.
- Replacing sidecar policy logic with sandbox-local policy logic.
- Delivering Claude Code specialization in this ADR (that is FIR-62).
- Shipping Docker/Podman as a Firma Run backend in this phase.
- Requiring one universal sandbox implementation across all operating systems.

## Rollout plan alignment

- FIR-60 (this ADR): backend selection and constraints.
- FIR-61: implement `firma run` wrapper and default backend path.
- FIR-62: Claude Code/run_shell specialization on top of FIR-61.

## Owner and sign-off

- Author: Dario
- Sign-off required: Derek
- External narrative alignment required: Tommaso
