# Firma Run Deep Dive: Sandbox Launcher

## Purpose

This document translates the sandbox-boundary decision into an implementation-ready blueprint for `firma run`.

- Decision: move enforcement boundary to sandboxed runtime, keep sidecar as single enforcement plane.
- Scope: implement generic wrapper plumbing (`firma run`) with cross-OS backend paths.
- Follow-up scope: Claude-specific specialization.

## Scope Reconciliation

The architecture accepted an OS-matrix strategy (`bwrap`, `vz`, `wsl2`, optional Firecracker). `firma run` now ships runtime paths for Linux, macOS, and Windows.

Implementation stance:

1. Keep backend contract pluggable and backend-neutral in orchestration.
2. Ship Linux `bwrap`, macOS `vz`, and Windows `wsl2` runtime paths.
3. Keep enterprise profile seam additive (no rewrites).

## Architecture Blueprint

### Runtime topology (cross-OS)

```text
Host:
  firma-run orchestrator
  firma-sidecar
  sidecar uds: /run/firma-sidecar/<sandbox_id>.sock

Sandbox / wrapped runtime:
  agent process (python/node/codex/...)
  local egress bridge (127.0.0.1:18080)
  local dns stub (127.0.0.1:53)
```

### Path of a successful outbound call

1. Agent issues HTTP request.
2. Agent uses sandbox-local proxy endpoint (`127.0.0.1:18080`) automatically from wrapper-provided env.
3. Bridge forwards request to sidecar UDS endpoint.
4. Sidecar enforces Stage 1 + Stage 2 and dispatches allowed call.
5. Response returns through sidecar and bridge to agent.

### Path of direct bypass attempt

1. Agent attempts direct external connect (ignores proxy vars).
2. Network confinement blocks external path (no direct egress route from sandbox).
3. Call fails deterministically.
4. No sidecar bypass occurs.

## Decision: DNS Confinement (Comment 1)

### Problem

DNS confinement was required but initially lacked concrete implementation. With `bwrap`, relying on inherited host resolver is a bypass risk.

### Implementation decision

1. `firma-run` generates sandbox-specific `resolv.conf`.
2. `resolv.conf` points to sandbox-local DNS stub (`127.0.0.1`).
3. DNS stub forwards through a Firma-controlled path tied to sidecar mediation endpoint.
4. Direct resolver traffic outside the controlled path is blocked by sandbox confinement.

### Security invariant

DNS resolution from inside sandbox is sidecar-controlled or fails; host ambient resolver is never a successful bypass path.

## Decision: Long-Running Agent Capability Lifecycle (Comment 2)

### Is this a real issue?

Yes. Persistent processes (OpenClaw-like) outlive short token/session assumptions and will hit expiry unless capability material rotates.

### Implementation decision

Add a capability rotation contract in wrapper runtime:

1. Capability source abstraction (file/command/provider contract).
2. Renewal before expiry with overlap window.
3. If renewal fails beyond grace threshold, egress remains fail-closed.
4. Renewal events are observable and attributable by run identity.

### Why in this phase

This is runtime-plumbing behavior, not Claude specialization. Deferring it fully to the Claude-specific phase leaves a correctness gap for generic persistent agents.

## Identity and Attribution Model

Per run, wrapper generates deterministic identity:

- `sandbox_id`
- `session_id`
- `profile`

These values are injected into mediated requests (header/claim projection), so sidecar audit can distinguish concurrent `firma-run` instances.

## Failure Modes and Required Behavior

1. Sidecar unreachable at startup -> wrapped agent must not launch.
2. Sidecar unreachable mid-session -> requests fail deterministically; no external fallback.
3. Bridge failure -> fail-closed, no direct egress.
4. DNS stub failure -> resolution fails closed.
5. Capability renewal failure past grace window -> egress blocked until valid capability restored.

## Benchmark plan

Required metrics:

- `t_backend_ready`
- `t_sidecar_ready`
- `t_first_request`
- request latency deltas (direct vs wrapped), p50/p95/p99
- profile split: `generic`, `codex`

Artifacts:

- JSON: `target/benchmarks/firma-run/*.json`
- Human summary: docs (`docs/architecture/` or `docs/security/`)

## Construction Plan

Recommended bolt order:

1. `014-cli-runtime-orchestrator`
2. `015-bwrap-backend-contract`
3. `019-profiles-and-config` (parallel with early confinement work)
4. `016-egress-routing-and-dns-confinement`
5. `017-egress-routing-and-dns-confinement`
6. `018-identity-and-capability-lifecycle`
7. `020-e2e-bench-and-docs`

## Non-goals

- Firecracker runtime implementation.
- Claude-specific workflow behavior.
- New policy logic plane outside sidecar.
