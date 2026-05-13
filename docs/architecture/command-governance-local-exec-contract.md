# Command Governance Local-Exec Contract

Status: active  
Date: 2026-05-13  
Scope: cross-platform contract (`firma run` + Sidecar governance services)

## Overview

This document defines the platform-neutral request/response contract between runtime launchers and Sidecar local-exec governance endpoints.

It focuses on governance semantics that are not kernel-specific, including HITL signaling and budget context propagation.

## Request Contract

Runtime sends one JSON line request per launch decision:

```json
{"action":"local.exec","executable":"...","args":[...],"sandbox_id":"...","session_id":"...","profile":"...","hitl_mode":"sync_wait|async_token","budget_state_ref":"optional-ref"}
```

Fields:

1. `action`: canonical governance action name (currently `local.exec`).
2. `executable`: resolved executable path/string the runtime intends to launch.
3. `args`: launch argument vector.
4. `sandbox_id`: runtime sandbox identity for traceability and binding.
5. `session_id`: runtime session identity for traceability and binding.
6. `profile`: runtime profile name.
7. `hitl_mode`: requested HITL behavior (`sync_wait` or `async_token`).
8. `budget_state_ref`: optional budget context reference forwarded by runtime.

## Response Contract

Governance endpoint returns one JSON line response:

```json
{"decision":"allow|deny|pending_hitl","reason":"optional","approval_token":"optional","retry_after_ms":500}
```

Decision behavior:

1. `allow`: runtime proceeds with launch.
2. `deny`: runtime blocks launch (fail-closed).
3. `pending_hitl` + `sync_wait`: runtime blocks launch (fail-closed pending).
4. `pending_hitl` + `async_token`: runtime blocks current launch attempt and expects non-empty `approval_token`.
5. Missing required fields or unsupported decision value: runtime blocks launch (fail-closed).

## `FIRMA_BUDGET_STATE_REF`

### Purpose

`FIRMA_BUDGET_STATE_REF` is an optional runtime environment variable used to populate request field `budget_state_ref`.

### Ownership Model

1. Runtime owns forwarding `budget_state_ref`.
2. Sidecar/governance services own interpretation and enforcement.
3. Budget systems own state consistency, freshness, and quota/rate accounting.

### Current Runtime Behavior

1. Runtime reads `FIRMA_BUDGET_STATE_REF` if present and non-empty.
2. Runtime serializes it into request payload as `budget_state_ref`.
3. Runtime does not parse, validate, persist, or enforce budget semantics locally.

### Why This Is Platform-Neutral

1. `budget_state_ref` is governance context, not a kernel primitive.
2. Same governance contract can be used by Linux/macOS/Windows runtime paths.
3. Platform-specific containment (seccomp/sandbox backend) remains separate from budget semantics.

### Suggested Reference Format (initial)

Recommended shape (subject to governance-team finalization):

1. Prefix + namespace + version + opaque token.
2. Example: `budget:team-demo:v1:3f65b1e2`.

Guidelines:

1. Avoid embedding sensitive raw billing data in the reference itself.
2. Treat it as a lookup key or signed pointer.
3. Keep compatibility/versioning explicit.

## Failure Semantics

For governed mode, runtime remains fail-closed:

1. Governance endpoint unavailable/timeout -> deny launch.
2. Invalid response schema -> deny launch.
3. `pending_hitl` async without token -> deny launch.
4. Missing `budget_state_ref` can be denied by governance policy where required.

Optional strict startup gate:

1. Set `FIRMA_RUN_REQUIRE_LOCAL_EXEC_GOVERNANCE=true` to require `sidecar_local_exec` config at startup.
2. When enabled and config is missing, `firma run` fails before launching the wrapped command.

## Security Notes

1. `budget_state_ref` must not be trusted as authoritative budget state by itself.
2. Governance endpoint should bind decision to `sandbox_id` + `session_id` to reduce replay/confusion.
3. Audit logs should include decision reason and budget reference usage outcome.

## Testing Guidance

Minimum contract tests:

1. Request includes `budget_state_ref` when env var is set.
2. Request omits/sets null-equivalent when env var is missing/empty.
3. Governance deny path remains fail-closed regardless of budget context.
4. Async HITL path enforces token requirement.
5. Budget-required policy path denies missing/invalid references.
