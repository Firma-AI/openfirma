# Command Governance Local-Exec Contract

Status: active\
Date: 2026-05-13\
Scope: cross-platform contract (`firma run` + Sidecar governance services)

## Overview

This document defines the platform-neutral request/response contract between runtime launchers and Sidecar local-exec governance endpoints.

It focuses on governance semantics that are not kernel-specific, including HITL signaling.

## Request Contract

Runtime sends one JSON line request per launch decision:

```json
{"action":"local.exec","executable":"...","args":[...],"sandbox_id":"...","session_id":"...","agent_id":"optional","profile":"...","hitl_mode":"sync_wait|async_token","request_fingerprint":"optional-sha256hex","approval_token":"optional-token-id"}
```

Fields:

1. `action`: canonical governance action name (currently `local.exec`).
2. `executable`: resolved, canonicalized executable path.
3. `args`: launch argument vector.
4. `sandbox_id`: runtime sandbox identity for traceability and token binding.
5. `session_id`: runtime session identity for traceability and token binding.
6. `agent_id`: optional agent identity string for token context binding.
7. `profile`: runtime profile name.
8. `hitl_mode`: requested HITL behavior (`sync_wait` or `async_token`).
9. `request_fingerprint`: optional SHA-256 hex digest of the request context (executable + args + session + sandbox + agent). When present, the sidecar independently recomputes and verifies it (defense-in-depth; mismatch → deny).
10. `approval_token`: present only on retry attempts — the opaque token ID issued in a prior `pending_hitl` response.

## Response Contract

Governance endpoint returns one JSON line response:

```json
{"decision":"allow|deny|pending_hitl","reason":"optional","approval_token":"optional","retry_after_ms":500}
```

Decision behavior:

1. `allow`: runtime proceeds with launch.
2. `deny`: runtime blocks launch (fail-closed).
3. `pending_hitl` + `sync_wait`: runtime blocks launch (fail-closed pending).
4. `pending_hitl` + `async_token`: runtime expects non-empty `approval_token`, then retries internally (same launch attempt) until `allow|deny` or the configured `hitl_max_wait` timeout.
5. Missing required fields or unsupported decision value: runtime blocks launch (fail-closed).

## Failure Semantics

For governed mode, runtime remains fail-closed:

1. Governance endpoint unavailable/timeout -> deny launch.
2. Invalid response schema -> deny launch.
3. `pending_hitl` async without token -> deny launch.
4. Repeated `pending_hitl` past runtime `hitl_max_wait` -> deny launch.

Optional strict startup gate:

1. Set `FIRMA_RUN_REQUIRE_LOCAL_EXEC_GOVERNANCE=true` to require `sidecar_local_exec` config at startup.
2. When enabled and config is missing, `firma run` fails before launching the wrapped command.

## Security Notes

1. Governance endpoint should bind decision to `sandbox_id` + `session_id` to reduce replay/confusion.
2. On Linux, local-exec UDS endpoint validates peer UID (`SO_PEERCRED`) and rejects cross-UID callers fail-closed.
3. Socket file permissions are hardened to owner-only (`0600`) at bind time; operator/CLI access assumes same-UID local control plane.
4. `approval_token` replay prevention is enforced server-side via token state (`Pending/Approved/Consumed/Expired/Revoked`) and context binding (fingerprint + session/sandbox/agent).

## Testing Guidance

Minimum contract tests:

1. Request fingerprint mismatches fail closed.
2. Governance deny path remains fail closed.
3. Async HITL path enforces the token requirement.
