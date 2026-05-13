# Linux Local Command Enforcement

Status: implementation complete (Linux path)  
Date: 2026-05-13  
Scope: `firma run` + Linux `bwrap` backend

## Overview

This document defines the Linux product architecture for local-command governance and containment.

The model is layered:

1. Kernel-enforced static seccomp as authoritative syscall deny boundary.
2. Optional userspace command mediator for dynamic pre-exec decisions.
3. Optional operator-managed kernel hardening extensions (for higher-assurance deployments).
3. Deterministic fail-closed behavior across policy resolution and runtime checks.

This is the canonical architecture + operations + validation guide for Linux local-command enforcement.

## Design Goals

1. Keep Linux syscall deny enforcement in-kernel and fail-closed.
2. Preserve policy intent where safely mappable into static seccomp.
3. Support controlled policy lifecycle via versioned artifacts.
4. Enable dynamic command governance through a mandatory pre-exec decision gate when configured.
5. Provide reproducible verification and guardrails for latency and failure behavior.
6. Make non-cooperative bypass limits explicit and provide stronger controls where possible.

## Enforcement Architecture

### Layer 1: Static Seccomp (authoritative)

1. Runtime resolves managed seccomp artifact (`policy.bpf` + metadata).
2. Runtime verifies metadata contract and artifact checksum.
3. Runtime performs artifact trust-path checks (owner/perms/symlink policy).
4. Linux backend passes seccomp descriptor into `bwrap --seccomp`.
5. Any failure in steps above blocks launch (fail-closed).

### Layer 2: Userspace Command Mediator (optional but mandatory when enabled)

When `command_mediator` is configured:

1. Runtime builds final executable + args.
2. Runtime sends a pre-exec decision request to mediator.
3. Only explicit `allow` proceeds.
4. `deny`, `pending_hitl`, timeout, unavailable endpoint, malformed/unsupported response all block launch.
5. No direct execution fallback path exists in mediated mode.

The mediator layer complements seccomp; it does not replace kernel containment.

### Layer 3: Optional Operator Hardening Extensions

Some deployments require stronger non-cooperative guarantees than cooperative tool mediation can provide.

Optional hardening layers can be added by operators, including:

1. eBPF LSM policy programs (cluster/host operator managed).
2. LSM profile frameworks such as AppArmor/SELinux when available in environment.

These layers are optional and environment-specific. Static seccomp remains the default portable kernel baseline.

## Managed Policy Model

### Supported deny-action subset

1. `system.execute`
2. `filesystem.delete`
3. `credential.write`

Unsupported actions are rejected with explicit validation errors.

### Current syscall mapping

1. `system.execute` -> `execve`, `execveat`
2. `filesystem.delete` -> `unlink`, `unlinkat`, `rmdir`, `rename`, `renameat`, `renameat2`
3. `credential.write` -> `setuid`, `setgid`, `setresuid`, `setresgid`

### Fidelity caveats

1. Seccomp is syscall-number enforcement, not semantic policy interpretation.
2. No argument/path-level expression at kernel layer (`filesystem.delete` cannot encode path scopes like workspace-only).
3. `rename*` blocking is intentionally conservative and may block benign atomic-update flows.
4. Arch-specific syscall surfaces differ (`aarch64` behavior may map through `*at` variants where legacy syscalls are absent).
5. Dynamic context (HITL, budgets, tenant/session business logic) must stay in userspace governance.

## Artifact Contract

Metadata fields:

1. `policy_schema_version`
2. `policy_id`
3. `policy_version`
4. `sha256`
5. `generated_at`
6. `compiler_version`
7. `target_arch`
8. `default_action`
9. `source_policy_refs`
10. `source_policy_sha256`
11. `denied_syscalls`

Artifact layout:

1. `<artifact_dir>/<policy_id>/<policy_version>/<target_arch>/policy.bpf`
2. `<artifact_dir>/<policy_id>/<policy_version>/<target_arch>/policy.metadata.json`

## Runtime Hardening Invariants

1. Environment-variable seccomp-path injection is not authoritative.
2. `seccomp_policy.verify_checksum=false` is rejected.
3. Checksum verification is mandatory in compile-on-launch and precompiled-only modes.
4. Artifact root/leaf paths and files must be owned by current runtime uid.
5. Symlinked managed artifact paths are rejected.
6. Other-write permissions on managed artifact paths are rejected.
7. Invalid-but-checksummed BPF content still fails closed at runtime load.
8. Mediated mode is fail-closed on timeout/unavailable/error/invalid response.
9. When `enforce_known_executables=true`, launch is fail-closed if executable basename is not allowlisted.
10. Mediator request includes `sandbox_id` + `session_id` for identity/session binding.

## Mediator Contract

### Configuration

`command_mediator` supports:

1. `tcp://host:port`
2. `unix:///absolute/path.sock`

`timeout_ms` must be `> 0`.

Optional governance controls:

1. `hitl_mode = "sync_wait" | "async_token"` (default: `sync_wait`).
2. `enforce_known_executables = true|false` (default: `false`).
3. `allowed_executables = ["bash", "sh", "python3", ...]` (required when enforcement is enabled).

### Request (JSON line)

```json
{"action":"local.exec","executable":"...","args":[...],"sandbox_id":"...","session_id":"...","profile":"...","hitl_mode":"sync_wait|async_token","budget_state_ref":"optional-ref"}
```

### Response (JSON line)

```json
{"decision":"allow|deny|pending_hitl","reason":"optional","approval_token":"optional","retry_after_ms":500}
```

Decision handling:

1. `allow` -> launch proceeds.
2. `deny` -> blocked.
3. `pending_hitl` with `sync_wait` -> blocked (explicit pending fail-closed).
4. `pending_hitl` with `async_token` -> blocked with explicit approval-token required for caller retry flow.
5. Missing token for async mode -> blocked (invalid pending state).
6. Any other/invalid response -> blocked.

### HITL Runtime Model

1. `sync_wait`: mediator must return final `allow|deny` in request timeout window.
2. `async_token`: mediator may return `pending_hitl` with `approval_token`; current launch attempt fails closed and caller may retry later with approved context.
3. No background in-place escalation of an already running sandbox process.

### Budget Source of Truth

1. Runtime passes `budget_state_ref` from environment (`FIRMA_BUDGET_STATE_REF`) to mediator for traceable decision context.
2. Runtime does not own budget state consistency; mediator-side governance system is source of truth.
3. Missing `budget_state_ref` is allowed, but policy can deny when budget reference is mandatory.

### Non-Cooperative Anti-Bypass Guarantees

Current guarantees:

1. Cooperative governed path has one mandatory pre-exec mediation point in runtime.
2. No runtime fail-open fallback when mediator is configured.
3. Optional executable allowlist blocks unknown launch targets before execution.

Current limits:

1. Arbitrary child processes spawned after initial launch are constrained primarily by sandbox/seccomp/namespace boundaries.
2. Mediator is not itself a full containment boundary for non-cooperative process trees.

Required deployment position:

1. Treat mediator as governance control for governed execution path.
2. Treat kernel sandboxing and seccomp as containment baseline.
3. Add optional operator kernel controls (for example eBPF LSM) when stronger non-cooperative guarantees are required.

## Default Linux Behavior

For `generic` profile on Linux + `bwrap`:

1. Managed seccomp default-enabled.
2. Source policy defaults to bundled `crates/firma-run/policies/generic-local-command-v1.toml`.
3. Artifact root defaults to `/tmp/firma/seccomp-artifacts`.
4. Runtime mode defaults to `compile_on_launch`.

Optional overrides:

1. `FIRMA_RUN_MANAGED_SECCOMP_POLICY_PATH`
2. `FIRMA_RUN_MANAGED_SECCOMP_ARTIFACT_DIR`
3. `FIRMA_RUN_MANAGED_SECCOMP_RUNTIME_MODE`
4. `FIRMA_RUN_MANAGED_SECCOMP_DISABLE_DEFAULT`

## Policy Update and Lifecycle Model

1. Seccomp is static per sandbox process instance.
2. Policy update is versioned artifact update plus new process launch.
3. No in-place hot reload for running sandbox process.
4. Rollback is profile-level switch to known-good artifact version (or temporary default disable flag).

## eBPF LSM Option (Operator-Managed)

eBPF LSM is not the default enforcement path in this product baseline, but it is documented as an advanced optional layer.

Rationale:

1. It can add dynamic kernel-level controls beyond static seccomp in some environments.
2. It has significant operational/security requirements (program loading privileges and lifecycle).

Operational notes:

1. Loader privilege is sensitive (`CAP_SYS_ADMIN` / equivalent capability concerns).
2. Recommended model is host/operator-managed loader, not untrusted workload-owned loader.
3. If `firma run` loads programs directly, that path must be explicitly privileged and audited.
4. This option coexists with static seccomp; it does not replace the seccomp baseline.

## Compatibility Matrix

Supported:

1. OS: Linux
2. Backend: `bwrap`
3. Arch: `x86_64`, `aarch64`
4. Kernel: `>= 4.14`
5. Seccomp actions required: `kill_process`, `errno`, `allow`

Compatibility command:

```bash
make managed-seccomp-compat-check
```

## CI/Local Guardrails

Primary command:

```bash
make managed-seccomp-guardrail
```

Checks:

1. Baseline vs managed benchmark.
2. Overhead budget (`<= 3%` average on shell-heavy workload).
3. Artifact/metadata generation and integrity inspection.
4. Fail-closed matrix:
5. missing policy source
6. missing precompiled artifact
7. invalid metadata format
8. checksum mismatch
9. invalid readable BPF
10. unloadable artifact
11. mediated mode fail-closed behavior for allow/deny/pending/unavailable/invalid-response
12. executable allowlist enforcement behavior when enabled

## End-to-End Validation Runbook

### Step 1: Fresh Checkout

```bash
git fetch --all
git checkout <branch>
git pull --ff-only
cargo clean
```

### Step 2: Build + Unit Tests

```bash
cargo build -p firma --release
cargo test -p firma-run -- --nocapture
```

### Step 3: Compatibility Gate

```bash
make managed-seccomp-compat-check
```

### Step 4: Guardrail Matrix

```bash
make managed-seccomp-guardrail
```

Faster local smoke:

```bash
MANAGED_SECCOMP_GUARDRAIL_ITERATIONS=3 \
MANAGED_SECCOMP_GUARDRAIL_INNER_LOOPS=20 \
make managed-seccomp-guardrail
```

### Step 5: Explicit Mediator Tests

Create `tmp/firma-run.mediator.toml`:

```toml
[profiles.generic]
backend = "bwrap"

[profiles.generic.seccomp_policy]
source_policy_path = "/ABS/PATH/TO/crates/firma-run/policies/generic-local-command-v1.toml"
artifact_dir = "/tmp/firma/seccomp-artifacts"
verify_checksum = true
runtime_mode = "compile_on_launch"

[profiles.generic.command_mediator]
endpoint = "tcp://127.0.0.1:28991"
timeout_ms = 500
hitl_mode = "async_token"
enforce_known_executables = true
allowed_executables = ["echo", "bash", "sh"]
```

Allow response server example:

```bash
python3 - <<'PY'
import socket
host, port = "127.0.0.1", 28991
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(5)
while True:
    conn, _ = s.accept()
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    conn.sendall(b'{"decision":"allow","reason":"ok"}\n')
    conn.close()
PY
```

Run governed command:

```bash
target/release/firma run \
  --profile generic \
  --config /ABS/PATH/TO/tmp/firma-run.mediator.toml \
  --sidecar-endpoint tcp://127.0.0.1:65535 \
  -- /bin/echo mediator-allow
```

Repeat with decision responses:

1. `{"decision":"deny","reason":"blocked-by-policy"}` -> must fail closed.
2. `{"decision":"pending_hitl","reason":"awaiting-approval"}` -> must fail closed.
3. `{"decision":"pending_hitl","reason":"awaiting-approval","approval_token":"tok_123","retry_after_ms":500}` with `async_token` -> must fail closed and surface token in error context.
4. mediator stopped/unavailable -> must fail closed.
5. response missing `approval_token` in async mode -> must fail closed.
6. run non-allowlisted executable (`/usr/bin/env`) -> must fail closed before launch.

### Step 6: Negative Config Validation

1. `endpoint = "unix://relative.sock"` -> validation error (requires absolute path).
2. `timeout_ms = 0` -> validation error.

### Step 7: Final Acceptance

All must be true:

1. `cargo test -p firma-run -- --nocapture` passes.
2. `make managed-seccomp-compat-check` passes.
3. `make managed-seccomp-guardrail` passes.
4. Mediator allow/deny/pending/unavailable behavior matches fail-closed model.
5. No direct exec fallback path observed in mediated mode.
6. Allowlist enforcement blocks unknown executable when enabled.

## Operations and Rollback

### Publish/Promote

1. Update policy source (`policy_id`, `policy_version`, deny actions).
2. Run compatibility + guardrail commands.
3. Promote artifact version through profile config (or precompiled-only path).

### Rollout Strategy

1. Phase 1: opt-in profile enables managed seccomp + mediator.
2. Phase 2: enable executable allowlist in governed environments after command inventory stabilization.
3. Phase 3: default-enable governed path for target profile once latency and fail-closed gates pass.
4. Phase 4: deprecate legacy unmanaged launch patterns for governed mode.

### Incident Rollback

1. Switch to previous known-good artifact version.
2. If needed, temporarily disable generic managed default with:
`FIRMA_RUN_MANAGED_SECCOMP_DISABLE_DEFAULT=1`
3. Re-enable only after compatibility + guardrail pass.

## Notes

1. `scripts/ci/managed-seccomp-guardrail.sh` is both CI automation and local reproducible verification harness.
2. Production enforcement logic is in Rust runtime path (`seccomp` + mediator gate), not in shell scripts.
