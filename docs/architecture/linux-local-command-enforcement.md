# Linux Local Command Enforcement

Status: implementation complete (Linux path)\
Date: 2026-05-13\
Scope: `firma run` + Linux `bwrap` backend

## Overview

This document defines the Linux product architecture for local-command governance and containment.

The model is layered:

1. Kernel-enforced static seccomp as authoritative syscall deny boundary.
2. Optional Sidecar local-exec governance endpoint for dynamic pre-exec decisions.
3. Optional operator-managed kernel hardening extensions (for higher-assurance deployments).
4. Deterministic fail-closed behavior across policy resolution and runtime checks.

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

### Layer 2: Sidecar Local-Exec Governance (optional but mandatory when enabled)

When `sidecar_local_exec` is configured:

1. Runtime builds final executable + args.
2. Runtime sends a pre-exec decision request to mediator.
3. Only explicit `allow` proceeds.
4. `deny`, `pending_hitl`, timeout, unavailable endpoint, malformed/unsupported response all block launch.
5. No direct execution fallback path exists in mediated mode.

The sidecar-governance layer complements seccomp; it does not replace kernel containment.

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

`filesystem.delete` is still a supported mapping, but the shipped managed
baselines no longer deny it. Seccomp cannot encode path scopes, so denying the
delete syscalls blocks deletes everywhere — including inside the workspace, which
breaks tools like Cargo. Workspace-scoped delete is instead enforced
structurally by the bwrap backend: a read-only rootfs with a read-write
workspace (and runtime home), so deletes outside the workspace fail on the
read-only mount. Operators can still opt back into the syscall-level deny with a
custom policy via `FIRMA_MANAGED_POLICY`.

### Current syscall mapping

1. `system.execute` -> `execve`, `execveat`
2. `filesystem.delete` -> `unlink`, `unlinkat`, `rmdir`, `rename`, `renameat`, `renameat2`
3. `credential.write` -> `setuid`, `setgid`, `setresuid`, `setresgid`

### Fidelity caveats

1. Seccomp is syscall-number enforcement, not semantic policy interpretation.
2. No argument/path-level expression at kernel layer (`filesystem.delete` cannot encode path scopes like workspace-only).
3. `rename*` blocking is intentionally conservative and may block benign atomic-update flows.
4. Arch-specific syscall surfaces differ (`aarch64` behavior may map through `*at` variants where older syscall variants are absent).
5. Dynamic context (HITL and tenant/session business logic) must stay in userspace governance.

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
9. Runtime canonicalizes the executable path (resolving symlinks, enforcing UTF-8) before governance request construction.
10. When `enforce_known_executables=true`, canonical executable is checked against `allowed_executables`. Any executable not in the list is fail-closed.
11. Mediator request includes `sandbox_id` + `session_id` for identity/session binding.

## Local-Exec Governance Contract

### Configuration

`sidecar_local_exec` supports:

1. `tcp://host:port`
2. `unix:///absolute/path.sock`
3. On Unix hosts, governed mode requires `unix://` endpoint for peer-credential validation.

`timeout_ms` must be `> 0`.

Optional governance controls:

1. `hitl_mode = "sync_wait" | "async_token"` (default: `sync_wait`).
2. `enforce_known_executables = true|false` (default: `false`).
3. `allowed_executables = ["/usr/bin/bash", "/bin/sh", "/usr/bin/python3"]` (required when enforcement is enabled; entries must be absolute canonical paths).
4. If `endpoint` is omitted and sidecar endpoint is unix socket, runtime derives `*-tools.sock` next to sidecar socket.
5. On Unix hosts, `sidecar_endpoint` must also use `unix://` when `sidecar_local_exec` is enabled.

### Request (JSON line)

```json
{"action":"local.exec","executable":"...","args":[...],"sandbox_id":"...","session_id":"...","agent_id":"optional","profile":"...","hitl_mode":"sync_wait|async_token","request_fingerprint":"optional-sha256hex","approval_token":"optional-token-id"}
```

### Response (JSON line)

```json
{"decision":"allow|deny|pending_hitl","reason":"optional","approval_token":"optional","retry_after_ms":500}
```

Decision handling:

1. `allow` -> launch proceeds.
2. `deny` -> blocked.
3. `pending_hitl` with `sync_wait` -> blocked (explicit pending fail-closed).
4. `pending_hitl` with `async_token` -> runtime enters internal retry loop, carrying `approval_token` on subsequent requests.
5. Missing token for async mode -> blocked (invalid pending state).
6. Retry deadline exceeded (`hitl_max_wait_ms`) -> blocked (fail-closed timeout).
7. Any other/invalid response -> blocked.

### HITL Runtime Model

1. `sync_wait`: governance endpoint must return final `allow|deny` in request timeout window.
2. `async_token`: governance endpoint may return `pending_hitl` with `approval_token`; runtime sleeps `retry_after_ms` and retries internally until `allow|deny` or `hitl_max_wait_ms` expires.
3. No background in-place escalation of an already running sandbox process.

### Non-Cooperative Anti-Bypass Guarantees

Current guarantees:

1. Cooperative governed path has one mandatory pre-exec mediation point in runtime.
2. No runtime fail-open fallback when mediator is configured.
3. Optional executable allowlist blocks unknown launch targets before execution.

Current limits:

1. Arbitrary child processes spawned after initial launch are constrained primarily by sandbox/seccomp/namespace boundaries.
2. Sidecar governance is not itself a full containment boundary for non-cooperative process trees.

Required deployment position:

1. Treat Sidecar local-exec governance as control for governed execution path.
2. Treat kernel sandboxing and seccomp as containment baseline.
3. Add optional operator kernel controls (for example eBPF LSM) when stronger non-cooperative guarantees are required.

## Default Linux Behavior

For `generic` profile on Linux + `bwrap`:

1. Managed seccomp default-enabled.
2. Source policy defaults to bundled `crates/firma-run/policies/generic-local-command-v1.toml`.
3. Artifact root defaults to `<system-temp>/firma/seccomp-artifacts` (resolved via `std::env::temp_dir()`).
4. Runtime mode defaults to `compile_on_launch`.

Optional overrides:

1. `FIRMA_RUN_MANAGED_SECCOMP_POLICY_PATH`
2. `FIRMA_RUN_MANAGED_SECCOMP_ARTIFACT_DIR`
3. `FIRMA_RUN_MANAGED_SECCOMP_RUNTIME_MODE`
4. `FIRMA_RUN_MANAGED_SECCOMP_DISABLE_DEFAULT`
5. `FIRMA_RUN_REQUIRE_LOCAL_EXEC_GOVERNANCE` (when `true`, runtime fails startup unless `sidecar_local_exec` is configured)

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
just managed-seccomp-compat-check
```

## CI/Local Validation

Primary deterministic gate:

```bash
just managed-seccomp-guardrail
```

Recommended runtime validation:

1. Artifact/metadata generation and integrity inspection.
2. Fail-closed behavior for policy resolution/load failures.
3. Mediated mode fail-closed behavior for allow/deny/pending/unavailable/invalid-response.
4. Executable allowlist enforcement behavior when enabled.

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

### Step 3: Compatibility + Guardrail Gate

```bash
just managed-seccomp-compat-check
just managed-seccomp-guardrail
```

### Step 4: Explicit Mediator Tests

Create `/tmp/firma-run.mediator.toml`:

```toml
[profiles.generic]
backend = "bwrap"
sidecar_endpoint = "unix:///tmp/firma-sidecar.sock"

[profiles.generic.seccomp_policy]
source_policy_path = "/ABS/PATH/TO/crates/firma-run/policies/generic-local-command-v1.toml"
artifact_dir = "/ABS/PATH/TO/.artifacts/seccomp-artifacts"
verify_checksum = true
runtime_mode = "compile_on_launch"

[profiles.generic.sidecar_local_exec]
endpoint = "unix:///tmp/firma-sidecar-tools.sock"
timeout_ms = 500
hitl_mode = "async_token"
enforce_known_executables = true
allowed_executables = ["/usr/bin/echo", "/usr/bin/bash", "/bin/sh"]
```

Allow response server example (for isolated local testing only; production uses the
real sidecar `[local_exec]` endpoint — see `docs/configuration.md`):

```bash
python3 - <<'PY'
import os, socket
path = "/tmp/firma-sidecar-tools.sock"
try:
    os.unlink(path)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
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
cargo run -p firma -- run \
  --profile generic \
  --config /tmp/firma-run.mediator.toml \
  --sidecar unix:///tmp/firma-sidecar.sock \
  -- /bin/echo mediator-allow
```

Repeat with decision responses:

1. `{"decision":"deny","reason":"blocked-by-policy"}` -> must fail closed.
2. `{"decision":"pending_hitl","reason":"awaiting-approval"}` with `sync_wait` -> must fail closed.
3. `{"decision":"pending_hitl","reason":"awaiting-approval","approval_token":"tok_123","retry_after_ms":500}` with `async_token` -> runtime should retry internally and only proceed on final `allow`.
4. governance endpoint stopped/unavailable -> must fail closed.
5. response missing `approval_token` in async mode -> must fail closed.
6. persistent `pending_hitl` responses beyond `hitl_max_wait_ms` -> must fail closed.
7. run non-allowlisted executable (`/usr/bin/env`) -> must fail closed before launch.

### Step 5: Negative Config Validation

1. `endpoint = "unix://relative.sock"` -> validation error (requires absolute path).
2. `timeout_ms = 0` -> validation error.

### Step 6: Final Acceptance

All must be true:

1. `cargo test -p firma-run -- --nocapture` passes.
2. `just managed-seccomp-compat-check` passes.
3. `just managed-seccomp-guardrail` passes.
4. Sidecar local-exec governance allow/deny/pending/unavailable behavior matches fail-closed model.
5. No direct exec fallback path observed in mediated mode.
6. Allowlist enforcement blocks unknown executable when enabled.

## Operations and Rollback

### Publish/Promote

1. Update policy source (`policy_id`, `policy_version`, deny actions).
2. Run compatibility + runtime validation commands.
3. Promote artifact version through profile config (or precompiled-only path).

### Rollout Strategy

1. Current baseline: Linux `generic` + `bwrap` default-enables managed static seccomp.
2. Phase 1: opt-in profile enables sidecar local-exec mediation for governed workflows.
3. Phase 2: enable executable allowlist in governed environments after command inventory stabilization.
4. Phase 3: default-enable governed local-exec mediation for target profile(s) once latency and fail-closed gates pass.
5. Phase 4: deprecate unmanaged launch patterns for governed mode.

### Incident Rollback

1. Switch to previous known-good artifact version.
2. If needed, temporarily disable generic managed default with:
   `FIRMA_RUN_MANAGED_SECCOMP_DISABLE_DEFAULT=1`
3. Re-enable only after compatibility + runtime validation pass.

## Notes

1. Production enforcement logic is in Rust runtime path (`seccomp` + mediator gate), not in shell scripts.
2. BPF program compilation uses the [`seccompiler`](https://crates.io/crates/seccompiler) crate
   (rust-vmm/Firecracker) rather than hand-emitted BPF opcodes. Per-arch syscall-number
   resolution uses `seccompiler::SyscallTable` (from a `lu-zero/seccompiler` fork branch
   pending upstream, gated behind the `syscall-table` feature) instead of a hand-maintained
   numeric table; `crates/firma-run/src/seccomp.rs` has a regression test pinning its output
   against the previously hand-maintained numbers.
