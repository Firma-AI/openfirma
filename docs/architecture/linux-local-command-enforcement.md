# Linux Local Command Enforcement

Status: implementation complete (Linux path)  
Date: 2026-05-13  
Scope: `firma run` + Linux `bwrap` backend

## Overview

This document defines the Linux product architecture for local-command governance and containment.

The model is layered:

1. Kernel-enforced static seccomp as authoritative syscall deny boundary.
2. Optional userspace command mediator for dynamic pre-exec decisions.
3. Deterministic fail-closed behavior across policy resolution and runtime checks.

This is the canonical architecture + operations + validation guide for Linux local-command enforcement.

## Design Goals

1. Keep Linux syscall deny enforcement in-kernel and fail-closed.
2. Preserve policy intent where safely mappable into static seccomp.
3. Support controlled policy lifecycle via versioned artifacts.
4. Enable dynamic command governance through a mandatory pre-exec decision gate when configured.
5. Provide reproducible verification and guardrails for latency and failure behavior.

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

## Mediator Contract

### Configuration

`command_mediator` supports:

1. `tcp://host:port`
2. `unix:///absolute/path.sock`

`timeout_ms` must be `> 0`.

### Request (JSON line)

```json
{"action":"local.exec","executable":"...","args":[...],"sandbox_id":"...","session_id":"...","profile":"..."}
```

### Response (JSON line)

```json
{"decision":"allow|deny|pending_hitl","reason":"optional"}
```

Decision handling:

1. `allow` -> launch proceeds.
2. `deny` -> blocked.
3. `pending_hitl` -> blocked (explicit pending fail-closed).
4. Any other/invalid response -> blocked.

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
3. mediator stopped/unavailable -> must fail closed.

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

## Operations and Rollback

### Publish/Promote

1. Update policy source (`policy_id`, `policy_version`, deny actions).
2. Run compatibility + guardrail commands.
3. Promote artifact version through profile config (or precompiled-only path).

### Incident Rollback

1. Switch to previous known-good artifact version.
2. If needed, temporarily disable generic managed default with:
`FIRMA_RUN_MANAGED_SECCOMP_DISABLE_DEFAULT=1`
3. Re-enable only after compatibility + guardrail pass.

## Notes

1. `scripts/ci/managed-seccomp-guardrail.sh` is both CI automation and local reproducible verification harness.
2. Production enforcement logic is in Rust runtime path (`seccomp` + mediator gate), not in shell scripts.
