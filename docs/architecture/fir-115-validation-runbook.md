# FIR-115 Validation Runbook (Linux, End-to-End)

Status: active verification procedure  
Date: 2026-05-13  
Scope: `firma run` Linux `bwrap` path with managed static seccomp and optional command mediator

## Purpose

This runbook validates FIR-115 from a clean checkout with explicit, reproducible steps.

It covers:

1. Managed static seccomp compilation/load path.
2. Artifact metadata/checksum/trust-path fail-closed checks.
3. Performance guardrail (`<= 3%` overhead budget).
4. Optional userspace command mediator fail-closed gating.

## Preconditions

Supported host/runtime constraints:

1. Linux.
2. `x86_64` or `aarch64`.
3. Kernel `>= 4.14`.
4. `bwrap` installed and executable.
5. Rust toolchain + `cargo`.
6. `sha256sum` available.

Quick check:

```bash
uname -s
uname -m
uname -r
command -v bwrap
command -v cargo
command -v sha256sum
```

## Step 1: Fresh Checkout and Clean Build State

```bash
git fetch --all
git checkout <fir-115-branch>
git pull --ff-only
cargo clean
```

## Step 2: Build and Unit Validation

Build release binary:

```bash
cargo build -p firma --release
```

Run full `firma-run` test suite:

```bash
cargo test -p firma-run -- --nocapture
```

Expected:

1. All tests pass.
2. No failures in `seccomp`, `config`, `runtime`, `mediator`.

## Step 3: Managed Seccomp Compatibility Gate

```bash
make managed-seccomp-compat-check
```

Expected:

1. `[ok] managed seccomp compatibility check passed`.
2. Output includes kernel release, architecture, and seccomp actions list.

## Step 4: Full Guardrail (Perf + Fail-Closed Matrix)

Primary command:

```bash
make managed-seccomp-guardrail
```

Faster local smoke option:

```bash
MANAGED_SECCOMP_GUARDRAIL_ITERATIONS=3 \
MANAGED_SECCOMP_GUARDRAIL_INNER_LOOPS=20 \
make managed-seccomp-guardrail
```

What this validates:

1. Baseline benchmark run.
2. Managed-seccomp benchmark run.
3. Overhead gate `<= 3%` average latency overhead.
4. Artifact + metadata generation and integrity inspection.
5. Fail-closed scenarios:
6. missing policy source
7. missing precompiled artifact
8. invalid metadata format
9. checksum mismatch
10. invalid readable BPF (checksum-valid, load-rejected)
11. unloadable artifact
12. focused seccomp unit tests in release profile

Expected final signal:

1. `[ok] managed seccomp guardrail passed`.
2. `guardrail_output_dir=...` printed.

Artifacts are stored under:

1. `.spike-output/managed-seccomp-guardrail-<timestamp>/`

## Step 5: Explicit Mediator-Gating Validation

This step verifies mandatory pre-exec command mediation when configured.

### 5.1 Create a mediator-enabled profile config

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

Notes:

1. `source_policy_path` must be absolute.
2. `command_mediator.timeout_ms` must be `> 0`.

### 5.2 Allow path (launch should proceed through mediator gate)

Terminal A:

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

Terminal B:

```bash
target/release/firma run \
  --profile generic \
  --config /ABS/PATH/TO/tmp/firma-run.mediator.toml \
  --sidecar-endpoint tcp://127.0.0.1:65535 \
  -- /bin/echo mediator-allow
```

Expected:

1. Mediator decision is `allow`, launch path passes governance gate.
2. Any later failure would be from downstream runtime dependencies, not mediation gate.

### 5.3 Deny path (must fail closed)

Terminal A responder decision:

```json
{"decision":"deny","reason":"blocked-by-policy"}
```

Terminal B same `firma run` command.

Expected:

1. Non-zero exit.
2. Error indicates governance denial.
3. Wrapped command does not execute.

### 5.4 Pending HITL path (must fail closed)

Responder decision:

```json
{"decision":"pending_hitl","reason":"awaiting-approval"}
```

Expected:

1. Non-zero exit.
2. Launch blocked in fail-closed mode.

### 5.5 Mediator unavailable path (must fail closed)

Stop mediator listener and run the same command.

Expected:

1. Non-zero exit.
2. Error indicates mediator unavailable in fail-closed mode.
3. No direct exec fallback path.

## Step 6: Config-Negative Validation

### 6.1 Relative Unix socket path should fail validation

Set:

```toml
[profiles.generic.command_mediator]
endpoint = "unix://relative.sock"
timeout_ms = 500
```

Expected:

1. Validation error: unix endpoint path must be absolute.

### 6.2 Zero timeout should fail validation

Set:

```toml
[profiles.generic.command_mediator]
endpoint = "tcp://127.0.0.1:28991"
timeout_ms = 0
```

Expected:

1. Validation error: `command_mediator.timeout_ms must be > 0`.

## Step 7: Acceptance Checklist

Declare FIR-115 validation successful only if all are true:

1. `cargo test -p firma-run -- --nocapture` passes.
2. `make managed-seccomp-compat-check` passes.
3. `make managed-seccomp-guardrail` passes.
4. Mediator allow/deny/pending/unavailable behavior matches fail-closed model.
5. No bypass path observed when mediator is configured.

## Operational Notes

1. `scripts/ci/managed-seccomp-guardrail.sh` is both CI automation and local reproducible harness.
2. Production enforcement logic is in Rust runtime path (`seccomp` + mediator gate), not in the shell script.
3. Seccomp policy update model remains static-per-sandbox-process: new artifact version + relaunch.
