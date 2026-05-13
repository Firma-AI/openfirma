# Local Command Governance Showcase

This folder provides runnable examples for Linux local-command enforcement with managed static seccomp + optional mediator governance.

These examples are for review/testing/showcase. They are not production runtime components.

## What You Can Demo

1. Allow path: mediator returns `allow` and command executes.
2. Deny path: mediator returns `deny` and launch fails closed.
3. HITL async path: mediator returns `pending_hitl` with token and launch fails closed with retry context.
4. Allowlist anti-bypass: non-allowlisted executable blocked before launch.
5. Tampered artifact: checksum mismatch blocks launch.

## Prerequisites

1. Linux host.
2. `cargo` available.
3. `python3` available for the mock mediator helper only (dev/test utility).

Build once:

```bash
cargo build -p firma --release
```

## Quick Start

Run each scenario from repo root:

```bash
./examples/firma-run/local-command-governance/scripts/run-allow.sh
./examples/firma-run/local-command-governance/scripts/run-deny.sh
./examples/firma-run/local-command-governance/scripts/run-hitl-async.sh
./examples/firma-run/local-command-governance/scripts/run-allowlist-block.sh
./examples/firma-run/local-command-governance/scripts/run-tampered-artifact.sh
```

Each script prints whether the expected behavior occurred.

If you already run real local services, you can override endpoints:

```bash
FIRMA_SHOWCASE_SIDECAR_ENDPOINT="unix:///run/firma/sidecar.sock" \
FIRMA_SHOWCASE_MEDIATOR_ENDPOINT="unix:///run/firma/sidecar-tools.sock" \
./examples/firma-run/local-command-governance/scripts/run-allow.sh
```

## Manual Run (No Helper Script)

If you want to validate the real `firma run` flow manually, use these exact steps.

1. Start mock Sidecar liveness endpoint (Terminal A):

```bash
python3 examples/firma-run/local-command-governance/scripts/mock_sidecar.py \
  --unix-path /tmp/firma-sidecar.sock
```

2. Start mock local-exec governance endpoint (Terminal B):

```bash
python3 examples/firma-run/local-command-governance/scripts/mock_mediator.py \
  --mode allow \
  --unix-path /tmp/firma-sidecar-tools.sock
```

3. Create runtime config (Terminal C):

```bash
cat >/tmp/firma-run.mediator.toml <<'EOF'
[profiles.generic]
backend = "bwrap"
sidecar_endpoint = "unix:///tmp/firma-sidecar.sock"

[profiles.generic.seccomp_policy]
source_policy_path = "/home/dario/Work/Firma/firma-oss/crates/firma-run/policies/generic-local-command-v1.toml"
artifact_dir = "/home/dario/Work/Firma/firma-oss/.artifacts/seccomp-artifacts"
verify_checksum = true
runtime_mode = "compile_on_launch"

[profiles.generic.sidecar_local_exec]
endpoint = "unix:///tmp/firma-sidecar-tools.sock"
timeout_ms = 500
hitl_mode = "async_token"
enforce_known_executables = true
allowed_executables = ["echo", "bash", "sh"]
EOF
```

4. Run `firma run` directly:

```bash
cargo run -p firma -- run \
  --profile generic \
  --config /tmp/firma-run.mediator.toml \
  --sidecar-endpoint unix:///tmp/firma-sidecar.sock \
  -- /bin/echo FIRMA_OK
```

Expected result:

1. Runtime logs `resolved managed static seccomp artifact ... policy.bpf`.
2. Runtime logs mediator decision `allow`.
3. Terminal prints `FIRMA_OK`.

Quick fail-closed checks:

1. Change mediator mode to `deny`: command must be blocked.
2. Change mediator mode to `hitl_async`: command must be blocked with pending-HITL context.
3. Run `./examples/firma-run/local-command-governance/scripts/run-tampered-artifact.sh`: checksum mismatch must block launch.

## Notes

1. The mock local-exec governance endpoint uses Unix socket at `${XDG_RUNTIME_DIR:-/tmp}/firma-showcase-sidecar-tools.sock` (override with `FIRMA_SHOWCASE_MEDIATOR_UNIX_PATH`).
2. The mock sidecar liveness stub uses Unix socket at `${XDG_RUNTIME_DIR:-/tmp}/firma-showcase-sidecar.sock` (override with `FIRMA_SHOWCASE_SIDECAR_UNIX_PATH`).
3. Scripts inject `FIRMA_BUDGET_STATE_REF` to demonstrate budget context propagation.
4. Seccomp artifacts are generated under `.artifacts/firma-local-command-governance/` in repo root.
5. For real rollout validation, also run:

```bash
make managed-seccomp-compat-check
```
