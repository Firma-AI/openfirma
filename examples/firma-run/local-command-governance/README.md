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
FIRMA_SHOWCASE_SIDECAR_ENDPOINT="tcp://127.0.0.1:18080" \
FIRMA_SHOWCASE_MEDIATOR_ENDPOINT="unix:///run/firma/sidecar-tools.sock" \
./examples/firma-run/local-command-governance/scripts/run-allow.sh
```

## Notes

1. The mock local-exec governance endpoint uses Unix socket at `.artifacts/firma-local-command-governance/sidecar-tools.sock`.
2. The mock sidecar liveness stub uses TCP on `127.0.0.1:28992`.
3. Scripts inject `FIRMA_BUDGET_STATE_REF` to demonstrate budget context propagation.
4. Seccomp artifacts are generated under `.artifacts/firma-local-command-governance/` in repo root.
5. For real rollout validation, also run:

```bash
make managed-seccomp-compat-check
make managed-seccomp-guardrail
```
