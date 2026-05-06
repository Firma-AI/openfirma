# Firma Run E2E harness

This example verifies that `firma run` can launch a governed command, route its traffic through the Sidecar, emit audit events, and fail closed when the Sidecar is unavailable.

It is Linux-only because it validates the structural sandbox path that depends on the `bwrap` backend.

## Run it

From the repository root:

```bash
examples/firma-run/e2e/run.sh
```

Useful variants:

```bash
examples/firma-run/e2e/run.sh --https-check
examples/firma-run/e2e/run.sh --profile claude-code
examples/firma-run/e2e/run.sh --claude-acceptance
examples/firma-run/e2e/run.sh --keep-artifacts
```

`--keep-artifacts` preserves the temporary configs and logs so you can inspect failures.

## What it checks

The harness starts a temporary `firma-sidecar`, runs a command through `firma run`, confirms audit output was written, stops the Sidecar, and then confirms that the next wrapped command fails instead of bypassing enforcement.
