# Firma Run E2E Harness

This example validates local `firma run` plumbing end to end on Linux.

`run.sh` starts a temporary `firma-sidecar`, launches a sandboxed command
through `firma run`, checks that audit events were emitted, and verifies the
fail-closed behavior when the Sidecar is unavailable.

```bash
examples/firma-run/e2e/run.sh
examples/firma-run/e2e/run.sh --https-check
examples/firma-run/e2e/run.sh --profile claude-code
examples/firma-run/e2e/run.sh --claude-acceptance
```

Use `--keep-artifacts` to preserve temporary logs and configs for debugging.
