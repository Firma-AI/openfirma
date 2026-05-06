# Firma Run examples

These examples show how to run an agent command through `firma run` instead of launching it directly.

`firma run` gives each agent run a profile, session identity, environment, and routing path to the Sidecar. The examples here are meant for local development: they help you prepare a local config, run smoke tests, and inspect what happens when traffic is forced through the governed path.

## Start here

If you want to try the wrapper locally, begin with `local/`:

```bash
examples/firma-run/local/setup.sh
cargo run -p firma-sidecar -- -c .local/firma_sidecar.local.toml
cargo run -p firma-run -- run --profile generic -- curl https://example.com
```

If you are on Linux and want to verify the structural sandbox path, use the E2E harness:

```bash
examples/firma-run/e2e/run.sh
```

## Folders

- `local/` contains setup scripts, config templates, capability renewal helpers, and local runbook docs.
- `e2e/` contains the Linux end-to-end harness for sandbox routing, audit output, and fail-closed behavior.

Each folder keeps its scripts, documentation, and supporting assets together so example-specific material does not live in the main `docs/` tree.
