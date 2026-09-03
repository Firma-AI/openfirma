# Firma Run examples

These examples show how to run an agent command through `firma run` instead of launching it directly.

`firma run` gives each agent run a profile, session identity, environment, and routing path to the Sidecar. The examples here are meant for local development: they help you prepare a local config, run smoke tests, and inspect what happens when traffic is forced through the governed path.

## Start here

If you want to try the wrapper locally, begin with `local/`:

```bash
examples/firma-run/local/setup.sh
cargo run -p firma -- sidecar -c .local/firma.toml
cargo run -p firma -- run --profile generic -- curl https://example.com
```

Skip the dedicated Sidecar terminal by relying on autostart — `firma run` spawns a per-run Sidecar as a child and tears it down on exit:

```bash
examples/firma-run/local/setup.sh
cargo run -p firma -- run --sidecar-config .local/firma.toml \
  --profile generic -- curl https://example.com
```

Opt out for CI or production: `--no-autostart` fails loudly if the configured endpoint is unreachable; `--sidecar=external` skips the spawn and only uses an existing Sidecar. See [`docs/cli.md`](../../docs/cli.md) `## firma run` for the full flag list, marker layout, and typed errors.

If you are on Linux and want to verify the structural sandbox path, use the E2E harness:

```bash
examples/firma-run/e2e/run.sh
```

If you want concrete local-command governance scenarios (allow/deny/HITL/allowlist/tamper), use:

```bash
examples/firma-run/local-command-governance/scripts/run-allow.sh
```

## Folders

- `local/` contains setup scripts, config templates, capability renewal helpers, and local runbook docs.
- `e2e/` contains the Linux end-to-end harness for sandbox routing, audit output, and fail-closed behavior.
- `local-command-governance/` contains focused Linux demos for managed static seccomp + mediator governance behavior.
- `spikes/` contains focused research harnesses for architecture decisions.

Each folder keeps its scripts, documentation, and supporting assets together so example-specific material does not live in the main `docs/` tree.
