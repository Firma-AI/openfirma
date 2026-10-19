# Local Firma Run setup

This folder helps you prepare a local `.local/` workspace for experimenting with `firma run`, a local Authority, and a per-session Sidecar.

Use it when you want to run an agent command through Firma on your own machine without committing local keys, policies, or runtime files.

## Quick start

From the repository root:

```bash
examples/firma-run/local/setup.sh
cargo run -p firma -- config --yes --mode agent-local --profile codex \
  --agent-id agt_01j0000000e008000000000001 --output-dir .local
cargo run -p firma -- authority --config .local/firma.toml
```

In a second terminal, run the agent with a per-session Sidecar:

```bash
cargo run -p firma -- run --config .local/firma.toml --profile codex \
  --authority https://127.0.0.1:50051 --sidecar local -- codex
```

Every Sidecar requires the Authority: it publishes the policy and mapping
snapshot, and traffic no mapping rule classifies is denied.

PowerShell users can run the equivalent setup script:

```powershell
pwsh ./examples/firma-run/local/setup.ps1
```

## What the setup script creates

The setup script creates `.local/` at the repository root. It copies starter config files from `assets/` and generates a local audit signing key. `firma config` then completes the `[authority]` section, generates the Authority key and TLS material, and lists `mapping-rules.toml` plus the profile's shipped mappings in `[authority].mapping_rules_paths`.

Generated files are intentionally local-only. Edit `.local/` when testing; leave `assets/` as clean templates.

For Linux seccomp-policy hardening, an additional run-profile template is
available:

- `assets/firma_run.local.example.toml` (seccomp policy pipeline)

## Scripts

- `setup.sh` / `setup.ps1` create `.local/` config from the templates.
- `run.sh` / `run.ps1` run any command through `firma run`.
- `preflight.sh` / `preflight.ps1` check whether the host has the expected backend tools.

## More detail

The `docs/` folder contains focused local runbooks for Codex, Claude Code, verification, and ready-to-work setup flows.
