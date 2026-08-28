# Local Firma Run setup

This folder helps you prepare a local `.local/` workspace for experimenting with `firma run` and `firma-sidecar`.

Use it when you want to run an agent command through Firma on your own machine without committing local keys, policies, or runtime files.

## Quick start

From the repository root:

```bash
examples/firma-run/local/setup.sh
cargo run -p firma -- sidecar -c .local/firma.toml
examples/firma-run/local/run.sh -- curl https://example.com
```

PowerShell users can run the equivalent setup script:

```powershell
pwsh ./examples/firma-run/local/setup.ps1
```

## What the setup script creates

The setup script creates `.local/` at the repository root. It copies starter config files from `assets/` and generates a local audit signing key.

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
