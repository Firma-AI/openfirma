# Local Firma Run Setup

This example prepares a local `.local/` runtime directory for experimenting
with `firma run` and `firma-sidecar`.

## Scripts

- `setup.sh` / `setup.ps1` copy example Sidecar and mapping configs into
  `.local/` and generate a local audit signing key.
- `run.sh` / `run.ps1` run an arbitrary command through `firma run`.
- `preflight.sh` / `preflight.ps1` check whether the host has the expected
  runtime dependencies for the default backend.
- `renew-capability.sh` / `renew-capability.ps1` issue a fresh capability seed
  through `firma-authority`.

## Assets

`assets/` contains the example Sidecar and mapping templates copied by the setup
scripts. Edit the generated files under `.local/`; keep the templates here as
known-good starting points.

## Documentation

Additional local setup and verification notes live under `docs/` in this
directory.
