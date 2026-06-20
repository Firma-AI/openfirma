# Release checklist

Use this when cutting a new OpenFirma release. The goal is to keep prebuilt
installers, the Homebrew tap, and the docs in sync.

## Before tagging

1. Confirm `workspace.package.version` in the root `Cargo.toml` matches the tag
   you are about to ship (without the leading `v`).
2. Run CI-parity checks locally:

   ```bash
   just check
   ```

3. Confirm `main` is green in GitHub Actions.

## Cut the release

1. Tag and push:

   ```bash
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

2. Watch the release workflow:

   ```bash
   gh run watch --repo Firma-AI/openfirma
   ```

   The workflow builds six platform tarballs/zip files, generates a changelog
   with git-cliff, and publishes the GitHub Release assets.

## After the GitHub Release is published

1. Bump the Homebrew tap (automated when `HOMEBREW_TAP_TOKEN` is configured,
   or run manually):

   ```bash
   ./scripts/update-homebrew-tap.sh 0.1.0
   ```

   Commit and push the result to `Firma-AI/homebrew-openfirma`.

2. Verify the install path end-to-end:

   ```bash
   brew uninstall firma 2>/dev/null || true
   curl -sSf https://install.openfirma.ai | sh
   firma --version
   firma config --help
   firma sidecar start --help
   ```

3. Smoke-test the quickstart on macOS and Linux:

   ```bash
   firma config --yes
   firma sidecar start --detach
   firma run -- echo hello
   firma monitor --tail
   ```

## Notes

- The installer prefers Homebrew on macOS when `brew` is available. If the tap
  lags the GitHub Release, users get a stale binary — always bump the tap in the
  same release window.
- Release notes for each version live in `docs/release/v0.x.y.md`. Update that
  file in the same PR as the version bump when the user-facing story changes.
