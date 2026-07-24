# Release OpenFirma

OpenFirma releases start from GitHub Actions. Do not edit versions or push
release tags manually.

## Repository setup

Configure these Actions secrets before preparing a release:

- `RELEASE_PR_TOKEN`: a GitHub App token or fine-grained token that can push a
  branch and open a pull request. Do not use the workflow's `GITHUB_TOKEN`:
  GitHub does not start PR workflows for pull requests it creates.
- `HOMEBREW_TAP_TOKEN`: a token with write access to
  `Firma-AI/homebrew-openfirma`. A missing token fails the release rather than
  leaving Homebrew on an older version.

Make `Validate PR metadata`, `Release tooling`, and `Release E2E` required
checks. `Release E2E` is inexpensive on ordinary PRs and runs the full
Claude/Codex matrix only for same-repository `release/v*` PRs. It also supports
merge queue candidates. Require release PRs to be up to date with `main` before
merging.

## Prepare a release

Start the `Prepare Release` workflow on `main` and choose `patch`, `minor`, or
`major`:

```bash
gh workflow run prepare-release.yml -f bump=patch
```

The workflow:

1. Uses `cargo-release` to bump the shared workspace version and versioned path
   dependencies.
2. Refreshes and validates `Cargo.lock` and `fuzz/Cargo.lock`.
3. Generates `docs/release/vX.Y.Z.md` from the dedicated `Release note` fields
   of merged PRs.
4. Pushes `release/vX.Y.Z` and opens `chore(release): vX.Y.Z`.

The generated notes use a fixed user-facing taxonomy: Breaking changes,
Security, Added, Fixed, Changed, and Documentation. `ai`, `build`, `chore`,
`ci`, `refactor`, and `test` changes are omitted. Entries link back to their
PRs; full PR bodies and internal verification details are never rendered.

## Review the release PR

Review the version changes, both lockfiles, and the generated release notes.
Edit the notes in the release PR when a clearer summary or ordering would help
users. The release-note validator rejects unexpected headings, a mismatched
version, and notes larger than 30,000 characters.

The release PR records the exact `main` commit covered by its notes. If `main`
advances while the PR is open, its required candidate check fails. Close that
PR, delete its `release/vX.Y.Z` branch, and dispatch a new release so the version
and notes are regenerated from the new release range.

The release PR runs normal CI and the complete Linux/macOS by Claude/Codex E2E
matrix. Do not merge until those checks pass.

## Publish

Merge the release PR. The `Release` workflow then operates on that exact merge
commit and only performs release packaging:

1. Validate the merged version, lockfiles, branch, title, and reviewed notes.
2. Build six platform archives with `cargo build --locked`.
3. Create an annotated `vX.Y.Z` tag after every build succeeds.
4. Publish the GitHub Release with the reviewed notes, archives, and checksums.
5. Update the Homebrew tap.

No E2E tests run after merge. If packaging or publication fails, rerun the
failed workflow. Reruns accept an existing tag only when it already points to
the same merge commit.

## Verify installation

After publication, verify the install path and basic commands:

```bash
brew uninstall firma 2>/dev/null || true
curl -sSf https://install.openfirma.ai | sh
firma --version
firma config --help
firma sidecar start --help
```

The installer prefers Homebrew on macOS when `brew` is available. Confirm the
tap reports the same version as the GitHub Release before announcing it.
