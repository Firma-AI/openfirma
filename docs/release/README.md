# Release OpenFirma

OpenFirma releases are prepared and published by GitHub Actions. Do not edit
versions or push release tags manually.

## Prepare the release

Dispatch the `Prepare Release` workflow on `main`:

```bash
gh workflow run prepare-release.yml
```

The workflow infers the next SemVer version from the changes since the previous
release. There is no version-bump input. When preparation finishes, it opens a
release PR containing the proposed version and changelog.

## Review the release PR

Review the complete diff, paying particular attention to:

- The proposed version.
- The new `CHANGELOG.md` section and its links.
- Any generated dependency or lockfile changes.

Edit the changelog when an entry needs clearer user-facing wording. If the
release PR becomes stale, dispatch `Prepare Release` again and review the
updated candidate.

Do not merge until every required check passes, including the release E2E
matrix. Changes that land immediately ahead of the release PR in the merge
queue may be included in the release without appearing in its changelog. This
narrow ordering race is accepted.

## Publish

Merge the release PR, then monitor the workflows triggered by the merge. A
successful run creates the version tag, publishes the GitHub Release and its
artifacts, and updates the Homebrew tap.

If publication fails, rerun the failed workflow. Do not create the tag or
partially publish the release by hand.

## Verify the release

After publication, verify the install path and basic commands:

```bash
brew uninstall firma 2>/dev/null || true
curl -sSf https://install.openfirma.ai | sh
firma --version
firma config --help
firma sidecar start --help
```

Confirm that the installed version matches the GitHub Release and that the
Homebrew tap reports the same version before announcing the release.
