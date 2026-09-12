# Release OpenFirma

OpenFirma releases are exported from the private Firma Team source repository
and published by GitHub Actions. Do not edit versions or push release tags in
this public snapshot repository.

## Prepare and validate the release

Release metadata is source-owned. Prepare and review it in Firma Team before
exporting a release snapshot. The committed workspace version and newest
`CHANGELOG.md` release must match. Review the complete candidate diff, paying
particular attention to:

- The proposed version.
- The new `CHANGELOG.md` section and its links.
- Generated dependency and lockfile changes.
- The `Firma-Team-Source` and `OpenFirma-Tree-SHA256` commit trailers.

Firma Team CI validates the deterministic standalone snapshot before it is
published. The public `Snapshot Candidate` workflow then packages the workspace
without publishing and runs a non-publishing cargo-dist artifact build.
Promotion fails closed unless its single `Snapshot gate` job succeeds for the
exact candidate SHA.

## Publish

After the approved candidate is promoted to public `main`, `Publish Release
Tag` revalidates its metadata and provenance trailer format and creates
`v<version>` at that exact `main` SHA. The tag-triggered `Release` workflow
publishes the GitHub Release and artifacts and updates the Homebrew tap.

Rerunning tag publication is safe only for the same SHA; an existing tag at any
other SHA fails. If artifact publication fails, rerun it for the same tag. Do
not move or create a release tag by hand.

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
