# Release binary dependency snapshot

This example captures the shared-library dependencies of the release `firma-sidecar` binary on the current host.

Use it before release review when you want to see whether the binary's runtime dependencies changed.

## Run it

```bash
cargo build --release -p firma-sidecar
examples/release/binary-deps/snapshot.sh
```

The script writes `docs/release/binary-deps.md`. Commit that file when the dependency snapshot is intentionally updated.
