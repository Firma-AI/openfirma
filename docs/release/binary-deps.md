# firma-sidecar release binary dependency snapshot

Placeholder — populated by `examples/release/binary-deps/snapshot.sh` on each
release host.

Run from the repo root after `cargo build --release -p firma-sidecar`:

```bash
./examples/release/binary-deps/snapshot.sh
```

The script overwrites this file with the host's `otool -L` (macOS) or
`ldd` (Linux) output plus a captured timestamp. Commit the updated
file so reviewers can see runtime-dependency drift.
