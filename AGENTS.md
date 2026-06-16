# AGENTS.md

Guidance for coding agents working in this repository.

## Build Commands

```bash
make check # Run fmt + lint + test + build (CI parity)
make fmt # cargo fmt --check
make lint # cargo clippy --workspace -- -D warnings
make test # cargo nextest run + cargo test --doc
make build # cargo build --workspace
```

Tests run via `cargo nextest` (process-per-test isolation); doctests run
separately via `cargo test --doc` since nextest does not run them.

Single crate: `cargo nextest run -p firma-sidecar`
Single test: `cargo nextest run -p firma-sidecar test_enforce_happy_path`

Requires `protoc` installed for `firma-proto` protobuf compilation.

## Documentation

After any major behavior, architecture, CLI, configuration, or public API change,
update the docs site under `docs-site/` in the same change set. If the change
affects how people should discover or integrate OpenFirma, update
`docs-site/public/llms.txt` as well.

Write docs for a human reader first:

- Start from the user's task or question, not from internal implementation order.
- Keep prose concise, concrete, and free of marketing filler.
- Prefer small examples, commands, and links to related pages over long theory.
- Name important invariants explicitly: fail closed, no network on the hot path,
  deterministic enforcement, and immutable execution envelopes.
- Document sharp edges and operational gotchas when they affect real use.
