# E2E Tests

End-to-end validation of the OpenFirma enforcement boundary against real coding
agent workloads.

## Running locally

```sh
make e2e
```

nextest builds the debug `firma` binary as part of compiling the e2e test;
`firma_bin()` reads its path from `CARGO_BIN_EXE_firma` — no manual build needed.

Run only Claude or only Codex scenarios:

```sh
cargo nextest run -p firma --test e2e --run-ignored all -E 'test(claude::)'
cargo nextest run -p firma --test e2e --run-ignored all -E 'test(codex::)'
```

Run a single scenario:

```sh
cargo nextest run -p firma --test e2e --run-ignored all -E 'test(claude::simple_prompt)'
```

## Scenarios

Each scenario runs in two phases:

1. **Baseline** — agent runs directly (no firma). Confirms the agent can complete
   the task and reach the mock server when unconfined.
2. **Enforcement** — agent runs under `firma run`. Confirms enforcement produces
   the expected ALLOW or DENY outcome and emits the correct audit events.
