# E2E Tests

End-to-end validation of the OpenFirma enforcement boundary against real coding
agent workloads. Covers Claude Code and Codex CLI as the primary targets for
v0.1.3+.

## Prerequisites

- At least one agent installed: `claude` (Claude Code) or `codex` (Codex CLI)
- `bwrap` on Linux; `vz` sandbox on macOS (provided by the OS)

## Running locally

```sh
make e2e
```

The nextest `e2e` profile builds `firma` automatically unless `FIRMA_BIN`
is already set to a prebuilt binary.

Run only Claude or only Codex scenarios:

```sh
cargo nextest run -p firma --test e2e --profile e2e -E 'test(claude::)'
cargo nextest run -p firma --test e2e --profile e2e -E 'test(codex::)'
```

Run a single scenario:

```sh
cargo nextest run -p firma --test e2e --profile e2e -E 'test(claude::normal_llm_call)'
```

Use a prebuilt release binary to skip the build step:

```sh
FIRMA_BIN=./target/release/firma make e2e
```

## Scenarios

Each scenario runs in two phases:

1. **Baseline** — agent runs directly (no firma). Confirms the agent can complete
   the task and reach the mock server when unconfined.
2. **Enforcement** — agent runs under `firma run`. Confirms enforcement produces
   the expected ALLOW or DENY outcome and emits the correct audit events.

## Audit output

Each enforcement phase writes a JSONL audit log to a temp directory. The harness
parses it automatically. To inspect it manually, set `FIRMA_KEEP_TMPDIR=1` (if
supported) or look for the temp path printed on test failure.

## CI

The CI matrix (`e2e-tests.yml`) runs on `ubuntu-latest` (bwrap) and
`macos-latest` (vz) for each agent. The sandbox backend is selected automatically
by the OS — no manual configuration is needed.
