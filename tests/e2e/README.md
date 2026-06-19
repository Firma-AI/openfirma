# Integration Tests

End-to-end validation of the OpenFirma enforcement boundary against real coding
agent workloads. Covers Claude Code and Codex CLI as the primary targets for
v0.1.3+.

## Prerequisites

- `firma` binary on `PATH` or `FIRMA_BIN` env var pointing to it
- At least one agent installed: `claude` (Claude Code) or `codex` (Codex CLI)
- `bwrap` on Linux; `vz` sandbox on macOS (provided by the OS)

## Running locally

All integration tests are marked `#[ignore]` and are skipped by default.
Pass `--include-ignored` to run them.

Run all scenarios for all available agents:

```sh
cargo test --test e2e -- --include-ignored
```

Run only Claude scenarios:

```sh
cargo test --test e2e -- claude:: --include-ignored
```

Run only Codex scenarios:

```sh
cargo test --test e2e -- codex:: --include-ignored
```

Run a single scenario:

```sh
cargo test --test e2e -- claude::normal_llm_call --include-ignored
```

Use a pre-built release binary to avoid a rebuild:

```sh
FIRMA_BIN=./target/release/firma cargo test --test e2e
```

## Scenarios

| Scenario              | Agents | Expected outcome                                      |
| --------------------- | ------ | ----------------------------------------------------- |
| `normal_llm_call`     | all    | ALLOW — legitimate LLM traffic passes                 |
| `block_paste_service` | all    | DENY — POST to paste service blocked by policy        |
| `block_unlisted_host` | all    | DENY — host not in capability scope                   |
| `tool_call_exfil`     | all    | DENY — exfil POST blocked before reaching destination |
| `direct_tcp_bypass`   | all    | DENY — sandbox blocks raw TCP egress bypassing proxy  |
| `fs_read_deny`        | all    | DENY — sandbox blocks read outside workspace          |
| `fs_delete_deny`      | all    | DENY — sandbox blocks delete outside workspace        |
| `code_fibonacci`      | all    | ALLOW — pure local coding task passes end-to-end      |

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

The CI matrix (`integration-tests.yml`) runs on `ubuntu-latest` (bwrap) and
`macos-latest` (vz) for each agent. The sandbox backend is selected automatically
by the OS — no manual configuration is needed.
