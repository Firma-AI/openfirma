# `firma doctor`

Print a structured diagnostic report of "what's installed, what's
reachable, what's configured". The first command to run if anything is
wrong. Per Firma CLI Unified Spec v0.5 §3.7.

`firma doctor` is read-only. It only reads config files and connects to
already-configured sockets/ports — no state is mutated. Safe to run on a
live stack.

## Quickstart

```bash
firma doctor                                    # pretty, all checks
firma doctor --json | jq .                      # machine-readable
firma doctor --config /etc/firma/firma.toml     # explicit unified config
firma doctor --state-dir /run/user/1000/firma   # explicit state dir
firma doctor --timeout-ms 1500                  # slower network probe
```

## Surface

```text
firma doctor [--config <firma.toml>]
             [--state-dir <dir>]
             [--json]
             [--timeout-ms <ms>]
```

## Flags

| Flag           | Env               | Default    | Description                                                    |
| -------------- | ----------------- | ---------- | -------------------------------------------------------------- |
| `--config`     | —                 | discovered | Unified `firma.toml` to inspect. Otherwise auto-discovered.    |
| `--state-dir`  | `FIRMA_STATE_DIR` | resolved   | Override the runtime state directory.                          |
| `--json`       | —                 | _off_      | Emit a single JSON object instead of pretty text.              |
| `--timeout-ms` | —                 | `500`      | Per-probe network timeout (TCP / UDS connect) in milliseconds. |

`firma doctor` resolves the shared `firma.toml` via the same Config
Discovery precedence as every other subcommand (see
[`docs/cli.md`](../cli.md)). It actively consumes `--config` to locate that
unified file. `state_dir` is never a config-file key.

## Status taxonomy

| Status | Meaning                                          |
| ------ | ------------------------------------------------ |
| `OK`   | Check passed.                                    |
| `WARN` | Not applicable on this host, or not configured.  |
| `FAIL` | Configured and broken. Operator action required. |

A fresh install with no stack config is expected to produce a mix of
`OK` and `WARN` lines, never a `FAIL`. `FAIL` always points to something
the operator already declared and that is now misbehaving.

## Check categories

| Category              | What it inspects                                                                 |
| --------------------- | -------------------------------------------------------------------------------- |
| `firma binary`        | `current_exe()` path and crate version.                                          |
| `sandbox bwrap`       | `bwrap --version`. Linux only; `WARN` on macOS / Windows.                        |
| `sandbox vz`          | macOS Virtualization.framework. `WARN` (no CLI probe).                           |
| `sandbox wsl2`        | `wsl.exe --version`. Windows only; `WARN` elsewhere.                             |
| `sandbox firecracker` | `firecracker --version`. Linux only; `WARN` elsewhere.                           |
| `sidecar reachable`   | TCP / UDS connect to the address from `[sidecar.interceptor]` in `firma.toml`.   |
| `authority reachable` | TCP connect to `listen_addr` in `[authority]` of `firma.toml`.                   |
| `config parsed`       | Resolves the unified `firma.toml`; parses `[authority]` + `[sidecar]` sections.  |
| `capability seed`     | `<state_dir>/capabilities/` non-empty.                                           |
| `state dir`           | Existence + mode `0700` (Unix) of the resolved state dir.                        |
| `data dir`            | Existence + mode `0700` (Unix) of `$XDG_DATA_HOME/firma` (or platform fallback). |

Unsupported-on-this-OS sandbox backends always report `WARN`, never
`FAIL`. A backend probe only reports `FAIL` when the host *is* the right
OS and the binary is missing or refuses to run.

## Output

### Pretty (default)

```text
firma doctor
=============
[OK]   firma binary           /usr/local/bin/firma (v0.1.0)
[OK]   sandbox bwrap          bubblewrap 0.8.0 available
[WARN] sandbox vz             framework available on macOS 13+; run-time probe not implemented
[WARN] sandbox wsl2           not supported on linux
[OK]   sandbox firecracker    Firecracker v1.7.0 available
[OK]   sidecar reachable      127.0.0.1:8080
[FAIL] authority reachable    127.0.0.1:50051: connection refused
[OK]   config parsed          ~/.config/firma/firma.toml
[WARN] capability seed        /run/user/1000/firma/capabilities: directory does not exist
[OK]   state dir              /run/user/1000/firma: mode 0700
[WARN] data dir               could not resolve XDG_DATA_HOME / fallback
```

Categories are emitted in a fixed order; columns are left-padded so a
diff between two runs only changes the lines that actually moved.

### JSON (`--json`)

A single top-level object, suitable for `jq` and CI gating.

```json
{
  "checks": [
    {
      "category": "firma binary",
      "status": "ok",
      "reason": "/usr/local/bin/firma (v0.1.0)",
      "detail": {
        "path": "/usr/local/bin/firma",
        "version": "0.1.0"
      }
    },
    {
      "category": "authority reachable",
      "status": "fail",
      "reason": "127.0.0.1:50051: connection refused",
      "detail": { "address": "127.0.0.1:50051" }
    }
  ],
  "worst": "fail",
  "exit_code": 1
}
```

Fields:

| Field       | Type   | Description                                                         |
| ----------- | ------ | ------------------------------------------------------------------- |
| `checks`    | array  | One entry per check, in the order listed under "Check categories".  |
| `worst`     | string | `ok` \| `warn` \| `fail` — worst status across all checks.          |
| `exit_code` | number | The process exit code (`0` or `1`); mirrors the OS-level exit code. |

The `detail` map is omitted when empty. Keys inside `detail` are
category-specific (`path`, `version`, `address`, `mode`, ...).

The schema is append-only within a major release: new check categories
may be added but existing categories will not be renamed or removed
without a major-version bump.

## Reachability semantics

For each of `sidecar reachable` and `authority reachable`:

1. Read the endpoint from the resolved unified `firma.toml`
   (`[sidecar.interceptor]` / `[authority]`).
2. If no `firma.toml` is loadable, or the section can't be parsed, or the
   endpoint field is empty → `WARN("not configured")`.
3. Otherwise, attempt one TCP (or UDS) connect with a `--timeout-ms`
   deadline. Success → `OK`. Any error → `FAIL` with the underlying
   error text.

This matches the spec acceptance criterion: "an unconfigured Authority
should be `WARN`, not `FAIL`, when no `[authority]` is set."

For TCP endpoints written as wildcards (`0.0.0.0`, `[::]`), the probe
rewrites the host to the matching loopback (`127.0.0.1`, `[::1]`) before
connecting. Otherwise the connect would always fail on macOS.

## State / data directory resolution

| Directory   | Resolution order                                                                                                                                                                                          |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `state_dir` | `--state-dir` → `FIRMA_STATE_DIR` → `$XDG_RUNTIME_DIR/firma` (or `/tmp/firma-$UID` on Unix; `%LOCALAPPDATA%\firma\runtime` or `%TEMP%\firma` on Windows). `state_dir` is never read from the config file. |
| `data_dir`  | `$XDG_DATA_HOME/firma` → `~/.local/share/firma` (Linux), `~/Library/Application Support/firma` (macOS), `%APPDATA%\firma\data` (Windows).                                                                 |

On Unix, both directories are required to exist with mode `0700` (per
Hardening Issue 5: keep sockets and audit material out of other users'
reach). Wider modes are reported as `FAIL`.

## Exit codes

| Code | Meaning                                                                      |
| ---- | ---------------------------------------------------------------------------- |
| `0`  | Every check is `OK` or `WARN`.                                               |
| `1`  | At least one check is `FAIL`.                                                |
| `2`  | Internal error (render failure, tokio runtime failure). Not a check failure. |

Suitable for use in CI as `firma doctor --json > report.json` followed
by a `jq -e '.exit_code == 0'` gate.

## See also

- [`docs/markdown/firma_stack_command.md`](firma_stack_command.md) — `firma stack {init,start,stop,status}`.
- [`docs/markdown/firma_monitor_command.md`](firma_monitor_command.md) — tail the audit stream.
- [`docs/markdown/firma_action_class_registry.md`](firma_action_class_registry.md) — action class registry.
