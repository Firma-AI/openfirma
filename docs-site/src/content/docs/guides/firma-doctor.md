---
title: Diagnose with firma doctor
description: Run firma doctor to get a structured, pass/warn/fail snapshot of your OpenFirma installation — before opening an issue, in CI, or any time something looks off.
---

`firma doctor` prints a structured diagnostic report: what's installed, what's
reachable, what's configured. It is read-only — no state is mutated — so it is
safe to run against a live stack at any time.

## When to run it

- **After a fresh install** — confirm the binary is on PATH and the sandbox
  backends you care about are present.
- **Before opening a bug report** — attach `firma doctor --json` to the issue
  for a reproducible baseline.
- **In CI** — gate on exit code 0 to catch configuration drift before tests run.
- **Any time `firma stack status` looks wrong** — doctor tells you *why*.

## Quickstart

```bash
firma doctor                                   # pretty output, all checks
firma doctor --json | jq .                     # machine-readable, pipe-friendly
firma doctor --config /etc/firma/firma.toml    # use an explicit unified config
firma doctor --state-dir /run/user/1000/firma  # override runtime state dir
firma doctor --timeout-ms 1500                 # slower network probe (ms)
```

## Flags

| Flag           | Env               | Default    | Description                                                    |
| -------------- | ----------------- | ---------- | -------------------------------------------------------------- |
| `--config`     | —                 | discovered | Unified `firma.toml`. Otherwise auto-discovered.               |
| `--state-dir`  | `FIRMA_STATE_DIR` | resolved   | Override the runtime state directory.                          |
| `--json`       | —                 | _off_      | Emit a single JSON object instead of pretty text.              |
| `--timeout-ms` | —                 | `500`      | Per-probe network timeout (TCP / UDS connect) in milliseconds. |

## Status semantics

| Status | Meaning                                                               |
| ------ | --------------------------------------------------------------------- |
| `OK`   | Check passed.                                                         |
| `WARN` | Not applicable on this host, or not yet configured. No action needed. |
| `FAIL` | Configured and broken. Operator action required.                      |

A fresh install with no `firma.toml` is expected to produce a mix of `OK` and
`WARN` — never `FAIL`. `FAIL` always points to something the operator already
declared that is now misbehaving.

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

Categories are emitted in a fixed order; columns are padded so a diff between
two runs only shows lines that actually changed.

### JSON (`--json`)

```json
{
  "checks": [
    {
      "category": "firma binary",
      "status": "ok",
      "reason": "/usr/local/bin/firma (v0.1.0)",
      "detail": { "path": "/usr/local/bin/firma", "version": "0.1.0" }
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

`worst` is `ok | warn | fail`. `exit_code` mirrors the OS-level exit code.
The `detail` map is omitted when empty; keys are category-specific.

## Exit codes

| Code | Meaning                                                                |
| ---- | ---------------------------------------------------------------------- |
| `0`  | Every check is `OK` or `WARN`.                                         |
| `1`  | At least one check is `FAIL`.                                          |
| `2`  | Internal error (render failure, runtime failure). Not a check failure. |

CI pattern: `firma doctor --json > report.json && jq -e '.exit_code == 0' report.json`

## See also

- [Manage the stack with `firma stack` and `firma monitor`](../manage-the-stack/) — start, stop, and observe the full stack.
- Full reference: `docs/markdown/firma_doctor_command.md` in the repository.
