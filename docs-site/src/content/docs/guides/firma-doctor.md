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
- **Any time `firma sidecar status` looks wrong** — doctor tells you *why*.

:::caution[v0.1.0 and earlier]
OpenFirma **v0.1.0** shipped doctor and monitor behavior that did not match
what `firma run` actually does: misleading sandbox backend verdicts, false
`FAIL` on missing long-lived daemons in `firma run`-only workflows, empty
`firma monitor` output after real decisions, and one-shot reads that skipped
existing audit records. Upgrade to **v0.1.1** or later before trusting
doctor/monitor for troubleshooting.
:::

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
| `--config`     | `FIRMA_STACK_CONFIG` | discovered | Unified `firma.toml`. When unset, auto-discovery uses `$FIRMA_CONFIG` or walk-up to `<dir>/.firma/firma.toml`; selected files must load successfully. |
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
[WARN] sandbox vz             not used on linux
[WARN] sandbox wsl2           not used on native Linux (runtime selects bwrap)
[OK]   sandbox firecracker    Firecracker v1.7.0 available
[OK]   sidecar reachable      2 live per-run instances (firma run)
[OK]   authority reachable    2 live per-run instances (firma run)
[OK]   config parsed          ./.firma/firma.toml
[OK]   capability seed        not present (optional; capabilities disabled by default)
[OK]   state dir              /run/user/1000/firma: mode 0700
[OK]   data dir               ~/.local/share/firma: not present (created on first use)
```

Categories are emitted in a fixed order; columns are padded so a diff between
two runs only shows lines that actually changed.

### Verdicts match what `firma run` actually does

Doctor does not rely on a static OS → backend table, and does not probe only
the configured daemon. Its verdicts mirror the runtime:

- **Sandbox backends** use the same selection and preflight logic as
  `firma run`. On WSL, `sandbox bwrap` is **not** `OK` (the runtime refuses
  bubblewrap there — unprivileged user namespaces are unavailable) and
  `sandbox wsl2` is `OK` (the backend the runtime auto-selects), instead of the
  misleading "not supported on linux". On a hardened native-Linux kernel where
  unprivileged user namespaces are disabled by sysctl, `sandbox bwrap` is
  `FAIL` — matching the error `firma run` would raise.
- **Live per-run instances** are cross-checked against the same runtime markers
  `firma sidecar status` reads. While an agent runs under `firma run`,
  `sidecar reachable` and `authority reachable` report the live per-run
  instances as `OK` even though no long-lived daemon is listening.
- **No long-lived daemon** is not a failure in a `firma run`-only workflow.
  When nothing is reachable and no per-run instance is live, these checks are a
  `WARN` ("no long-lived daemon reachable (normal if you only use firma run)"),
  never a `FAIL`.
- **Optional, created-on-demand paths** (capability seed, data dir) report `OK`
  when absent — they are expected to be missing on a healthy install.

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

- [Start and monitor the daemon with `firma sidecar` and `firma monitor`](../manage-the-stack/) — start, stop, and observe Authority + Sidecar as one unit.
- Full reference: `docs/markdown/firma_doctor_command.md` in the repository.
