---
title: Manage the stack with firma stack and firma monitor
description: Scaffold, start, stop, and observe the Authority + Sidecar as a single unit using the firma stack supervisor and the firma monitor live tail.
---

`firma stack` supervises the Authority and Sidecar as one unit: scaffold once, start, status, stop. `firma monitor` is its read-only counterpart — a live tail of audit events and component logs from a running stack. Together they replace the hand-rolled `firma authority &` / `firma sidecar &` pattern from earlier guides.

This guide covers a typical operator flow: scaffold a deployment, boot it, observe what it's doing, and tear it down cleanly.

## Prerequisites

- A built workspace: `cargo build --release` from the repo root.
- `protoc` installed.
- Familiarity with the [Quickstart](../../quickstart/) and [Run the Sidecar standalone](../run-the-sidecar/). Those pages show what `stack` automates away.

## Scaffold a deployment

`firma stack init` writes a fresh deployment into two separate directories — one for configs and keys, one for mutable runtime state. Both directories are optional and default sensibly:

```bash
# Defaults: config dir = XDG/platform config dir, state dir = XDG runtime.
firma stack init

# Or pin both explicitly.
firma stack init \
  --config-dir /etc/firma \
  --state-dir  /var/run/firma
```

Layout written:

```text
/etc/firma/
  firma.toml            authority.key       audit.key
  mapping-rules.toml    policies/           issuance-policies/

/var/run/firma/
  revocations.txt
  generated-firma-ca/
  # populated later by start: authority.pid, sidecar.pid, stack.pid,
  # stack.lock, authority.log, sidecar.log, supervisor.log,
  # *.listen, audit.jsonl
```

`init` writes a single sectioned `firma.toml` (`[authority]` +
`[sidecar.*]`); there is no `firma-stack.toml`, `authority.toml`, or
`sidecar.toml`. On success it prints a `next:` hint of `firma stack start`.
`state_dir` is not embedded in the config — it is always resolved from
`--state-dir` / `FIRMA_STATE_DIR` / XDG.

`init` flags:

| Flag                 | Default               | Description                                     |
| -------------------- | --------------------- | ----------------------------------------------- |
| `--config-dir`       | XDG/platform config   | Where to write `firma.toml`, keys, policy dirs. |
| `--state-dir`        | `FIRMA_STATE_DIR`/XDG | Where to write `revocations.txt` and CA dir.    |
| `--force`            | _off_                 | Overwrite existing files.                       |
| `--authority-listen` | `127.0.0.1:50051`     | Authority gRPC listen address.                  |
| `--sidecar-listen`   | `127.0.0.1:8080`      | Sidecar HTTP proxy listen.                      |

Existing files are preserved unless `--force` is set; safe to re-run after editing one config by hand.

## Start the stack

```bash
# Foreground. Ctrl-C cleanly tears both children down.
# --config defaults to the discovered firma.toml.
firma stack start

# Detached. Forks a supervisor process after readiness probes pass.
firma stack start --detach
```

What `start` does, in order:

1. Boots the Authority in its own process group.
2. Probes the Authority's gRPC port until it accepts connections.
3. Boots the Sidecar in its own process group.
4. Probes the Sidecar's listen port and waits for `generated-firma-ca/` material.
5. With `--detach`: forks a `__supervise` child that re-attaches to the pidfiles, then exits 0.
6. Without `--detach`: blocks in the foreground until signalled.

If readiness fails at any step, `start` rolls back — every spawned child is signalled and pid/listen/lock files are cleaned up. You won't be left with half a stack.

`start` flags:

| Flag          | Env               | Default                                      |
| ------------- | ----------------- | -------------------------------------------- |
| `--config`    | —                 | discovered `firma.toml`                      |
| `--state-dir` | `FIRMA_STATE_DIR` | `$XDG_RUNTIME_DIR/firma` → `/tmp/firma-$UID` |
| `--detach`    | —                 | _off_                                        |

`start` resolves `firma.toml` via the shared [Config Discovery](../../../docs/cli.md) precedence and passes that exact file to both children with `--config`. `state_dir` is never a config-file key.

## Check status

```bash
firma stack status --state-dir /var/run/firma
firma stack status --state-dir /var/run/firma --json
```

Reports per-component pid, listen address, state (running / stopped / unhealthy), and uptime. Exit codes:

| Code | Meaning                          |
| ---- | -------------------------------- |
| `0`  | All components running.          |
| `1`  | Any component unhealthy/stopped. |
| `2`  | Internal error.                  |

Wire the `0`/`1` split into a healthcheck: cron, systemd `ExecStartPre`, container liveness probe, etc.

## Stop the stack

```bash
firma stack stop --state-dir /var/run/firma
firma stack stop --state-dir /var/run/firma --timeout 10
```

Stop order is intentional: the Sidecar is soft-signalled first so the Authority's tonic graceful shutdown isn't blocked on long-lived gRPC streams. The supervisor and Authority follow. Survivors past `--timeout` (default 2s) are hard-killed; children are reaped via `waitpid(WNOHANG)` so zombies aren't mistaken for live processes.

Exit codes: `0` on success (graceful or hard-kill fallback), `2` on error.

## Tail decisions and logs with firma monitor

`firma monitor` is read-only and decoupled from `stack`: it tails files in the state directory. Multiple concurrent monitors are safe; the stack doesn't need to know they exist.

```bash
# Everything: audit events plus authority + sidecar logs.
firma monitor --state-dir /var/run/firma

# Just denials, last 15 minutes, JSON output for piping into jq or a collector.
firma monitor --state-dir /var/run/firma \
  --source audit --decision deny --since 15m --format json

# Authority logs only, one shot (no follow).
firma monitor --state-dir /var/run/firma \
  --source authority --no-follow

# Filter by action class.
firma monitor --state-dir /var/run/firma \
  --source audit --action-class communication.external.send
```

`monitor` flags:

| Flag             | Default  | Description                                              |
| ---------------- | -------- | -------------------------------------------------------- |
| `--config`       | _unset_  | Accepted for compatibility; not used to resolve state.   |
| `--state-dir`    | resolved | State dir override.                                      |
| `--source`       | `all`    | `audit`, `authority`, `sidecar`, or `all`.               |
| `--no-follow`    | _off_    | Read once and exit; default is to follow tail.           |
| `--decision`     | _unset_  | Audit-only: `allow`, `deny`, `passthrough`.              |
| `--action-class` | _unset_  | Audit-only: exact match on `intent.action_class`.        |
| `--since`        | _unset_  | Backfill window: `15m`, `2h`, `1d` or RFC3339 timestamp. |
| `--format`       | `pretty` | `pretty` (human) or `json` (one object per line).        |

`--decision` and `--action-class` apply to audit events only — they're silently ignored for `authority` and `sidecar` log lines. The tailer detects log rotation by inode and reopens automatically.

For everything you can do with the underlying audit JSONL — signature verification, structured search, debugging surprise denies — see [Read & verify the audit log](../audit-log/).

## State directory layout

`stack` and `monitor` both operate on the state directory:

```text
<state_dir>/
  authority.pid          authority.log          authority.listen
  sidecar.pid            sidecar.log            sidecar.listen
  stack.pid              stack.lock             supervisor.log
  audit.jsonl
  generated-firma-ca/
```

Resolution order: `--state-dir` flag → `FIRMA_STATE_DIR` env → platform default. The Unix default is `$XDG_RUNTIME_DIR/firma`, falling back to `/tmp/firma-$UID`. Windows uses `%LOCALAPPDATA%\firma\runtime` then `%TEMP%\firma`. `state_dir` is never read from the config file.

## Common gotchas

**`stack start` exits 2 with "address in use".** Another sidecar or authority is bound to the listen address — most often a previous foreground run that wasn't fully reaped. Run `firma stack stop --state-dir ...` first, or pick different addresses with `--authority-listen` / `--sidecar-listen` at `init` time.

**`stack status` reports "stopped" but the pidfile exists.** The process is gone but the file wasn't cleaned up (sigkill from outside, OOM, host reboot). `stack start` will not refuse to boot in this case; the stale pidfile is overwritten once the new process registers. If in doubt, `stack stop` first.

**`monitor --since 24h` returns nothing.** `audit.jsonl` is append-only but is created fresh on each `stack init`. If the state dir was wiped or recreated, there's nothing to backfill. Confirm with `ls -l <state_dir>/audit.jsonl`.

**Two `firma stack start` invocations against the same state dir.** The second one fails fast on `stack.lock`. This is intentional — running two supervisors against one set of pidfiles is undefined.

**Detached supervisor doesn't exit when the terminal closes.** That's the point of `--detach`. The supervisor reparents to PID 1 (Unix) or runs as a Job Object (Windows) and survives the shell exiting. Stop it with `firma stack stop`, not by killing the terminal.

## What's next

- [Read & verify the audit log](../audit-log/) — turn `audit.jsonl` into a tamper-evident record.
- [Issue capability tokens](../issue-capability-tokens/) — drive the Authority that `stack` boots for you.
- [Write your first Cedar policy](../write-a-cedar-policy/) — change what the Sidecar permits.
- [Run the Sidecar standalone](../run-the-sidecar/) — the hand-rolled equivalent, useful when you want to understand what `stack` is automating.

## See also

- [Diagnose with `firma doctor`](../firma-doctor/) — first command to run when anything looks off.
