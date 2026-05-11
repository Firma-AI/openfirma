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

`firma stack init` writes a fresh deployment into two separate directories — one for configs and keys, one for mutable runtime state:

```bash
firma stack init \
  --config-dir /etc/firma \
  --state-dir  /var/run/firma
```

Layout written:

```text
/etc/firma/
  firma-stack.toml      authority.toml      sidecar.toml
  mapping-rules.toml    authority.key       authority.pub      audit.key
  policies/             issuance-policies/

/var/run/firma/
  revocations.txt
  generated-firma-ca/
  # populated later by start: authority.pid, sidecar.pid, stack.pid,
  # stack.lock, authority.log, sidecar.log, supervisor.log,
  # *.listen, audit.jsonl
```

The generated `firma-stack.toml` embeds `state_dir = "/var/run/firma"` so subsequent `start` / `stop` / `status` / `monitor` invocations only need `--config`. Pass `--state-dir` to override at any point.

`init` flags:

| Flag                 | Default           | Description                                  |
| -------------------- | ----------------- | -------------------------------------------- |
| `--config-dir`       | _required_        | Where to write TOMLs, keys, policy dirs.     |
| `--state-dir`        | _required_        | Where to write `revocations.txt` and CA dir. |
| `--force`            | _off_             | Overwrite existing files.                    |
| `--authority-listen` | `127.0.0.1:50051` | Authority gRPC listen address.               |
| `--sidecar-listen`   | `127.0.0.1:8080`  | Sidecar HTTP proxy listen.                   |

Existing files are preserved unless `--force` is set; safe to re-run after editing one config by hand.

## Start the stack

```bash
# Foreground. Ctrl-C cleanly tears both children down.
firma stack start --config /etc/firma/firma-stack.toml

# Detached. Forks a supervisor process after readiness probes pass.
firma stack start --config /etc/firma/firma-stack.toml --detach
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

| Flag          | Env                  | Default                                           |
| ------------- | -------------------- | ------------------------------------------------- |
| `--config`    | `FIRMA_STACK_CONFIG` | `./firma-stack.toml`                              |
| `--state-dir` | `FIRMA_STATE_DIR`    | `state_dir` from `--config` then platform default |
| `--detach`    | —                    | _off_                                             |

## Check status

```bash
firma stack status --config /etc/firma/firma-stack.toml
firma stack status --config /etc/firma/firma-stack.toml --json
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
firma stack stop --config /etc/firma/firma-stack.toml
firma stack stop --config /etc/firma/firma-stack.toml --timeout 10
```

Stop order is intentional: the Sidecar is soft-signalled first so the Authority's tonic graceful shutdown isn't blocked on long-lived gRPC streams. The supervisor and Authority follow. Survivors past `--timeout` (default 2s) are hard-killed; children are reaped via `waitpid(WNOHANG)` so zombies aren't mistaken for live processes.

Exit codes: `0` on success (graceful or hard-kill fallback), `2` on error.

## Tail decisions and logs with firma monitor

`firma monitor` is read-only and decoupled from `stack`: it tails files in the state directory. Multiple concurrent monitors are safe; the stack doesn't need to know they exist.

```bash
# Everything: audit events plus authority + sidecar logs.
firma monitor --config /etc/firma/firma-stack.toml

# Just denials, last 15 minutes, JSON output for piping into jq or a collector.
firma monitor --config /etc/firma/firma-stack.toml \
  --source audit --decision deny --since 15m --format json

# Authority logs only, one shot (no follow).
firma monitor --config /etc/firma/firma-stack.toml \
  --source authority --no-follow

# Filter by action class.
firma monitor --config /etc/firma/firma-stack.toml \
  --source audit --action-class communication.external.send
```

`monitor` flags:

| Flag             | Default  | Description                                              |
| ---------------- | -------- | -------------------------------------------------------- |
| `--config`       | _unset_  | Stack config; `state_dir` read from it when set.         |
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

Resolution order: `--state-dir` flag → `FIRMA_STATE_DIR` env → `state_dir` field in `--config` → platform default. The Unix default is `$XDG_RUNTIME_DIR/firma`, falling back to `/tmp/firma-$UID`. Windows uses `%LOCALAPPDATA%\firma\runtime` then `%TEMP%\firma`.

## Common gotchas

**`stack start` exits 2 with "address in use".** Another sidecar or authority is bound to the listen address — most often a previous foreground run that wasn't fully reaped. Run `firma stack stop --config ...` first, or pick different addresses with `--authority-listen` / `--sidecar-listen` at `init` time.

**`stack status` reports "stopped" but the pidfile exists.** The process is gone but the file wasn't cleaned up (sigkill from outside, OOM, host reboot). `stack start` will not refuse to boot in this case; the stale pidfile is overwritten once the new process registers. If in doubt, `stack stop` first.

**`monitor --since 24h` returns nothing.** `audit.jsonl` is append-only but is created fresh on each `stack init`. If the state dir was wiped or recreated, there's nothing to backfill. Confirm with `ls -l <state_dir>/audit.jsonl`.

**Two `firma stack start` invocations against the same state dir.** The second one fails fast on `stack.lock`. This is intentional — running two supervisors against one set of pidfiles is undefined.

**Detached supervisor doesn't exit when the terminal closes.** That's the point of `--detach`. The supervisor reparents to PID 1 (Unix) or runs as a Job Object (Windows) and survives the shell exiting. Stop it with `firma stack stop`, not by killing the terminal.

## What's next

- [Read & verify the audit log](../audit-log/) — turn `audit.jsonl` into a tamper-evident record.
- [Issue capability tokens](../issue-capability-tokens/) — drive the Authority that `stack` boots for you.
- [Write your first Cedar policy](../write-a-cedar-policy/) — change what the Sidecar permits.
- [Run the Sidecar standalone](../run-the-sidecar/) — the hand-rolled equivalent, useful when you want to understand what `stack` is automating.
