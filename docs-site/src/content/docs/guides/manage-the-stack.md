---
title: Start and monitor the daemon with firma sidecar and firma monitor
description: Boot, observe, and tear down the Authority + Sidecar pair using the firma sidecar daemon lifecycle and the firma monitor live tail.
---

`firma sidecar start` boots the Authority and Sidecar as a single
daemon-mode pair. `firma sidecar stop` tears them back down. `firma
monitor` is the read-only counterpart — a live tail of audit events
and component logs from the running daemon. Together they replace the
old `firma stack` supervisor and the hand-rolled `firma authority &` /
`firma sidecar &` pattern from earlier guides.

This guide covers a typical operator flow: scaffold a project, boot
the daemon, observe what it's doing, and tear it down cleanly.

## Prerequisites

- A built workspace: `cargo build --release` from the repo root.
- `protoc` installed.
- Familiarity with the [Quickstart](../../quickstart/) and
  [Run the Sidecar standalone](../run-the-sidecar/). Those pages show
  what `firma sidecar start` automates away.

## Scaffold the project

`firma config` writes a fresh project layout. Project-local config goes
under `<workspace>/.firma/`; keys and revocation state go under the
user-global state directory.

```bash
# Interactive wizard.
firma config

# Or scripted with every value supplied.
firma config --profile codex --mapping anthropic \
           --workspace ./proj --output-dir ./proj/.firma --yes
```

Layout written:

```text
./proj/.firma/
  firma.toml            mapping-rules.toml
  mappings/             policies/
  issuance-policies/

$XDG_DATA_HOME/firma/   # or %LOCALAPPDATA%\firma on Windows
  authority.key         authority.pub       audit.key
  revocations.txt
  generated-firma-ca/
  # populated by sidecar start: authority.pid, sidecar.pid, stack.pid,
  # stack.lock, authority.log, sidecar.log, supervisor.log,
  # *.listen, audit.jsonl
```

`firma config` writes a single sectioned `firma.toml` (`[authority]` +
`[sidecar.*]`). Existing files are preserved unless
`--force` is set. `state_dir` is not embedded in the config — it is
always resolved from `--state-dir` / `FIRMA_STATE_DIR` / XDG.

You can also skip `firma config` entirely: `firma run <agent>` invokes the
same scaffold implicitly the first time it cannot discover a
`firma.toml`.

See [Initialize a project with `firma config`](../initialize-a-project/)
for the full flag table.

## Start the daemon

```bash
# Foreground. Ctrl-C cleanly tears both children down.
# --config defaults to the discovered firma.toml.
firma sidecar start

# Detached. Forks a supervisor process after readiness probes pass.
firma sidecar start --detach
```

What `start` does, in order:

1. Boots the Authority in its own process group.
2. Probes the Authority's gRPC port until it accepts connections.
3. Boots the Sidecar in its own process group.
4. Probes the Sidecar's listen port and waits for `generated-firma-ca/` material.
5. With `--detach`: forks a `__supervise` child that re-attaches to the pidfiles, then exits 0.
6. Without `--detach`: blocks in the foreground until signalled.

If readiness fails at any step, `start` rolls back — every spawned child
is signalled and pid/listen/lock files are cleaned up. You will not be
left with half a daemon.

`start` flags:

| Flag          | Env                         | Default                                      |
| ------------- | --------------------------- | -------------------------------------------- |
| `--config`    | `FIRMA_SIDECAR_CONFIG_FILE` | discovered `firma.toml`                      |
| `--state-dir` | `FIRMA_STATE_DIR`           | `$XDG_RUNTIME_DIR/firma` → `/tmp/firma-$UID` |
| `--detach`    | —                           | _off_                                        |

`start` resolves `firma.toml` via the shared
[Config Discovery](../../../docs/cli.md) precedence and passes that
exact file to both children with `--config`. `state_dir` is never a
config-file key.

## Inspect live sidecars

```bash
firma sidecar status                       # docker-ps-style listing
firma sidecar status --json                # machine-readable
firma sidecar status --daemon              # daemon-mode pid only
```

See [Inspect live sidecars](../firma-sidecar-status/) for the full
table and exit codes.

## Stop the daemon

```bash
firma sidecar stop --state-dir /var/run/firma
firma sidecar stop --state-dir /var/run/firma --timeout 10
```

Stop order is intentional: the Sidecar is soft-signalled first so the
Authority's tonic graceful shutdown is not blocked on long-lived gRPC
streams. The supervisor and Authority follow. Survivors past
`--timeout` (default 2 s) are hard-killed; children are reaped via
`waitpid(WNOHANG)`. On Unix, an addressable process group is treated as
alive even when its leader has exited, ensuring orphaned descendants are
also hard-killed. A group containing only unreaped descendant zombies may
therefore be reported as requiring the hard-kill fallback.

If hard termination fails, `firma` returns an error and retains the stack
pidfiles and lock. Fix the underlying permission or platform error, then run
`firma stack stop` again; the persisted termination targets remain available
for that retry.

Exit codes: `0` on success (graceful or hard-kill fallback), `2` on error.

## Tail decisions and logs with firma monitor

`firma monitor` is read-only and decoupled from `sidecar`: it tails
files in the state directory. Multiple concurrent monitors are safe;
the daemon does not need to know they exist.

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
| `--source`       | `audit`  | `audit`, `authority`, `sidecar`, or `all`.               |
| `--no-follow`    | _off_    | Read once and exit; default is to follow tail.           |
| `--decision`     | _unset_  | Audit-only: `allow`, `deny`, `passthrough`.              |
| `--action-class` | _unset_  | Audit-only: exact match on `intent.action_class`.        |
| `--since`        | _unset_  | Backfill window: `15m`, `2h`, `1d` or RFC3339 timestamp. |
| `--format`       | `pretty` | `pretty` (human) or `json` (one object per line).        |

`--decision` and `--action-class` apply to audit events only — they
are silently ignored for `authority` and `sidecar` log lines. The
tailer detects log rotation by inode and reopens automatically.

Follow vs. one-shot:

- **Follow** (default when stdout is a TTY, or forced with `--tail`) starts at
  end-of-file and prints new records as they are appended.
- **One-shot** (`--no-follow`, or the default when stdout is piped) reads the
  file from the **start** and exits. This dumps the records already on disk —
  so `firma monitor --no-follow` after a `firma run` shows that run's
  decisions, rather than nothing. Combine with `--since` to bound the window.

For everything you can do with the underlying audit JSONL — signature
verification, structured search, debugging surprise denies — see
[Read & verify the audit log](../audit-log/).

## State directory layout

`firma sidecar` and `firma monitor` both operate on the state directory:

```text
<state_dir>/
  authority.pid          authority.log          authority.listen
  sidecar.pid            sidecar.log            sidecar.listen
  stack.pid              stack.lock             supervisor.log
  audit.jsonl
  generated-firma-ca/
```

Resolution order: `--state-dir` flag → `FIRMA_STATE_DIR` env →
platform default. The Unix default is `$XDG_RUNTIME_DIR/firma`,
falling back to `/tmp/firma-$UID`. Windows uses
`%LOCALAPPDATA%\firma\runtime` then `%TEMP%\firma`. `state_dir` is
never read from the config file.

## Common gotchas

**`sidecar start` exits 2 with "address in use".** Another sidecar or
authority is bound to the listen address — most often a previous
foreground run that was not fully reaped. Run `firma sidecar stop
--state-dir ...` first, or change the listeners by editing
`firma.toml` (or re-running `firma config --force` with a different
`--authority-listen`; edit `[sidecar.interceptor].listen_addr` for the Sidecar).

**`sidecar status` reports "stopped" but the pidfile exists.** The
process is gone but the file was not cleaned up (sigkill from
outside, OOM, host reboot). `sidecar start` will not refuse to boot
in this case; the stale pidfile is overwritten once the new process
registers. If in doubt, `sidecar stop` first.

**`monitor --since 24h` returns nothing.** `audit.jsonl` is
append-only but is created fresh on each `firma config`. If the state
dir was wiped or recreated, there is nothing to backfill. Confirm
with `ls -l <state_dir>/audit.jsonl`.

**Two `firma sidecar start` invocations against the same state dir.**
The second one fails fast on `stack.lock`. This is intentional —
running two supervisors against one set of pidfiles is undefined.

**Detached supervisor does not exit when the terminal closes.** That
is the point of `--detach`. The supervisor reparents to PID 1 (Unix)
or runs as a Job Object (Windows) and survives the shell exiting.
Stop it with `firma sidecar stop`, not by killing the terminal.

## What's next

- [Read & verify the audit log](../audit-log/) — turn `audit.jsonl` into a tamper-evident record.
- [Issue capability tokens](../issue-capability-tokens/) — drive the Authority that `sidecar start` boots for you.
- [Write your first Cedar policy](../write-a-cedar-policy/) — change what the Sidecar permits.
- [Run the Sidecar standalone](../run-the-sidecar/) — the hand-rolled equivalent, useful when you want to understand what the daemon-mode commands automate.

## See also

- [Initialize a project with `firma config`](../initialize-a-project/) — start every project here.
- [Diagnose with `firma doctor`](../firma-doctor/) — first command to run when anything looks off.
