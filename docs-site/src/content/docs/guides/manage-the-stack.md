---
title: Start and monitor the daemon with firma sidecar and firma monitor
description: Boot, observe, and tear down the Authority + Sidecar pair using the firma sidecar daemon lifecycle and the firma monitor live tail.
---

`firma sidecar start` boots the Authority and Sidecar as a single
daemon-mode pair. `firma sidecar stop` tears them back down. `firma
monitor` is the read-only counterpart — a live tail of audit events
and component logs from the running daemon.

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

# Detached. The hidden supervisor owns startup and the component children.
firma sidecar start --detach
```

What `start` does, in order:

1. With `--detach`, assigns a random startup generation and forks the hidden
   owning supervisor; without it, the current process remains the owner.
2. The owner boots the Authority in its own process group with a private,
   generation-scoped publication path. After binding, Authority atomically
   publishes its effective address there. The owner validates that address
   against the configured IP and port, then probes it while retaining the child
   handle.
3. If Authority was configured with port `0`, the owner uses the validated
   `authority.listen` value as the Sidecar's `--authority-connect-addr`. The
   configured Authority URL remains the logical HTTP origin and TLS identity;
   only the physical TCP destination changes.
4. The owner boots the Sidecar with the same private endpoint-publication
   contract and validates and probes its effective interceptor address. When
   HTTPS MITM is active, the Sidecar generates its `generated-firma-ca/`
   material before opening that port, so a connectable port already implies CA
   readiness; readiness is a single signal. Fixed configured ports remain
   unchanged; setting either listener to port `0` delegates port selection to
   the kernel.
5. With `--detach`, the supervisor announces readiness, waits for the launcher's
   acknowledgement, then confirms attachment. The launcher exits 0 only after
   that two-phase handoff. Without detachment, the owner continues blocking in
   the foreground.

If readiness fails at any step, `start` attempts to terminate and collect every
spawned child. It removes pid, listen, and lock files only after confirming
teardown; if termination or probing fails, it returns an error, retains runtime
state, and may continue collection in the background so cleanup can be retried.
Readiness polling also watches each owned component leader and fails immediately
if it exits instead of waiting for the probe timeout.
Canonical `authority.listen` and `sidecar.listen` files appear only after the
corresponding endpoint passes its readiness probe. Children never write these
canonical files.

`start` flags:

| Flag          | Env                         | Default                                      |
| ------------- | --------------------------- | -------------------------------------------- |
| `--config`    | `FIRMA_SIDECAR_CONFIG_FILE` | discovered `firma.toml`                      |
| `--state-dir` | `FIRMA_STATE_DIR`           | `$XDG_RUNTIME_DIR/firma` → `/tmp/firma-$UID` |
| `--detach`    | —                           | _off_                                        |

`start` uses its documented dedicated config input when supplied; otherwise it
follows the shared
[configuration resolution](https://github.com/Firma-AI/openfirma/blob/main/docs/configuration.md#configuration-resolution)
model. It passes one selected `firma.toml` to both children and never merges
multiple files. `state_dir` is never a config-file key.

For advanced direct-dial routing, `[sidecar.authority].connect_addr` selects a
physical TCP destination without changing `[sidecar.authority].url`. The URL
still controls the HTTP authority, TLS SNI, and certificate identity. The
precedence is `firma sidecar --authority-connect-addr`, then
`[sidecar.authority].connect_addr`, then normal URL DNS routing. Port `0` is
invalid for a connect address, and plaintext `http://` routing to a non-loopback
physical address still requires `allow_insecure_remote_authority = true`.

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
`--timeout` (default 2 s) are hard-killed. Firma then waits up to 2 seconds
for every termination target to disappear before deleting runtime state.
Cleanup is generation-fenced: `stack.lock` contains a random identity for the
current lock acquisition. A delayed stop or supervisor from an older generation
may still finish collecting its own children, but it cannot delete runtime state
written by a replacement stack. Startup and stop also serialize state snapshots
through `.stack-state.lock`; supervisor PIDs remain process identities and are
not treated as cleanup authority.

Detached rollback carries the generation assigned before the supervisor was
spawned. If another generation has replaced it, rollback skips both signalling
and cleanup rather than acting on the replacement's pidfiles.

Foreground startup retains the component child handles and collects those
children itself. In detached mode, the hidden supervisor spawns the components,
retains their child handles, and remains their owning parent until teardown.
Status and external stop commands use non-destructive probes and never attempt
to reap another process's child.

On Windows, the owner also retains duplicated handles to the components' Job
Object. Hard shutdown terminates the Job rather than only its leader, and the
final handle closing terminates descendants if the owner exits unexpectedly.
External status and stop processes reconstruct leader-only targets from
pidfiles; the owning supervisor remains responsible for full-tree cleanup.

The detached command returns success only after the supervisor has spawned both
components, completed their readiness checks, and acknowledged ownership. If a
component exits, the supervisor collects it and tears down the other component
before exiting. Attachment failure rolls the owned stack back.

On Unix, an addressable component process group is treated as alive even when
its leader has exited, ensuring orphaned descendants are also hard-killed. A
group containing only unreaped zombies remains conservatively present to a
non-owner status or stop process; owner supervision collects its own leaders.

If a process-group probe or hard termination fails, or a target remains present
after the post-termination settlement window, `firma` still attempts every
recorded target, then returns an error and retains the stack pidfiles and lock.
Fix the underlying permission or platform error, or allow the owning parent to
collect a zombie, then run `firma sidecar stop` again; the persisted termination
targets remain available for that retry.

If `stack.lock` contains a malformed generation, an explicit `firma sidecar
stop` still terminates the recorded targets while holding the state transaction,
but returns an error and retains all runtime state because cleanup ownership
cannot be established. Generation-scoped startup rollback remains fail closed
and does not signal targets when the lock cannot be matched.

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

| Flag             | Env             | Default    | Description                                                                                          |
| ---------------- | --------------- | ---------- | --------------------------------------------------------------------------------------------------- |
| `--config`       | `FIRMA_CONFIG`  | discovered | Unified `firma.toml` used to discover the audit log. When set, the file must load or `monitor` fails closed; it is not consulted once `--state-dir` is given. |
| `--state-dir`    | `FIRMA_STATE_DIR` | resolved | State dir override.                                                                                 |
| `--source`       | —               | `audit`     | `audit`, `authority`, `sidecar`, or `all`.               |
| `--no-follow`    | —               | _off_       | Read once and exit; default is to follow tail.           |
| `--decision`     | —               | _unset_     | Audit-only: `allow`, `deny`, `passthrough`.              |
| `--action-class` | —               | _unset_     | Audit-only: exact match on `intent.action_class`.        |
| `--since`        | —               | _unset_     | Backfill window: `15m`, `2h`, `1d` or RFC3339 timestamp. |
| `--format`       | —               | `pretty`    | `pretty` (human) or `json` (one object per line).        |

`--decision` and `--action-class` apply to audit events only — they
are silently ignored for `authority` and `sidecar` log lines. The
tailer detects log rotation by inode and reopens automatically.

## Open Policy Control

`firma control` opens Policy Control for the selected stack:

```bash
firma control --config .firma/firma.toml
```

`--config` is bound to `FIRMA_CONFIG`; when omitted it follows the shared
[configuration resolution](https://github.com/Firma-AI/openfirma/blob/main/docs/configuration.md#configuration-resolution)
model (`FIRMA_CONFIG`, then the nearest `.firma/firma.toml`). A selected file
that cannot load fails closed.

The policy pane reads Cedar files from the Authority policy directory in
`firma.toml`. Any policy with an `@id(...)` annotation is shown as a row:

```cedar
@id("block_payments")
forbid (
    principal,
    action == Firma::Action::"payment.transfer",
    resource
);
```

When a row is toggled, Policy Control rewrites the Cedar file and reloads from
disk. Disabled policies remain valid Cedar by adding a managed false condition:

```cedar
when { false }; // openfirma-control:disabled
```

The Authority picks up the file through its normal policy-dir hot reload path.

Press `e` in the policy pane to open the selected Cedar file in `$EDITOR`.

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
  stack.pid              stack.lock             .stack-state.lock
  supervisor.log
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

**Detached startup fails with access denied on Windows.** Firma requires the
supervisor to break away from the launcher's Job Object. If that Job forbids
breakaway, Firma fails startup rather than claim a detached lifetime it cannot
guarantee. Run foreground mode or launch Firma from a Job that permits
`CREATE_BREAKAWAY_FROM_JOB`.

## What's next

- [Read & verify the audit log](../audit-log/) — turn `audit.jsonl` into a tamper-evident record.
- [Issue capability tokens](../issue-capability-tokens/) — drive the Authority that `sidecar start` boots for you.
- [Write your first Cedar policy](../write-a-cedar-policy/) — change what the Sidecar permits.
- [Run the Sidecar standalone](../run-the-sidecar/) — the hand-rolled equivalent, useful when you want to understand what the daemon-mode commands automate.

## See also

- [Initialize a project with `firma config`](../initialize-a-project/) — start every project here.
- [Diagnose with `firma doctor`](../firma-doctor/) — first command to run when anything looks off.
