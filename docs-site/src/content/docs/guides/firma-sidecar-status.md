---
title: Inspect live sidecars with firma sidecar status
description: Use firma sidecar status to list and probe per-run sidecars started by firma run, with JSON output and stale-marker cleanup.
---

`firma sidecar status` prints a docker-ps-style table of every per-run sidecar
that `firma run --sidecar=auto` has started. It reads the marker directories
written under `$XDG_RUNTIME_DIR/firma/run/<sandbox_id>/` (fallback
`/tmp/firma-$UID`; override with `FIRMA_STATE_DIR`), probes each one for
liveness, and garbage-collects stale entries whose recorded process is dead.

## Quickstart

```bash
# List all live per-run sidecars.
firma sidecar status

# Single entry with a liveness probe.
firma sidecar status --sandbox-id my-sandbox

# JSON output, suitable for scripting.
firma sidecar status --json

# Probe the long-lived daemon sidecar.
firma sidecar status --daemon
```

## Output

### Table (default)

```text
SANDBOX_ID         AGENT           PID     STATE      LISTEN                          UPTIME
my-sandbox         claude-code      42891   running    /run/user/1000/firma/run/my…    00:02:34
old-sandbox        codex            51002   stopped    -                               00:14:08
```

Columns:

| Column       | Description                                         |
| ------------ | --------------------------------------------------- |
| `SANDBOX_ID` | The run's sandbox identifier.                       |
| `AGENT`      | Agent name from the marker metadata.                |
| `PID`        | Sidecar process ID, or `-` if absent.               |
| `STATE`      | `running`, `unhealthy`, `stopped`, or `unknown`.    |
| `LISTEN`     | UDS path or address the sidecar listens on, or `-`. |
| `UPTIME`     | `HH:MM:SS` since the marker was written, or `-`.    |

### JSON (`--json`)

```bash
firma sidecar status --json
```

Emits a single JSON array — one object per sidecar. An empty list prints `[]`.

```json
[
  {
    "sandbox_id": "my-sandbox",
    "agent_id": "claude-code",
    "session_id": "sess-abc123",
    "authority_url": "http://127.0.0.1:50051",
    "policy_bundle_version": "a1b2c3d4",
    "pid": 42891,
    "started_at": "2026-05-18T08:00:00Z",
    "state": "running",
    "listen": "/run/user/1000/firma/run/my-sandbox/sidecar.sock",
    "uptime_secs": 154
  }
]
```

## Modes

### Default: all per-run sidecars

Running `firma sidecar status` with no extra flags lists every sidecar marker
under `<state_dir>/run/`. Markers with an unreadable `metadata.toml` are
silently skipped (see [Stale-marker GC](#stale-marker-gc) below).

### `--sandbox-id <id>`: single entry

Targets one sandbox by ID and performs an active liveness probe (connect to the
recorded UDS socket). Useful in scripts that monitor a specific `firma run`
invocation.

If `<id>` does not match any marker directory, the result is an empty table
(or `[]` with `--json`) and the command exits `0` — vacuously, nothing is
unhealthy.

### `--daemon`: long-lived daemon sidecar

Probes the daemon sidecar — the one started by `firma sidecar start`, not by
`firma run`. `--daemon` reads the daemon state from `resolve_state_dir(None)`,
which resolves to `$XDG_RUNTIME_DIR/firma` (fallback `/tmp/firma-$UID`).

> **Implementation note:** The original FIR-104 specification referenced
> `$XDG_DATA_HOME/firma/sidecar/state/` as the daemon sidecar path. Nothing
> writes that directory in the current implementation. `--daemon` therefore
> probes the daemon state dir (`$XDG_RUNTIME_DIR/firma`) where the daemon
> sidecar actually registers its marker. This discrepancy is recorded on
> FIR-104.

## STATE semantics

| State       | Meaning                                                 |
| ----------- | ------------------------------------------------------- |
| `running`   | PID alive and UDS socket responds to a connect probe.   |
| `unhealthy` | PID alive but UDS socket is closed or unresponsive.     |
| `stopped`   | PID is dead (or no PID is recorded in the marker).      |
| `unknown`   | Probe was inconclusive (no socket path recorded, etc.). |

## Exit codes

| Code | Meaning                                            |
| ---- | -------------------------------------------------- |
| `0`  | All listed sidecars are `running` (or list empty). |
| `1`  | Any sidecar is `unhealthy` or `stopped`.           |
| `2`  | Internal error; message written to stderr.         |

An empty sidecar list exits `0` — vacuously, nothing is unhealthy. Wire the
`0`/`1` split into healthchecks, systemd `ExecStartPost`, or CI gates:

```bash
firma sidecar status --json | jq -e 'all(.[]; .state == "running")'
```

## Stale-marker GC

Every run of `firma sidecar status` cleans up marker directories whose
recorded PID is dead. Rules:

- A marker directory is removed when its recorded PID does not exist in
  `/proc` (Linux) or is not visible to `kill(pid, 0)`.
- A marker whose `metadata.toml` is **unreadable or unparseable** is
  **never deleted**. It is skipped from the listing instead. This prevents
  `status` from destroying a live sidecar's socket directory during a
  mid-write race or after a schema change that the older binary produced.

`firma run` also removes its own marker directory on clean exit, so GC is a
last-resort safety net, not the primary cleanup mechanism.

## What's next

- [Wrap an agent with firma run](../firma-run/) — the command that creates the
  per-run sidecar markers that `firma sidecar status` reads.
- [Start and monitor the daemon (firma sidecar & monitor)](../manage-the-stack/) — supervise
  Authority and the daemon Sidecar as one unit.
- [Run the sidecar standalone](../run-the-sidecar/) — start a Sidecar directly
  without `firma run` or `firma sidecar start`.
