# `firma` — Unified Firma OSS CLI

Single binary exposing every Firma OSS production component as a subcommand.

## Trust chain

1. **`firma authority`** — pre-flight only. Issues PASETO v4 capability
   tokens, streams policy bundles and revocations.
2. **`firma sidecar`** — hot-path enforcement. Every outbound agent call
   passes through it; fail-closed.
3. **`firma run`** — wrapper that confines an agent process inside a
   sandbox backend and forces all egress through the sidecar.
4. **`firma stack`** — supervisor that runs authority + sidecar as one
   unit (start, stop, status). Reuses the same library as
   `firma-demo-tui`.
5. **`firma monitor`** — read-only tail of audit events and component
   logs from a running stack.
6. **`firma doctor`** — one-shot diagnostic that prints what's installed,
   reachable, and configured.

## Install

From source:

```bash
cargo install --path crates/firma
```

The resulting binary is named `firma`.

## Global flags

| Flag           | Env                | Default  | Description                                 |
| -------------- | ------------------ | -------- | ------------------------------------------- |
| `--log-filter` | `FIRMA_LOG_FILTER` | `info`   | `EnvFilter` directive (e.g. `firma=debug`). |
| `--log-file`   | `FIRMA_LOG_FILE`   | _stderr_ | Write logs to file (truncated on open).     |
| `--help`       | —                  | —        | Print help.                                 |
| `--version`    | —                  | —        | Print version.                              |

## Subcommands

### `firma sidecar`

Run the enforcement proxy.

```bash
firma sidecar --config-file /etc/firma/sidecar.toml
```

| Flag                 | Env                              | Default              |
| -------------------- | -------------------------------- | -------------------- |
| `-c, --config-file`  | `FIRMA_SIDECAR_CONFIG_FILE`      | `firma_sidecar.toml` |
| `--health-bind-addr` | `FIRMA_SIDECAR_HEALTH_BIND_ADDR` | `127.0.0.1:9000`     |

Config schema: see `crates/firma-sidecar/src/config.rs`.

### `firma authority`

Run the mini-Authority dev server (no subcommand) or manage on-disk
state. Pre-flight only — not on the hot path.

```bash
firma authority --config /etc/firma/authority.toml          # serve gRPC
firma authority generate-key -o auth.key                    # signing key
firma authority issue --agent-id ... --output seed.toml     # issue token
firma authority revocations add <token-id>                  # revoke
firma authority revocations compact                         # gc revocations
```

Top-level flags:

| Flag           | Description                       |
| -------------- | --------------------------------- |
| `-c, --config` | TOML config path (serve / issue). |

Subcommands:

| Subcommand            | Description                              |
| --------------------- | ---------------------------------------- |
| _(none)_              | Serve gRPC (default action).             |
| `generate-key`        | Generate an Ed25519 signing key pair.    |
| `issue`               | Issue a signed capability seed file.     |
| `revocations add`     | Append a token ID to the revocation log. |
| `revocations compact` | Remove expired entries from the log.     |

`generate-key` flags:

| Flag           | Default               | Description             |
| -------------- | --------------------- | ----------------------- |
| `-o, --output` | `firma-authority.key` | Output secret-key path. |

`issue` flags:

| Flag               | Default            | Description                                              |
| ------------------ | ------------------ | -------------------------------------------------------- |
| `--agent-id`       | _required_         | Agent identity for the issued token.                     |
| `--session-id`     | _required_         | Session identity (UUID).                                 |
| `--action`         | _required, repeat_ | Action class(es) the token covers.                       |
| `--resource-scope` | `*`                | Resource scope pattern (e.g. `wttr.in*`).                |
| `--ttl-seconds`    | `3600`             | Requested TTL; clamped by `max_ttl_seconds` from config. |
| `-o, --output`     | _required_         | Output seed TOML path.                                   |

`revocations add` flags:

| Arg / Flag     | Default            | Description                    |
| -------------- | ------------------ | ------------------------------ |
| `<token-id>`   | _required_         | Positional token ID to revoke. |
| `-r, --reason` | `operator-revoked` | Human-readable reason.         |

Config schema: see `crates/firma-authority/src/config.rs`.

### `firma run`

Wrap an agent command behind a sandbox backend.

```bash
firma run --profile generic -- python agent.py
```

| Flag                       | Description                                     |
| -------------------------- | ----------------------------------------------- |
| `--profile <id>`           | Built-in profile id (default: `generic`).       |
| `--config <path>`          | Optional runtime config (.toml/.yaml).          |
| `--backend <kind>`         | Override: `bwrap`, `vz`, `wsl2`, `firecracker`. |
| `--sidecar-endpoint <url>` | Override sidecar endpoint.                      |
| `--capability-file <path>` | Capability lease refresh source.                |
| `--identity-mode <mode>`   | `sandbox-user` or `host-user`.                  |
| `--preserve-host-user`     | Force host UID/GID inside sandbox.              |
| `--print-effective-config` | Dump resolved config as JSON before exec.       |

Wrapped command and args after `--`.

### `firma stack`

Supervise the full stack (authority + sidecar) as one unit. Plug and play:

```bash
# Scaffold two separate dirs: configs/keys vs. mutable runtime state.
firma stack init --config-dir /etc/firma --state-dir /var/run/firma

# Boot. State dir is read from firma-stack.toml unless --state-dir overrides.
firma stack start --config /etc/firma/firma-stack.toml             # foreground
firma stack start --config /etc/firma/firma-stack.toml --detach    # daemon

# Observe.
firma stack status --state-dir /var/run/firma
firma stack status --state-dir /var/run/firma --json

# Tear down.
firma stack stop --state-dir /var/run/firma
```

Layout written by `init`:

```text
<config_dir>/
  firma-stack.toml      authority.toml      sidecar.toml
  mapping-rules.toml    authority.key       authority.pub      audit.key
  policies/             issuance-policies/

<state_dir>/
  revocations.txt
  generated-firma-ca/   # populated by sidecar
  # populated by start: authority.pid, sidecar.pid, stack.pid, stack.lock,
  # authority.log, sidecar.log, supervisor.log, *.listen, audit.jsonl
```

Subcommands:

| Subcommand | Description                                              |
| ---------- | -------------------------------------------------------- |
| `init`     | Scaffold state directory with keys + default configs.    |
| `start`    | Boot authority + sidecar. `--detach` forks a supervisor. |
| `stop`     | Soft-signal then hard-kill on `--timeout` (default 10s). |
| `status`   | Per-component pid, listen, state, uptime.                |

`init` flags:

| Flag                 | Default           | Description                                |
| -------------------- | ----------------- | ------------------------------------------ |
| `--config-dir`       | _required_        | Where to write TOMLs, keys, policy dirs.   |
| `--state-dir`        | _required_        | Where to write `revocations.txt` + CA dir. |
| `--force`            | _off_             | Overwrite existing files.                  |
| `--authority-listen` | `127.0.0.1:50051` | Authority gRPC listen address.             |
| `--sidecar-listen`   | `127.0.0.1:8080`  | Sidecar HTTP proxy listen.                 |

`start` / `stop` / `status` flags:

| Flag          | Env                  | Default                                    |
| ------------- | -------------------- | ------------------------------------------ |
| `--config`    | `FIRMA_STACK_CONFIG` | `./firma-stack.toml` (`start` only)        |
| `--state-dir` | `FIRMA_STATE_DIR`    | `state_dir` from `--config` → XDG fallback |
| `--detach`    | —                    | _off_ (`start` only)                       |
| `--timeout`   | —                    | `2` seconds (`stop` only)                  |
| `--json`      | —                    | _off_ (`status` only)                      |

All three subcommands accept `--config` and read `state_dir` from the stack
config when `--state-dir` is not given. The intuitive path is to pass only
`--config` everywhere; pass `--state-dir` to override.

State-dir resolution order: `--state-dir` flag → `FIRMA_STATE_DIR` env →
`state_dir` field in `--config` → `$XDG_RUNTIME_DIR/firma` → `/tmp/firma-$UID`
on Unix; `%LOCALAPPDATA%\firma\runtime` → `%TEMP%\firma` on Windows.

Exit codes:
- `status`: `0` all running, `1` any unhealthy/stopped, `2` internal error.
- `stop`: `0` on success (graceful or forced hard-kill), `2` on error.

Full reference: `docs/markdown/firma_stack_command.md`.

### `firma doctor`

Print a structured diagnostic report — `firma binary`, sandbox backends,
sidecar reachability, authority reachability, config parse status,
capability seed presence, state directories. Read-only.

```bash
firma doctor                          # pretty
firma doctor --json | jq .            # machine-readable
firma doctor --timeout-ms 1500        # slower network probe
```

Flags:

| Flag           | Env                  | Default  | Description                                               |
| -------------- | -------------------- | -------- | --------------------------------------------------------- |
| `--config`     | `FIRMA_STACK_CONFIG` | _unset_  | Explicit stack config path. Otherwise walked up from cwd. |
| `--state-dir`  | `FIRMA_STATE_DIR`    | resolved | Override the runtime state directory.                     |
| `--json`       | —                    | _off_    | Emit a single JSON object instead of pretty text.         |
| `--timeout-ms` | —                    | `500`    | Per-probe network timeout (TCP / UDS connect).            |

Each check is `OK` / `WARN` / `FAIL` with a one-line reason. Categories
that don't apply to the current OS report `WARN`, never `FAIL`.

Exit codes:

- `0` — every check is `OK` or `WARN`.
- `1` — at least one check is `FAIL`.
- `2` — internal error (render or runtime failure).

Full reference: [`docs/markdown/firma_doctor_command.md`](../../docs/markdown/firma_doctor_command.md).

### `firma monitor`

Tail the local audit stream (and optionally the authority and sidecar
component logs). Read-only; multiple concurrent monitors are safe.

```bash
firma monitor                                          # audit, follow if TTY
firma monitor --only-deny                              # audit, deny only
firma monitor --agent codex --since 15m                # filtered backfill
firma monitor --json | jq .                            # byte-for-byte pass-through
firma monitor --source all --no-follow                 # one-shot, all sources
```

Flags:

| Flag             | Env                  | Default  | Description                                      |
| ---------------- | -------------------- | -------- | ------------------------------------------------ |
| `--config`       | `FIRMA_STACK_CONFIG` | _unset_  | Stack config; `state_dir` read from it when set. |
| `--state-dir`    | `FIRMA_STATE_DIR`    | resolved | State dir override.                              |
| `--source`       | —                    | `audit`  | `audit`, `authority`, `sidecar`, or `all`.       |
| `--decision`     | —                    | _unset_  | Audit filter: `allow`, `deny`, `passthrough`.    |
| `--only-deny`    | —                    | _off_    | Shortcut for `--decision deny`.                  |
| `--action-class` | —                    | _unset_  | Audit filter: exact match on `action`.           |
| `--agent`        | —                    | _unset_  | Audit filter: exact match on `agent_id`.         |
| `--since`        | —                    | _unset_  | Backfill: `15m`, `2h`, RFC3339 timestamp.        |
| `--format`       | —                    | `pretty` | `pretty` or `json` (byte-for-byte pass-through). |
| `--json`         | —                    | _off_    | Shortcut for `--format json`.                    |
| `--tail`         | —                    | _off_    | Force follow even when piped.                    |
| `--no-follow`    | —                    | _off_    | Read once and exit (overrides TTY auto-tail).    |

Auto-tail: follows when stdout is a TTY; one-shot when piped, unless
`--tail` or `--no-follow` is set. Ctrl-C exits with code 0.

Full reference: [`docs/markdown/firma_monitor_command.md`](../../docs/markdown/firma_monitor_command.md).

### Hidden helpers

Internal subcommands. Not for direct operator use; documented for
completeness.

| Subcommand       | Spawned by                   | Purpose                                        |
| ---------------- | ---------------------------- | ---------------------------------------------- |
| `__dns-stub`     | `firma run`                  | In-sandbox UDP/TCP DNS stub for the agent.     |
| `__proxy-bridge` | `firma run`                  | TCP↔UDS bridge from sandbox to sidecar socket. |
| `__supervise`    | `firma stack start --detach` | Re-attaches to authority + sidecar pidfiles.   |

Each takes a `--listen` (and `--upstream-uds` / `--state-dir`) flag set
by its spawner.
