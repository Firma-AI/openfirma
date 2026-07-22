# `firma` — Unified Firma OSS CLI

Single binary exposing every Firma OSS production component as a subcommand.

## Trust chain

1. **`firma authority`** — pre-flight only. Issues PASETO v4 capability
   tokens, streams policy bundles and revocations.
2. **`firma sidecar`** — hot-path enforcement. Every outbound agent call
   passes through it; fail-closed.
3. **`firma run`** — wrapper that confines an agent process inside a
   sandbox backend and forces all egress through the sidecar.
4. **`firma config`** — scaffold a fresh project: config dir, signing keys,
   default policies. Also runs implicitly on first `firma run` if no
   `firma.toml` is found.
5. **`firma sidecar {start,stop,status}`** — operator-facing daemon
   lifecycle for the sidecar (and the authority started alongside it).
6. **`firma monitor`** — read-only tail of audit events and component
   logs from a running sidecar.
7. **`firma doctor`** — one-shot diagnostic that prints what's installed,
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
firma sidecar --config /etc/firma/firma.toml
```

| Flag                 | Env                              | Default          |
| -------------------- | -------------------------------- | ---------------- |
| `-c, --config`       | `FIRMA_SIDECAR_CONFIG_FILE`      | discovered       |
| `--health-bind-addr` | `FIRMA_SIDECAR_HEALTH_BIND_ADDR` | `127.0.0.1:9000` |

When `--config` is omitted, a shared `firma.toml` is discovered from
`$FIRMA_CONFIG` or by walking up to `.firma/firma.toml` — see the Config
Discovery section in `docs/cli.md`.

Config schema: see `crates/firma-sidecar/src/config.rs`.

### `firma authority`

Run the mini-Authority dev server (no subcommand) or manage on-disk
state. Pre-flight only — not on the hot path.

```bash
firma authority --config /etc/firma/firma.toml              # serve gRPC
firma authority generate-key -o auth.key                    # signing key
firma authority init-tls --out-dir .                   # transport TLS
firma authority issue --agent-id ... --output seed.toml     # issue token
firma authority revocations add <token-id>                  # revoke
firma authority revocations compact                         # gc revocations
```

Top-level flags:

| Flag           | Description                       |
| -------------- | --------------------------------- |
| `-c, --config` | TOML config path (serve / issue). |

Subcommands:

| Subcommand            | Description                               |
| --------------------- | ----------------------------------------- |
| _(none)_              | Serve gRPC (default action).              |
| `generate-key`        | Generate an Ed25519 signing key pair.     |
| `init-tls`            | Generate CA + Authority TLS PEM material. |
| `issue`               | Issue a signed capability seed file.      |
| `revocations add`     | Append a token ID to the revocation log.  |
| `revocations compact` | Remove expired entries from the log.      |

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

| Arg / Flag     | Default            | Description                                     |
| -------------- | ------------------ | ----------------------------------------------- |
| `<token-id>`   | _required_         | Canonical `ctok` capability token ID to revoke. |
| `-r, --reason` | `operator-revoked` | Human-readable reason.                          |

Config schema: see `crates/firma-authority/src/config.rs`.

### `firma run`

Wrap an agent command behind a sandbox backend.

```bash
firma run --profile generic -- python agent.py
```

| Flag                       | Description                                            |
| -------------------------- | ------------------------------------------------------ |
| `--profile <id>`           | Built-in profile id (default: `generic`).              |
| `--config <path>`          | Optional runtime config (.toml/.yaml).                 |
| `--backend <kind>`         | Override: `bwrap`, `vz`, `wsl2`, `firecracker`.        |
| `--sidecar <local\|url>`   | `local` autostarts; a URL targets an external sidecar. |
| `--capability-file <path>` | Capability lease refresh source.                       |
| `--identity-mode <mode>`   | `sandbox-user` or `host-user`.                         |
| `--preserve-host-user`     | Force host UID/GID inside sandbox.                     |
| `--print-effective-config` | Dump resolved config as JSON before exec.              |

Wrapped command and args after `--`.

### `firma config`

Scaffold a fresh project: signing keys, default `firma.toml`, empty
policy directories. Three usage shapes:

```bash
firma config                                              # interactive wizard
firma config --yes                                        # non-interactive defaults
firma config --output-dir .local                          # specific directory
firma config --mode agent-local --profile codex \
           --mapping anthropic --workspace ./proj --yes # scripted full setup
```

`firma run <agent>` invokes the same scaffold implicitly on first use
when no `firma.toml` is discoverable, so the one-command path works
from a fresh clone.

Layout written by `firma config`:

```text
<workspace>/.firma/        # project-local config dir
  firma.toml            authority.key       audit.key
  mapping-rules.toml    policies/           issuance-policies/

<state_dir>/               # user-global runtime state (XDG default)
  revocations.txt
  generated-firma-ca/    # populated by the sidecar
```

`firma.toml` is one sectioned file: `[project]`, `[authority]`,
`[sidecar.*]`, and `[run]`. The post-config `next:` hint is `firma run <agent>`
(or `firma sidecar start` for the daemon path).

`[sidecar.authority].agent_id` is the Authority-registered UUID. It is
independent from `[run].profile`, which selects local sandbox and runtime
behaviour. New local configs generate a UUIDv7. Remote configs require the UUID
returned by registration, supplied with `--agent-id` or entered interactively.

`firma config` flags:

| Flag                    | Default                 | Description                                           |
| ----------------------- | ----------------------- | ----------------------------------------------------- |
| `--output-dir <dir>`    | `.firma` in current dir | Where firma.toml, policies, and mappings are written. |
| `--workspace <dir>`     | current directory       | Agent RW access path (bwrap mount).                   |
| `--profile <profile>`   | wizard / `generic`      | Local execution profile written to `[run].profile`.   |
| `--agent-id <agent-id>` | generated / prompt      | Authority-registered `agt_` TypeID.                   |
| `--posture <val>`       | wizard / `dev`          | Cedar enforcement posture.                            |
| `--mapping <val>`       | wizard / `anthropic`    | Mapping file(s) — repeat for multiple.                |
| `--yes`                 | _off_                   | Skip the wizard; use defaults for any unset flag.     |
| `--state-dir <dir>`     | `FIRMA_STATE_DIR` / XDG | State dir (keys, revocations, generated CA).          |
| `--force`               | _off_                   | Overwrite existing files.                             |

### `firma sidecar` (daemon lifecycle)

Operator-facing daemon control. `firma sidecar` with no subcommand still
runs the enforcement server (used by `firma run` autostart).

```bash
# Start (foreground or detached). Discovers firma.toml; boots
# authority + sidecar pair from the same file.
firma sidecar start
firma sidecar start --detach

# Inspect (docker-ps-style across live per-run sidecars).
firma sidecar status
firma sidecar status --json
firma sidecar status --daemon          # daemon-mode pid

# Tear down (soft-signal then hard-kill after --timeout).
firma sidecar stop --timeout 10
```

Subcommands:

| Subcommand | Description                                      |
| ---------- | ------------------------------------------------ |
| _(none)_   | Run the enforcement proxy in the foreground.     |
| `start`    | Daemon-mode boot. `--detach` forks a supervisor. |
| `stop`     | Soft-signal then hard-kill on `--timeout`.       |
| `status`   | docker-ps-style listing of live sidecars.        |

`start` / `stop` flags:

| Flag          | Env                         | Default                                      |
| ------------- | --------------------------- | -------------------------------------------- |
| `--config`    | `FIRMA_SIDECAR_CONFIG_FILE` | discovered `firma.toml` (`start` only)       |
| `--state-dir` | `FIRMA_STATE_DIR`           | `$XDG_RUNTIME_DIR/firma` → `/tmp/firma-$UID` |
| `--detach`    | —                           | _off_ (`start` only)                         |
| `--timeout`   | —                           | `2` seconds (`stop` only)                    |

State-dir resolution order: `--state-dir` flag → `FIRMA_STATE_DIR` env →
`$XDG_RUNTIME_DIR/firma` → `/tmp/firma-$UID` on Unix;
`%LOCALAPPDATA%\firma\runtime` → `%TEMP%\firma` on Windows.

Exit codes:

- `stop`: `0` on success (graceful or forced hard-kill), `2` on error.

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

| Flag           | Env               | Default    | Description                                                 |
| -------------- | ----------------- | ---------- | ----------------------------------------------------------- |
| `--config`     | —                 | discovered | Unified `firma.toml` to inspect. Otherwise auto-discovered. |
| `--state-dir`  | `FIRMA_STATE_DIR` | resolved   | Override the runtime state directory.                       |
| `--json`       | —                 | _off_      | Emit a single JSON object instead of pretty text.           |
| `--timeout-ms` | —                 | `500`      | Per-probe network timeout (TCP / UDS connect).              |

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

| Flag             | Env               | Default  | Description                                            |
| ---------------- | ----------------- | -------- | ------------------------------------------------------ |
| `--config`       | —                 | _unset_  | Accepted for compatibility; not used to resolve state. |
| `--state-dir`    | `FIRMA_STATE_DIR` | resolved | State dir override.                                    |
| `--source`       | —                 | `audit`  | `audit`, `authority`, `sidecar`, or `all`.             |
| `--decision`     | —                 | _unset_  | Audit filter: `allow`, `deny`, `passthrough`.          |
| `--only-deny`    | —                 | _off_    | Shortcut for `--decision deny`.                        |
| `--action-class` | —                 | _unset_  | Audit filter: exact match on `action`.                 |
| `--agent`        | —                 | _unset_  | Audit filter: exact match on `agent_id`.               |
| `--since`        | —                 | _unset_  | Backfill: `15m`, `2h`, RFC3339 timestamp.              |
| `--format`       | —                 | `pretty` | `pretty` or `json` (byte-for-byte pass-through).       |
| `--json`         | —                 | _off_    | Shortcut for `--format json`.                          |
| `--tail`         | —                 | _off_    | Force follow even when piped.                          |
| `--no-follow`    | —                 | _off_    | Read once and exit (overrides TTY auto-tail).          |

Auto-tail: follows when stdout is a TTY; one-shot when piped, unless
`--tail` or `--no-follow` is set. Ctrl-C exits with code 0.

Full reference: [`docs/markdown/firma_monitor_command.md`](../../docs/markdown/firma_monitor_command.md).

### Hidden helpers

Internal subcommands. Not for direct operator use; documented for
completeness.

| Subcommand       | Spawned by                     | Purpose                                        |
| ---------------- | ------------------------------ | ---------------------------------------------- |
| `__dns-stub`     | `firma run`                    | In-sandbox UDP/TCP DNS stub for the agent.     |
| `__proxy-bridge` | `firma run`                    | TCP↔UDS bridge from sandbox to sidecar socket. |
| `__supervise`    | `firma sidecar start --detach` | Re-attaches to authority + sidecar pidfiles.   |

Each takes a `--listen` (and `--upstream-uds` / `--state-dir`) flag set
by its spawner.
