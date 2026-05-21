# `firma sidecar` — daemon lifecycle

`firma sidecar` covers both the in-process enforcement server (used by
`firma run` autostart) and the operator-facing daemon lifecycle —
`start`, `stop`, `status`. The previous `firma stack` command is gone;
`firma sidecar start` and `firma sidecar stop` now own daemon-mode boot
and shutdown.

For live activity tailing, see
[`firma monitor`](firma_monitor_command.md). For sidecar enforcement
internals (interceptor, policy, mapping), see the
[sidecar README](../../crates/firma-sidecar/README.md).

## Quickstart

```bash
firma sidecar start --detach           # daemon-mode boot
firma sidecar status                   # docker-ps-style listing
firma sidecar stop --timeout 10        # graceful tear-down
```

## `firma sidecar start`

```text
firma sidecar start [--config <firma.toml>] [--detach] [--state-dir <dir>]
```

- `--config`: the unified `firma.toml`. Defaults to the discovered
  `firma.toml` (same Config Discovery precedence as `sidecar` /
  `authority` / `run`; see [`docs/cli.md`](../cli.md)). The resolved file
  is passed to both the spawned authority and sidecar with `--config`.
- `--detach`: fork a hidden `__supervise` child after readiness and
  return immediately.
- `--state-dir`: state directory override. Env: `FIRMA_STATE_DIR`. When
  unset, the XDG/platform default applies. `state_dir` is never read
  from the config file.

`start` boots the authority first, waits for its TCP listener, boots
the sidecar, waits for CA material on disk, then either blocks
(`Foreground`) or detaches (`Detached`). On any error after the children
have been spawned, `start` tears them down and removes any pid / listen
/ lock files it wrote — fail-closed.

## `firma sidecar stop`

```text
firma sidecar stop [--config <firma.toml>] [--state-dir <dir>] [--timeout <secs>]
```

`--timeout` defaults to 2 seconds and controls the soft-signal grace
period before hard kill. `--config` is accepted for compatibility but
not used to resolve `state_dir`; use `--state-dir` / `FIRMA_STATE_DIR`.

Exit codes: `0` on success (graceful or hard-kill fallback); `2` on error.

## `firma sidecar status`

Docker-ps-style listing of live sidecars. See
[`firma sidecar status`](../../docs-site/src/content/docs/guides/firma-sidecar-status.md)
for the full surface.

## State directory layout

```text
<state_dir>/
  authority.pid
  authority.log
  authority.listen
  sidecar.pid
  sidecar.log
  sidecar.listen
  stack.pid              # supervisor pid (detached mode)
  stack.lock
  supervisor.log
  audit.jsonl
  generated-firma-ca/
```

State-dir resolution order: `--state-dir` flag → `FIRMA_STATE_DIR` env
→ `$XDG_RUNTIME_DIR/firma` → `/tmp/firma-$UID` on Unix;
`%LOCALAPPDATA%\firma\runtime` → `%TEMP%\firma` on Windows.

## See also

- [`firma init`](firma_init_command.md) — project scaffold (config dir + keys).
- [`firma monitor`](firma_monitor_command.md) — tail audit + component logs.
- [Configuration reference](../configuration.md) — full `firma.toml` shape.
