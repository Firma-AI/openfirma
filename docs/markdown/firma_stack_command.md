# `firma stack`

`firma stack` supervises authority and sidecar as one unit. For live
activity tailing, see [`firma monitor`](firma_monitor_command.md).

## Quickstart

```bash
firma stack init --config-dir /etc/firma --state-dir /var/run/firma
firma stack start --config /etc/firma/firma-stack.toml --detach
# For `firma monitor` see firma_monitor_command.md.
firma stack status --config /etc/firma/firma-stack.toml
firma stack stop --config /etc/firma/firma-stack.toml
```

## `firma stack init`

```text
firma stack init --config-dir <dir> --state-dir <dir>
                 [--force]
                 [--authority-listen <addr>]
                 [--sidecar-listen <addr>]
```

Scaffolds a fresh deployment in two separate directories:

- `<config_dir>/`: `firma-stack.toml`, `authority.toml`, `sidecar.toml`,
  `mapping-rules.toml`, `authority.key`/`.pub`, `audit.key`, empty
  `policies/`, `issuance-policies/`.
- `<state_dir>/`: empty `revocations.txt`, `generated-firma-ca/`.
  Pid/listen/log files are written here later by `start`.

Existing files are preserved unless `--force` is set. The generated
`firma-stack.toml` embeds `state_dir = "<state_dir>"` so subsequent
`start` / `stop` / `status` / [`monitor`](firma_monitor_command.md) invocations only need `--config`.

## `firma stack start`

```text
firma stack start [--config <stack.toml>] [--detach] [--state-dir <dir>]
```

- `--config`: stack config file. Default: `./firma-stack.toml`. Env:
  `FIRMA_STACK_CONFIG`.
- `--detach`: run the supervisor in the background after readiness succeeds.
- `--state-dir`: override the state directory. Env: `FIRMA_STATE_DIR`.
  When unset, the `state_dir` field in `--config` wins; otherwise the
  XDG/platform default applies.

## `firma stack stop`

```text
firma stack stop [--config <stack.toml>] [--state-dir <dir>] [--timeout <secs>]
```

`--timeout` defaults to 2 seconds and controls the soft-signal grace period
before hard kill. `--config` is accepted as a shortcut for reading
`state_dir`; pass it alone for the intuitive path.

Exit codes: `0` on success (graceful or hard-kill fallback); `2` on error.

## `firma stack status`

```text
firma stack status [--config <stack.toml>] [--state-dir <dir>] [--json]
```

Exit codes: `0` all running; `1` any unhealthy or stopped; `2` internal error.

## Stack Config

```toml
authority_config = "authority.toml"
sidecar_config = "sidecar.toml"
# state_dir = "<absolute or relative path>"
```

## State Directory Layout

```text
<state_dir>/
  authority.pid
  authority.log
  authority.listen
  sidecar.pid
  sidecar.log
  sidecar.listen
  stack.pid
  stack.lock
  supervisor.log
  audit.jsonl
  generated-firma-ca/
```

State directory resolution is `--state-dir`, then `FIRMA_STATE_DIR`, then the
platform default. Unix uses `$XDG_RUNTIME_DIR/firma` or `/tmp/firma-$UID`.
Windows uses `%LOCALAPPDATA%\firma\runtime` or `%TEMP%\firma`.
