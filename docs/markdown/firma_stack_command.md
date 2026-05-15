# `firma stack`

`firma stack` supervises authority and sidecar as one unit. For live
activity tailing, see [`firma monitor`](firma_monitor_command.md).

## Quickstart

```bash
firma stack init                       # config + state dirs default
firma stack start --detach             # discovers firma.toml
# For `firma monitor` see firma_monitor_command.md.
firma stack status --state-dir /var/run/firma
firma stack stop --state-dir /var/run/firma
```

## `firma stack init`

```text
firma stack init [--config-dir <dir>] [--state-dir <dir>]
                 [--force]
                 [--authority-listen <addr>]
                 [--sidecar-listen <addr>]
```

`--config-dir` and `--state-dir` are optional. When omitted:

- `--config-dir` defaults to the platform config dir (`$FIRMA_CONFIG_DIR`
  → `$XDG_CONFIG_HOME/firma` → `~/.config/firma` on Unix /
  `%USERPROFILE%\.firma` on Windows → platform default).
- `--state-dir` defaults to `FIRMA_STATE_DIR`, then
  `$XDG_RUNTIME_DIR/firma`, then `/tmp/firma-$UID`.

Scaffolds a fresh deployment in two separate directories:

- `<config_dir>/`: a single sectioned `firma.toml`, `mapping-rules.toml`,
  `authority.key`, `audit.key`, empty `policies/`, `issuance-policies/`.
  There is no `firma-stack.toml`, `authority.toml`, or `sidecar.toml`.
- `<state_dir>/`: empty `revocations.txt`, `generated-firma-ca/`.
  Pid/listen/log files are written here later by `start`.

Existing files are preserved unless `--force` is set. On success the
command prints:

```text
next:
  firma stack start
```

## `firma stack start`

```text
firma stack start [--config <firma.toml>] [--detach] [--state-dir <dir>]
```

- `--config`: the unified `firma.toml`. Defaults to the discovered
  `firma.toml` (same Config Discovery precedence as `sidecar` /
  `authority` / `run`; see [`docs/cli.md`](../cli.md)). The resolved file
  is passed to **both** spawned children with `--config`.
- `--detach`: run the supervisor in the background after readiness succeeds.
- `--state-dir`: override the state directory. Env: `FIRMA_STATE_DIR`.
  When unset, the XDG/platform default applies. `state_dir` is never read
  from the config file.

## `firma stack stop`

```text
firma stack stop [--config <firma.toml>] [--state-dir <dir>] [--timeout <secs>]
```

`--timeout` defaults to 2 seconds and controls the soft-signal grace period
before hard kill. `--config` is accepted for compatibility but is not used
to resolve `state_dir`; use `--state-dir` / `FIRMA_STATE_DIR`.

Exit codes: `0` on success (graceful or hard-kill fallback); `2` on error.

## `firma stack status`

```text
firma stack status [--config <firma.toml>] [--state-dir <dir>] [--json]
```

Exit codes: `0` all running; `1` any unhealthy or stopped; `2` internal error.
`--config` is accepted for compatibility but is not used to resolve
`state_dir`.

## Config

The whole stack reads one sectioned `firma.toml` — `[authority]` plus
`[sidecar.interceptor]` / `[sidecar.policy]` / `[sidecar.ca]` /
`[sidecar.audit]` / `[sidecar.mapping]`. There is no separate stack config
file and no `[stack]` section. See
[Configuration Reference](../configuration.md) for the scaffolded shape and
[`docs/cli.md`](../cli.md) for discovery precedence.

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
Windows uses `%LOCALAPPDATA%\firma\runtime` or `%TEMP%\firma`. It is never
read from the config file.
