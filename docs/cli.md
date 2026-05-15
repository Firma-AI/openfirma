# CLI Reference

Single binary: `firma <subcommand>`. All examples below assume `firma` is on
PATH or invoked via `cargo run -p firma --`.

## `firma sidecar`

### Usage

```text
firma sidecar [OPTIONS]
```

### Options

| Flag                 | Short | Env var                          | Default              | Description               |
| -------------------- | ----- | -------------------------------- | -------------------- | ------------------------- |
| `--config-file`      | `-c`  | `FIRMA_SIDECAR_CONFIG_FILE`      | `firma_sidecar.toml` | TOML configuration file   |
| `--health-bind-addr` |       | `FIRMA_SIDECAR_HEALTH_BIND_ADDR` | `127.0.0.1:9000`     | Health check bind address |

Log-level flags are global (placed **before** the subcommand):

| Flag           | Env                | Default | Description                                |
| -------------- | ------------------ | ------- | ------------------------------------------ |
| `--log-filter` | `FIRMA_LOG_FILTER` | `info`  | `EnvFilter` directive (e.g. `firma=debug`) |
| `--log-file`   | `FIRMA_LOG_FILE`   | none    | File path for log output                   |

All options can be set through environment variables. CLI flags take precedence
over environment variables.

Valid log-filter values include `trace`, `debug`, `info`, `warn`, and `error`.

### Examples

Start with defaults:

```bash
firma sidecar
```

Specify a config file and debug logging:

```bash
firma --log-filter debug sidecar -c /etc/firma/sidecar.toml
```

Log to a file with a filter:

```bash
firma --log-file /var/log/firma.log --log-filter "firma_sidecar=debug,tower=warn" sidecar
```

Use environment variables:

```bash
export FIRMA_SIDECAR_CONFIG_FILE=/etc/firma/sidecar.toml
export FIRMA_LOG_FILTER=debug
firma sidecar
```

### Health Check

The sidecar exposes an HTTP health check server on the address specified by
`--health-bind-addr`. The default is `127.0.0.1:9000`.

### Shutdown

The sidecar handles `SIGTERM` and `SIGINT` for graceful shutdown:

1. Stop accepting new connections.
2. Drain in-flight requests up to `interceptor.drain_timeout_secs`.
3. Exit with code `0`.

### Standalone startup log contract

On every successful start the sidecar emits exactly seven INFO lines
in order. Operators automating the binary should wait for the final
`ready` line before sending traffic; the `examples/demo/` runbook
reproduces the contract and the `demo-e2e` CI gate scrapes it.

```text
config loaded             path="…"
mapping table loaded      rules=N
policy bundle loaded      version="…" policies=N
authority stream connected endpoint="…"
connector registry built  hosts=N default_timeout_ms=T
interceptor listening     addr="…"
ready
```

`policy bundle loaded version` is the eight-character hex prefix of
the SHA-256 of the concatenated `.cedar` files in `policy.dir`. Line 4
fires unconditionally; when `policy.authority_url` is unset the
endpoint is reported as `(disabled)`.

### Exit codes

| Code | When                                                             |
| ---- | ---------------------------------------------------------------- |
| `0`  | Graceful shutdown after `SIGINT` / `SIGTERM`.                    |
| `1`  | Configuration parse error, validation error, or startup failure. |


## `firma authority`

Reference Authority binary used for local development. Issues
PASETO v4 capability tokens, streams policy bundles and
revocations. Pre-flight only, never on the hot path.

### `firma authority issue`

Issues a signed capability token directly from the loaded Cedar
bundle and writes it to a TOML seed file consumable by the
sidecar `[capability_seed]` section. Stop-gap until the sidecar
wires the gRPC `IssueCapability` client; not intended for
production traffic.

```bash
firma authority --config authority.toml issue \
  --agent-id demo-agent \
  --session-id demo-session \
  --action communication.external.send \
  --resource-scope '*' \
  --ttl-seconds 3600 \
  --output capability-demo-agent.toml
```

| Flag               | Required | Default | Description                                            |
| ------------------ | -------- | ------- | ------------------------------------------------------ |
| `--agent-id`       | yes      |         | Token agent identity.                                  |
| `--session-id`     | yes      |         | Token session identity.                                |
| `--action`         | yes      |         | Action class. Repeat the flag for multiple.            |
| `--resource-scope` | no       | `*`     | Resource scope pattern.                                |
| `--ttl-seconds`    | no       | `3600`  | Requested TTL. Clamped by `max_ttl_seconds` in config. |
| `--output`/`-o`    | yes      |         | Path to write the seed TOML.                           |

The subcommand evaluates the loaded Cedar bundle exactly like
the gRPC `IssueCapability` handler — a Cedar deny exits non-zero
with `issuance failed: cedar denied issuance (...): ...`.

The output TOML carries the raw `v4.public....` token plus the
matching claims; the sidecar consumes it via
`[capability_seed].paths` and verifies the signature with
`[authority].public_key_path`.

## `firma run`

Wraps an agent process inside a sandbox and forces all outbound traffic
through the Sidecar. When no Sidecar is reachable at the configured
endpoint, `firma run` autostarts a per-run Sidecar that lives only for
the duration of the wrapped process.

### Autostart

The autostart path runs only when all of the following are true:

- The configured sidecar endpoint is unreachable (the probe returns an
  error within 500ms).
- `--sidecar` is at its default value of `auto`.
- `--no-autostart` is **not** set.
- The host network policy has `fail_closed = true` (the default).

When autostart fires, `firma run`:

1. Resolves the per-sandbox marker directory under
   `$XDG_RUNTIME_DIR/firma/run/<sandbox_id>/` (Linux), `/tmp/firma-$UID/firma/run/<sandbox_id>/` (macOS fallback), or `%LOCALAPPDATA%\firma\runtime\run\<sandbox_id>\` (Windows; see platform caveat below).
2. Synthesizes a sidecar TOML by inheriting the operator template
   (`--sidecar-config` → `FIRMA_SIDECAR_CONFIG_FILE` → `./firma_sidecar.toml` → minimal) and overriding the `[interceptor]` section to bind a Unix-domain socket at `<marker_dir>/sidecar.sock`.
3. Spawns `firma sidecar --config-file <marker_dir>/sidecar.toml` as a
   child process with stderr piped.
4. Reads stderr line by line and waits for the seven-line ready log
   contract documented under [`firma sidecar`](#firma-sidecar). The third
   and fourth lines populate `policy_bundle_version` and `authority_url`
   in the marker `metadata.toml`.
5. On `ready`, writes `sidecar.pid` and `metadata.toml` and continues to
   drain stderr into `<marker_dir>/sidecar.log` for the lifetime of the
   run.
6. Substitutes `unix://<sock>` as the effective endpoint and proceeds.

When the `firma run` process exits — by clean exit, `SIGINT`, or
`SIGTERM` — the supervisor sends `SIGTERM` to the spawned sidecar, waits
up to 5 seconds, then `SIGKILL`. The marker directory is removed on a
best-effort basis (FIR-103's `firma sidecar status` also garbage-collects
stale entries).

### Flags

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--sidecar <auto\|external>` | `auto` | `auto` autostarts when unreachable; `external` requires an already-running sidecar at `--sidecar-endpoint`. |
| `--no-autostart` | off | Fail with a typed error if the endpoint is unreachable. CI safety net. Mutually exclusive with `--sidecar`. |
| `--sidecar-config <path>` | — | Sidecar TOML template for autostart. Overrides `FIRMA_SIDECAR_CONFIG_FILE` and the CWD fallback. |
| `--sidecar-startup-timeout-secs <int>` | `10` | Maximum wait for the `ready` line. `0` reverts to the built-in default. |

### Typed errors

| Error | Trigger |
| ----- | ------- |
| `SidecarUnreachable` | Endpoint unreachable and autostart disabled (`--no-autostart` or `--sidecar=external`). |
| `SidecarReadyTimeout` | Spawned sidecar did not emit `ready` within the configured budget. Error message points to `<marker_dir>/sidecar.log`. |
| `SidecarStartupFailed` | Spawn or stderr-pipe setup failed; or stderr closed before `ready`. |
| `UnsupportedPlatform` | Autostart requested on a platform that does not support a UDS interceptor (e.g. Windows). Use `--sidecar=external` instead. |

### Operator caveats

- A template with `interceptor.https_mitm.enabled = true` may fail
  validation when the interceptor is forced to `unix_socket` mode.
  Either disable MITM in the template or use `--sidecar=external` with a
  long-lived externally-managed sidecar.
- Autostart currently requires Unix (Linux + macOS). On Windows,
  `--sidecar=auto` returns `UnsupportedPlatform`; pre-start the sidecar
  yourself and pass `--sidecar=external`.
- The marker layout is the contract consumed by `firma sidecar status`
  (see FIR-103). Do not write or edit those files manually.

### Authority bootstrap

`firma run` decides whether to autostart a Mini Authority before it
launches the per-run Sidecar. Decision precedence:

1. `--authority local` or `--authority <url>` — skip the prompt entirely.
2. Persisted `[authority]` table in `$XDG_CONFIG_HOME/firma/firma.toml`
   (Linux), `~/Library/Application Support/firma/firma.toml` (macOS),
   `%APPDATA%\firma\firma.toml` (Windows) — skip the prompt.
3. Neither set, stdin is a TTY — print a single y/N prompt:

   ```text
   No Authority is configured for this project.
   firma run can start a local Mini Authority for development on [::1]:50051.
   This is suitable for a single developer on a trusted workstation.

   Start a local Mini Authority? [y/N]:
   ```

   On `y` / `Y` / `yes`, `firma run` persists
   `[authority].type = "local"` (file mode `0600`, parent mode `0700`)
   and autostarts. On anything else, it aborts with `AuthorityDeclined`.

4. Neither set, stdin is not a TTY — abort with `AuthorityPromptNoTty`.

On `local` selection, `firma run` probes `[::1]:50051` first. If
reachable, no autostart fires. Otherwise the per-run Mini Authority is
spawned with an ephemeral signing key and the embedded `developer`
policy profile materialised under
`<runtime>/firma/run/<sandbox_id>/authority/`. The Authority is killed
on `firma run` exit (`SIGTERM` then `SIGKILL` after a 5s grace).

### Authority flags

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--authority <local\|url>` | unset | Skip the y/N prompt. `local` autostarts on `[::1]:50051`; any other value is treated as a remote Authority URL. |
| `--authority-profile <name>` | `developer` | Profile materialised by the autostarted Mini Authority. Currently only `developer` ships. Ignored when Authority is remote or already reachable. |

The `--no-autostart` flag also suppresses Authority autostart. With
`--no-autostart --authority local` `firma run` exits immediately with a
typed argument-conflict error.

### Authority typed errors

| Error | Trigger |
| ----- | ------- |
| `MissingAuthority` | `--no-autostart` and nothing configured. |
| `AuthorityDeclined` | User answered `n` (or empty / garbage) at the prompt. |
| `AuthorityPromptNoTty` | No config, no CLI flag, stdin is not a TTY. |
| `AuthorityStartupFailed` | Spawn or stderr-pipe setup failed; stderr closed before `ready`. |
| `AuthorityReadyTimeout` | Spawned authority did not emit `ready` within the budget. |
| `AuthorityUnreachable` | Remote URL did not answer a TCP connect probe. |
| `AuthorityUnknownProfile` | `--authority-profile` is not a registered profile. |
