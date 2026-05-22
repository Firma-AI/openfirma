# CLI Reference

Single binary: `firma <subcommand>`. All examples below assume `firma` is on
PATH or invoked via `cargo run -p firma --`.

## `firma sidecar`

### Usage

```text
firma sidecar [OPTIONS]
```

### Options

| Flag                 | Short | Env var                          | Default                                                | Description               |
| -------------------- | ----- | -------------------------------- | ------------------------------------------------------ | ------------------------- |
| `--config`           | `-c`  | `FIRMA_SIDECAR_CONFIG_FILE`      | discovered (see [Config Discovery](#config-discovery)) | TOML configuration file   |
| `--health-bind-addr` |       | `FIRMA_SIDECAR_HEALTH_BIND_ADDR` | `127.0.0.1:9000`                                       | Health check bind address |

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
firma --log-filter debug sidecar -c /etc/firma/firma.toml
```

Log to a file with a filter:

```bash
firma --log-file /var/log/firma.log --log-filter "firma_sidecar=debug,tower=warn" sidecar
```

Use environment variables:

```bash
export FIRMA_SIDECAR_CONFIG_FILE=/etc/firma/firma.toml
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

Line 7 (`ready`) is held until the Authority streams have hydrated —
both the policy bundle stream and the revocation stream must report
themselves ready before the line is emitted. When
`policy.authority_url` is unset, both flags are pre-seeded as ready, so
the gate is a no-op and `ready` fires immediately after line 6. This
prevents the first wrapped-agent call from racing the readiness gate
and hitting a DENY before policy is in place.

### Exit codes

| Code | When                                                             |
| ---- | ---------------------------------------------------------------- |
| `0`  | Graceful shutdown after `SIGINT` / `SIGTERM`.                    |
| `1`  | Configuration parse error, validation error, or startup failure. |

## `firma sidecar status`

Docker-ps-style table of live per-run sidecars. Reads marker directories written
by `firma run --sidecar local` under the per-run state dir.

### Usage

```text
firma sidecar status [OPTIONS]
```

### Options

| Flag                | Default | Description                                  |
| ------------------- | ------- | -------------------------------------------- |
| `--sandbox-id <id>` | —       | Show one entry and probe it for liveness.    |
| `--json`            | _off_   | Emit a JSON array; empty list prints `[]`.   |
| `--daemon`          | _off_   | Probe the long-lived daemon sidecar instead. |

State directory resolution: `FIRMA_STATE_DIR` → `$XDG_RUNTIME_DIR/firma` →
`/tmp/firma-$UID`. Marker directories live under `<state_dir>/run/<sandbox_id>/`.

### Output columns (table mode)

| Column       | Description                                          |
| ------------ | ---------------------------------------------------- |
| `SANDBOX_ID` | The run's sandbox identifier.                        |
| `AGENT`      | Agent name from the marker metadata.                 |
| `PID`        | Sidecar process ID, or `-` if absent.                |
| `STATE`      | `running`, `unhealthy`, `stopped`, or `unknown`.     |
| `LISTEN`     | UDS path or address the sidecar is bound to, or `-`. |
| `UPTIME`     | `HH:MM:SS` since the marker was written, or `-`.     |

### STATE semantics

| State       | Meaning                                                 |
| ----------- | ------------------------------------------------------- |
| `running`   | PID alive and UDS socket responds to a connect probe.   |
| `unhealthy` | PID alive but UDS socket is closed or unresponsive.     |
| `stopped`   | PID is dead (or absent from the marker).                |
| `unknown`   | Probe was inconclusive (e.g., no socket path recorded). |

### Exit codes

| Code | Meaning                                            |
| ---- | -------------------------------------------------- |
| `0`  | All listed sidecars are `running` (or list empty). |
| `1`  | Any sidecar is `unhealthy` or `stopped`.           |
| `2`  | Internal error; message on stderr.                 |

An empty sidecar list exits `0` (vacuously: nothing is unhealthy).

### Stale-marker GC

`firma sidecar status` removes marker directories whose recorded PID is dead.
It **never** deletes a marker whose `metadata.toml` is unreadable or
unparseable — that marker is skipped from the listing instead of deleted.
This guards against destroying a live sidecar's socket directory under schema
drift or a mid-write race.

### `--daemon` path note

`--daemon` probes the long-lived daemon sidecar by reading `firma-stack`'s
stack state over `resolve_state_dir(None)` — the same path the daemon sidecar
actually uses: `$XDG_RUNTIME_DIR/firma` (fallback `/tmp/firma-$UID`).

The original FIR-104 spec text referenced `$XDG_DATA_HOME/firma/sidecar/state/`
for the daemon path. Nothing writes that directory today, so the implementation
uses the stack state dir instead. This discrepancy is intentional and noted on
FIR-104.

## Config Discovery

When `--config` is **omitted**, every subcommand — `sidecar`
(`start`/`stop`/`status`), `authority`, `run`, `init`, `monitor`, and
`doctor` — discovers the same single shared `firma.toml` from
platform-standard directories. That one file holds top-level
`[project]` / `[sidecar]` / `[authority]` / `[run]` sections; each
subcommand reads only its own section. The first existing file wins:

1. `--config <path>` flag — always wins. It only relocates the file;
   the file still uses the sectioned schema.
2. **Project-local `.firma/firma.toml`**, found by walking up from
   `cwd` (spec §4 step 1). The closest ancestor with a `.firma/firma.toml`
   wins; the walk stops at the filesystem root. This is what
   `firma init` writes by default.
3. `$FIRMA_CONFIG_DIR/firma.toml` if the env var is set.
4. User config dir (first existing wins). This is what
   `firma init --global` writes:
   - Linux: `$XDG_CONFIG_HOME/firma` → `~/.config/firma`
   - macOS: `$XDG_CONFIG_HOME/firma` → `~/.config/firma` →
     `~/Library/Application Support/firma`
   - Windows: `%XDG_CONFIG_HOME%\firma` (if set) →
     `%USERPROFILE%\.firma` → `%APPDATA%\Roaming\firma`
5. System-wide config dir:
   - Linux: `/etc/firma/firma.toml`
   - macOS: `/Library/Application Support/firma/firma.toml`
   - Windows: `%PROGRAMDATA%\firma\firma.toml`
6. CWD-relative `firma.toml` — last fallback.
7. None found and config is required → exit non-zero with a message listing
   every directory searched.

On macOS the user tier is a dual path: `$XDG_CONFIG_HOME/firma` is tried
first, then `~/.config/firma` (CLI/dev-tool convention, preferred), then
`~/Library/Application Support/firma`. On Linux `~/.config/firma` and the
platform default coincide and are de-duplicated. On Windows the
home-convention tier is the bare `%USERPROFILE%\.firma` dotdir (matching
agent/dev CLIs such as `.claude` and `.codex`), distinct from the
`%APPDATA%\Roaming\firma` platform tier tried after it.

The resolved path and its source are emitted on startup as a single
`config resolved` INFO line (with `path` and `source` fields) so operators
can confirm which file actually loaded.

There is exactly **one** schema: the sectioned `firma.toml`. A file passed
via explicit `--config` uses the same sectioned shape — the flag only
overrides the file location. The needed `[section]` must be present;
section extraction is fail-closed (a missing required section is a hard
error). Relative resource paths re-base under the resolved config
directory (see [Configuration Reference](configuration.md) for the
config-relative resource table).

`state_dir` is **never** a config-file key. The runtime state directory is
resolved only from `--state-dir`, then `FIRMA_STATE_DIR`, then
`$XDG_RUNTIME_DIR/firma` (with a `/tmp/firma-$UID` fallback) — independent
of config discovery. The `--config` flag on `sidecar stop`/`status`,
`monitor`, and `doctor` is accepted for compatibility; only `doctor`
actively consumes it to locate the unified file.

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
firma authority --config firma.toml issue \
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

The autostart path runs whenever the selection resolves to `local`
autostart — i.e. `--sidecar local`, or `--sidecar` omitted with no persisted
`sidecar_endpoint`. Local autostart is unconditional: no endpoint probe and
no `fail_closed` gate apply. (`--no-autostart` cannot reach this path — it is
rejected against `--sidecar local` with `SidecarLocalNoAutostart`, and against
the omitted-with-no-endpoint case with `MissingSidecar`.)

The probe and `fail_closed` checks apply only to the external path
(`--sidecar <url>` or a persisted endpoint): the endpoint is probed, and an
unreachable external sidecar fails with `SidecarUnreachable` — it never
autostarts.

When autostart fires, `firma run`:

1. Resolves the per-sandbox marker directory under
   `$XDG_RUNTIME_DIR/firma/run/<sandbox_id>/` (Linux), `/tmp/firma-$UID/firma/run/<sandbox_id>/` (macOS fallback), or `%LOCALAPPDATA%\firma\runtime\run\<sandbox_id>\` (Windows; see platform caveat below).
2. Synthesizes a sidecar TOML by inheriting the operator template
   (`--sidecar-config` → `FIRMA_SIDECAR_CONFIG_FILE` → the discovered
   `firma.toml` → minimal) and overriding the `[interceptor]` section to
   bind a Unix-domain socket at `<marker_dir>/sidecar.sock`. Relative
   resource paths in the inherited template (e.g. `audit.signing_key_path`,
   `policy.dir`, `mapping.rules_path`, `authority.public_key_path`) are
   rebased to absolute paths anchored on the **template's** config
   directory so they keep pointing at the operator's files after the
   synthesized config is written into `<marker_dir>/`.
3. Spawns `firma sidecar --config <marker_dir>/sidecar.toml` as a
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

| Flag                                   | Default | Description                                                                                                                                                                                               |
| -------------------------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--sidecar <local\|url>`               | —       | `local` autostarts a per-run sidecar. A `tcp://host:port` / `unix:///path` value targets an external sidecar and never autostarts. Omitted: persisted `sidecar_endpoint` (external) else local autostart. |
| `--no-autostart`                       | off     | Fail with a typed error instead of autostarting any missing component. CI safety net. Incompatible with `--sidecar local` and `--authority local`.                                                        |
| `--sidecar-config <path>`              | —       | Sidecar TOML template for autostart. Overrides `FIRMA_SIDECAR_CONFIG_FILE` and the CWD fallback.                                                                                                          |
| `--sidecar-startup-timeout-secs <int>` | `10`    | Maximum wait for the `ready` line. `0` reverts to the built-in default.                                                                                                                                   |

### Typed errors

| Error                     | Trigger                                                                                                                                             |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SidecarUnreachable`      | An external sidecar (`--sidecar <url>` or persisted endpoint) is unreachable.                                                                       |
| `SidecarLocalNoAutostart` | `--sidecar local` combined with `--no-autostart`.                                                                                                   |
| `MissingSidecar`          | `--sidecar` omitted, no persisted endpoint, and `--no-autostart` set.                                                                               |
| `SidecarReadyTimeout`     | Spawned sidecar did not emit `ready` within the configured budget. Error message points to `<marker_dir>/sidecar.log`.                              |
| `SidecarStartupFailed`    | Spawn or stderr-pipe setup failed; or stderr closed before `ready`.                                                                                 |
| `UnsupportedPlatform`     | Autostart requested on a platform that does not support a UDS interceptor (e.g. Windows). Use `--sidecar <url>` with a pre-started sidecar instead. |

### Operator caveats

- A template with `interceptor.https_mitm.enabled = true` may fail
  validation when the interceptor is forced to `unix_socket` mode.
  Either disable MITM in the template or use `--sidecar <url>` with a
  long-lived externally-managed sidecar.
- Autostart currently requires Unix (Linux + macOS). On Windows,
  `--sidecar local` returns `UnsupportedPlatform`; pre-start the sidecar
  yourself and pass `--sidecar <url>`.
- The marker layout is the contract consumed by `firma sidecar status`
  (see FIR-103). Do not write or edit those files manually.

### Authority bootstrap

`firma run` decides whether to autostart a Mini Authority before it
launches the per-run Sidecar. Decision precedence:

1. `--authority local` or `--authority <url>` — skip the prompt entirely.
2. Persisted `[authority]` table in the discovered `firma.toml`
   (`~/.config/firma/firma.toml` on Linux/macOS,
   `%USERPROFILE%\.firma\firma.toml` on Windows) — skip the prompt.
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

| Flag                         | Default     | Description                                                                                                                                      |
| ---------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--authority <local\|url>`   | unset       | Skip the y/N prompt. `local` autostarts on `[::1]:50051`; any other value is treated as a remote Authority URL.                                  |
| `--authority-profile <name>` | `developer` | Profile materialised by the autostarted Mini Authority. Currently only `developer` ships. Ignored when Authority is remote or already reachable. |

The `--no-autostart` flag also suppresses Authority autostart. With
`--no-autostart --authority local` `firma run` exits immediately with a
typed argument-conflict error.

### Authority typed errors

| Error                     | Trigger                                                          |
| ------------------------- | ---------------------------------------------------------------- |
| `MissingAuthority`        | `--no-autostart` and nothing configured.                         |
| `AuthorityDeclined`       | User answered `n` (or empty / garbage) at the prompt.            |
| `AuthorityPromptNoTty`    | No config, no CLI flag, stdin is not a TTY.                      |
| `AuthorityStartupFailed`  | Spawn or stderr-pipe setup failed; stderr closed before `ready`. |
| `AuthorityReadyTimeout`   | Spawned authority did not emit `ready` within the budget.        |
| `AuthorityUnreachable`    | Remote URL did not answer a TCP connect probe.                   |
| `AuthorityUnknownProfile` | `--authority-profile` is not a registered profile.               |
