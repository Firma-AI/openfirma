# CLI Reference

Single binary: `firma <subcommand>`. All examples below assume `firma` is on
PATH or invoked via `cargo run -p firma --`.

## `firma config`

`firma run` works out of the box with no prior setup — it auto-scaffolds a
default config on first use. `firma config` lets you override those defaults:
posture, mappings, authority mode, workspace path, and more. When config files
already exist, their current values become the wizard and non-interactive
defaults; supplied flags override those values.

When an existing config includes a local `[authority]` section and you switch
to `--mode agent-remote`, the regenerated `firma.toml` normally removes that
section; otherwise `firma run` starts the Authority locally instead of using
only the remote Authority. Non-force runs warn about the local startup
behavior. Interactive runs ask whether to keep the section and use that answer
to rewrite `firma.toml`; non-interactive non-force runs preserve the existing
file. `--force` overwrites the config directly and removes the section.

### Usage

```text
firma config [OPTIONS]
```

### Options

| Flag                         | Short | Default                  | Description                                                                |
| ---------------------------- | ----- | ------------------------ | -------------------------------------------------------------------------- |
| `--mode`                     |       | wizard / `agent-local`   | `agent-local`, `agent-remote`, or `authority`                              |
| `--name`                     | `-n`  | wizard / `my-agent`      | Agent slug — used as `agent_id` in `[sidecar.preflight]`                   |
| `--posture`                  |       | wizard / `dev`           | Cedar policy posture written under `policies/`                             |
| `--mapping`                  |       | wizard / `anthropic`     | Mapping file(s) to include — repeat for multiple                           |
| `--requested-action`         |       | derived from posture     | Preflight requested actions — repeat or comma-separate                     |
| `--extra-hosts`              |       | none                     | Comma-separated extra hosts the agent may reach                            |
| `--workspace`                |       | CWD                      | Agent RW path written to `firma.toml` `[run.profiles.generic]` bwrap mount |
| `--output-dir`               | `-o`  | `.firma` in CWD          | Config dir — where `firma.toml`, policies, mappings land                   |
| `--state-dir`                |       | `$FIRMA_STATE_DIR` / XDG | State dir — keys, revocations, generated CA                                |
| `--authority-listen <addr>`  |       | `127.0.0.1:9443`         | gRPC listen address (`agent-local` / `authority` modes only)               |
| `--authority-url <url>`      |       | wizard prompt            | Authority URL written to `[sidecar.authority].url` (`agent-remote`)        |
| `--authority-ca-cert <path>` |       | wizard prompt            | Authority CA cert PEM path (`agent-remote`)                                |
| `--authority-pub-key <path>` |       | derived from state dir   | Authority public key path                                                  |
| `--yes`                      | `-y`  | off                      | Skip all prompts; use existing values or flag defaults                     |
| `--force`                    |       | off                      | Overwrite existing files, including the authority keypair                  |
| `--dry-run`                  |       | off                      | Print generated files to stdout; no disk writes                            |
| `--list-templates`           |       | off                      | Print posture × mapping catalogue and exit                                 |

An explicit `--posture` rewrites the selected `policies/<posture>.cedar`
file even without `--force`; other existing generated files are still
preserved unless `--force` is set.

### Generated layout

```
<output-dir>/
  firma.toml                     — unified config (authority + sidecar + run sections)
  mapping-rules.toml             — base routing rules (localhost, extra hosts)
  mappings/<name>.toml           — one file per selected mapping
  policies/<posture>.cedar       — Cedar enforcement policy
  issuance-policies/
    issuance.cedar               — token issuance policy

<state-dir>/
  authority.key                  — Ed25519 signing key (never commit)
  authority.pub                  — matching public key
  audit.key                      — audit signing key
  revocations.txt                — empty revocations list
  tls/                           — self-signed TLS material
  generated-firma-ca/            — populated by sidecar on first start
```

### Examples

Interactive:

```bash
firma config
```

Non-interactive agent-local:

```bash
firma config --yes --name claude-code --posture dev --mapping anthropic
```

Agent connecting to a remote authority:

```bash
firma config --yes --mode agent-remote \
  --authority-url https://authority.example.com:9443 \
  --authority-ca-cert /path/to/ca.crt \
  --name my-agent --posture strict --mapping anthropic
```

Multiple mappings:

```bash
firma config --name my-agent --posture dev \
  --mapping anthropic --mapping github --mapping npm
```

Preview without writing:

```bash
firma config --dry-run
```

Re-render an existing scaffold, keeping current values unless a flag overrides:

```bash
firma config --yes --dry-run
firma config --yes --name codex --mapping openai --force
```

After scaffolding, run the agent:

```bash
firma run -- <agent-command>
```

### Postures

| Name                    | Description                                                |
| ----------------------- | ---------------------------------------------------------- |
| `strict`                | Default-deny + communication only (no code ops)            |
| `dev`                   | Adds code.read/write, issues, package install              |
| `dev-with-delete-watch` | Dev + code.destructive allowed (local-exec / delete-watch) |

### Mappings

| Name        | Covers                                                                       |
| ----------- | ---------------------------------------------------------------------------- |
| `anthropic` | api.anthropic.com — Anthropic Claude API (CONNECT, no MITM)                  |
| `openai`    | api.openai.com — OpenAI API (CONNECT, no MITM)                               |
| `github`    | api.github.com — GitHub REST API (MITM for per-endpoint classification)      |
| `gmail`     | gmail.googleapis.com — Gmail REST API (MITM for per-endpoint classification) |
| `npm`       | registry.npmjs.org — npm package registry                                    |
| `pypi`      | pypi.org, files.pythonhosted.org — PyPI                                      |
| `cargo`     | crates.io, static.crates.io — Rust package registry                          |
| `stripe`    | api.stripe.com — Stripe REST API                                             |

## `firma policy`

Browse the posture × mapping template catalogue and validate Cedar policy bundles.

### `firma policy list`

Print available postures and mapping files:

```bash
firma policy list
```

### `firma policy validate`

Validate a Cedar policy bundle (one or more `.cedar` files):

```bash
firma policy validate --file policies/dev.cedar
```

### `firma policy test`

Run fixture-based authorization tests against a Cedar policy bundle:

```bash
firma policy test --fixture tests/my-fixture.json
```

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
fires unconditionally; when `authority.url` is unset the
endpoint is reported as `(disabled)`.

Line 7 (`ready`) is held until the Authority streams have hydrated —
both the policy bundle stream and the revocation stream must report
themselves ready before the line is emitted. When
`authority.url` is unset, both flags are pre-seeded as ready, so
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

In JSON mode, an absent PID is emitted as `null`.

### STATE semantics

| State       | Meaning                                                         |
| ----------- | --------------------------------------------------------------- |
| `running`   | PID alive and interceptor endpoint responds to a connect probe. |
| `unhealthy` | PID alive but interceptor endpoint is closed or unresponsive.   |
| `stopped`   | PID is dead (or absent from the marker).                        |
| `unknown`   | Probe was inconclusive.                                         |

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

`--daemon` probes the long-lived daemon sidecar by reading runtime state from the
runtime state dir — the same path the daemon sidecar actually uses:
`$XDG_RUNTIME_DIR/firma` (fallback `/tmp/firma-$UID`).

The original FIR-104 spec text referenced `$XDG_DATA_HOME/firma/sidecar/state/`
for the daemon path. Nothing writes that directory today, so the implementation
uses the runtime state dir instead. This discrepancy is intentional and noted
on FIR-104.

## Config Discovery

When `--config` is **omitted**, every subcommand — `sidecar`
(`start`/`stop`/`status`), `authority`, `run`, `config`, `monitor`, and
`doctor` — discovers the same single shared `firma.toml`. That one file holds top-level
`[project]` / `[sidecar]` / `[authority]` / `[run]` sections; each
subcommand reads only its own section. The first selected file wins:

1. `--config <path>` flag — always wins. It only relocates the file;
   the file still uses the sectioned schema.
2. `$FIRMA_CONFIG` env var if set — overrides walk, points directly to file.
3. **Project-local `.firma/firma.toml`**, found by walking up from
   `cwd`. The closest ancestor with a `.firma/firma.toml` wins; the
   walk stops at the filesystem root. This is what `firma config` writes.
4. None found and config is required → exit non-zero. Optional flows such as
   zero-config `firma run` may continue without a config.

A selected file must be readable and valid TOML. An explicit `--config`,
`$FIRMA_CONFIG`, or discovered project-local file that cannot be loaded fails
closed instead of falling through to another tier or to zero-config defaults.

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

1. `--authority local` or `--authority <url>` — explicit CLI override.
2. `[authority]` table present in the discovered `firma.toml`
   (`~/.config/firma/firma.toml` on Linux/macOS,
   `%USERPROFILE%\.firma\firma.toml` on Windows) — autostart a local
   Mini Authority.
3. `[sidecar.authority].url` set in `firma.toml` — connect to that
   remote Authority.
4. Nothing configured — `firma run` falls back to local autostart so
   zero-config works. `--no-autostart` overrides this to fail with
   `MissingAuthority`.

On `local` selection, `firma run` probes `[::1]:50051` first. If
reachable, no autostart fires. Otherwise the per-run Mini Authority is
spawned with an ephemeral signing key and the embedded `developer`
policy profile materialised under
`<runtime>/firma/run/<sandbox_id>/authority/`. The Authority is killed
on `firma run` exit (`SIGTERM` then `SIGKILL` after a 5s grace).

### Authority flags

| Flag                         | Default     | Description                                                                                                                                      |
| ---------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--authority <local\|url>`   | unset       | Override config. `local` autostarts on `[::1]:50051`; any other value is treated as a remote Authority URL.                                      |
| `--authority-profile <name>` | `developer` | Profile materialised by the autostarted Mini Authority. Currently only `developer` ships. Ignored when Authority is remote or already reachable. |

`--no-autostart` suppresses Authority autostart. With
`--no-autostart --authority local` `firma run` exits immediately with a
typed argument-conflict error.

### Authority typed errors

| Error                     | Trigger                                                          |
| ------------------------- | ---------------------------------------------------------------- |
| `MissingAuthority`        | `--no-autostart` and nothing configured.                         |
| `AuthorityStartupFailed`  | Spawn or stderr-pipe setup failed; stderr closed before `ready`. |
| `AuthorityReadyTimeout`   | Spawned authority did not emit `ready` within the budget.        |
| `AuthorityUnreachable`    | Remote URL did not answer a TCP connect probe.                   |
| `AuthorityUnknownProfile` | `--authority-profile` is not a registered profile.               |
