# `firma config`

`firma run` works out of the box with no prior setup — it auto-scaffolds a
default config on first use. `firma config` lets you override those defaults:
posture, mappings, authority mode, workspace path, and more. Run it when you
want control over what `firma run` uses, or to update an existing config.

When config files already exist in the target directory, their current values
become the defaults for every prompt and non-interactive run. Supply only the
flags you want to change; everything else is preserved.

Switching an existing local-authority config to `--mode agent-remote`
normally removes the top-level `[authority]` section from the generated
`firma.toml`; otherwise `firma run` starts the Authority locally instead
of using only the remote Authority. Non-force runs warn about that.
Interactive runs ask whether to keep the section and use that answer to
rewrite `firma.toml`; non-interactive non-force runs preserve the existing
file. `--force` overwrites the config directly and removes the section.

## Quickstart

```bash
firma config                          # interactive wizard
firma config --yes                    # non-interactive defaults
firma config --output-dir .local      # specific output directory
firma config --mode agent-local \
  --profile codex --posture dev \
  --mapping anthropic --yes           # scripted full setup
```

## Modes

| Mode           | What it creates                                                                    |
| -------------- | ---------------------------------------------------------------------------------- |
| `agent-local`  | Sidecar config + co-located mini-authority (`[authority]` + `[sidecar.authority]`) |
| `agent-remote` | Sidecar config only, connecting to an existing authority (`[sidecar.authority]`)   |
| `authority`    | Standalone authority server only — no sidecar config                               |

## Flags

```text
firma config [--mode <mode>] [--profile <profile>] [--agent-id <agent-id>]
             [--posture <posture>] [--mapping <mapping>]
             [--extra-hosts <hosts>]
             [--workspace <dir>] [--output-dir <dir>] [--state-dir <dir>]
             [--authority-url <url>] [--authority-ca-cert <path>]
             [--authority-pub-key <path>] [--authority-listen <addr>]
             [--yes] [--force] [--dry-run] [--list-templates]
```

| Flag                         | Short | Default                  | Description                                                                     |
| ---------------------------- | ----- | ------------------------ | ------------------------------------------------------------------------------- |
| `--mode <mode>`              |       | wizard / `agent-local`   | What to configure: `agent-local`, `agent-remote`, or `authority`                |
| `--profile <profile>`        |       | wizard / `generic`       | Execution profile written to `[run].profile`                                    |
| `--agent-id <agent-id>`      |       | generated / prompt       | Registered `agt_` TypeID written to `[sidecar.authority].agent_id`              |
| `--posture <posture>`        |       | wizard / `dev`           | Cedar policy posture written under `policies/`                                  |
| `--mapping <mapping>`        |       | wizard / `anthropic`     | Mapping file(s) to include — repeat for multiple                                |
| `--extra-hosts <hosts>`      |       | none                     | Comma-separated extra hosts the agent may reach                                 |
| `--workspace <dir>`          |       | CWD                      | Agent RW path written to `firma.toml` `[run.profiles.generic]` bwrap mount      |
| `--output-dir <dir>`         | `-o`  | `.firma` in CWD          | Config dir — where `firma.toml`, policies, mappings are written                 |
| `--state-dir <dir>`          |       | `$FIRMA_STATE_DIR` / XDG | State dir — keys, revocations, generated CA                                     |
| `--authority-listen <addr>`  |       | `127.0.0.1:9443`         | gRPC listen address written to `[authority]` (`agent-local` / `authority` only) |
| `--authority-url <url>`      |       | wizard prompt            | Authority URL written to `[sidecar.authority].url` (`agent-remote`)             |
| `--authority-ca-cert <path>` |       | wizard prompt            | Authority CA cert PEM path (`agent-remote`)                                     |
| `--authority-pub-key <path>` |       | derived from state dir   | Authority public key path (`agent-remote`)                                      |
| `--yes`                      | `-y`  | off                      | Skip all interactive prompts; use existing values or flag defaults              |
| `--force`                    |       | off                      | Overwrite existing files including the authority keypair                        |
| `--dry-run`                  |       | off                      | Print generated files to stdout without writing to disk                         |
| `--list-templates`           |       | off                      | Print the posture × mapping catalogue and exit                                  |

An explicit `--posture` rewrites the selected `policies/<posture>.cedar`
file even without `--force`; other existing generated files are still
preserved unless `--force` is set.

## Postures

| Name                    | Cedar policy behaviour                             |
| ----------------------- | -------------------------------------------------- |
| `strict`                | Default-deny + communication only (no code ops)    |
| `dev`                   | Adds code.read/write, issues, package install      |
| `dev-with-delete-watch` | Dev + code.destructive (local-exec / delete-watch) |

## Mappings

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
| `composio`  | app.composio.dev, backend.composio.dev — governed tool execution with MITM   |

## Scaffolded layout

```text
<output-dir>/                    # project-local config dir
  firma.toml                    # unified config (authority + sidecar + run profiles)
  mapping-rules.toml            # base routing rules
  mappings/<name>.toml          # one file per selected mapping
  policies/<posture>.cedar      # Cedar enforcement policy
  issuance-policies/
    issuance.cedar              # token issuance policy

<state-dir>/                     # user-global state (XDG default)
  authority.key                 # Ed25519 signing key — never commit
  authority.pub                 # matching public key
  audit.key                     # audit signing key
  revocations.txt               # empty revocations list
  tls/                          # self-signed TLS material
  generated-firma-ca/           # populated by sidecar on first start
```

## Generated `firma.toml` structure

`agent-local` produces an `[authority]` section plus a
`[sidecar.authority]` block with the connect coordinates.
`agent-remote` produces only the `[sidecar.authority]` connect block.
`authority` mode produces only `[authority]`.

```toml
[authority] # present for agent-local and authority modes
listen_addr = "127.0.0.1:9443"
key_file = "/path/to/state/authority.key"
# ...

[sidecar.authority] # connect coords for agent-local / agent-remote
agent_id = "agt_01j0000000e008000000000001"
url = "https://127.0.0.1:9443"
ca_cert_path = "/path/to/state/tls/authority-ca.crt"
public_key_path = "/path/to/state/authority.pub"
# ... plus connect_timeout_secs / reconnect_* / revocation_* tuning

# Uncomment for remote Authorities that require Sidecar PSK authentication.
# [sidecar.authority.credentials]
# workspace_id = "ws-acme"
# sidecar_id = "sc-eu-1"
# pre_shared_key_env = "FIRMA_SIDECAR_PSK"

[run]
profile = "codex"
```

FirmaTeam registration returns an Authority-assigned `agt_` TypeID alongside
the Sidecar ID and token. Copy that ID into remote configuration with
`--agent-id`. New `agent-local` configs generate an agent TypeID backed by
UUIDv7 when the flag is omitted. Existing valid IDs survive subsequent runs
unless explicitly replaced.

Existing configs are not silently migrated. If the field is absent, or contains
an old execution-profile value such as `codex`, run
`firma config --agent-id <agent-id>` and leave the profile under
`[run].profile`.

## Implicit init on `firma run`

`firma run` checks for a discoverable `firma.toml` at launch. If none is
found it scaffolds one with non-interactive defaults and proceeds. This keeps
`firma run codex` working from a fresh clone.

## See also

- [`docs/markdown/firma_sidecar_daemon_command.md`](firma_sidecar_daemon_command.md) — `firma sidecar {start,stop,status}`.
- [`docs/markdown/firma_monitor_command.md`](firma_monitor_command.md) — `firma monitor`.
- [Configuration reference](../configuration.md) — full `firma.toml` schema.
