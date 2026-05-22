# `firma config`

`firma config` scaffolds a fresh project: keys, default `firma.toml`,
empty policy directories. Run it once when you start a new project;
`firma run` invokes the same scaffold implicitly the first time it
finds no `firma.toml`.

## Quickstart

```bash
firma config                                              # interactive wizard
firma config --yes                                        # non-interactive defaults
firma config --global                                     # user-global scaffold (~/.config/firma)
firma config --agent codex --provider anthropic \
           --workspace ./proj --authority local         # scripted full setup
```

`--workspace`, `--global`, and `--config-dir` are mutually exclusive:

| Form                              | Where the scaffold lands                                   |
| --------------------------------- | ---------------------------------------------------------- |
| _(default)_                       | `<cwd>/.firma/` — project-local.                           |
| `--workspace <dir>`               | `<dir>/.firma/` — project-local.                           |
| `--global`                        | `$FIRMA_CONFIG_DIR` → `$XDG_CONFIG_HOME/firma` → `~/.config/firma`. |
| `--config-dir <path>`             | `<path>` verbatim — advanced override.                     |

## Usage shapes

| Form                                          | When                                                  |
| --------------------------------------------- | ----------------------------------------------------- |
| `firma config`                                  | Interactive wizard. Default for human developers.     |
| `firma config --yes`                            | Non-interactive. CI / container init / daemon-mode.   |
| `firma config --agent X --provider Y …`         | Scripted with every value supplied up-front.          |

The wizard prompts for: workspace path, agent, provider, authority shape
(local or remote URL). A flag on the command line short-circuits the
matching prompt.

## Flags

```text
firma config [--workspace <dir> | --global | --config-dir <dir>]
           [--agent <name>] [--provider <name>]
           [--authority <local|url>]
           [--yes] [--force]
           [--state-dir <dir>]
           [--authority-listen <addr>] [--sidecar-listen <addr>]
```

| Flag                 | Default                     | Description                                            |
| -------------------- | --------------------------- | ------------------------------------------------------ |
| `--workspace <dir>`  | _cwd_ (wizard prompt)       | Project root. Config lands at `<workspace>/.firma`.    |
| `--global`           | _off_                       | Scaffold into the user-global config dir.              |
| `--config-dir <dir>` | derived from above          | Advanced override; bypasses `--workspace`/`--global`.  |
| `--agent <name>`     | wizard prompt / `generic`   | Persisted to `[project].agent` in firma.toml.          |
| `--provider <name>`  | wizard prompt / `anthropic` | Persisted to `[project].provider`.                     |
| `--authority <val>`  | wizard prompt / `local`     | `local` or a URL. Persisted to `[authority]`.          |
| `--yes`              | _off_                       | Skip the wizard. Required in non-TTY contexts.         |
| `--state-dir <dir>`  | `FIRMA_STATE_DIR` / XDG     | User-global state (keys, revocations, CA material).    |
| `--force`            | _off_                       | Overwrite existing files instead of preserving them.   |
| `--authority-listen` | `127.0.0.1:50051`           | Local authority gRPC listen address.                   |
| `--sidecar-listen`   | `127.0.0.1:8080`            | Sidecar HTTP proxy listen.                             |

## Scaffolded layout

```text
<workspace>/.firma/        # project-local config dir
  firma.toml              # one sectioned file
  authority.key           # Ed25519 signing key (never commit)
  audit.key
  mapping-rules.toml      # placeholder
  policies/
  issuance-policies/

<state_dir>/               # user-global state (XDG default)
  revocations.txt
  generated-firma-ca/     # populated by the sidecar on first start
```

`firma.toml` has three sections after init: `[project]` (agent +
provider metadata), `[authority]` (local or remote shape), and
`[sidecar.*]` (interceptor + policy + ca + audit + mapping).

## Implicit init on `firma run`

`firma run <agent>` checks for a discoverable `firma.toml` at launch
time. If none is found, `firma run` calls the same scaffold with
non-interactive defaults (agent = `<agent>` from `--profile`, provider
= `anthropic`, authority = `local`) and continues. This keeps the
one-command path working from a fresh clone, as called out by the
spec's zero-config development mode.

## See also

- [`firma sidecar start/stop`](firma_sidecar_daemon_command.md) — daemon
  lifecycle for the sidecar (and the authority started alongside it).
- [`firma monitor`](firma_monitor_command.md) — tail audit + component logs.
- [Configuration reference](../configuration.md) — full `firma.toml` shape.
