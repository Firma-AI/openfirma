# `firma config`

`firma config` scaffolds or updates a project: keys, default `firma.toml`,
policy files, and mapping files. Run it when you start a new project or
when you want to re-render the scaffold with a few overrides. `firma run`
invokes the same scaffold implicitly the first time it finds no
`firma.toml`.

## Quickstart

```bash
firma config                                              # interactive wizard
firma config --yes                                        # non-interactive defaults
firma config --output-dir .local                          # specific directory
firma config --agent codex --provider anthropic \
           --workspace ./proj --authority local         # scripted full setup
```

Config always lands in the current directory or an explicit `--output-dir`:

| Form                  | Where the scaffold lands |
| --------------------- | ------------------------ |
| _(default)_           | Current working directory. |
| `--output-dir <path>` | `<path>` verbatim.       |

## Usage shapes

| Form                                          | When                                                  |
| --------------------------------------------- | ----------------------------------------------------- |
| `firma config`                                  | Interactive wizard. Default for human developers.     |
| `firma config --yes`                            | Non-interactive. CI / container init / daemon-mode.   |
| `firma config --agent X --provider Y …`         | Scripted with every value supplied up-front.          |

The wizard prompts for: workspace path, agent, provider, authority shape
(local or remote URL). A flag on the command line short-circuits the
matching prompt.

If the target config directory already contains `firma.toml` or
`firma-run.toml`, `firma config` reads them first and uses the current
values as defaults.
For example, `firma config --yes --name codex` keeps the existing mode,
state directory, authority settings, posture, mappings, preflight action
list, and workspace, but writes `agent_id = "codex"` in the generated
output. Existing files are still preserved unless `--force` is set.

## Flags

```text
firma config [--output-dir <dir>]
           [--name <name>] [--posture <posture>] [--mapping <mapping>]
           [--workspace <dir>] [--yes] [--force] [--dry-run]
           [--state-dir <dir>]
```

| Flag                 | Default                     | Description                                            |
| -------------------- | --------------------------- | ------------------------------------------------------ |
| `--output-dir <dir>` | current directory           | Where firma.toml, policies, and mappings are written.  |
| `--workspace <dir>`  | _cwd_ (wizard prompt)       | Agent RW access path (bwrap mount).                    |
| `--name <name>`      | wizard prompt / `my-agent`  | Agent slug — used as `agent_id` in generated config.   |
| `--posture <val>`    | wizard prompt / `dev`       | Cedar enforcement posture.                             |
| `--mapping <val>`    | wizard prompt / `anthropic` | Mapping file(s) — repeat for multiple.                 |
| `--yes`              | _off_                       | Skip the wizard. Required in non-TTY contexts.         |
| `--state-dir <dir>`  | `FIRMA_STATE_DIR` / XDG     | State dir (keys, revocations, CA material).            |
| `--force`            | _off_                       | Overwrite existing files instead of preserving them.   |

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
