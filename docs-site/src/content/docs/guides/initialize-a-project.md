---
title: Initialize a project with firma config
description: Scaffold a fresh Firma project — config dir, signing keys, default policies — interactively or in scripted form.
---

`firma config` writes a fresh project layout in one command: a sectioned
`firma.toml`, signing and audit keys, empty policy directories, a
placeholder mapping file. Run it once per project. `firma run <agent>`
calls the same scaffold implicitly on first use, so you can also skip
this step if you only want the one-command path.

## Usage shapes

```bash
firma config                                              # interactive wizard
firma config --yes                                        # non-interactive defaults
firma config --output-dir .local                          # specific directory
firma config --agent codex --provider anthropic \
           --workspace ./proj --authority local         # scripted full setup
```

Config always lands in the current directory or an explicit `--output-dir`:

| Form                              | Destination                                |
| --------------------------------- | ------------------------------------------ |
| _(default)_                       | Current working directory.                 |
| `--output-dir <path>`             | `<path>` verbatim.                         |

| Form                                          | When                                                  |
| --------------------------------------------- | ----------------------------------------------------- |
| `firma config`                                  | Interactive wizard. Default for human developers.     |
| `firma config --yes`                            | Non-interactive. CI / container init / daemon-mode.   |
| `firma config --agent X --provider Y …`         | Scripted with every value supplied up-front.          |

The wizard prompts for: workspace path, agent, provider, authority
shape (`local` or a remote URL). Supplying the matching flag on the
command line short-circuits that prompt.

## Flags

```text
firma config [--output-dir <dir>]
           [--name <name>] [--posture <posture>] [--mapping <mapping>]
           [--workspace <dir>]
           [--yes] [--force] [--dry-run]
           [--state-dir <dir>]
```

| Flag                 | Default                     | Description                                            |
| -------------------- | --------------------------- | ------------------------------------------------------ |
| `--output-dir <dir>` | current directory           | Where firma.toml, policies, and mappings are written.  |
| `--workspace <dir>`  | _cwd_ (wizard prompt)       | Agent RW access path (bwrap mount).                    |
| `--name <name>`      | wizard prompt / `my-agent`  | Agent slug — used as `agent_id` in generated config.   |
| `--posture <val>`    | wizard prompt / `dev`       | Cedar enforcement posture.                             |
| `--mapping <val>`    | wizard prompt / `anthropic` | Mapping file(s) to include — repeat for multiple.      |
| `--yes`              | _off_                       | Skip the wizard; use defaults for any unset flag.      |
| `--state-dir <dir>`  | `FIRMA_STATE_DIR` / XDG     | State dir (keys, revocations, generated CA).           |
| `--force`            | _off_                       | Overwrite existing files instead of preserving them.   |
| `--authority-listen` | `127.0.0.1:50051`           | Local authority gRPC listen address.                   |
| `--sidecar-listen`   | `127.0.0.1:8080`            | Sidecar HTTP proxy listen.                             |

## Scaffolded layout

```text
<workspace>/.firma/        # project-local config (per spec §6.2)
  firma.toml              # one sectioned file
  authority.key           # Ed25519 signing key — never commit
  audit.key
  mapping-rules.toml      # placeholder
  policies/
  issuance-policies/

<state_dir>/               # user-global state (XDG default)
  revocations.txt
  generated-firma-ca/     # populated by the sidecar on first start
```

The generated `firma.toml` has three sections after init:

- `[project]` — `agent` and `provider` metadata, for downstream tooling.
- `[authority]` — either `type = "local"` with a `listen_addr`, or
  `type = "remote"` with a `url`.
- `[sidecar.interceptor]` / `[sidecar.policy]` / `[sidecar.ca]` /
  `[sidecar.audit]` / `[sidecar.mapping]` — the sidecar's runtime
  surface.

Existing files are preserved unless `--force` is set, so it is safe
to re-run after editing one config by hand.

## Implicit init on `firma run`

`firma run <agent>` checks for a discoverable `firma.toml` at launch
time. If none is found, it invokes the same scaffold with
non-interactive defaults (`agent` derived from `--profile`,
`provider = anthropic`, `authority = local`) and proceeds. This keeps
the spec's one-command zero-config path (`firma run codex`) working
from a fresh clone.

## Common gotchas

**Wizard refuses to run in CI.** `firma config` without `--yes` requires
a TTY. Pass `--yes` (and any flags you want to override) when running
unattended.

**`firma.toml` already exists.** By design `init` preserves existing
files. Use `--force` to overwrite, or remove the file by hand if you
want a clean slate.

**Keys in the wrong place.** Keys live under `<config_dir>/` because
that is where `firma.toml` references them. Do not commit
`authority.key` to a shared repository. Use `.gitignore` to exclude
`.firma/*.key`.

## See also

- [Start and monitor the daemon](../manage-the-stack/) — what to do after `init`.
- [Wrap an agent with `firma run`](../firma-run/) — the one-command path that calls `init` implicitly.
- [Configuration reference](../../../docs/configuration.md) — the full `firma.toml` schema.
