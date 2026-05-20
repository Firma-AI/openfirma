---
title: Initialize a project with firma init
description: Scaffold a fresh Firma project — config dir, signing keys, default policies — interactively or in scripted form.
---

`firma init` writes a fresh project layout in one command: a sectioned
`firma.toml`, signing and audit keys, empty policy directories, a
placeholder mapping file. Run it once per project. `firma run <agent>`
calls the same scaffold implicitly on first use, so you can also skip
this step if you only want the one-command path.

## Usage shapes

```bash
firma init                                              # interactive wizard
firma init --yes                                        # non-interactive defaults
firma init --global                                     # user-global scaffold (~/.config/firma)
firma init --agent codex --provider anthropic \
           --workspace ./proj --authority local         # scripted full setup
```

`--workspace`, `--global`, and `--config-dir` are mutually exclusive
and pick where the scaffold lands:

| Form                              | Destination                                                |
| --------------------------------- | ---------------------------------------------------------- |
| _(default)_                       | `<cwd>/.firma/` — project-local.                           |
| `--workspace <dir>`               | `<dir>/.firma/` — project-local.                           |
| `--global`                        | `$FIRMA_CONFIG_DIR` → `$XDG_CONFIG_HOME/firma` → `~/.config/firma`. |
| `--config-dir <path>`             | `<path>` verbatim — advanced override.                     |

| Form                                          | When                                                  |
| --------------------------------------------- | ----------------------------------------------------- |
| `firma init`                                  | Interactive wizard. Default for human developers.     |
| `firma init --yes`                            | Non-interactive. CI / container init / daemon-mode.   |
| `firma init --agent X --provider Y …`         | Scripted with every value supplied up-front.          |

The wizard prompts for: workspace path, agent, provider, authority
shape (`local` or a remote URL). Supplying the matching flag on the
command line short-circuits that prompt.

## Flags

```text
firma init [--workspace <dir> | --global | --config-dir <dir>]
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
| `--agent <name>`     | wizard prompt / `generic`   | Persisted to `[project].agent`.                        |
| `--provider <name>`  | wizard prompt / `anthropic` | Persisted to `[project].provider`.                     |
| `--authority <val>`  | wizard prompt / `local`     | `local` or a URL. Persisted to `[authority]`.          |
| `--yes`              | _off_                       | Skip the wizard; use defaults for any unset flag.      |
| `--state-dir <dir>`  | `FIRMA_STATE_DIR` / XDG     | User-global state (keys, revocations, generated CA).   |
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

**Wizard refuses to run in CI.** `firma init` without `--yes` requires
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
