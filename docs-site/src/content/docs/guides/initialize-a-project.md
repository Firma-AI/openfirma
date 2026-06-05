---
title: Customize the default config with firma config
description: firma run works with no setup. firma config lets you override the defaults — posture, mappings, authority mode, workspace, and more.
---

`firma run` works out of the box with no prior setup: it auto-scaffolds a
default config the first time it runs in a directory. `firma config` lets
you override those defaults — posture, mappings, authority mode, workspace
path, and more. Run it when you want control over what `firma run` uses, or
to update an existing config.

## Usage shapes

```bash
firma config                          # interactive wizard
firma config --yes                    # non-interactive defaults
firma config --output-dir .local      # specific output directory
firma config --yes --mode agent-local \
  --name codex --posture dev \
  --mapping anthropic                 # scripted full setup
```

Config lands in `.firma/` inside the current directory, or an explicit
`--output-dir`:

| Form                  | Destination                        |
| --------------------- | ---------------------------------- |
| _(default)_           | `.firma/` in current directory     |
| `--output-dir <path>` | `<path>` verbatim                  |

## Modes

| Mode            | What it scaffolds                                                              |
| --------------- | ------------------------------------------------------------------------------ |
| `agent-local`   | Sidecar + co-located mini-authority (`[authority]` + `[sidecar.authority]`)        |
| `agent-remote`  | Sidecar only, pointing at an existing authority (`[sidecar.authority]`)            |
| `authority`     | Standalone authority server — no sidecar config                               |

## Flags

```text
firma config [--mode <mode>]
             [--name <name>] [--posture <posture>] [--mapping <mapping>]
             [--requested-action <action>] [--extra-hosts <hosts>]
             [--workspace <dir>] [--output-dir <dir>] [--state-dir <dir>]
             [--authority-url <url>] [--authority-ca-cert <path>]
             [--authority-pub-key <path>] [--authority-listen <addr>]
             [--yes] [--force] [--dry-run] [--list-templates]
```

| Flag                         | Default                  | Description                                                          |
| ---------------------------- | ------------------------ | -------------------------------------------------------------------- |
| `--mode`                     | wizard / `agent-local`   | What to configure: `agent-local`, `agent-remote`, or `authority`     |
| `--name` / `-n`              | wizard / `my-agent`      | Agent slug — written as `agent_id` in `[sidecar.preflight]`          |
| `--posture`                  | wizard / `dev`           | Cedar policy posture written under `policies/`                       |
| `--mapping`                  | wizard / `anthropic`     | Mapping file(s) to include — repeat for multiple                     |
| `--requested-action`         | derived from posture     | Preflight requested actions — repeat or comma-separate               |
| `--extra-hosts`              | none                     | Comma-separated extra hosts the agent may reach                      |
| `--workspace`                | CWD                      | Agent RW path written to `firma.toml` `[run.profiles.generic]` bwrap mount |
| `--output-dir` / `-o`        | `.firma` in CWD          | Where `firma.toml`, policies, and mappings are written               |
| `--state-dir`                | `$FIRMA_STATE_DIR` / XDG | Keys, revocations, generated CA                                      |
| `--authority-listen`         | `127.0.0.1:50051`        | gRPC listen address (`agent-local` / `authority` modes only)         |
| `--authority-url`            | wizard prompt            | Authority URL for `agent-remote` mode                                |
| `--authority-ca-cert`        | wizard prompt            | Authority CA cert PEM path for `agent-remote` mode                   |
| `--authority-pub-key`        | derived from state dir   | Authority public key path                                            |
| `--yes` / `-y`               | off                      | Skip all prompts; use existing values or flag defaults               |
| `--force`                    | off                      | Overwrite existing files including the authority keypair             |
| `--dry-run`                  | off                      | Print generated files to stdout without writing to disk              |
| `--list-templates`           | off                      | Print the posture × mapping catalogue and exit                       |

An explicit `--posture` rewrites the selected `policies/<posture>.cedar`
file even without `--force`; other existing generated files are still
preserved unless `--force` is set.

## Re-running on an existing config

When `firma config` finds `firma.toml` in the target directory, it reads the
current values and uses them as defaults for every prompt and non-interactive
run. Pass only the flags you want to change; everything else is preserved.

Changing an existing local-authority config to `--mode agent-remote`
normally removes the top-level `[authority]` section from the generated
`firma.toml`; otherwise `firma run` starts the Authority locally instead
of using only the remote Authority. Non-force runs warn about that.
Interactive runs ask whether to keep the section and use that answer to
rewrite `firma.toml`; non-interactive non-force runs preserve the existing
file. `--force` overwrites the config directly and removes the section.

```bash
# Keep everything, just rename the agent
firma config --yes --name new-agent

# Preview what would change without writing
firma config --yes --dry-run
```

## Scaffolded layout

```
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

`agent-local` emits both sections. `agent-remote` emits only the
`[sidecar.authority]` connect block. `authority` mode emits only
`[authority]`.

```toml
[authority]                   # agent-local and authority modes
listen_addr   = "127.0.0.1:50051"
key_file      = "/path/to/state/authority.key"
# ...

[sidecar.authority]           # agent-local and agent-remote modes
url             = "http://127.0.0.1:50051"
ca_cert_path    = "/path/to/state/tls/authority-ca.crt"
public_key_path = "/path/to/state/authority.pub"
# ... plus connect_timeout_secs / reconnect_* / revocation_* tuning

[sidecar.preflight]
agent_id          = "my-agent"
requested_actions = ["credential.read", "code.read", ...]
```

## Implicit init on `firma run`

`firma run` checks for a discoverable `firma.toml` at launch. If none is
found, it scaffolds one with non-interactive defaults and proceeds. This
keeps `firma run codex` working from a fresh clone without any prior setup.

## Common gotchas

**Wizard refuses to run in CI.** `firma config` without `--yes` requires a
TTY. Pass `--yes` in non-interactive contexts.

**`firma.toml` already exists.** By design, existing files are preserved.
Use `--force` to overwrite, or remove the file by hand for a clean slate.

**Keys must not go in the config dir.** Keys live in `<state-dir>`, not
`<output-dir>`. Do not commit `authority.key`. Add `.firma/*.key` to
`.gitignore`.

## See also

- [Start and monitor the daemon](../manage-the-stack/) — what to do after `firma config`.
- [Wrap an agent with `firma run`](../firma-run/) — the one-command path that calls `firma config` implicitly.
- [Configuration reference](../../../docs/configuration.md) — the full `firma.toml` schema.
