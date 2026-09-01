# Config env unification

## Goal

Select the unified `firma.toml` through one canonical flag and environment
variable — the global `--config` / `-c` / `FIRMA_CONFIG` — shared by every
subcommand that consumes it, and fully retire `FIRMA_SIDECAR_CONFIG_FILE`.

## Motivation

Every command that consumes the unified `firma.toml` resolves it through the
same `firma_config_loader::ConfigResolver`, whose fixed precedence is:

1. explicit `--config`;
2. `FIRMA_CONFIG` environment variable;
3. nearest `.firma/firma.toml` by walking up from the current directory.

Before this change each command declared its own `--config`, and the bindings
had drifted: `sidecar` bound `FIRMA_SIDECAR_CONFIG_FILE`, `authority` bound no
env, and the stack-inspection commands bound `FIRMA_CONFIG`. All pointed at the
same file. A single global flag makes `FIRMA_CONFIG` canonical everywhere and
removes the duplicated per-command declarations.

### Sharp edge: `FIRMA_SIDECAR_CONFIG_FILE` was overloaded

The same env name also fed a **second, unrelated** input: `firma run`'s
autostart read `FIRMA_SIDECAR_CONFIG_FILE` (`crates/firma-run/src/routing.rs`,
consumed by `select_template` in `crates/firma-run/src/sidecar/config.rs`) as
one fallback source for the **sidecar TOML template** used to synthesize the
per-run sidecar — not the unified `firma.toml`. So setting it to select a
`firma sidecar` config would also, silently, alter `firma run`'s autostart
template. Retiring the env removes that cross-talk.

## Design

- Add a global `--config` / `-c` bound to `FIRMA_CONFIG` on the top-level `Cli`
  (`crates/firma/src/args/mod.rs`), alongside the existing global `--log-*`
  flags. clap propagates it to every subcommand and accepts it before or after
  the subcommand name.
- Remove the per-command `--config` from `control`, `doctor`, `monitor`,
  `sidecar` (`serve`/`start`/`stop`), and `authority`. `main.rs` threads the
  resolved path (`cli.config`) into each service; state-dir flags stay
  per-command.
- `firma run` keeps `firma run --config` working through the global. Its
  `--config` was already the unified-`firma.toml` selector (feeds
  `maybe_implicit_init` and `RunInput.user_config_path`), so it needs no rename;
  the local field is dropped and the service reads the global path. `firma run
  --runtime-config` is **not** introduced — there is no separate overlay flag.
- Retire `FIRMA_SIDECAR_CONFIG_FILE` entirely: `firma run` autostart drops the
  env template source (removing the read in `routing.rs`, the `env_template`
  field on `SynthesizeRequest` / `PrepareRequest`, and the `TemplateSource::Env`
  variant). Template selection becomes `--sidecar-config` → `./firma_sidecar.toml`
  → synthesized minimal; no template feature is lost.

The path — not a pre-resolved config — is threaded, because consumers apply
different resolution policies: `doctor` reports resolution as a check instead of
failing, `run` may scaffold a `firma.toml` via implicit init, `sidecar start`
uses `firma_stack::resolve_stack_config`, and the others differ in fail-closed
versus tolerant handling.

## Alternatives considered

- **Per-command shared `ConfigArg` flattened into each command.** Keeps
  `--config` off commands that do not consume the config, but repeats a flatten
  in every consumer and yields nested field access. Rejected in favour of a
  single global declaration.
- **Keep `FIRMA_SIDECAR_CONFIG_FILE` as the run-autostart template env.** Would
  remove only the sidecar/run cross-talk. Rejected: the fallback is one of
  several template sources and autostart works without it, so a single canonical
  config env is cleaner than carrying a second name.

Trade-off accepted: as a clap global, `--config` is also accepted (and ignored)
by commands that do not consume the unified config, such as `token`, `policy`,
`supervise`, and the internal `__*` commands.

## Breaking change and migration

- `FIRMA_SIDECAR_CONFIG_FILE` is removed. This is a user-facing configuration
  contract, so the change is `feat!` and ships with a migration note:
  - to select the unified `firma.toml`, export `FIRMA_CONFIG` (same file);
  - to supply a `firma run` autostart sidecar template previously passed via the
    env var, use `--sidecar-config <path>` or `./firma_sidecar.toml`.
- Docs updated in the same change: `docs/cli.md`, `crates/firma/README.md`,
  `examples/firma-run/README.md`, the `docs-site` guides (`manage-the-stack.md`,
  `firma-run.md`), and the plan cross-reference in `docs/configuration.md` /
  `docs-site/public/llms.txt` where relevant.

## Proof obligations

- `cli_help`: `doctor` / `control` / `monitor` / `sidecar` / `authority`
  `--help` each expose `FIRMA_CONFIG` and none expose `FIRMA_STACK_CONFIG` or
  `FIRMA_SIDECAR_CONFIG_FILE`.
- `config_selection`: the runtime precedence contract (explicit flag,
  `FIRMA_CONFIG` env, walk-up discovery, fail-closed) still holds for the
  stack-inspection commands.
- Regression: `sidecar start` / `sidecar serve` still resolve the same
  `firma.toml` when only `FIRMA_CONFIG` is set.
- `firma run` autostart still synthesizes a sidecar config with no
  `FIRMA_SIDECAR_CONFIG_FILE` set (synthesis tests cover the flag / cwd / minimal
  sources; the env-source assertions are removed).

## Risk

Low logic risk — the resolver and precedence are unchanged. The cost is the
breaking env rename plus its documentation and test surface. Because the env
var is a user-facing contract, an independent review is required before merge.

## Sequencing

Stacked on top of the canonical-config-discovery branch. Land after that base
merges (or retarget the base once it does).
