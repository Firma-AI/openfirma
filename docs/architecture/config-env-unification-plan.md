# Config env unification

## Goal

Bind the unified-`firma.toml` selection flag to one canonical environment
variable — `FIRMA_CONFIG` — on every subcommand that selects that file, and
fully retire `FIRMA_SIDECAR_CONFIG_FILE`.

## Motivation

`firma sidecar` (`serve`, `start`, `stop`) resolves the unified `firma.toml`
through the shared `firma_config_loader::ConfigResolver`
(`crates/firma/src/services/sidecar.rs` confirms it). The resolver's fixed
precedence is:

1. explicit `--config`;
2. `FIRMA_CONFIG` environment variable;
3. nearest `.firma/firma.toml` by walking up from the current directory.

Its `--config` clap arg is bound to `FIRMA_SIDECAR_CONFIG_FILE`, so `sidecar`
honours both that name (via the flag) and `FIRMA_CONFIG` (via resolver tier 2)
for the *same* file. Two names for one file is confusing.

### Sharp edge: `FIRMA_SIDECAR_CONFIG_FILE` is overloaded

The same env var name is also used for a **second, unrelated** input:
`firma run --sidecar-config` reads `FIRMA_SIDECAR_CONFIG_FILE`
(`crates/firma-run/src/routing.rs`, consumed by `select_template` in
`crates/firma-run/src/sidecar/config.rs`) as one fallback source for the
**sidecar TOML template** used to synthesize the autostarted per-run sidecar —
not the unified `firma.toml`. Template selection precedence is:

1. `--sidecar-config` flag;
2. `FIRMA_SIDECAR_CONFIG_FILE` env;
3. `./firma_sidecar.toml`;
4. synthesized minimal config.

Because the same env name drives both, an operator who sets
`FIRMA_SIDECAR_CONFIG_FILE` to point `firma run` at a sidecar template also,
silently, redirects `firma sidecar`'s unified-config selection.

`firma run --config` (run.rs) is a third, separate thing — a profile-layer
runtime config (`.toml`/`.yaml`), not the unified `firma.toml`. `firma run`
selects the unified file only through the resolver (no flag), so it already
honours `FIRMA_CONFIG` and needs no flag change.

## Non-goals

- No change to config resolution precedence or fail-closed behaviour; the
  resolver is untouched.
- No change to `--state-dir` / `FIRMA_STATE_DIR`.
- No change to `firma run --config` (profile-layer config) or the
  `--sidecar-config` flag itself.
- Not a clap `global` argument (see Alternatives).

## Design

Extend the shared argument group introduced by the canonical-config-discovery
change:

- `args/common.rs`: `ConfigArg { #[arg(long, env = "FIRMA_CONFIG")] config }` —
  the single owner of the flag name, env binding, and help text.
- `StackPaths` composes `ConfigArg` plus `state_dir` for the stack-inspection
  commands (`control`, `doctor`, `monitor`).
- Flatten `ConfigArg` into `sidecar` (`ServeArgs`, `StartArgs`, `StopArgs`) and
  `authority`, replacing their `FIRMA_SIDECAR_CONFIG_FILE` / no-env bindings.

Retire the env var entirely:

- `firma sidecar --config` binds `FIRMA_CONFIG` (was `FIRMA_SIDECAR_CONFIG_FILE`).
- `firma authority --config` gains the `FIRMA_CONFIG` clap binding. It resolves
  the same file via the resolver today (env-only, no clap binding); binding it
  on the flag surfaces it in `--help` and reports provenance as `EnvVar` rather
  than `Flag`.
- `firma run` autostart drops the `FIRMA_SIDECAR_CONFIG_FILE` template fallback:
  remove the env read in `routing.rs`, the `env_template` field on
  `SynthesizeRequest`, and the `TemplateSource::Env` variant / `select_template`
  branch. Template selection becomes `--sidecar-config` → `./firma_sidecar.toml`
  → synthesized minimal. No template feature is lost; only the redundant env
  source is removed, so `FIRMA_SIDECAR_CONFIG_FILE` no longer exists anywhere.

## Alternatives considered

- **Keep `FIRMA_SIDECAR_CONFIG_FILE` as the run-autostart template env.** Would
  remove only the sidecar/run cross-talk. Rejected in favour of full retirement:
  the fallback is one of four template sources and autostart works without it,
  so a single canonical config env is cleaner than carrying a second name.
- **Top-level clap `global` `--config`.** Rejected. A global argument leaks
  `--config` into every subcommand, including `token`, `policy`, `supervise`,
  and the internal `__dns-stub` / `__proxy-bridge` commands that do not consume
  the unified config. `--state-dir` is not uniform across commands, so it cannot
  be globalised alongside `--config` without fragmenting the cohesive
  config-plus-state-dir group. clap globals also cannot be required and appear
  at every level. A shared flattened group scopes the binding to exactly the
  commands that opt in.

## Breaking change and migration

- `FIRMA_SIDECAR_CONFIG_FILE` is removed. This is a user-facing configuration
  contract, so the change is `feat!` and ships with a migration note:
  - to select the unified `firma.toml`, export `FIRMA_CONFIG` (same file);
  - to supply a `firma run` autostart sidecar template previously passed via the
    env var, use `--sidecar-config <path>` or `./firma_sidecar.toml`.
- Docs to update in the same change: `docs/cli.md`, `docs/configuration.md`,
  `crates/firma/README.md`, `examples/firma-run/README.md`, the `docs-site`
  guides (`manage-the-stack.md` start table, `firma-run.md`), and
  `docs-site/public/llms.txt`.

## Proof obligations

- `cli_help`: `sidecar` / `authority` `--help` shows `FIRMA_CONFIG` and no
  command's `--help` shows `FIRMA_SIDECAR_CONFIG_FILE`. Extend `sidecar_help_ok`,
  which currently asserts the retired name.
- `config_selection`: extend the runtime precedence contract (explicit flag,
  `FIRMA_CONFIG` env, walk-up discovery, fail-closed) to `sidecar` and
  `authority`.
- Regression: `sidecar start` / `sidecar serve` still resolve the same
  `firma.toml` when only `FIRMA_CONFIG` is set; reported provenance is `EnvVar`.
- `firma run` autostart still synthesizes a sidecar config with no
  `FIRMA_SIDECAR_CONFIG_FILE` set (existing synthesis tests already cover the
  flag / cwd / minimal sources; drop any that assert the env source).

## Risk

Low logic risk — the resolver and precedence are unchanged. The cost is the
breaking env rename plus its documentation and test surface. Because the env
var is a user-facing contract, an independent review is required before merge.

## Sequencing

Stacked on top of the canonical-config-discovery branch, which introduces the
`StackPaths` group this plan extends. Land after that base merges (or retarget
the base once it does).
