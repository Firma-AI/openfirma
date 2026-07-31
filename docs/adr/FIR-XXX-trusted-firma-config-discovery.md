---
adr: FIR-XXX
title: Trusted-location discovery for Firma config
created: 2026-08-06T00:00:00Z
status: proposed
superseded_by: null
---

# FIR-XXX ADR: Trusted-location discovery for Firma config

`firma run` and the other CLI entry points resolve `firma.toml` through
`firma_config_loader::ConfigResolver::resolve_config`. Today the precedence is:

1. `--config` flag.
2. `FIRMA_CONFIG` environment variable.
3. Walk up from the current working directory, taking the nearest
   `<dir>/.firma/firma.toml`, unbounded to the filesystem root.

The configuration is a security boundary: it carries enforcement policy, action
mappings, allowlists (`allowed_executables`, allowed hosts), authority and
sidecar endpoints and keys, secret providers, sandbox backend selection, and
egress/DNS confinement. Whoever controls the selected file controls the
guardrails.

Walk-up discovery lets an untrusted party plant that file:

- **Subdirectory / cwd planting.** A compromised prompt writes
  `./.firma/firma.toml` (or into any subdir the user later `cd`s into). The next
  `firma run` from that directory selects the crafted config and weakens its own
  enforcement.
- **Ancestor planting.** Any writable directory on the walk path can host a
  `.firma/` that wins for every child directory.
- **TOCTOU.** Even a legitimately discovered path can be swapped between
  resolution and use (directory/file symlink, mount races). FIR-463 masks the
  discovered `.firma/` inside the sandbox but does not remove the discovery-time
  trust problem, and its own adversarial tests already record open gaps.

The root cause: the trust root is a path the agent/repo controls (cwd and its
ancestors), not a path the user controls. A convenience borrowed from
git/npm/eslint/dotenv, where nearest-file-wins is expected, is unsafe for a
policy boundary.

## Decision drivers

1. **Fail closed against planting.** No agent- or repo-writable path may become
   the config source without explicit user action.
2. **Automatic pickup.** The common case (one machine-wide config) must need no
   flags.
3. **Cross-platform.** Linux, macOS, Windows need one coherent model.
4. **Explicit escapes stay.** CI, tests, and multi-config workflows still need
   `--config` / `FIRMA_CONFIG`.
5. **Determinism.** Same host state yields the same selected config.
6. **Room to grow.** Per-workspace profiles/policies must be expressible later
   without reintroducing planting.

## Decision outcome

Adopt a trusted-location discovery model and remove unbounded cwd walk-up.
Deliver in phases.

### Phase 1 — Trusted-location config

Resolve `firma.toml` from a user-controlled trusted directory, per OS, with no
directory-tree walk:

| OS      | Trusted config directory                  |
| ------- | ----------------------------------------- |
| Linux   | `$XDG_CONFIG_HOME/firma`, else `~/.firma` |
| macOS   | `~/.firma` (HOME-rooted; keep parity)     |
| Windows | `%USERPROFILE%\.firma`                    |

New precedence:

1. `--config <path>` flag (explicit, launcher-controlled escape).
2. `FIRMA_CONFIG` env var (explicit, launcher-controlled escape).
3. The trusted config directory above. **No walk-up.**

`--config` and `FIRMA_CONFIG` are kept. They are explicit escapes, not
discovery: CI, tests, and multi-config-per-machine workflows depend on pointing
at an out-of-HOME file, and both are read from the launcher's environment, which
a sandboxed agent cannot set (see threat model). They do not widen the trust
surface — but they do widen the mask surface, handled below.

### Masking follows the resolved source

The in-sandbox mask must cover exactly what discovery could select — but the
selectable set is now bounded and known before launch, so the mask keys off the
resolved source, not a fixed location and not a walk:

```
mask set = trusted config dir
         ∪ resolved --config / FIRMA_CONFIG target (file + its `.firma` parent)
         ∪ $HOME/.firma
```

### Override target inside a writable mount

`--config`/env protect selection, not runtime integrity. If the resolved config
lives inside a sandbox-writable mount (typically the workspace), the agent can
read or swap it at runtime → TOCTOU, and masking-to-`/dev/null` is what prevents
the read. Rule:

- A resolved config that lands inside any sandbox-writable mount is masked and
  warned, and SHOULD be refused under strict posture.
- Prefer configs outside agent-writable paths. The trusted dir is outside mounts
  by construction and is always clean; only overrides can hit this case.

### Phase 2 — Derived artifact paths

Phase 1 only moves config selection; it does not change how paths inside the
config work. Phase 2 does: stop persisting artifact paths in `firma.toml` and
derive every position instead. This is not user-facing path normalization — it
removes paths from the config so no absolute path can drift, bloat the file, or
become a repointing surface, and new artifacts are added by extending the
derivation rather than rewriting existing configs.

Every file has a natural static position, split into two buckets:

- **Durable artifacts** — Authority keys, revocation store, audit log and its
  signing key — derive under the **resolved config's `.firma/` directory**, not
  a hardcoded `~/.firma`. When a run resolves config via
  `--config /elsewhere/firma.toml`, its durable state lands under
  `/elsewhere/.firma`, so two configs on one machine never clobber each other's
  keys, revocation, or audit log. Durable state is the real conflict axis this
  closes.
- **Volatile artifacts** — sockets, per-run sidecar config, CA material — derive
  under a **per-run entry in the runtime dir** (`$XDG_RUNTIME_DIR`, e.g.
  `/run/user/1000`), already keyed by `sandbox_id` via
  `firma_runtime_state::runtime_paths::run_entry_from`. Requirement: every
  volatile artifact sits under that per-run entry, never a shared fixed name —
  otherwise concurrent runs collide in `/run/user/1000`.

```
~/.firma/                                                     # (or the resolved --config dir)
  firma.toml
  state/authority.key   state/authority.pub   state/revocation.txt   # durable, derived
  audit/audit.jsonl     audit/audit.key                              # durable, derived
# volatile (sockets, per-run sidecar config, CA) → $XDG_RUNTIME_DIR/<per-run entry>
```

Two properties this must preserve:

- **Masking follows.** The derived durable `.firma/` dir is part of the mask set
  from Phase 1 (mask-follows-resolved-source). When durable state derives from a
  `--config` dir outside HOME, the mask covers that dir too.
- **Determinism.** Same host state plus the same resolved config yields the same
  derived positions.

### Phase 3 — Agent Profile Selection

After Phase 1, mapping and posture are globally defined. After Phase 2, these
parameters can be resolved dynamically at run time based on the selected agent
(see [Config shape and override semantics](#config-shape-and-override-semantics)).

During execution, a run determines two components:

- **provider** — inferred from the binary command name or the specific LLM
  provider (such as `codex` or `claude`). The `--provider` flag serves as an
  override option exclusively if the command remains unrecognized. To improve UX
  when a command is unknown, a selection TUI could be implemented to prompt the
  user.
- **agent** — specified explicitly via `--agent <agent_id>`. Because `agent_id`
  could be unfriendly, users could assign a name to an agent, like `crm-agent`.
  This parameter is strictly required when multiple agents exist within the
  configuration. An interactive selection TUI can also list and choose from all
  configured agents.

## Config shape and override semantics

One `firma.toml` in the trusted `.firma/` directory holds global defaults; each
agent overrides only what differs. Paths are not persisted (see Phase 2);
durable artifacts live at fixed, derived locations under `.firma/` and volatile
artifacts under the per-run runtime dir.

### Layering

- `[authority]` — local Authority server definition (managed mode).
- `[sidecar]` — sidecar defaults.
- `[run]` — sandbox/launch defaults.
- `[[agents]]` — per-agent entries keyed by `agent_id`, each overriding a subset
  of the three global sections.

The agent CLI adapter (`codex`, `claude`, …) is derived from the command name,
not declared in the file.

### Merge rules

Effective config for an agent is layered low-to-high:

```
built-in defaults  <  global section  <  [[agents]] override  <  CLI flags
```

Merge is per key:

- **Tables** deep-merge (recurse, union keys).
- **Scalars** — the higher layer wins.
- **Arrays** — the higher layer replaces the whole array (no implicit append, so
  a resolved value is always predictable).

### Example

```toml
# ── GLOBAL DEFAULTS ─────────────────────────────────────────────
[authority]
listen_addr = "127.0.0.1:50051" # optional; pins managed port, else ephemeral loopback
max_ttl_seconds = 3600
bundle_ttl_seconds = 30
log_level = "info"
# policies, keys, TLS, revocation: derived under .firma/ — not listed

[sidecar]
mode = "enforce"
default_protected = true # fail-closed; warn on false
[sidecar.interceptor]
mode = "http_proxy"
[sidecar.mapping]
rules_paths = ["mappings/anthropic.toml"]
[sidecar.authority]
mode = "managed" # managed | connect

[run]
backend = "bwrap"
[run.env_set]
FIRMA_RUN_BWRAP_ROOTFS_MODE = "readonly"
FIRMA_RUN_BWRAP_MASK_HOME_PATHS = ".ssh,.gnupg,.aws"

# ── AGENT A: connect to a remote Authority; own mapping + workspace mount ──
[[agents]]
agent_id = "agt_01A"
[agents.sidecar.authority] # override only these keys
mode = "connect"
url = "https://authority.corp.internal:8443"
public_key = "k4.public.…" # pinned signing anchor
[agents.sidecar.mapping] # replaces the global mapping for this agent
rules_paths = ["mappings/github.toml", "mappings/stripe.toml"]
[[agents.run.mounts]]
source = "/home/luca/code/repo-a"
target = "/home/luca/code/repo-a"
read_only = false

# ── AGENT B: inherit managed Authority; tweak one env key + mount ──
[[agents]]
agent_id = "agt_01B"
[agents.run.env_set] # deep-merge into global env_set
FIRMA_RUN_BWRAP_MASK_HOME_PATHS = ".ssh,.gnupg,.aws,.config/gcloud,.env"
[[agents.run.mounts]]
source = "/home/luca/code/repo-b"
target = "/home/luca/code/repo-b"
read_only = false
```

Three things the resolution makes explicit:

- **Deep-merge under a table.** Agent A overrode only `[sidecar.authority]` and
  `[sidecar.mapping]`; the rest of `[sidecar]` (`mode`, `default_protected`,
  interceptor) is inherited. Within `[sidecar.authority]`, `mode` is replaced and
  `url`/`public_key` are added — sibling keys elsewhere are untouched.
- **Array replace, per agent.** Agent A's `[sidecar.mapping].rules_paths`
  (`github` + `stripe`) replaces the global `anthropic` mapping entirely — it
  does not append. Each agent gets exactly the action mapping it declares.
- **Scalar-in-table replace, siblings inherited.** Agent B sets one key of
  `run.env_set`; `FIRMA_RUN_BWRAP_ROOTFS_MODE` is inherited from global while
  `FIRMA_RUN_BWRAP_MASK_HOME_PATHS` is replaced.
