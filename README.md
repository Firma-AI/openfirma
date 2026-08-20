<div align="center">
  <img src="docs-site/src/assets/openfirma-logo.png" alt="OpenFirma" width="440" />

<br/>

<img src="docs-site/src/assets/Subtitle.gif" alt="OpenFirma" width="600" />

<br/>
<br/>

**Every call passes through a sidecar that decides whether it happens.**
<br/>
Policy in, signed decision out. Deterministic. At call-level.

[Docs](https://firma-ai.github.io/openfirma)
&nbsp;·&nbsp;
[Website](https://openfirma.netlify.app/)

<br/>

<div align="center">

[![CI](https://github.com/Firma-AI/openfirma/actions/workflows/ci.yml/badge.svg)](https://github.com/Firma-AI/openfirma/actions/workflows/ci.yml)
[![License: GPL 3.0](https://img.shields.io/badge/License-GPL_3.0-blue.svg)](https://opensource.org/licenses/GPL-3.0)
[![Built with Rust](https://img.shields.io/badge/Built_with-Rust-orange.svg)](https://www.rust-lang.org)

</div>

</div>

<br/>
<div align="center">
  <img src="docs-site/src/assets/home-diagram.svg" alt="OpenFirma diagram" width="100%" />
</div>
<br/>

## 1. What is OpenFirma?

OpenFirma is a runtime enforcement boundary that sits between your AI agents and the outside world. Every outbound call an agent makes passes through a local Sidecar that decides whether it happens: using Cedar policies you own, evaluated locally, with no model on the hot path.

**Why we built it:** AI agents are becoming software operators. They call APIs, read and write files, send messages, and execute code. That is useful but it also means a bad prompt, a compromised dependency, or a confused model can turn into a real outbound action before anyone notices. OpenFirma gives those actions a boundary.

**How it works:** You define a policy that says what each agent is allowed to do. Every outbound call passes through the Sidecar, which intercepts the request and evaluates it locally before execution. The Sidecar classifies the action (e.g. `code.read`, `communication.external.send`), validates the capability token, and checks the policy. On ALLOW, the call proceeds and credentials are injected just-in-time. On DENY, the call is blocked and a signed audit event is written. The enforcement logic lives outside the agent process.

<br/>

## 2. Run your coding agent with OpenFirma

### Install

**Linux / macOS:**

```bash
curl -fsSL https://install.openfirma.ai | sh
```

On macOS with Homebrew installed, the installer uses `brew install firma-ai/openfirma/firma`
automatically. You can also install directly:

```bash
brew install firma-ai/openfirma/firma
```

**Build and install from source** (requires Rust 1.88+ and `protoc`):

```bash
git clone https://github.com/Firma-AI/openfirma
cd openfirma
cargo install --path crates/firma --locked
```

### Quickstart

`firma` ships as a single precompiled static binary, no build toolchain or API keys required to get started.

There are two ways to start OpenFirma. Both end up in the same place (your agent running under enforcement) but the first is faster to try, the second gives you more control.

**Option A: zero config**

`firma run` autostarts a local Authority and Sidecar for the duration of the session and shuts them down when the agent exits. One command, nothing to configure, nothing left running when you are done. On first launch it prompts once to confirm the autostart; subsequent runs are silent.

```bash
firma run -- claude
```

Every outbound call is normalized, checked against your Cedar policy, and either forwarded or denied. Watch decisions live in a second terminal:

```bash
firma monitor
```

**Option B: explicit setup**

`firma sidecar start` boots Authority and Sidecar as persistent daemons that stay alive across sessions.

```bash
firma config                       # scaffold once: keys, policy, mappings
firma sidecar start --detach       # boot Authority + Sidecar as persistent daemons
firma run -- claude
firma monitor
```

Use this when you want to run multiple agents against the same Authority, keep enforcement running between sessions, or configure posture and mappings upfront with `firma config` before starting anything.

### Policies

Cedar policy files live under `.firma/policies/`. The Authority watches that directory and pushes any change to all connected Sidecars automatically — edit a file, save it, enforcement updates within 30 seconds. No restart needed.

```bash
firma policy validate .firma/policies/my-policy.cedar  # check before it goes live
firma policy test     .firma/policies/fixture.toml      # run allow/deny fixtures
```

**Packs**

`firma config` scaffolds your first policy from a **pack** — a pre-built combination of a posture and one or more mappings. A posture defines what action classes are permitted by default. A mapping translates the raw HTTP calls of a specific service into those action classes. Without a mapping for a service, the Sidecar cannot classify its calls and blocks them.

**Posture packs**, choose one per project:

| Posture                 | What it permits                                                                  |
| ----------------------- | -------------------------------------------------------------------------------- |
| `strict`                | `credential.read` and `communication.external.send` only. No code operations.    |
| `dev`                   | Adds `code.read/write`, issues, package install. No payments or destructive ops. |
| `dev-with-delete-watch` | `dev` plus `code.destructive` for local-exec and delete-watch scenarios.         |

**Mapping packs**, add one per service your agent calls:

| Mapping     | Covers                                                               |
| ----------- | -------------------------------------------------------------------- |
| `anthropic` | `api.anthropic.com`                                                  |
| `openai`    | `api.openai.com`                                                     |
| `github`    | GitHub REST + smart HTTP → 12 action classes                         |
| `gmail`     | 41 Gmail REST endpoints → 7 action classes                           |
| `stripe`    | 88 Stripe REST endpoints → 14 action classes                         |
| `composio`  | `app.composio.dev`, `backend.composio.dev` — governed tool execution |
| `npm`       | `registry.npmjs.org`                                                 |
| `pypi`      | `pypi.org`, `files.pythonhosted.org`                                 |
| `cargo`     | `crates.io`                                                          |

```bash
firma policy list                                        # browse all available packs
firma config --posture dev --mapping github --mapping stripe
```

**Live policy update**

Edit a Cedar policy file on disk at any point. The Authority picks up the change via file watcher and pushes the updated bundle to all connected Sidecars. No restart needed.

> Full policy reference: [Concepts: Policies](https://firma-ai.github.io/openfirma/concepts/policies/) · [Write your first Cedar policy](https://firma-ai.github.io/openfirma/guides/write-a-cedar-policy/)

### Different operating models

The **Sidecar** sits next to each agent process and enforces every outbound call. The **Authority** is a single trust root: it issues capability tokens and streams policy bundles to one or more Sidecars. A single Authority can govern many agents concurrently; the Sidecar enforces locally without calling back on every request.

<table><tr><td width="55%">

**1. Single agent (like Quickstart)**

OpenFirma first looks for an existing Authority. If none is configured, it offers to autostart a local Mini Authority and Sidecar for the session, wraps the agent process, and applies the selected policy profile automatically.

```bash
firma run -- claude
```

</td><td>
<img src="docs-site/src/assets/Picture1.png" width="100%"/>
</td></tr></table>

<table><tr><td width="55%">

**2. Local Authority, multiple agents**

The Authority becomes persistent and shared across local agent sessions. Each new `firma run` attaches to the same trust root and pulls the current policy bundle without restarting existing agents.

```bash
firma config
firma sidecar start --detach

firma run -- claude   &
firma run -- codex    &
firma run -- opencode
```

</td><td>
<img src="docs-site/src/assets/Picture2.png" width="100%"/>
</td></tr></table>

<table><tr><td width="55%">

**3. Team Authority, agents on multiple machines**

Each Sidecar enforces policy locally on its own machine while the shared Authority distributes policy bundles, capability tokens, and revocation updates across the team.

```bash
# On each developer machine or CI runner:
firma run \
  --authority https://authority.internal \
  --profile claude-code \
  -- claude
```

</td><td>
<img src="docs-site/src/assets/Picture3.png" width="100%"/>
</td></tr></table>

<table><tr><td width="55%">

**4. Custom Authority, custom agents without `firma run`**
<br/><em>Ideal for more structured enterprise use cases</em>

The Sidecar runs independently as a standalone enforcement proxy. Any agent, CI worker, or custom runtime that respects `HTTP_PROXY` / `HTTPS_PROXY` can be governed without SDK integrations or agent-specific wrappers.

```bash
firma authority --config firma.toml
firma sidecar   --config firma.toml

export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
python my_agent.py
```

The Authority can be the Mini Authority included in this repo or your own implementation of the `FirmaAuthority` gRPC interface.

</td><td>
<img src="docs-site/src/assets/Picture4.png" width="100%"/>
</td></tr></table>

### CLI reference

**Standalone commands** (flags only, no subcommands)

| Command         | Description                                           |
| --------------- | ----------------------------------------------------- |
| `firma run`     | Launch an agent in a sandbox via the Sidecar          |
| `firma config`  | Scaffold a new agent config directory (`--mode…`)     |
| `firma monitor` | Tail audit decisions and component logs (`--source…`) |
| `firma doctor`  | Diagnose a Firma install                              |
| `firma help`    | Print help for any command                            |

**`firma sidecar`** — run and manage the enforcement Sidecar daemon. Bare form (no subcommand) = foreground server.

| Subcommand       | Description                                       |
| ---------------- | ------------------------------------------------- |
| `sidecar start`  | Start Sidecar (+ local Authority) as a daemon     |
| `sidecar stop`   | Stop the daemon gracefully (`--timeout` fallback) |
| `sidecar status` | List live Sidecars + health (table or `--json`)   |

**`firma authority`** — issue tokens, stream policy bundles and revocations.

| Subcommand                     | Description                                     |
| ------------------------------ | ----------------------------------------------- |
| `authority revocations`        | Manage the revocation list (nested group)       |
| `authority generate-key`       | Generate a new Ed25519 signing key pair         |
| `authority init-tls`           | Bootstrap local CA + Authority↔Sidecar certs    |
| `authority issue`              | Sign and emit a capability token to a TOML seed |
| `authority issue-client-cert`  | Sign an mTLS client cert for a Sidecar          |
| `authority generate-client-ca` | Generate a new mTLS client CA key pair          |

**`firma policy`** — browse the template catalogue and validate Cedar bundles.

| Subcommand        | Description                                |
| ----------------- | ------------------------------------------ |
| `policy list`     | Print all posture and mapping templates    |
| `policy validate` | Parse and schema-check a Cedar policy file |
| `policy test`     | Run an allow/deny fixture against a bundle |

**`firma token`** — approve and revoke local-execution governance tokens (HITL).

| Subcommand      | Description                                   |
| --------------- | --------------------------------------------- |
| `token approve` | Approve a pending governance token            |
| `token revoke`  | Revoke a pending or approved governance token |

> Full CLI reference: [`docs/cli.md`](docs/cli.md)

<br/>

## 3. Architecture

<div align="center">
  <img src="docs-site/src/assets/product-diagram.svg" alt="OpenFirma flow diagram" width="100%" />
</div>
<br/>

**[Mini Authority](crates/firma-authority/):** issues capability tokens and distributes policy bundles to connected Sidecars. Sits off the request path.

**[Sidecar](crates/firma-sidecar/):** runs next to the agent process and intercepts outbound calls. Evaluates policy locally before execution and emits signed audit events.

**[Audit](crates/firma-core/):** every enforcement decision produces a signed audit record with the evaluated action, outcome, and metadata.

### Features

- **Structural interception:** every modality of action funnels through the Sidecar, with the kernel sandbox as the floor
- **Deterministic intent:** every tool call is classified into an enforceable action class; Cedar evaluates the same input to the same decision, every time
- **Per-call enforcement:** policy is evaluated before execution, against current policy and accumulated session state
- **JIT credentials:** a federated broker issues credentials per call on ALLOW; the agent never holds raw tokens; exfiltration is structurally impossible
- **Signed audit:** every decision emits a signed execution event with the exact envelope the policy saw

<br/>

## 4. Repo structure

**Infrastructure**

|                                                             |                                                                               |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------- |
| [`crates/firma`](crates/firma/)                             | CLI entrypoint: `firma run`, `firma sidecar`, `firma monitor`, `firma doctor` |
| [`crates/firma-sidecar`](crates/firma-sidecar/)             | The enforcement Sidecar: interceptors, pipeline, connectors                   |
| [`crates/firma-authority`](crates/firma-authority/)         | Mini Authority: file-based trust root for local development                   |
| [`crates/firma-core`](crates/firma-core/)                   | Shared types, Cedar schema, action classes, audit event format                |
| [`crates/firma-identifiers`](crates/firma-identifiers/)     | Agent, sandbox, session, capability, audit, and approval identifiers          |
| [`crates/firma-run`](crates/firma-run/)                     | Agent process confinement: bwrap backend, profile resolution, autostart       |
| [`crates/firma-runtime-state`](crates/firma-runtime-state/) | Runtime filesystem layout, persisted markers, and local liveness snapshots    |
| [`crates/firma-stack`](crates/firma-stack/)                 | Firma Authority and Sidecar lifecycle used by `firma sidecar start`           |

**Examples**

|                                       |                                                                   |
| ------------------------------------- | ----------------------------------------------------------------- |
| [`examples/demos`](examples/demos/)   | TUI demo runner with three self-contained enforcement scenarios   |
| [`examples/agents`](examples/agents/) | Intentionally risky demo agents (OpenAI Agents SDK + Google ADK)  |
| [`examples/e2e`](examples/e2e/)       | Local stack example: Authority + Sidecar + agent via `HTTP_PROXY` |

**Docs**

|                            |                                                      |
| -------------------------- | ---------------------------------------------------- |
| [`docs/`](docs/)           | Architecture, CLI reference, configuration reference |
| [`docs-site/`](docs-site/) | Astro/Starlight documentation site                   |

<br/>

## License

GPL 3.0. See [LICENSE](LICENSE)
