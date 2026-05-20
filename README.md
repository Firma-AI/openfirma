<div align="center">
  <img src="docs-site/src/assets/openfirma-logo-animated.gif" alt="OpenFirma" width="600" />

  <br/>
  <br/>

  **Every call passes through a sidecar that decides whether it happens.**
  <br/>
  Policy in, signed decision out. Open by default. Deterministic.

  <br/>

  [Docs](https://firma-ai.github.io/openfirma)
  &nbsp;·&nbsp;
  [Website](https://openfirma.netlify.app/)

</div>

<br/>

## 1. What is OpenFirma?

OpenFirma is a runtime enforcement boundary that sits between your AI agents and the outside world. Every outbound call an agent makes passes through a local Sidecar that decides whether it happens: using Cedar policies you own, evaluated locally, with no model on the hot path.
 
**Why we built it:** AI agents are becoming software operators. They call APIs, read and write files, send messages, and execute code. That is useful — but it also means a bad prompt, a compromised dependency, or a confused model can turn into a real outbound action before anyone notices. OpenFirma gives those actions a boundary.
 
**How it works:** You define a Cedar policy that says what each agent is allowed to do. When an agent makes an outbound call, the Sidecar intercepts it, classifies it into a canonical action class (e.g. `code.read`, `communication.external.send`), validates the capability token, and evaluates the policy. On ALLOW, the call goes through and credentials are injected just-in-time. On DENY, the call is blocked and a signed audit event is written. The agent code contains none of this logic.
<br/>

## 2. Run your coding agent with OpenFirma

### Quickstart

**macOS:**

```bash
brew tap Firma-AI/openfirma
brew install firma
```

**Linux / other:**

```bash
curl -sSf https://install.openfirma.ai | sh
```

Then wrap your agent:

```bash
firma run --profile claude-code -- claude
```

No Rust toolchain, no `protoc`, no API keys required to get started.

> **Build from source:** if you want to contribute or run the deterministic CI demo, you need Rust 1.86+ and `protoc`. Clone the repo and run `make demo-ci`.

### Demo

> _Coming soon — the demo section will be updated once the new agent demo flow is finalized._

<br/>

## 3. Architecture

<div align="center">
  <img src="docs-site/src/assets/openfirma-flow-slow.gif" alt="OpenFirma flow diagram" width="100%" />
</div>
<br/>
**[Authority](crates/firma-authority/):** policy lives in one place. It issues short-lived capability tokens and streams Cedar policy bundles to the Sidecar. One policy file governs every agent, every call, every surface. Never on the hot path: once the Sidecar has the token and policy bundle, all decisions are local.

**[Sidecar](crates/firma-sidecar/):** the interception layer. Every outbound action funnels through it. Stage 1 validates the capability token locally (signature, integrity, revocation) in microseconds. Stage 2 evaluates the Cedar policy against the current session state. Sub-millisecond. Deterministic. On ALLOW, credentials are injected; the agent never holds raw tokens.

**[Audit emitter](crates/firma-core/):** every decision, ALLOW or DENY, produces a signed `ExecutionEvent` written to your configured sink (file, stdout, or gRPC).


### Features
 
- **Structural interception:** every modality of action funnels through the Sidecar, with the kernel sandbox as the floor
- **Deterministic intent:** every tool call is classified into an enforceable action class; Cedar evaluates the same input to the same decision, every time
- **Per-call enforcement:** policy is evaluated before execution, against current policy and accumulated session state
- **JIT credentials:** a federated broker issues credentials per call on ALLOW; the agent never holds raw tokens; exfiltration is structurally impossible
- **Signed audit:** every decision emits a signed execution event with the exact envelope the policy saw
<br/>

## 4. Repo structure

| | |
|---|---|
| **[`crates/firma`](crates/firma/)** | CLI entrypoint: `firma run`, `firma stack`, `firma monitor`, `firma doctor` |
| **[`crates/firma-sidecar`](crates/firma-sidecar/)** | The enforcement Sidecar: interceptors, pipeline, connectors |
| **[`crates/firma-authority`](crates/firma-authority/)** | Mini Authority: file-based trust root for local development |
| **[`crates/firma-core`](crates/firma-core/)** | Shared types, Cedar schema, action classes, audit event format |
| **[`crates/firma-run`](crates/firma-run/)** | Sandbox launcher: bwrap backend, profile resolution, autostart |
| **[`crates/firma-stack`](crates/firma-stack/)** | Stack supervisor: Authority + Sidecar lifecycle as one unit |
| **[`crates/firma-proto`](crates/firma-proto/)** | Protobuf/gRPC service definitions |
| **[`examples/demo`](examples/demo/)** | Quickstart demo: deterministic CI, LLM-backed, interactive REPL |
| **[`examples/agents`](examples/agents/)** | Intentionally risky demo agents (OpenAI Agents SDK + Google ADK) |
| **[`examples/generic-agent`](examples/generic-agent/)** | `firma run` profile and stack runner for wrapping any agent command |
| **[`docs/`](docs/)** | Architecture, CLI reference, configuration reference |
| **[`docs-site/`](docs-site/)** | Astro/Starlight documentation site |

## 5. License
 
Apache 2.0. See [LICENSE](LICENSE).