# FIRMA OSS

AI agents are becoming software operators. They call APIs, read and write files, query databases, send messages, run tools, and sometimes execute code. To do that, they often receive broad credentials and run inside a normal developer or server environment.

FIRMA is a governed runtime for those agents.

It starts an agent with a runtime profile, routes the agent's outbound traffic through a local enforcement process, checks protected actions against policy, and records the result. The goal is simple: an agent should only be able to do what it was allowed to do, and every important decision should be visible afterwards.

## How FIRMA is structured

FIRMA has three main runtime pieces.

`firma run` is the launcher. It starts the agent command with a selected profile. A profile defines how the process should run, what environment it receives, how traffic is routed, and which runtime backend is used. On Linux, the strongest current backend uses `bwrap` to constrain the process and its network path. On other platforms, FIRMA still provides a governed wrapper path, but isolation guarantees depend on the backend.

The **Sidecar** is the local enforcement point. It receives outbound requests from the agent, turns each request into a clear action, checks whether that action is allowed, and forwards only allowed traffic. The Sidecar is not the sandbox. The sandbox constrains the process; the Sidecar decides application-level policy.

The **Authority** is the source of permission. It loads policy, signs short-lived permission tokens, and sends policy updates and revocations to Sidecars. A revocation cancels a token before it naturally expires. A permission token is a signed statement that says what an agent may do, where it may do it, and for how long.

```text
+-------------+        starts with profile        +---------------+
|  firma run  | -------------------------------> | Agent process |
+-------------+                                  +---------------+
                                                        |
                                                        | routed traffic
                                                        v
+-----------------+    tokens, policies, revocations   +---------------+    allowed traffic    +-------------------+
| FIRMA Authority | ----------------------------------> | FIRMA Sidecar | -------------------> | External services |
+-----------------+                                    +---------------+                      +-------------------+
                                                             |
                                                             | policy decision + audit event
                                                             v
```

## What happens during a run

A typical FIRMA run follows this sequence:

1. You start an agent with `firma run`.
2. FIRMA chooses a profile and creates a session identity.
3. The agent starts inside the selected runtime backend.
4. Outbound traffic is routed toward the Sidecar.
5. The Sidecar identifies the action the agent is trying to perform.
6. The Sidecar verifies the agent's permission token.
7. The Sidecar checks policy for that action and resource.
8. The request is allowed or denied.
9. FIRMA writes an audit event for the decision.

The important runtime property is local enforcement. Once the Sidecar has the current policy and revocation data, it can decide on each request without calling the Authority on the hot path.

## Authority, tokens, and certificates

FIRMA uses two different kinds of cryptographic material.

The **Authority signing key** is used to sign permission tokens. The Authority keeps the private key. The Sidecar gets the matching public key so it can verify tokens locally. In the demo configuration, these files are `examples/demo/firma-authority.key` and `examples/demo/firma-authority.pub`.

The **Sidecar HTTPS CA** is used when the Sidecar decrypts selected HTTPS traffic for policy enforcement. The CA lets the Sidecar create certificates for intercepted hosts. This is separate from the Authority signing key. In the demo configuration, this material lives under `examples/demo/firma-ca/`.

The basic setup flow is:

1. Start the Authority with a policy directory and signing key.
2. Configure the Sidecar with the Authority address and public key.
3. Issue a permission token for an agent session.
4. Start the Sidecar with policies, mappings, and token material.
5. Run the agent through `firma run` so traffic reaches the Sidecar.

In the current local demo path, tokens can be pre-issued into a capability seed file and loaded by the Sidecar at startup. In a fuller deployment, the same permission model is served through the Authority API before or during an agent session.

## Core components in this repository

`firma-run` starts governed agent processes. It applies profiles, prepares runtime identity, configures proxy and certificate environment, and launches the selected backend.

`firma-sidecar` enforces policy on outbound agent traffic. It normalizes requests, validates permission tokens, evaluates policy, injects credentials when configured, forwards allowed traffic, and emits audit events.

`firma-authority` is the local development Authority. It loads policy files, signs permission tokens, and streams policy and revocation updates to Sidecars.

`firma-core` and `firma-proto` contain the shared types and wire contracts used by the runtime components.

The examples and demo agents show how policies, mappings, profiles, and agent traffic fit together.

## Repository map

```text
crates/          Rust workspace crates for the launcher, Sidecar, Authority, shared types, and demos.
examples/        Runnable demo stacks, policy files, mapping files, and end-to-end assets.
example_agents/  Demo agents used to show risky tool behavior and FIRMA enforcement.
docs/            Architecture notes, configuration references, CLI docs, security analysis, and release notes.
scripts/         Legacy helper scripts. These are expected to move under examples as the repo is reorganized.
context/         Internal design material and early proof-of-concept references.
memory-bank/     specsmd planning artifacts for structured feature work.
.github/         GitHub Actions workflows.
.specsmd/        specsmd templates and workflow scripts.
.cursor/         Cursor workspace guidance.
```

The top-level `Cargo.toml` defines the Rust workspace. The `Makefile` contains the common build, lint, test, and demo commands.

## Build

```bash
cargo build --workspace
make check
```

## License

Apache 2.0
