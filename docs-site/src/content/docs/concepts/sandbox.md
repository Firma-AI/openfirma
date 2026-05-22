---
title: The sandbox boundary
description: Why and how firma run wraps an agent so that all of its traffic must go through the Sidecar.
---

The Sidecar can only enforce on traffic it sees. The simplest way to feed it traffic is to set `HTTP_PROXY=http://127.0.0.1:8080` in the agent's environment — and that works fine for cooperative agents in trusted environments. But it does not work when the agent is *not* cooperative, when the agent process can spawn children that don't inherit the env, or when you want a hard guarantee that nothing escapes.

That guarantee is what `firma run` provides. It launches the agent inside an OS-level sandbox where every outbound network call is *forced* to go through the Sidecar, regardless of what the agent's code does. This page explains why the sandbox exists, what backends it uses, and what it does and does not protect against.

## The problem with proxy env vars alone

`HTTP_PROXY` is a hint, not a constraint. It works because most HTTP libraries respect it by convention. But:

- A library that doesn't respect proxy env vars (some Go binaries, some C libraries) bypasses it silently.
- An agent that opens raw TCP sockets bypasses it.
- An agent that spawns a child process with a clean environment bypasses it.
- Anything that reads `/etc/hosts`, makes its own DNS query, or talks UDP bypasses it.

For a cooperative agent on a developer laptop, none of this matters. For a less-trusted agent — anything you didn't write, anything running prompts you don't fully control, anything that could be compromised — the proxy hint is not a security boundary. It's a convention, and the agent can choose to ignore it.

## What `firma run` does

`firma run` wraps the agent's launch in a sandbox that *removes* the agent's ability to bypass the proxy. Concretely:

1. **Network namespace.** The agent runs in a sandbox where the only reachable network destination is a host-side process listening on `127.0.0.1:18080` (the proxy bridge).
2. **Proxy bridge.** A small helper inside the sandbox listens on `127.0.0.1:18080` and forwards bytes over a Unix socket to the host's Sidecar (typically at `$XDG_RUNTIME_DIR/firma/sidecar.sock`). The agent's traffic has nowhere else to go.
3. **DNS stub.** A stub resolver inside the sandbox answers DNS queries deterministically — only hostnames the Sidecar will route receive answers. Random outbound DNS is impossible.
4. **`HTTP_PROXY` injection.** For agents that *do* respect proxy env vars, `firma run` sets `HTTP_PROXY=http://127.0.0.1:18080` so they don't need any code change.
5. **Identity remap.** The agent runs under a sandbox user (configurable via `--identity-mode`), so it can't read host secrets via filesystem.

The result is that an agent running under `firma run` can attempt to bypass the proxy in any way it likes — open raw sockets, set its own DNS, fork a child process — and *every one of those attempts dead-ends inside the sandbox*. The only exit is through the Sidecar.

## The four backends

Network sandboxing primitives differ across OSes, so `firma run` selects a backend by platform:

| Backend       | Platform | Mechanism                                    | When to use                                     |
| ------------- | -------- | -------------------------------------------- | ----------------------------------------------- |
| `bwrap`       | Linux    | Unprivileged user namespaces (bubblewrap)    | Default on native Linux. Lightweight, no VM overhead. |
| `vz`          | macOS    | Apple Virtualization framework, Linux guest  | Default on macOS. Native Apple Silicon support. |
| `wsl2`        | Windows  | Linux guest under WSL2                       | Default on Windows.                             |
| `firecracker` | Linux    | KVM micro-VM                                 | Higher isolation than bwrap; opt-in.            |

You can override the platform default with `--backend`:

```bash
firma run --profile generic --backend firecracker -- python my_agent.py
```

The choice is mostly an operational one: bwrap is fast to start and lightweight; vz and wsl2 are the only options on their platforms; firecracker gives you a real micro-VM at the cost of slightly slower start time.

`firma run` cannot escalate privileges. On Linux it requires unprivileged user namespaces (which most modern distros enable by default). On WSL hosts, implicit backend selection fails early with a typed error instead of attempting `bwrap`.

## Profiles

A **profile** declares the runtime shape: env injection, sandbox identity, network policy, capability lease behavior. The shipped profiles are:

- **`generic`** — works for any agent. Sandboxed, proxy-routed, `HTTP_PROXY` set. The default.
- **`codex`** — tuned for code-generation agents (Claude Code, Codex, Cursor) that need filesystem access to a project directory. Allows mounting a workspace path.

Custom profiles live in TOML and you can pass them via `--config`. For most workloads, `generic` is correct and you should reach for a custom profile only when you've hit a limit.

The profile resolves at startup, before the sandbox is built. You can preview it without launching the agent:

```bash
firma run --profile generic --print-effective-config -- echo hi
```

This prints the resolved config as JSON so you can see exactly what mounts, env vars, and identity remaps will be applied.

## Capability handling

The agent inside the sandbox does not handle the capability token. Instead:

1. **Before** the sandbox starts, `firma run` obtains a capability — either by reading `--capability-file` (a TOML seed) or, in future iterations, by calling the Authority's `IssueCapability` gRPC.
2. The capability is written to a path the host-side Sidecar reads via its `[capability_seed]` config — *outside* the sandbox.
3. **Inside** the sandbox, the agent only sees `HTTP_PROXY=http://127.0.0.1:18080`. It never sees the token.
4. When the agent makes an outbound call, the Sidecar selects the right capability based on `(session_id, action_class, resource)` — which it knows from the request, not from the agent.

This is a meaningful security property: a compromised agent **cannot exfiltrate the capability token**, because it never had it. The agent's only superpower is "ask the Sidecar to do this thing"; the Sidecar decides whether the capability covers it.

## What the sandbox protects against

The sandbox boundary is a real security boundary, but it has a specific shape. Here's what it does and does not buy you.

**Protects against:**

- An agent that intentionally tries to bypass the proxy with raw TCP / UDP / non-HTTP protocols.
- An agent that spawns child processes that don't inherit `HTTP_PROXY`.
- DNS exfiltration via crafted lookups.
- Filesystem-mediated leaks across user boundaries (via identity remap).
- An agent reading host environment variables it shouldn't see.

**Does not protect against:**

- Bugs in the chosen backend (bwrap escapes, VZ guest-host vulnerabilities, etc.). The sandbox is as strong as the backend.
- An agent that targets the Sidecar itself (e.g. exhausts its connections, exploits a parsing bug). The Sidecar is your TCB; treat it that way.
- Side channels (timing, power consumption, etc.). OpenFirma is a network policy boundary, not a side-channel boundary.
- Cooperative protocol abuse (e.g. an agent that uses an *allowed* destination to smuggle data). That's a policy problem, not a sandbox problem — see [Threat model & bypasses](../threat-model/).
- Anything that happens *inside* the sandbox that doesn't generate network traffic (an agent that just churns CPU, or that writes to its own scratch space).

The sandbox is the *plumbing* that ensures every outbound call reaches the Sidecar. It is the policy and capability layers, not the sandbox, that decide whether a given call is OK.

## When to use `firma run` vs proxy env vars alone

Use proxy env vars alone when:

- You're developing OpenFirma itself or a policy bundle.
- The agent is your own code, running on a machine you trust, and you're using OpenFirma for *audit and policy*, not for *containment*.
- You want the lowest-friction setup — no sandbox, just `HTTPS_PROXY=…`.

Use `firma run` when:

- The agent is third-party, untrusted, or runs prompts you don't fully control.
- You want a hard guarantee that nothing escapes the policy boundary.
- You're shipping an agent runtime to others and the policy boundary is part of the product (rather than an add-on operators have to remember to wire up).
- Your threat model includes a compromised agent process that might actively try to evade enforcement.

For a worked example of using `firma run` to govern a real coding agent, see [Secure a local coding agent](../../guides/secure-a-coding-agent/).

## Where to go next

- [Wrap an agent with `firma run`](../../guides/firma-run/) — the operator-side walkthrough.
- [Threat model & bypasses](../threat-model/) — what's in scope and what's not.
- [Interception](../interception/) — what happens once traffic reaches the Sidecar.
