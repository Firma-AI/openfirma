---
title: Working with Coding Agents
description: Use agent-friendly docs and a focused workflow to integrate OpenFirma with your own systems.
---

This page is for teams using coding agents to integrate OpenFirma into an app,
toolchain, or local development workflow. The examples are tool-agnostic: they
apply whether your agent runs in an editor, a terminal, or a hosted coding
environment.

The goal is to give the agent enough context to be useful without letting it
invent the security model. OpenFirma is a boundary around concrete outbound
actions, so integration work should stay grounded in capabilities, policy,
mapping rules, credentials, and audit events.

## Start with `llms.txt`

OpenFirma publishes an agent-readable index at
[`/llms.txt`](https://firma-ai.github.io/firma-oss/llms.txt). The file follows
the emerging `llms.txt` convention: a short Markdown document at a predictable
URL, with a summary and curated links to the most useful docs. The docs site
also publishes [`/llms-full.txt`](https://firma-ai.github.io/firma-oss/llms-full.txt),
which contains the full documentation as one Markdown-oriented context file.

Give that URL to the coding agent before asking it to design or edit an
integration:

```text
Use https://firma-ai.github.io/firma-oss/llms.txt as your entry point for
OpenFirma docs. Read the quickstart, architecture page, and any guide relevant
to this integration before proposing code. If you need full-doc context, use
https://firma-ai.github.io/firma-oss/llms-full.txt.
```

If the agent is working inside a clone of this repository, also point it at
`AGENTS.md`, `README.md`, and the relevant docs under `docs-site/src/content/docs/`.

## Recommended workflow

1. Run the [Quickstart](../quickstart/) yourself first. You should see one
   allowed request, one denied request, and audit events for both.
2. Ask the agent to summarize the OpenFirma pieces it plans to use: Sidecar,
   Authority, `firma run`, capabilities, policies, mapping rules, and audit log.
3. Define the boundary in plain language: which agent identity is running, which
   hosts it may reach, which actions it may take, and where credentials live.
4. Have the agent make small, reviewable edits. Policy, mapping rules, config,
   and docs should change together when they describe the same behavior.
5. Test with a known allowed call and a known denied call. Treat the audit log as
   the source of truth for what actually happened.

## Prompt template

Use a prompt like this when you want an agent to help with an integration:

```text
I am integrating OpenFirma into <system>. Use the OpenFirma llms.txt entry point
and read the relevant docs before editing.

Goal:
- <what the agent or app should be allowed to do>

Boundary:
- Agent identity: <agent_id>
- Allowed destinations: <hosts or APIs>
- Denied destinations: <known exfiltration or production-risk hosts>
- Credentials: injected by the Sidecar, never exposed to the agent process

Please propose the smallest change set first. Include config, Cedar policy,
mapping changes, tests or demo commands, and docs updates if behavior changes.
```

## Best practices

Keep permissions narrow. Start with the smallest host and action set that works,
then expand based on observed DENY events you understand.

Use `firma run` for third-party or prompt-driven agents. Proxy environment
variables are useful for cooperative processes, but a sandbox boundary is the
right default for coding agents that can spawn tools.

Do not paste live API keys into the agent prompt. Put secrets in the Sidecar's
environment or your secret manager, then use credential injection so the agent
process never holds the key.

Ask the agent to include a negative test. A good integration proves that the
intended call succeeds and a plausible misuse is denied.

Review generated Cedar and mapping rules carefully. If a rule says "allow all"
or adds a broad wildcard, make the agent justify it against the concrete task.

Keep the docs current. When an integration changes user-visible behavior,
update the docs page that a future agent or human would read next.

## When to pause for human review

Pause before accepting broad network access, long-lived capabilities, production
credentials, new action classes, or any change that lets traffic bypass the
Sidecar. Those are design decisions, not implementation details.

If the audit log and the agent's explanation disagree, trust the audit log.
OpenFirma is built so the policy decision can be inspected after the fact.

## Useful next pages

- [Architecture & invariants](../concepts/architecture/) for the mental model.
- [The enforcement pipeline](../concepts/pipeline/) for the request path.
- [Wrap an agent with `firma run`](../guides/firma-run/) for the sandbox boundary.
- [Secure a local coding agent](../guides/secure-a-coding-agent/) for a concrete
  local-agent setup.
- [Read & verify the audit log](../guides/audit-log/) for validating behavior.
