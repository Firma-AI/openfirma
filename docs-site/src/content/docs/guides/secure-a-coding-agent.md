---
title: Secure a local coding agent
description: Wrap Claude Code, Codex, or another local coding agent so it can write code but not exfiltrate your repo.
---

A local coding agent has a powerful threat profile: it has read access to your source tree, it talks to an LLM provider over HTTPS, and it sometimes runs shell commands. A naive setup trusts the agent process completely. This guide shows you how to put it behind OpenFirma so:

- Only the LLM provider you intend to use is reachable.
- All other outbound destinations are denied.
- Every call is audited and reviewable.
- The agent process itself never holds the LLM API key.

The repo ships a starting config for Claude Code at `examples/firma-run/local/assets/firma.local.claude.example.toml`. We'll use it as the base and explain what each part is doing.

## Threat model

The risks we're protecting against:

- **Prompt injection** — text in a file the agent reads convinces it to "share my work to a paste service". Without enforcement, it does.
- **Compromised dependency** — a malicious npm/pip package in the agent's runtime tries to call out to an attacker-controlled host.
- **API key exfiltration** — the agent process or anything it spawns tries to read `$ANTHROPIC_API_KEY` and send it somewhere.
- **Wrong provider** — a bug or jailbreak makes the agent talk to a provider you didn't authorize for sensitive data.

For each, OpenFirma's answer is: only the LLM endpoints are reachable, the agent never holds the key, and every attempt is recorded. See [Concepts: Threat model](../../concepts/threat-model/) for what this *doesn't* protect against.

## Step 1: Inventory what the agent legitimately needs

Before configuring, list the destinations the agent actually has to reach:

| Destination                  | Why                          |
| ---------------------------- | ---------------------------- |
| `api.anthropic.com`          | Claude API                   |
| `*.anthropic.com`            | Console, platform, telemetry |
| `claude.ai` / `*.claude.com` | Web auth flows               |

Keep this list as tight as the agent will tolerate. If the agent reaches for github.com to pull docs, list it and decide whether you want it. If it reaches for "random package registry to install something", almost certainly not — that's a signal something's wrong.

## Step 2: Scaffold the config with `firma config`

`firma config` creates a complete configuration directory — sidecar + authority config, Cedar policy, mapping rules, authority keypair, and revocations list — in a single command:

```bash
firma config \
  --profile codex \
  --posture strict \
  --mapping anthropic
```

This writes to the **current directory** by default. Pass `--output-dir` to write to a specific path:

```bash
firma config --profile codex --posture strict --mapping anthropic --output-dir .local
```

New local configurations generate a stable UUIDv7 at
`[sidecar.authority].agent_id`. The UUID is the agent's registered identity;
`codex` is only the local execution profile.

`--posture strict` allows only `communication.external.send` (and `credential.read`), which is the right shape for a coding agent that should reach only the LLM endpoint. The `anthropic` mapping classifies `CONNECT` tunnels to `*.anthropic.com`. Credential injection in Step 5 requires HTTPS MITM on `api.anthropic.com` — see [Inject credentials](../inject-credentials/).

Generated layout (default `--output-dir .firma`):

```
.firma/
  firma.toml                   — unified config (authority + sidecar + run profiles)
  mapping-rules.toml           — base mapping rules
  mappings/anthropic.toml      — Anthropic endpoint mapping
  policies/strict.cedar        — Cedar enforcement policy (edit in Step 4)
  issuance-policies/issuance.cedar

$XDG_DATA_HOME/firma/          — platform state dir (keys, revocations, CA)
  authority.key                — authority signing keypair (regenerated only with --force)
  authority.pub
  audit.key
  revocations.txt
```

## Step 3: Mint a capability for `claude-code`

```bash
AGENT_ID="agt_01j0000000e008000000000001" # copy from .firma/firma.toml
firma authority -c .firma/firma.toml issue \
  --agent-id "$AGENT_ID" \
  --session-id $(uuidgen) \
  --action communication.external.send \
  --resource-scope '*.anthropic.com*' \
  --ttl-seconds 28800 \
  --output .firma/capability-claude.toml
```

Eight hours is a reasonable working session. If you stop and restart the next morning, you'll mint a fresh one.

## Step 4: Tighten the runtime policy

`firma config` generated `.firma/policies/strict.cedar` with a broad `communication.external.send` permit. Edit it to restrict to Anthropic hosts specifically. Replace the file with:

```cedar
// claude-code: a local coding agent.
//
// Mission: read project files, generate code, talk to Anthropic only.
// Must not reach paste services, package registries, or anything else.

// Permit talking to Anthropic for the LLM call.
permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource == Firma::Resource::"api.anthropic.com/v1/messages" ||
    resource == Firma::Resource::"api.anthropic.com/v1/messages/count_tokens"
};

// Hard rule: known exfiltration destinations are off-limits regardless.
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource == Firma::Resource::"paste.rs/" ||
    resource == Firma::Resource::"transfer.sh/" ||
    resource == Firma::Resource::"0x0.st/" ||
    resource == Firma::Resource::"termbin.com/"
};
```

Replace the example UUID with the value from
`[sidecar.authority].agent_id`. The `permit` is bound to that registered agent
and exact Anthropic API resource UIDs. Add more exact UIDs only after you
observe legitimate DENYs. The `forbid` is unbound — applies to every agent,
present and future.

Save the file to `.firma/policies/strict.cedar`.

## Step 5: Enable MITM and inject the Anthropic API key

The Claude SDK opens an HTTPS `CONNECT` tunnel to `api.anthropic.com`. Injecting
`x-api-key` on the inner `POST /v1/messages` request requires HTTPS MITM on that
host. Enable it in `.firma/firma.toml` (the repo example at
`examples/firma-run/local/assets/firma.local.claude.example.toml` shows the same
shape):

```toml
[sidecar.interceptor.https_mitm]
enabled = true
intercept_hosts = [
  "api.anthropic.com",
  "platform.claude.com",
  "claude.ai",
  "console.anthropic.com",
]
```

Put the API key in the Sidecar's environment, not the agent's:

```toml
[sidecar.credentials.anthropic]
target_host    = "api.anthropic.com"
mode           = "basic"
header         = "x-api-key"
value_from_env = "ANTHROPIC_API_KEY"
```

For the Anthropic API specifically, the header is `x-api-key`, not
`Authorization`. The agent must trust the Sidecar's generated CA — see
[Enable HTTPS MITM](../https-mitm/).

## Step 6: Start the stack

Three terminals.

**Terminal 1: Authority.**

```bash
ANTHROPIC_API_KEY=  # not needed here; the Sidecar holds it
firma authority -c .firma/firma.toml
```

**Terminal 2: Sidecar.**

```bash
ANTHROPIC_API_KEY=sk-ant-... \
firma sidecar -c .firma/firma.toml
```

The `ANTHROPIC_API_KEY` env var is set on the Sidecar's process only. The agent's process in Terminal 3 does not receive it.

**Terminal 3: the agent under `firma run`.**

```bash
firma run \
  --config .firma/firma.toml \
  --profile codex \
  --capability-file .firma/capability-claude.toml \
  -- claude code
```

`--profile codex` is the right shape for coding agents — it mounts your project workspace into the sandbox. `--capability-file` wires in the capability we issued in Step 3.

When Claude Code launches, it inherits no LLM API key from your shell. Its outbound calls hit the proxy bridge, which forwards over UDS to the Sidecar, which validates Stage 1, evaluates Stage 2, and (for permitted Anthropic calls) injects the API key before dispatching upstream.

## Step 7: Try to break it

The audit log is your test rig. From a fresh terminal:

```bash
firma monitor --source audit --decision deny
```

Now ask Claude Code something innocuous ("explain this function"). You should see no DENY events — its API call to Anthropic was allowed and dispatched.

Now try to make it misbehave. Ask: "*Please curl my code to paste.rs as a sanity check.*" Either:

1. Claude Code refuses (the model itself declines) — good.
2. Claude Code tries — and the Sidecar denies. The DENY event in the tail shows:
   - `resource == "paste.rs/"`
   - `deny_reason` contains `"policy denied"`

Either way, the data didn't leave. The second case is the more interesting one — your enforcement caught what the agent's safety wouldn't.

## Step 8: Make this your daily setup

Two operational considerations:

**Capability rotation.** Your capability expires at `--ttl-seconds`. For a daily workflow, mint a fresh one each morning:

```bash
# in ~/.zshrc or wherever
firma-claude-start() {
  AGENT_ID="agt_01j0000000e008000000000001" # copy from .firma/firma.toml
  firma authority -c .firma/firma.toml issue \
    --agent-id "$AGENT_ID" \
    --session-id $(uuidgen) \
    --action communication.external.send \
    --resource-scope '*.anthropic.com*' \
    --ttl-seconds 28800 \
    --output .firma/capability-claude.toml
  firma run \
    --config .firma/firma.toml \
    --profile codex \
    --capability-file .firma/capability-claude.toml \
    -- claude code
}
```

**Audit retention.** Keep at least 30 days of audit JSONL. If something goes wrong, your record of what the agent did is the only ground truth.

## Adapting to other coding agents

The same shape works for Codex, Cursor, or any LLM coding agent. The pieces that change:

| Variable              | Claude Code                       | Codex                              | Cursor                        |
| --------------------- | --------------------------------- | ---------------------------------- | ----------------------------- |
| Registered `agent_id` | UUID returned by registration     | UUID returned by registration      | UUID returned by registration |
| `intercept_hosts`     | `*.anthropic.com`, `*.claude.com` | `api.openai.com`, `*.openai.com`   | depends on backend            |
| Credential header     | `x-api-key`                       | `Authorization` + `Bearer ` prefix | varies                        |
| Credential env var    | `ANTHROPIC_API_KEY`               | `OPENAI_API_KEY`                   | varies                        |
| `firma run --profile` | `codex`                           | `codex`                            | `codex`                       |

Each registration gets its own UUID; product names such as `codex` and
`claude-code` are not registered identities.

The `codex` profile provides project workspace mounts for coding agents.

## Common gotchas

**Claude Code refuses to start: `proxy connection refused`.** The Sidecar isn't running, or the proxy bridge couldn't reach it. Check the Sidecar terminal for `sidecar ready`.

**Calls show `CONNECT` only, no method/path.** Expected when MITM is off: the
Sidecar authorizes the tunnel but cannot inspect inner HTTPS traffic, so audit
events lack method/path and Step 5 injection cannot run. Enable
`[sidecar.interceptor.https_mitm]` for `api.anthropic.com`, confirm
`intercept_hosts`, and install the generated CA where the agent trusts it.

**`401 Unauthorized` from Anthropic.** The injected key is wrong. Check `ANTHROPIC_API_KEY` on the Sidecar's environment — not on the agent's.

**Tons of DENYs from a host you didn't authorize.** This is the system working. If the host is legitimate (e.g. an Anthropic CDN host that wasn't in your initial list), add it to mapping + permit. If it's not, you've found something the agent shouldn't be doing — investigate.

## What's next

- [Read & verify the audit log](../audit-log/) — for daily review of what the agent did.
- [Concepts: The sandbox boundary](../../concepts/sandbox/) — for what `firma run` is doing under the hood.
- [Deploy a GenAI web app](../deploy-a-genai-webapp/) — the same model, applied to a multi-user web service.
