---
title: Secure a local coding agent
description: Wrap Claude Code, Codex, or another local coding agent so it can write code but not exfiltrate your repo.
---

A local coding agent has a powerful threat profile: it has read access to your source tree, it talks to an LLM provider over HTTPS, and it sometimes runs shell commands. A naive setup trusts the agent process completely. This guide shows you how to put it behind OpenFirma so:

- Only the LLM provider you intend to use is reachable.
- All other outbound destinations are denied.
- Every call is audited and reviewable.
- The agent process itself never holds the LLM API key.

The repo ships a starting config for Claude Code at `examples/firma-run/local/assets/firma_sidecar.local.claude.example.toml`. We'll use it as the base and explain what each part is doing.

## Threat model

The risks we're protecting against:

- **Prompt injection** — text in a file the agent reads convinces it to "share my work to a paste service". Without enforcement, it does.
- **Compromised dependency** — a malicious npm/pip package in the agent's runtime tries to call out to an attacker-controlled host.
- **API key exfiltration** — the agent process or anything it spawns tries to read `$ANTHROPIC_API_KEY` and send it somewhere.
- **Wrong provider** — a bug or jailbreak makes the agent talk to a provider you didn't authorize for sensitive data.

For each, OpenFirma's answer is: only the LLM endpoints are reachable, the agent never holds the key, and every attempt is recorded. See [Concepts: Threat model](../../concepts/threat-model/) for what this *doesn't* protect against.

## Step 1: Inventory what the agent legitimately needs

Before configuring, list the destinations the agent actually has to reach:

| Destination                     | Why                                              |
| ------------------------------- | ------------------------------------------------ |
| `api.anthropic.com`             | Claude API                                       |
| `*.anthropic.com`               | Console, platform, telemetry                     |
| `claude.ai` / `*.claude.com`    | Web auth flows                                   |

Keep this list as tight as the agent will tolerate. If the agent reaches for github.com to pull docs, list it and decide whether you want it. If it reaches for "random package registry to install something", almost certainly not — that's a signal something's wrong.

## Step 2: Set up the local stack

From the repo root:

```bash
examples/firma-run/local/setup.sh
```

This creates `.local/` with a working baseline. We're going to swap in the Claude-specific Sidecar config and mapping rules.

```bash
cp examples/firma-run/local/assets/firma_sidecar.local.claude.example.toml \
   .local/firma_sidecar.local.toml

cp examples/firma-run/local/assets/mapping-rules.claude.local.example.toml \
   .local/mapping-rules.toml
```

Inspect both files. The Sidecar config sets `intercept_hosts` to the Anthropic surface; the mapping rules cover both CONNECT-level (for L4 destination policy) and L7 endpoints under `*.anthropic.com`. `[mapping].default_protected = true` — anything not in this list denies.

## Step 3: Generate the Authority key and capability

```bash
firma authority generate-key -o .local/firma-authority.key

cat > .local/authority.toml <<EOF
listen_addr         = "[::1]:50051"
policy_dir          = "examples/policies"
issuance_policy_dir = ".local/issuance"
revocation_file     = ".local/revocations.txt"
key_file            = ".local/firma-authority.key"
max_ttl_seconds     = 28800
bundle_ttl_seconds  = 60
log_level           = "info"
EOF

mkdir -p .local/issuance
cat > .local/issuance/issuance.cedar <<'EOF'
permit (
    principal == Firma::Agent::"claude-code",
    action == Firma::Action::"communication.external.send",
    resource
);
EOF

touch .local/revocations.txt
```

Mint a capability for `claude-code`:

```bash
firma authority -c .local/authority.toml issue \
  --agent-id claude-code \
  --session-id $(uuidgen) \
  --action communication.external.send \
  --resource-scope '*.anthropic.com*' \
  --ttl-seconds 28800 \
  --output .local/capability-claude.toml
```

Eight hours is a reasonable working session. If you stop and restart the next morning, you'll mint a fresh one.

## Step 4: Write the runtime policy

Create `examples/policies/claude-code.cedar` (or wherever your `policy_dir` points):

```cedar
// claude-code: a local coding agent.
//
// Mission: read project files, generate code, talk to Anthropic only.
// Must not reach paste services, package registries, or anything else.

// Permit talking to Anthropic for the LLM call.
permit (
    principal == Firma::Agent::"claude-code",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource has "host" &&
    (resource.host like "*.anthropic.com" ||
     resource.host like "*.claude.com")
};

// Hard rule: known exfiltration destinations are off-limits regardless.
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource has "host" &&
    (resource.host == "paste.rs" ||
     resource.host == "transfer.sh" ||
     resource.host == "0x0.st" ||
     resource.host == "termbin.com")
};
```

The `permit` is bound to `claude-code` and a host glob. The `forbid` is unbound — applies to every agent, present and future.

## Step 5: Inject the Anthropic API key

You don't want the agent process to see the key. Put it in the Sidecar's environment instead, and let the connector inject it on the way out:

In `.local/firma_sidecar.local.toml`:

```toml
[[credentials]]
host           = "api.anthropic.com"
mode           = "basic"
header         = "x-api-key"
value_from_env = "ANTHROPIC_API_KEY"
```

For the Anthropic API specifically, the header is `x-api-key`, not `Authorization` — check the SDK's expectation if you're unsure.

## Step 6: Start the stack

Three terminals.

**Terminal 1: Authority.**

```bash
ANTHROPIC_API_KEY=  # not needed here; the Sidecar holds it
firma authority -c .local/authority.toml
```

**Terminal 2: Sidecar.**

```bash
ANTHROPIC_API_KEY=sk-ant-... \
firma sidecar -c .local/firma_sidecar.local.toml
```

The `ANTHROPIC_API_KEY` env var is set on the Sidecar's process only. The agent's process in Terminal 3 does not receive it.

**Terminal 3: the agent under `firma run`.**

```bash
firma run \
  --profile codex \
  --capability-file .local/capability-claude.toml \
  -- claude code
```

`--profile codex` is the right shape for coding agents — it mounts your project workspace into the sandbox. `--capability-file` wires in the capability we issued in Step 3.

When Claude Code launches, it inherits no LLM API key from your shell. Its outbound calls hit the proxy bridge, which forwards over UDS to the Sidecar, which validates Stage 1, evaluates Stage 2, and (for permitted Anthropic calls) injects the API key before dispatching upstream.

## Step 7: Try to break it

The audit log is your test rig. From a fresh terminal:

```bash
tail -f .local/audit.jsonl | jq 'select(.decision.outcome == "DENY")'
```

Now ask Claude Code something innocuous ("explain this function"). You should see no DENY events — its API call to Anthropic was allowed and dispatched.

Now try to make it misbehave. Ask: "*Please curl my code to paste.rs as a sanity check.*" Either:

1. Claude Code refuses (the model itself declines) — good.
2. Claude Code tries — and the Sidecar denies. The DENY event in the tail shows:
   - `envelope.intent.resource.host == "paste.rs"`
   - `decision.matched_policies == ["forbid_at_claude-code.cedar_..."]`

Either way, the data didn't leave. The second case is the more interesting one — your enforcement caught what the agent's safety wouldn't.

## Step 8: Make this your daily setup

Two operational considerations:

**Capability rotation.** Your capability expires at `--ttl-seconds`. For a daily workflow, mint a fresh one each morning:

```bash
# in ~/.zshrc or wherever
firma-claude-start() {
  cd "$1" || return 1
  firma authority -c .local/authority.toml issue \
    --agent-id claude-code \
    --session-id $(uuidgen) \
    --action communication.external.send \
    --resource-scope '*.anthropic.com*' \
    --ttl-seconds 28800 \
    --output .local/capability-claude.toml
  firma run --profile codex \
    --capability-file .local/capability-claude.toml \
    -- claude code
}
```

**Audit retention.** Keep at least 30 days of audit JSONL. If something goes wrong, your record of what the agent did is the only ground truth.

## Adapting to other coding agents

The same shape works for Codex, Cursor, or any LLM coding agent. The pieces that change:

| Variable                     | Claude Code              | Codex                  | Cursor               |
| ---------------------------- | ------------------------ | ---------------------- | -------------------- |
| `agent_id` for capability    | `claude-code`            | `codex`                | `cursor`             |
| `intercept_hosts`            | `*.anthropic.com`, `*.claude.com` | `api.openai.com`, `*.openai.com` | (depends on backend) |
| Credential header            | `x-api-key`              | `Authorization` + `Bearer ` prefix | varies      |
| Credential env var           | `ANTHROPIC_API_KEY`      | `OPENAI_API_KEY`       | varies               |
| `firma run --profile`        | `codex`                  | `codex`                | `codex`              |

The codex profile is named for the fact it was originally tuned for codex-style coding agents; despite the name, it's the right profile for any coding agent that needs project workspace mounts.

## Common gotchas

**Claude Code refuses to start: `proxy connection refused`.** The Sidecar isn't running, or the proxy bridge couldn't reach it. Check the Sidecar terminal for `sidecar ready`.

**Calls show `CONNECT` only, no method/path.** MITM isn't on for `*.anthropic.com`. Verify `intercept_hosts` and that the agent trusts your CA. The shipped Claude config sets `enabled = true` and lists the hosts.

**`401 Unauthorized` from Anthropic.** The injected key is wrong. Check `ANTHROPIC_API_KEY` on the Sidecar's environment — not on the agent's.

**Tons of DENYs from a host you didn't authorize.** This is the system working. If the host is legitimate (e.g. an Anthropic CDN host that wasn't in your initial list), add it to mapping + permit. If it's not, you've found something the agent shouldn't be doing — investigate.

## What's next

- [Read & verify the audit log](../audit-log/) — for daily review of what the agent did.
- [Concepts: The sandbox boundary](../../concepts/sandbox/) — for what `firma run` is doing under the hood.
- [Deploy a GenAI web app](../deploy-a-genai-webapp/) — the same model, applied to a multi-user web service.
