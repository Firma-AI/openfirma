---
title: Write your first Cedar policy
description: Author, validate, and reload a Cedar policy that decides ALLOW or DENY for an agent action.
---

This guide takes you from "I have a running Sidecar" to "I am writing my own runtime policy". You'll start from a copy of the demo bundle, narrow it for a real agent identity, add a forbid rule for a sensitive destination, and observe the decision change in the audit log.

You should already have completed [Run the sidecar standalone](../run-the-sidecar/). This guide assumes the Sidecar is running with a `[policy]` directory you can edit.

## What we're building

A small policy bundle for an agent identified as `support-agent`:

- It can `communication.external.send` to known SaaS APIs (`api.openai.com`, `api.slack.com`).
- It must not send to anywhere else, period.
- It cannot `payment.transfer` at all.

This is a realistic shape for a "customer support" agent that drafts replies and posts updates but has no business moving money.

## Step 1: Copy the schema

Cedar requires a schema to validate against. Copy the demo schema into your policy directory:

```bash
cp examples/demo/policies/schema.cedarschema \
   /tmp/firma-standalone/config/policies/
```

The schema declares the allowed entity types (`Firma::Agent`, `Firma::Action`, `Firma::Resource`), all 44 action classes, and the runtime context fields. **You should not edit it** — its job is to keep your policies in sync with the Sidecar's runtime expectations. If you reference a class that isn't in the schema, your bundle won't compile.

## Step 2: Write the base permit

Create `/tmp/firma-standalone/config/policies/support-agent.cedar`:

```cedar
// support-agent: a customer-support drafting/posting agent.
//
// Mission: read tickets, draft replies, post updates to allow-listed
// SaaS APIs. Must not exfiltrate, must not move money.

// Allow OpenAI calls — the agent drafts replies via chat completions.
permit (
    principal == Firma::Agent::"support-agent",
    action == Firma::Action::"model.inference.chat",
    resource
) when {
    resource == Firma::Resource::"api.openai.com/v1/chat/completions"
};

// Allow Slack posts — the agent posts ticket updates to a channel.
permit (
    principal == Firma::Agent::"support-agent",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource == Firma::Resource::"slack.com/api/chat.postMessage"
};
```

Two `permit` rules, each pinned to:

- A specific `principal` — only `support-agent` is granted these privileges.
- A specific `action` — only the action class needed.
- A specific `resource` — exact host+path.

This is least privilege expressed in Cedar. Anything outside these two rules falls through to the default-deny.

## Step 3: Add forbid rules for hard limits

In the same file, append:

```cedar
// Hard rule: this agent never moves money. Forbid wins over any future
// permit, so you can keep this rule even if you broaden permits later.
forbid (
    principal == Firma::Agent::"support-agent",
    action == Firma::Action::"payment.transfer",
    resource
);

// Hard rule: even for permitted classes, never send to known
// exfiltration destinations. Applies to all agents.
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource == Firma::Resource::"paste.rs/" ||
    resource == Firma::Resource::"transfer.sh/"
};
```

The first `forbid` is bound to `support-agent`: the rule is part of the agent's identity. The second is unbound: it covers the whole fleet. Both forbid types are valuable — the first gives you a per-agent "thou shalt not", the second gives you a fleet-wide deny list.

## Step 4: Validate the bundle

Restart the Sidecar (or wait for the next bundle reload). On startup, the Sidecar parses the bundle, validates it against the schema, and refuses to start if anything fails. Look for:

```text
INFO firma_sidecar::startup: bundle compiled (1 file, 4 policies)
```

If the parse fails, you'll see something like:

```text
ERROR firma_sidecar::startup: failed to compile policy bundle
  caused by: unknown action type 'Firma::Action::"communication.exterrnal.send"'
  in support-agent.cedar:9
```

Cedar errors are precise — line number plus offending identifier. Fix and restart.

The fail-loud behavior at startup is deliberate. A malformed bundle never reaches the hot path, and an unwilling-to-start Sidecar is much safer than one that is silently mis-enforcing.

## Step 5: Test with a real call

You need a capability for `support-agent` covering one of the permitted action classes. For now, use a quick dev capability — the full operator workflow is in [Issue capability tokens](../issue-capability-tokens/).

```bash
firma authority generate-key -o /tmp/firma-standalone/firma-authority.key

# Create a minimal authority config
cat > /tmp/firma-standalone/authority.toml <<EOF
listen_addr         = "[::1]:50051"
policy_dir          = "/tmp/firma-standalone/config/policies"
issuance_policy_dir = "/tmp/firma-standalone/issuance"
revocation_file     = "/tmp/firma-standalone/revocations.txt"
key_file            = "/tmp/firma-standalone/firma-authority.key"
max_ttl_seconds     = 3600
bundle_ttl_seconds  = 30
log_level           = "info"
EOF

# Permissive issuance policy for development
mkdir -p /tmp/firma-standalone/issuance
cat > /tmp/firma-standalone/issuance/issuance.cedar <<'EOF'
permit (principal, action, resource);
EOF

# Mint a capability for support-agent
firma authority -c /tmp/firma-standalone/authority.toml issue \
  --agent-id support-agent \
  --session-id session-001 \
  --action communication.external.send \
  --resource-scope '*' \
  --output /tmp/firma-standalone/capability-support.toml
```

Add `[authority]` and `[capability_seed]` sections to `firma_sidecar.toml`:

```toml
[authority]
public_key_path = "/tmp/firma-standalone/firma-authority.pub"

[capability_seed]
paths = ["/tmp/firma-standalone/capability-support.toml"]
```

Restart the Sidecar. Now make a forbidden call:

```bash
curl --proxy http://127.0.0.1:8080 -X POST http://paste.rs/ -d 'leaked'
```

You should see a 403. The audit log will show:

```json
{
  "decision": {
    "outcome": "DENY",
    "reason": "PolicyDenied",
    "matched_policies": ["forbid_at_support-agent.cedar_15"]
  },
  "envelope": {
    "intent": {
      "action_class": "communication.external.send",
      "resource": { "host": "paste.rs", "path": "/", "provider": null }
    }
  }
}
```

The matched-policy id tells you exactly which rule fired. That's the closing of the loop: you wrote a rule, you produced a request that should hit it, and the audit log proves it did.

## Iteration: hot-reload

For development, the Authority watches the `policy_dir` and pushes updated bundles to the Sidecar. Edit your `.cedar` file, save it, and within `bundle_ttl_seconds` (default 30) the Sidecar swaps the in-memory bundle.

In production this stream is what keeps the bundle fresh. In development it gives you a tight write-test loop without restarting the Sidecar.

## Patterns to internalize

A few patterns you'll write over and over:

**Default-deny + scoped permits.** Cedar's default is deny; never write a "permit everything" rule. Add narrow permits for what each agent needs.

**Forbid for hard limits.** Anything that should never happen, regardless of what permits exist now or in the future, deserves a `forbid` rule. Forbids override permits; they survive policy refactoring.

**Resource UIDs are exact strings.** `paste.rs/` and `paste.rs` are different UIDs. The normalizer always produces `host + path`, with `/` for empty paths. If you're not sure, log the resource from a denied call and copy it into your rule.

**Use context for graduated controls.** `risk_score`, `budget_remaining`, `action_count`, `session_duration_s` are all in the runtime context. Gate permits with `when { context.field … }` for "permitted up to a point" rules.

**Action sets for category controls.** `action in [Firma::Action::"filesystem.write", Firma::Action::"filesystem.delete"]` is more readable and harder to drift than two separate rules.

## What's next

- [Issue capability tokens](../issue-capability-tokens/) — full Authority workflow.
- [Inject credentials](../inject-credentials/) — what happens to allowed calls before they leave.
- [Read & verify the audit log](../audit-log/) — verify the signature on every decision.
- [Concepts: Policies](../../concepts/policies/) — for the deeper "why" behind these patterns.
