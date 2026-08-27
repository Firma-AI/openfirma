---
title: Issue capability tokens
description: Stand up a local Authority, mint a capability for an agent, and seed it into the Sidecar.
---

A capability token is what an agent needs to clear [Stage 1](../../concepts/pipeline/) of the enforcement pipeline. This guide walks you through running an Authority, minting a capability with the right scope, and getting it loaded into a Sidecar.

> **Note: this is the legacy operator path.** The primary way capabilities are
> issued today is automatic: `firma run` mints a per-session capability live via
> the Authority's `IssueCapability` gRPC call and writes it to
> `$XDG_RUNTIME_DIR/firma/capabilities/<sandbox_id>.toml`; the sidecar picks it
> up without any operator intervention. The manual `firma authority issue` +
> `[capability_seed]` workflow documented in this guide is kept working but is
> **deprecated** — use it only when you need to pre-provision a fixed, long-lived
> session outside of `firma run` (for example, a daemon or a CI agent with a
> known identity and scope that does not use the autostart flow).

For automatic issuance, `firma run` reads the registered UUID from
`[sidecar.authority].agent_id` and uses it for both the initial request and
every refresh. It never substitutes `[run].profile`. Authority denials with
`AGENT_NOT_REGISTERED` or `AGENT_PROFILE_MISMATCH` are reported as dedicated
errors while preserving the Authority's message.

By the end you will have:

- A running Authority with its own signing keypair and issuance policy.
- A signed PASETO v4 capability for an agent of your choosing.
- A Sidecar that recognizes the capability and uses it to validate Stage 1.

You should already have completed [Run the sidecar standalone](../run-the-sidecar/). This guide adds the Authority piece.

## When to issue capabilities at the CLI vs over gRPC

The reference Authority supports both:

- **CLI issuance** (`firma authority issue …`) writes a TOML "seed" file the Sidecar reads at startup. Right for fixed, long-lived sessions — a daemon, a CI agent, anything where the agent identity and scope are known at deploy time.
- **gRPC issuance** (the `IssueCapability` RPC) lets a controlled component request a capability dynamically. Right for orchestrators that spin up sessions on demand — a SaaS where each user gets their own short-lived session.

This guide covers the CLI path because it's the simpler starting point. The gRPC path uses the same underlying flow.

## Step 1: Generate the Authority signing key

The Authority signs every capability with an Ed25519 keypair. Generate one:

```bash
firma authority generate-key -o /tmp/firma-standalone/firma-authority.key
```

This writes two files:

- `firma-authority.key` — the **private** key. Keep it readable only by the Authority process.
- `firma-authority.pub` — the **public** key. The Sidecar holds a copy and uses it to verify signatures.

These keys are the trust root for capabilities. If the private key leaks, an attacker can mint capabilities your Sidecars will accept. Treat it like any signing key: file mode 600, never in a repo, rotated on a schedule.

## Step 2: Write the issuance policy

The Authority runs a separate Cedar bundle when deciding whether to mint a capability — the **issuance policy**. It answers "_should we ever mint this kind of capability for this agent?_", separate from the runtime policy that decides "_should we allow this specific call right now?_".

For development, a permissive issuance policy is fine:

```bash
mkdir -p /tmp/firma-standalone/issuance
cat > /tmp/firma-standalone/issuance/issuance.cedar <<'EOF'
// Development issuance policy: mint anything any agent asks for.
// Replace with mission-bounded rules in production.
permit (principal, action, resource);
EOF
```

For production, you'd write rules like:

```cedar
// Only mint capabilities for agents we know about.
permit (
    principal in [
        Firma::Agent::"agt_01j0000000e008000000000001",
        Firma::Agent::"agt_01j0000000e008000000000002"
    ],
    action,
    resource
);

// support-agent is never minted a payment capability.
forbid (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"payment.transfer",
    resource
);
```

## Step 3: Write the Authority config

Every subcommand reads one shared, sectioned `firma.toml`. Add an
`[authority]` section to `/tmp/firma-standalone/config/firma.toml`
(alongside the `[sidecar.*]` tables from
[Run the sidecar standalone](../run-the-sidecar/)):

```toml
[authority]
listen_addr = "[::1]:50051"
policy_dir = "/tmp/firma-standalone/config/policies"
issuance_policy_dir = "/tmp/firma-standalone/issuance"
revocation_file = "/tmp/firma-standalone/revocations.txt"
key_file = "/tmp/firma-standalone/firma-authority.key"
max_ttl_seconds = 3600
bundle_ttl_seconds = 30
```

Notable fields:

- `policy_dir` — the **runtime** Cedar bundle the Authority streams to Sidecars. Same directory the Sidecar would have read directly; using the Authority makes hot-reload work.
- `issuance_policy_dir` — the issuance bundle from Step 2.
- `revocation_file` — append-only file. Each line is a `token_id` to revoke. The Authority broadcasts revocations to connected Sidecars over gRPC.
- `max_ttl_seconds` — clamps `--ttl-seconds` requests. Even if a CLI invocation asks for a year, the Authority issues at most this much.
- `bundle_ttl_seconds` — freshness deadline advertised in streamed policy bundles. The Authority periodically refreshes connected Sidecars; protected requests fail closed with `PolicyBundleStale` if the advertised deadline expires.

Touch the revocations file so the Authority finds it:

```bash
touch /tmp/firma-standalone/revocations.txt
```

## Step 4: Start the Authority

In a dedicated terminal:

```bash
firma authority -c /tmp/firma-standalone/config/firma.toml
```

Expected output:

```text
INFO firma_authority::startup: loaded issuance bundle (1 file)
INFO firma_authority::startup: loaded runtime bundle (1 file)
INFO firma_authority::startup: gRPC listening on [::1]:50051
INFO firma_authority: authority ready
```

Leave it running. The next steps are CLI commands that don't need it (CLI issuance is offline; the Authority binary mints from your config), but the Sidecar in Step 7 will connect to it for policy and revocation streams.

The Authority **schema-validates the runtime bundle at load** against the canonical Firma Cedar schema, strictly. A bundle that fails to parse, or that validates but references something the schema does not declare (an unknown action class, a type mismatch), is a fail-closed startup error — the Authority refuses to come up rather than stream an invalid bundle:

```text
ERROR firma_authority::startup: runtime bundle failed schema validation
  caused by: unrecognized action `Firma::Action::"payment.tranfer"` in default.cedar:12
```

The same check runs on **hot-reload**. When you edit a `.cedar` file in `policy_dir`, the Authority re-validates before swapping the bundle. An invalid edit is rejected and logged; the Authority keeps streaming the previously-loaded valid bundle, so a typo in an editor never takes your Sidecars offline. Fix the file and save again to pick it up.

To catch these errors before they reach the Authority, run `firma policy validate <file.cedar>` as a pre-commit or CI gate — it uses the same embedded schema and exits non-zero on any schema error. See [Test policies offline](../test-policies-offline/).

## Step 5: Mint a capability

The CLI subcommand:

```bash
firma authority -c /tmp/firma-standalone/config/firma.toml issue \
  --agent-id agt_01j0000000e008000000000001 \
  --session-id session-001 \
  --action communication.external.send \
  --resource-scope '*' \
  --ttl-seconds 3600 \
  --output /tmp/firma-standalone/capability-support.toml
```

What just happened:

1. The Authority CLI loaded the issuance bundle.
2. It evaluated `(principal=support-agent, action=communication.external.send, resource=*)` against the bundle.
3. The request passed (we wrote a permissive issuance policy in Step 2).
4. It assembled a `CapabilityClaims` with these fields, signed it as a PASETO v4 token using `firma-authority.key`, and wrote both the raw token and the parsed claims to the output file.

Inspect the result:

```bash
cat /tmp/firma-standalone/capability-support.toml
```

You'll see the structure described in [Capabilities](../../concepts/capabilities/): `raw_token`, `token_id`, `agent_id`, `session_id`, `action_set`, `resource_scope`, `issued_at`, `expiry`, `context_hash`. The `raw_token` is the wire-format PASETO; everything else is a parsed mirror for convenience.

The `token_id` is a canonical `ctok` TypeID, for example
`ctok_01j0000000e008000000000001`. Raw UUID capability IDs are not accepted.

Note: `--action` can be repeated. `--resource-scope '*'` is the loosest scope — match anything. In production you would tighten this to e.g. `'api.openai.com*'`.

Do not hand-edit the claim fields in this file. The Sidecar treats `raw_token` as authoritative and checks that the TOML mirror matches the signed claims at startup. If you need a different `action_set`, `resource_scope`, `session_id`, TTL, or agent id, issue a new capability with the Authority instead of editing the seed.

## Step 6: Wire the capability into the Sidecar

Edit the `[sidecar.*]` tables in `firma.toml` to add:

```toml
[sidecar.authority]
url = "http://[::1]:50051"
public_key_path = "/tmp/firma-standalone/firma-authority.pub"

[sidecar.capability_seed]
paths = ["/tmp/firma-standalone/capability-support.toml"]
```

`[sidecar.authority].public_key_path` is what Stage 1 verifies signatures against. `[sidecar.capability_seed].paths` is a list — you can ship multiple capabilities, one per session, and the Sidecar will populate its `CapabilityMap` from all of them.

Restart the Sidecar. In its startup log:

```text
INFO firma_sidecar::startup::capability: seeded 1 capability (agent=support-agent session=session-001)
INFO firma_sidecar::startup::authority: connected to authority [::1]:50051
INFO firma_sidecar: sidecar ready
```

During startup the Sidecar reads each configured seed, verifies the `raw_token` with `[sidecar.authority].public_key_path`, and compares the signed claims with the TOML fields. This is fail-closed: a seed that cannot be verified, was signed by a different Authority key, is expired, or has mirrored claims that differ from the signed token prevents the Sidecar from becoming ready.

## Step 7: See Stage 1 in action

Make a permitted call (assuming the runtime policy from [Write your first Cedar policy](../write-a-cedar-policy/) is in place):

```bash
curl --proxy http://127.0.0.1:8080 \
  -X POST https://api.openai.com/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4","messages":[]}'
```

The audit event for this call will include the capability identity at the top level:

```json
{
  "token_id": "ctok_01j0000000e008000000000001",
  "agent_id": "agt_01j0000000e008000000000001",
  "session_id": "session-001",
  "action": "communication.external.send",
  "resource": "api.openai.com/v1/chat/completions",
  "decision": 1,
  "deny_reason": ""
}
```

If you delete the capability seed file and restart, the same call returns a 403 with `deny_reason` containing `"token invalid"`. That's Stage 1 doing its job.

## Revocation

To kill a specific capability immediately:

```bash
firma authority -c /tmp/firma-standalone/config/firma.toml revocations add ctok_01j0000000e008000000000001
```

The Authority appends the `token_id` to `revocations.txt` and broadcasts it on its gRPC stream. Connected Sidecars update their bloom filter + LRU cache within seconds. The next attempt by that capability gets `TokenRevoked`.

After upgrading from a release that issued raw UUID capability IDs, remove old
capability seed files and raw UUID revocation records, then mint replacement
capabilities. The cutover is strict: old capability tokens and state are not
read as aliases.

For housekeeping, clean expired entries periodically:

```bash
firma authority -c /tmp/firma-standalone/config/firma.toml revocations compact
```

## Common gotchas

**`TokenInvalid` for matching agent.** The map is keyed by `(session_id, action_class, resource)`. If the request's normalized resource doesn't fall inside `resource_scope`, the lookup misses. Loosen `--resource-scope` or add multiple capabilities for different scopes.

**`TokenExpired` right after issuance.** Clock drift between Authority and Sidecar. Set `[sidecar.capability_validation].clock_skew_tolerance_seconds` (default 0) higher if your clocks aren't tight.

**Authority refuses to mint.** Issuance policy denied the request. Check the Authority's stderr for the matched policy id. Loosen issuance policy or pick a different action class.

**Sidecar fails startup with `raw_token claims do not match seed claims`.** The seed file's TOML mirror no longer matches the signed PASETO payload. Common causes are editing `action_set` or `resource_scope` by hand, copying a `raw_token` from one seed into another, or deploying a stale seed next to a regenerated one. Treat the seed as immutable: re-run `firma authority ... issue` with the desired flags, deploy the complete new TOML file, and make sure `[sidecar.authority].public_key_path` points at the public key for the private key that signed it.

**Sidecar fails startup with `raw_token failed PASETO verification`.** The token cannot be parsed or its signature does not verify with the configured Authority public key. Check that `public_key_path` is the `.pub` file from the same keypair used by the Authority config's `key_file`, and replace any truncated or manually copied seed file with a freshly issued one.

**`PolicyBundleStale` denials.** The Sidecar did not receive a refresh before the Authority-advertised bundle TTL expired. Check its connection to the Authority and the Authority's health. The Sidecar retries streams with backoff, but it cannot receive updates while disconnected.

## What's next

- [Wrap an agent with `firma run`](../firma-run/) — same model, with a real sandbox boundary.
- [Inject credentials](../inject-credentials/) — what happens to capabilities-allowed calls.
- [Concepts: Capabilities](../../concepts/capabilities/) — for the design rationale.
