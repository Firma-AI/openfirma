# Firma Example Cedar Policies

Cedar policies for the Firma examples. Loaded by `firma-authority`
and streamed to `firma-sidecar` as a policy bundle.

> **NOT FOR PRODUCTION USE.** Starting points and demo policies only.

---

## Files

| File | Purpose |
|------|---------|
| `claude-code-agent.cedar` | Baseline policy for Claude Code / LLM agents |
| `demo.cedar` | E2E demo policy — permits normal agent traffic, hard-blocks `paste.rs` (exfiltration demo) |
| `communication.cedar` | Reference policy for `communication.internal.send` / `communication.external.send` |
| `credential.cedar` | Reference policy for `credential.read` / `credential.write` |
| `filesystem.cedar` | Reference policy for `filesystem.read` / `filesystem.write` / `filesystem.delete` |
| `payment.cedar` | Reference policy for `payment.purchase` / `payment.transfer` with Layer 2 counter constraints |

The canonical schema (`EnforcementContext`, 15 action classes) lives at
`crates/firma-authority/schema.cedarschema` and is embedded in the
`firma-authority` binary. Place a `schema.cedarschema` beside your `.cedar`
files to override it, or set `schema_path` in the authority config.

---

## Schema

`crates/firma-authority/schema.cedarschema` declares three entity types and
15 action classes:

```
namespace Firma {
    entity Agent;
    entity Resource;

    action "<action_class>" appliesTo {
        principal: [Agent],
        resource:  [Resource],
        context:   EnforcementContext
    };
}
```

**Entity UID conventions** (must match what Authority issues and Sidecar enforces):

| Role | Pattern |
|------|---------|
| Principal | `Firma::Agent::"<agent_id>"` |
| Action | `Firma::Action::"<action_class>"` (e.g. `"communication.external.send"`) |
| Resource | `Firma::Resource::"<host>"` |

**Context** (`EnforcementContext`) fields populated per request:

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | String | Enclosing session identity |
| `timestamp_ms` | Long | Unix epoch milliseconds |
| `params` | String | JSON-serialised `intent.params` |
| `risk_score` | Long | Pre-computed risk (0–100; V1 = 0) |
| `budget_remaining` | Long | Ceiling minus consumed; `i64::MAX` when unbounded |
| `session_duration_s` | Long | Seconds since `claims.issued_at` |
| `action_count` | Long | Monotonic per-session counter, 1-based |
| `raw_transport` | String | `"http"` or `"https"`; set by normalizer — use sparingly in policies |
| `transfer_amount` | Long | Current transfer amount in cents; `0` for non-payment actions |
| `daily_cumulative_amount` | Long | Rolling 24-hour committed amount in cents |
| `transfers_last_10m` | Long | Transfer count in the last 10-minute window |
| `same_payee_count_30m` | Long | Transfers to same payee in the last 30 minutes |
| `session_transfer_count` | Long | Total transfers in this session |

The last five fields are **Layer 2 counter fields** populated by the Sidecar's
runtime enforcement context builder. Policies should condition on the semantic
fields (`transfer_amount`, `daily_cumulative_amount`, etc.) rather than
`raw_transport` or `raw_action_ref`.

---

## Action classes

Full registry: `docs/markdown/firma_action_class_registry.md`.

| Action class | Typical trigger |
|---|---|
| `communication.external.send` | Outbound HTTP to external hosts |
| `communication.internal.send` | Inbound / internal service calls |
| `credential.read` | Reading secrets or tokens |
| `credential.write` | Writing secrets or tokens |
| `filesystem.read` | GET on storage endpoints |
| `filesystem.write` | POST / PUT on storage endpoints |
| `filesystem.delete` | DELETE on storage endpoints |
| `payment.purchase` | Browser purchase flows |
| `payment.transfer` | Transfer / wire operations |
| `memory.cross_namespace.read` | Cross-agent memory read |
| `memory.cross_namespace.write` | Cross-agent memory write |
| `system.execute` | Shell / process execution |
| `system.install` | Package installation |
| `browser.purchase` | In-browser purchase action |
| `account.permission.change` | IAM / role modifications |

---

## Writing policies

Cedar evaluation: **forbid beats permit**. No permit = implicit deny.

```cedar
// Permit with context guard
permit (
    principal == Firma::Agent::"my-agent",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    context.risk_score < 60
};

// Hard-block — overrides any permit
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"paste.rs"
);
```

All policies bind to `action_class` and `resource`. Conditions reference
Layer 2 context fields (`risk_score`, `budget_remaining`, `transfer_amount`,
`daily_cumulative_amount`, etc.). Do not reference `raw_transport` or
`raw_action_ref` in policy conditions — those are transport-layer facts.

The authority loads all `*.cedar` files in `policy_dir` alphabetically.

---

## Payment-splitting scenario (Layer 2 counter enforcement)

`payment.cedar` demonstrates how the daily cumulative limit blocks quota
circumvention. An agent attempting 6 × $2,000 transfers against a $10,000
daily cap:

| # | `transfer_amount` | `daily_cumulative_amount` | Cumulative total | Decision |
|---|---|---|---|---|
| 1 | $2,000 | $0 | $2,000 | **PERMIT** |
| 2 | $2,000 | $2,000 | $4,000 | **PERMIT** |
| 3 | $2,000 | $4,000 | $6,000 | **PERMIT** |
| 4 | $2,000 | $6,000 | $8,000 | **PERMIT** |
| 5 | $2,000 | $8,000 | $10,000 | **PERMIT** |
| 6 | $2,000 | $10,000 | $12,000 | **DENY** ← daily limit forbid fires |

Transfer 6 is blocked by the Cedar forbid:

```cedar
forbid (principal, action == Firma::Action::"payment.transfer", resource)
when { context.daily_cumulative_amount + context.transfer_amount > 1000000 };
```

No provenance or LLM reasoning is required — only deterministic Layer 2 counters.

---

## Testing locally

**Rust unit tests** (fastest; tests use inlined policy fixtures):

```bash
cargo test -p firma-sidecar payment_splitting_blocked_at_daily_limit
cargo test -p firma-sidecar payment_single_transfer_ceiling_enforced
cargo test -p firma-sidecar payment_payee_concentration_enforced
```

**E2E stack** (tests against a running Mini Authority + Sidecar):

```bash
cd examples/e2e && bash run.sh
```

**Cedar CLI** (requires `cedar` CLI: `brew install cedar-policy/tap/cedar`):

```bash
cedar authorize \
  --policies examples/policies/payment.cedar \
  --schema  crates/firma-authority/schema.cedarschema \
  --entities '[]' \
  --principal 'Firma::Agent::"example-agent"' \
  --action    'Firma::Action::"payment.transfer"' \
  --resource  'Firma::Resource::"payments.example.com"' \
  --context '{
    "session_id":"s1", "timestamp_ms":0, "params":"{}",
    "risk_score":10, "budget_remaining":5000000,
    "session_duration_s":0, "action_count":1,
    "raw_transport":"https",
    "transfer_amount":200000,
    "daily_cumulative_amount":1000000,
    "transfers_last_10m":0,
    "same_payee_count_30m":0,
    "session_transfer_count":5
  }'
# Expected output: DENY  (daily limit exceeded on transfer 6)
```
