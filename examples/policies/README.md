# Firma Example Cedar Policies

Cedar policies and schema for the Firma examples. Loaded by `firma-authority`
and streamed to `firma-sidecar` as a policy bundle.

> **NOT FOR PRODUCTION USE.** Starting points and demo policies only.

---

## Files

| File | Purpose |
|------|---------|
| `schema.cedarschema` | Canonical Firma schema — 15 FEP v0.1 action classes, shared by Authority and Sidecar |
| `demo.cedar` | E2E demo policy — permits normal agent traffic, hard-blocks `paste.rs` (exfiltration demo) |
| `communication.cedar` | Reference policy for `communication.internal.send` / `communication.external.send` |
| `filesystem.cedar` | Reference policy for `filesystem.read` / `filesystem.write` / `filesystem.delete` |
| `payment.cedar` | Reference policy for `payment.purchase` / `payment.transfer` |

---

## Schema

`schema.cedarschema` declares three entity types and 15 action classes:

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

---

## Action classes

Full registry: `docs/markdown/firma_action_class_registry.md`.

| Action class | Typical trigger |
|---|---|
| `communication.external.send` | Outbound HTTP to external hosts |
| `communication.internal.send` | Inbound / internal service calls |
| `filesystem.read` | GET on storage endpoints |
| `filesystem.write` | POST / PUT on storage endpoints |
| `filesystem.delete` | DELETE on storage endpoints |
| `payment.purchase` | Browser purchase flows |
| `payment.transfer` | Transfer / wire operations |
| `credential.read` | Reading secrets or tokens |
| `credential.write` | Writing secrets or tokens |
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

Place `.cedar` files alongside `schema.cedarschema`. The authority loads all
`*.cedar` files in the directory alphabetically.

---

## Using with the E2E example

`examples/e2e/authority.toml` points `policy_dir = "examples/policies"`.
The E2E demo uses `demo.cedar` only. Reference policies (`communication.cedar`,
`filesystem.cedar`, `payment.cedar`) are copy-paste starting points — they are
not loaded unless placed in the configured `policy_dir`.
