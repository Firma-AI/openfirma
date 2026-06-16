# Example Cedar policies

This folder contains the policy files used by the local Firma examples.

The policies are deliberately small. They are meant to show how a human-readable rule becomes a deterministic Sidecar decision, not to be copied into production as-is.

> These policies are for demos and tests only.

## How they are used

`firma-authority` loads the `.cedar` files from this folder, validates them against the Firma schema, and streams the resulting policy bundle to `firma-sidecar`.

The Sidecar uses that bundle when it decides whether a normalized agent action should be allowed or denied.

Cedar is default-deny: if no `permit` rule matches, the request is denied. A matching `forbid` rule wins over any permit.

## Files

| File                  | Purpose                                                                                                            |
| --------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `demo.cedar`          | Demo policy used by the E2E stack. It permits normal agent traffic and blocks the paste-service exfiltration path. |
| `communication.cedar` | Reference rules for internal and external communication actions.                                                   |
| `credential.cedar`    | Reference rules for credential read and write actions.                                                             |
| `filesystem.cedar`    | Reference rules for filesystem-style read, write, and delete actions.                                              |
| `payment.cedar`       | Reference rules for payment actions, including cumulative counter checks.                                          |

The canonical schema lives at `crates/firma-core/firma.cedarschema` and is embedded in the binary. Put a `schema.cedarschema` file beside your policies only when you need to override the embedded schema.

## Entity names

Firma policies use three Cedar entity types:

| Role      | Format                            |
| --------- | --------------------------------- |
| Principal | `Firma::Agent::"<agent_id>"`      |
| Action    | `Firma::Action::"<action_class>"` |
| Resource  | `Firma::Resource::"<resource>"`   |

For example, a request from `example-agent` to send data to `paste.rs` is evaluated as an agent principal, a communication action, and a resource that represents the destination.

## Context

The Sidecar adds request context before policy evaluation. Policy conditions can use fields such as:

| Field                     | Meaning                                   |
| ------------------------- | ----------------------------------------- |
| `session_id`              | The current agent session.                |
| `timestamp_ms`            | The request time.                         |
| `params`                  | Serialized action parameters.             |
| `risk_score`              | A precomputed risk value.                 |
| `budget_remaining`        | Remaining budget for bounded actions.     |
| `action_count`            | The request count within the session.     |
| `transfer_amount`         | Current transfer amount in cents.         |
| `daily_cumulative_amount` | Rolling 24-hour transfer amount in cents. |
| `transfers_last_10m`      | Recent transfer count.                    |
| `same_payee_count_30m`    | Recent transfer count to the same payee.  |
| `session_transfer_count`  | Total transfers in the session.           |

Prefer semantic fields such as `transfer_amount` or `daily_cumulative_amount` over transport details. Policies should describe the action, not the shape of the HTTP request that carried it.

## A minimal rule

```cedar
permit (
    principal == Firma::Agent::"example-agent",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    context.risk_score < 60
};

forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"paste.rs"
);
```

The first rule permits low-risk external communication for one agent. The second rule blocks sends to `paste.rs` for everyone, even if another permit rule would otherwise allow the request.

## Payment-splitting example

`payment.cedar` shows why Firma tracks counters at enforcement time.

A single $12,000 transfer is easy to block when the policy says the daily limit is $10,000. The harder case is six separate $2,000 transfers. Each individual transfer is under the single-transfer limit, but the sequence still exceeds the daily cap.

The policy blocks the sixth transfer with a deterministic counter check:

```cedar
forbid (principal, action == Firma::Action::"payment.transfer", resource)
when { context.daily_cumulative_amount + context.transfer_amount > 1000000 };
```

No model reasoning is needed. The Sidecar supplies the current counters, and Cedar evaluates the rule.

## Test the policies

Run the focused Rust tests:

```bash
cargo test -p firma-sidecar payment_splitting_blocked_at_daily_limit
cargo test -p firma-sidecar payment_single_transfer_ceiling_enforced
cargo test -p firma-sidecar payment_payee_concentration_enforced
```

Run the local E2E stack:

```bash
cd examples/e2e && bash run.sh
```

Or use the Cedar CLI directly:

```bash
cedar authorize   --policies examples/policies/payment.cedar   --schema crates/firma-core/firma.cedarschema   --entities '[]'   --principal 'Firma::Agent::"example-agent"'   --action 'Firma::Action::"payment.transfer"'   --resource 'Firma::Resource::"payments.example.com"'   --context '{
    "session_id":"s1",
    "timestamp_ms":0,
    "params":"{}",
    "risk_score":10,
    "budget_remaining":5000000,
    "session_duration_s":0,
    "action_count":1,
    "raw_transport":"https",
    "transfer_amount":200000,
    "daily_cumulative_amount":1000000,
    "transfers_last_10m":0,
    "same_payee_count_30m":0,
    "session_transfer_count":5
  }'
```

That command should return `DENY`, because the next transfer would exceed the daily limit.
