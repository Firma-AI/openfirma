# Writing Cedar Policies

## What policies decide

Stage 2 evaluates Cedar policies against the `ExecutionEnvelope`. The policy
receives the principal (agent identity), action (normalized `action_class`),
resource (normalized path string), and a context struct with `risk_score`,
`session_duration_s`, and `action_count`. The result is ALLOW or DENY;
`forbid` always overrides `permit`.

## Cedar in 2 minutes

Cedar uses `permit` and `forbid` statements with principal, action, and
resource. Conditions go in `when { ... }`. Policy files are stateless; the
Authority bundles all `.cedar` files in `policy_dir` and streams them to
Sidecars. No imports, no functions, no side effects.

## A first policy

The `examples/policies/communication.cedar` file demonstrates the three core
patterns:

```cedar
// Internal sends are always permitted — low blast radius.
permit (
    principal == Firma::Agent::"example-agent",
    action == Firma::Action::"communication.internal.send",
    resource
);

// External sends are permitted when risk is acceptable.
permit (
    principal == Firma::Agent::"example-agent",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    context.risk_score < 60
};

// Hard-block external sends at critical risk — prevents exfiltration.
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
) when {
    context.risk_score >= 80
};
```

Each clause does one thing:

1. **Internal send always permitted** — binds the policy to `example-agent`
   and allows `communication.internal.send` unconditionally. Low blast radius
   because internal sends stay within the trust boundary.
2. **External send permitted when `risk_score < 60`** — same agent, but gates
   the outbound call on an acceptable risk level injected into the context by
   the Authority at issuance time.
3. **`forbid` hard-blocks at critical risk** — applies to *any* principal, not
   just `example-agent`. When `risk_score >= 80`, the `forbid` fires and
   overrides any matching `permit` in any loaded file. This prevents data
   exfiltration regardless of which agent is making the call.

## Composing policies

All `.cedar` files in `policy.dir` are merged into a single bundle at startup:

- `forbid` overrides any `permit` in any file.
- There is no ordering dependency between files; the Cedar evaluator treats
  all policies as a flat set.
- The bundle SHA-256 is logged at sidecar startup:
  `policy bundle loaded version=<hash>`.

Split policies by concern — one file per capability domain — to keep each file
reviewable in isolation.

## Testing policies

Run the full test suite with:

```bash
make test
cargo test -p firma-sidecar pipeline::tests
```

Policy fixtures live in `crates/firma-sidecar/src/` test modules alongside the
enforcement code. For interactive validation, use the Cedar CLI:

```bash
cedar authorize --policies policies/ --entities entities.json
```

## Common patterns

### Capability scope check

Use `principal == Firma::Agent::"<id>"` to bind a policy to a specific agent
identity. The `agent_id` in the Cedar principal must match the `agent_id`
embedded in the capability token issued by the Authority.

### Resource prefix matching

Use `resource.host` or check the resource string with Cedar string operations.
Keep it simple — complex matching logic belongs in mapping rules
(`mapping-rules.toml`), not Cedar. Cedar is for authorization decisions, not
routing.

### Time-of-day window

Use `context.session_duration_s` to gate actions based on how long the session
has been active, or combine with an external authorization context if your
Authority injects timestamps into the capability token at issuance.

### Per-agent budget

Use `context.action_count` with a `when` condition to rate-limit total calls
per session:

```cedar
permit (
    principal == Firma::Agent::"budget-agent",
    action == Firma::Action::"http.get",
    resource
) when {
    context.action_count < 100
};
```

## Pitfalls

- Don't put authorization logic in connectors. The connector dispatches allowed
  requests; it does not evaluate policy. Policy evaluation happens in Stage 2
  before the connector is ever invoked.
- Don't use Cedar for transport-level checks such as host matching or TLS
  verification. Those are handled by the interceptor and mapping rules before
  the Cedar evaluation stage.
- `forbid` applies globally across all loaded policy files. A permissive policy
  in one file cannot override a `forbid` in another. Design `forbid` clauses
  carefully — they affect every agent unless scoped with a `principal`
  condition.
