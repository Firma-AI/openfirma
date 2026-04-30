// Communication capability policies — reference implementation.
//
// Principals: OpenAuthority::Agent::"<your-agent-id>"
// Actions:    communication.internal.send | communication.external.send
// Context:    risk_score (0–100), session_duration_s, action_count
//
// Internal messages are low-risk. External messages are gated on risk score
// to prevent data exfiltration by a compromised or mis-prompted agent.
// HTTP vs HTTPS enforcement is handled at the transport layer (normalizer),
// not in Cedar policies.

// Internal sends are always permitted — low blast radius.
permit (
    principal == OpenAuthority::Agent::"example-agent",
    action == OpenAuthority::Action::"communication.internal.send",
    resource
);

// External sends are permitted when risk is acceptable.
permit (
    principal == OpenAuthority::Agent::"example-agent",
    action == OpenAuthority::Action::"communication.external.send",
    resource
) when {
    context.risk_score < 60
};

// Hard-block external sends at critical risk — prevents exfiltration.
// Applies to any agent; overrides any permit above.
forbid (
    principal,
    action == OpenAuthority::Action::"communication.external.send",
    resource
) when {
    context.risk_score >= 80
};
