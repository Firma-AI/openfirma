// Communication capability policies — copy-paste starting point.
//
// Principals: Firma::Agent::"<your-agent-id>"
// Actions:    communication.internal.send | communication.external.send
// Context:    risk_score (0–100), session_duration_s, action_count
//
// Internal messages are low-risk. External messages are gated on risk score
// to prevent data exfiltration by a compromised or mis-prompted agent.

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
// Applies to any agent; overrides any permit above.
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
) when {
    context.risk_score >= 80
};

// Block plain-HTTP external sends — HTTPS only.
// HTTP is unencrypted; intercepted traffic could leak credentials or PII.
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
) when {
    context.raw_transport == "http"
};
