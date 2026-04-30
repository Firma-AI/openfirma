// Filesystem capability policies — copy-paste starting point.
//
// Principals: OpenAuthority::Agent::"<your-agent-id>"
// Actions:    filesystem.read | filesystem.write | filesystem.delete
// Context:    risk_score (0–100), action_count
//
// Read is low-risk and always permitted. Write is gated on risk score.
// Delete is denied by default — add a narrow permit only when required.

// Reads are always permitted.
permit (
    principal == OpenAuthority::Agent::"example-agent",
    action == OpenAuthority::Action::"filesystem.read",
    resource
);

// Writes are permitted at low risk.
permit (
    principal == OpenAuthority::Agent::"example-agent",
    action == OpenAuthority::Action::"filesystem.write",
    resource
) when {
    context.risk_score < 70
};

// Deletes are denied for all agents — too destructive to permit broadly.
// To enable for a specific agent, add a permit rule with narrow conditions
// and remove or tighten this forbid.
forbid (
    principal,
    action == OpenAuthority::Action::"filesystem.delete",
    resource
);
