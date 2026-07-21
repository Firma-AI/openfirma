// Credential capability policies — reference implementation.
//
// Principals: Firma::Agent::"<your-agent-id>"
// Actions:    credential.read | credential.write
// Context:    risk_score (0–100), session_duration_s, action_count
//
// Credential reads are permitted at acceptable risk. Writes are denied by
// default — secret provisioning / rotation agents require an explicit,
// narrow permit. Keep the write guard tighter than the read guard: a leaked
// write capability lets an agent plant credentials, not just exfiltrate them.

// Allow credential reads at acceptable risk.
permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"credential.read",
    resource
) when {
    context.risk_score < 50
};

// Credential writes are denied by default.
// Uncomment and narrow the guard only for agents that must provision or rotate
// secrets (e.g., a dedicated secrets-rotation agent with a low risk budget).
//
// permit (
//     principal == Firma::Agent::"agt_01j0000000e008000000000002",
//     action == Firma::Action::"credential.write",
//     resource
// ) when {
//     context.risk_score < 20
// };

// Hard-block both credential actions at elevated risk.
// Fires before any permit — prevents a compromised agent from reading or
// planting credentials once its risk score climbs.
forbid (
    principal,
    action in [
        Firma::Action::"credential.read",
        Firma::Action::"credential.write"
    ],
    resource
) when {
    context.risk_score >= 60
};
