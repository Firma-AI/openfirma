// E2E demo Cedar policy — loaded by the Mini Authority and streamed to the Sidecar.
//
// This policy is the Stage 2 Cedar gate. It will take full effect once
// IssueCapability → CapabilityMap population is wired in the Sidecar (task 007).
// Until then, Stage 1 (empty CapabilityMap) enforces: mapped hosts DENY, all
// others PASSTHROUGH (because default_protected = false in sidecar.toml).
//
// Principal: Firma::Agent::"example-agent"
// Actions:   the 15 canonical Firma action classes from FEP v0.1 §2.3.5
// Resource:  Firma::Resource::"<host/path>"

// Allow external communication (weather, LLM calls, email, Supabase).
permit (
    principal == Firma::Agent::"example-agent",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    context.risk_score < 80
};

// Allow filesystem reads (Supabase Storage GET).
permit (
    principal == Firma::Agent::"example-agent",
    action == Firma::Action::"filesystem.read",
    resource
);

// Allow filesystem writes (Supabase Storage POST/PUT).
permit (
    principal == Firma::Agent::"example-agent",
    action == Firma::Action::"filesystem.write",
    resource
) when {
    context.risk_score < 70
};

// Block ipinfo.io/json — exposes the agent's egress IP, data-leak risk.
// get_ip_info tool: GET https://ipinfo.io/json → DENY
forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"ipinfo.io/json"
);
