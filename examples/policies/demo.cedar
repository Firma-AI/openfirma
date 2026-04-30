// E2E demo Cedar policy — loaded by the Mini Authority and streamed to the Sidecar.
//
// This policy is the Stage 2 Cedar gate. It will take full effect once
// IssueCapability → CapabilityMap population is wired in the Sidecar (task 007).
// Until then, Stage 1 (empty CapabilityMap) enforces: mapped hosts DENY, all
// others PASSTHROUGH (because default_protected = false in sidecar.toml).
//
// Principal: OpenAuthority::Agent::"example-agent"
// Actions:   the 15 canonical OpenAuthority action classes from FEP v0.1 §2.3.5
// Resource:  OpenAuthority::Resource::"<host/path>"

// Allow external communication (weather, LLM calls, email, Supabase).
permit (
    principal == OpenAuthority::Agent::"example-agent",
    action == OpenAuthority::Action::"communication.external.send",
    resource
) when {
    context.risk_score < 80
};

// Allow filesystem reads (Supabase Storage GET).
permit (
    principal == OpenAuthority::Agent::"example-agent",
    action == OpenAuthority::Action::"filesystem.read",
    resource
);

// Allow filesystem writes (Supabase Storage POST/PUT).
permit (
    principal == OpenAuthority::Agent::"example-agent",
    action == OpenAuthority::Action::"filesystem.write",
    resource
) when {
    context.risk_score < 70
};

// Block paste.rs — data exfiltration risk.
// exfiltrate_to_paste tool: POST https://paste.rs → DENY
forbid (
    principal,
    action == OpenAuthority::Action::"communication.external.send",
    resource == OpenAuthority::Resource::"paste.rs"
);
