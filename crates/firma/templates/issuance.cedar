// Authority issuance policy — generic agent.
//
// Governs whether the Authority will ISSUE a capability token.
// Runtime enforcement (what the agent may actually do) is handled
// separately by policies/llm-agent.cedar evaluated by the sidecar.
permit (
    principal,
    action,
    resource
);
