// Payment capability policies — copy-paste starting point.
//
// Principals: Firma::Agent::"<your-agent-id>"
// Actions:    payment.purchase | payment.transfer
// Context:    risk_score (0–100), budget_remaining (i64), action_count
//
// Evaluation order: forbid beats permit. Add a forbid to hard-block; add a
// permit (with when{} guards) to allow. No permit = implicit deny.

// Allow purchases when budget is available and risk is low.
permit (
    principal == Firma::Agent::"example-agent",
    action == Firma::Action::"payment.purchase",
    resource
) when {
    context.budget_remaining > 0 &&
    context.risk_score < 50
};

// Allow transfers only at lower risk — transfers are higher-stakes than purchases.
permit (
    principal == Firma::Agent::"example-agent",
    action == Firma::Action::"payment.transfer",
    resource
) when {
    context.budget_remaining > 0 &&
    context.risk_score < 30
};

// Hard-block all payment actions for any agent when risk is critical.
// This overrides any permit above — useful for global circuit-breakers.
forbid (
    principal,
    action in [
        Firma::Action::"payment.purchase",
        Firma::Action::"payment.transfer"
    ],
    resource
) when {
    context.risk_score >= 80
};
