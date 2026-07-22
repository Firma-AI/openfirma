// Payment capability policies — reference implementation.
//
// Principals: Firma::Agent::"<your-agent-id>"
// Actions:    payment.purchase | payment.transfer
// Context (all monetary amounts in cents):
//   risk_score              — pre-computed risk (0–100)
//   transfer_amount         — amount of the current transfer
//   daily_cumulative_amount — rolling 24-hour committed amount
//   transfers_last_10m      — transfer count in the last 10-minute window
//   same_payee_count_30m    — transfers to the same payee in last 30 minutes
//   session_transfer_count  — total transfers this session
//
// Limits applied here:
//   Daily cap:               $10,000  (1_000_000 cents)
//   Single-transfer ceiling:  $5,000  (  500_000 cents)
//   Payee concentration:     < 3 transfers to same payee per 30-minute window
//   Velocity cap:            < 10 transfers in any 10-minute window

// Allow purchases when risk is acceptable.
permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"payment.purchase",
    resource
) when {
    context.risk_score < 50
};

// Allow transfers subject to all Layer 2 counter constraints.
// Each forbid below also fires independently — forbid beats permit.
permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"payment.transfer",
    resource
) when {
    context.risk_score < 30 &&
    context.transfer_amount <= 500000 &&
    context.daily_cumulative_amount + context.transfer_amount <= 1000000 &&
    context.same_payee_count_30m < 3
};

// Circuit-breaker: daily cumulative limit. Blocks quota circumvention via splitting.
// Example: after 5 × $2,000 = $10,000 committed, a 6th $2,000 attempt fails here.
forbid (
    principal,
    action == Firma::Action::"payment.transfer",
    resource
) when {
    context.daily_cumulative_amount + context.transfer_amount > 1000000
};

// Circuit-breaker: single-transfer ceiling — no single transfer may exceed $5,000.
forbid (
    principal,
    action == Firma::Action::"payment.transfer",
    resource
) when {
    context.transfer_amount > 500000
};

// Circuit-breaker: payee concentration — repeated small transfers to one payee.
forbid (
    principal,
    action == Firma::Action::"payment.transfer",
    resource
) when {
    context.same_payee_count_30m >= 3
};

// Circuit-breaker: transfer velocity in a 10-minute window.
forbid (
    principal,
    action == Firma::Action::"payment.transfer",
    resource
) when {
    context.transfers_last_10m >= 10
};

// Hard-block all payment actions at critical risk.
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
