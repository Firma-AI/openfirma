// Demo Cedar bundle — base permit gate.
//
// V1 risk_score is always 0 (see `crates/openauthority-authority/schema.cedarschema`),
// so this permit fires for every request that reaches Stage 2. The two
// `forbid` rules in the sibling files override on the DENY routes.

permit (
    principal,
    action == OpenAuthority::Action::"communication.external.send",
    resource
) when {
    context.risk_score < 80
};
