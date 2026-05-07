// Authority issuance policy.
//
// Governs whether the Authority will ISSUE a capability token.
// Enforcement (whether an action is ALLOWED at runtime) is handled
// separately by the sidecar's Cedar policies in examples/demo/policies/.
permit (
    principal,
    action,
    resource
);
