// Authority issuance policy — demo1.
//
// Governs whether the Authority will ISSUE a capability token.
// Enforcement (whether an action is ALLOWED at runtime) is handled
// separately by the sidecar's Cedar policies in examples/demos/demo1/policies/.
permit (
    principal,
    action,
    resource
);
