// Authority issuance policy — e2e demo.
//
// Governs whether the Authority will ISSUE a capability token.
// Enforcement (whether an action is ALLOWED at runtime) is handled
// separately by the sidecar's Cedar policies in examples/policies/.
//
// For the e2e demo: any agent may request any action. The sidecar's
// Cedar forbid on communication.external.send blocks the actual call.
permit (
    principal,
    action,
    resource
);
