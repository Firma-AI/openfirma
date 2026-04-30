// CI deny: the deterministic Rust client posts to
// `127.0.0.1:9100/deny`. The forbid fires Stage 2 PolicyDenied so the
// fixture never receives the request — exactly the shape the
// `firma-demo-fixture-client` asserts.

forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"127.0.0.1:9100/deny"
);
