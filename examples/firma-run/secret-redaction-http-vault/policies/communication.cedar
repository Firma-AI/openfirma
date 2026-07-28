// HTTP-vault secret interception & redaction — Cedar policies for the
// self-contained demo.
//
// The Sidecar intercepts the vault's response unconditionally: the
// demo-http-vault entry is listed in firma.toml's `secret_providers`, and
// being configured there is itself the authorization — no Cedar policy
// gates it. The Sidecar runs the demo-http-vault IntegrationSpec over the
// vault's JSON response body, stores the extracted value in the
// out-of-sandbox broker, and replaces it with a
// firma-secret://demo-http-vault/<name> placeholder before the agent sees
// the response — no firma-run broker round-trip for this, no shim.
//
// communication.internal.send (evaluated per outbound HTTP request)
// ───────────────────────────────────────────────────────────────
// A permit here allows the Sidecar to forward the request to either the
// vault or the capture server. When a request body contains
// firma-secret:// placeholders (the capture-server call below), the
// Sidecar resolves them to real values before forwarding — the same
// rehydration mechanism used by ../secret-redaction/, exercised here with a
// secret sourced from the HTTP vault instead of a CLI shim.

permit (
    principal,
    action == Firma::Action::"communication.internal.send",
    resource
);
