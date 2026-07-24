// HTTP-vault secret interception & redaction — Cedar policies for the
// self-contained demo.
//
// secret.mediate (evaluated by the Sidecar itself, on its own HTTP path)
// ─────────────────────────────────────────────────────────────────────
// A permit here means the Sidecar runs the demo-http-vault IntegrationSpec
// configured in firma.toml (secret_providers) over the vault's JSON response
// body, stores the extracted value in the out-of-sandbox broker, and
// replaces it with a firma-secret://demo-http-vault/<name> placeholder
// before the agent sees the response — no firma-run broker round-trip for
// this decision, no shim.
//
// communication.internal.send (evaluated per outbound HTTP request)
// ───────────────────────────────────────────────────────────────
// A permit here allows the Sidecar to forward the request to either the
// vault or the capture server. When a request body contains
// firma-secret:// placeholders (the capture-server call below), the
// Sidecar resolves them to real values before forwarding — the same
// rehydration mechanism used by ../secret-redaction/, exercised here with a
// secret sourced from the HTTP vault instead of a CLI shim.

permit(
    principal,
    action == Firma::Action::"secret.mediate",
    resource
) when {
    resource.id == "demo-http-vault"
};

permit (
    principal,
    action == Firma::Action::"communication.internal.send",
    resource
);
