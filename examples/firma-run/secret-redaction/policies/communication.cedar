// Secret interception & redaction — Cedar policies for the self-contained demo.
//
// mock-vault's stdout is intercepted unconditionally: it's listed in
// firma.toml's `secret_providers`, and being configured there is itself the
// authorization — no Cedar policy gates it. The broker extracts secret
// values via the mock-vault IntegrationSpec, stores them in the
// out-of-sandbox secret store, and replaces them with
// firma-secret://demo/<name> placeholders before the agent sees output.
//
// communication.internal.send (evaluated per outbound HTTP request)
// ──────────────────────────────────────────────────────────────────
// A permit here allows the Sidecar to forward the HTTP request. When the
// request body contains firma-secret:// placeholders, the Sidecar resolves
// them to real values before forwarding (rehydration). Any real secret values
// in the response are masked back to placeholders before the agent reads them.

permit (
    principal,
    action == Firma::Action::"communication.internal.send",
    resource
);
