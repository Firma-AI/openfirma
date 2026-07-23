// Secret interception & redaction — Cedar policies for the self-contained demo.
//
// secret.mediate (evaluated per shimmed-tool launch, via local-exec governance)
// ─────────────────────────────────────────────────────────────────────────────
// A permit here means the broker intercepts stdout, extracts secret values via
// the mock-vault IntegrationSpec configured in firma.toml (shim_specs),
// stores them in the out-of-sandbox secret store, and replaces them with
// firma-secret://demo/<name> placeholders before the agent sees output.
//
// communication.external.send (evaluated per outbound HTTP request)
// ─────────────────────────────────────────────────────────────────
// A permit here allows the Sidecar to forward the HTTP request. When the
// request body contains firma-secret:// placeholders, the Sidecar resolves
// them to real values before forwarding (rehydration). Any real secret values
// in the response are masked back to placeholders before the agent reads them.

permit(
    principal,
    action == Firma::Action::"secret.mediate",
    resource
) when {
    resource has bin && resource.bin == "mock-vault"
};

permit (
    principal,
    action == Firma::Action::"communication.internal.send",
    resource
);
