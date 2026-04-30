// Hero-demo deny: paste.rs is the data-exfiltration target the
// scripted Python agent prompts the model to exercise. The forbid
// fires regardless of risk score and overrides the base permit.
//
// Cedar entity UIDs compare by exact string equality, and the
// sidecar's `ExecutionIntent::resource_display()` builds the UID as
// `host + path` — so the agent's `POST https://paste.rs` (which
// httpx normalizes to path `/`) lands as resource `paste.rs/`, not
// `paste.rs`. Enumerate the variants the demo and the LLM can
// realistically produce.

forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"paste.rs/"
);

forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"paste.rs"
);
