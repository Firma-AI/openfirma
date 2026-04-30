// Hero-demo deny: paste.rs is the data-exfiltration target the
// scripted Python agent prompts the model to exercise. The forbid
// fires regardless of risk score and overrides the base permit.

forbid (
    principal,
    action == Firma::Action::"communication.external.send",
    resource == Firma::Resource::"paste.rs"
);
