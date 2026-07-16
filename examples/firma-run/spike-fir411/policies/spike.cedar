// FIR-411 spike policy bundle.
//
// approved-api is reachable (communication.external.send permitted).
// exfil-sink is never classified in the mapping, so it fails closed to DENY
// before any policy runs — no rule here needs to name it.
//
// Credential reads are denied outright: the spike has no agent that should be
// reading host secrets, so demo 3's ~/.aws/credentials attempt has no permit
// to fall back on even if the file were reachable.

permit (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
);

forbid (
    principal,
    action == Firma::Action::"credential.read",
    resource
);
