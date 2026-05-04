// Demo 0 — read-only agent policy.
//
// Rule: agent may read; never write, send, or destroy.
//
// Canonical action class taxonomy in scope for this demo (same vocabulary
// used by the normalizer regardless of which provider the call targets):
//
//   code.review.read              GitHub PR read           → ALLOW
//   filesystem.read               Internal service read    → ALLOW
//   communication.external.send   Gmail send               → DENY (default)
//   account.permission.change     Internal service delete  → DENY (default)
//
// Only the two permits below are evaluated; everything else falls through to
// default deny. One policy, one taxonomy, one enforcement point.

permit (
    principal == Firma::Agent::"demo0-agent",
    action == Firma::Action::"code.review.read",
    resource
);

permit (
    principal == Firma::Agent::"demo0-agent",
    action == Firma::Action::"filesystem.read",
    resource
);
