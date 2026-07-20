// Demo 2 — runtime enforcement under compromise.
//
// Agent task: review PRs, comment, and create issues. Full GitHub token in environment.
// Permitted: code.review.read, issue.write.
// Everything else — merge, push, secret read, exfiltration — default deny.
// Credentials are injected by the sidecar only after ALLOW; agent never holds them.

permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"code.review.read",
    resource
);

permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"issue.write",
    resource
);
