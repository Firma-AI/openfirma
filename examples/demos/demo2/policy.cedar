// Demo 2 — runtime enforcement under compromise.
//
// Agent task: review PRs and comment. Full GitHub token in environment.
// Permitted: code.review.read, issue.write.
// Everything else — merge, push, secret read, exfiltration — default deny.
// Credentials are injected by the sidecar only after ALLOW; agent never holds them.

permit (
    principal == Firma::Agent::"demo2-agent",
    action == Firma::Action::"code.review.read",
    resource
);

permit (
    principal == Firma::Agent::"demo2-agent",
    action == Firma::Action::"issue.write",
    resource
);
