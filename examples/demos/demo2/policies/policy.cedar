// Demo 2 — runtime enforcement under compromise.
//
// Agent task: review PRs, comment, and create issues. Full GitHub token in environment.
// Permitted: code.review.read, issue.write.
// Everything else — merge, push, secret read, exfiltration — default deny.
// Credentials are injected by the sidecar only after ALLOW; agent never holds them.

permit (
    principal == OpenAuthority::Agent::"demo2-agent",
    action == OpenAuthority::Action::"code.review.read",
    resource
);

permit (
    principal == OpenAuthority::Agent::"demo2-agent",
    action == OpenAuthority::Action::"issue.write",
    resource
);
