// Demo 0 — read-only agent policy.
//
// Rule: agent may read, but not write, merge, transfer, or change permissions.
// Only code.review.read and filesystem.read are permitted.
// Everything else: default deny.

permit (
    principal == OpenAuthority::Agent::"demo0-agent",
    action == OpenAuthority::Action::"code.review.read",
    resource
);

permit (
    principal == OpenAuthority::Agent::"demo0-agent",
    action == OpenAuthority::Action::"filesystem.read",
    resource
);
