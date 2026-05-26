// Dev posture with code.destructive allowed (local-exec watch mode).
//
// Same as dev but code.destructive is permitted so the agent can perform
// file deletion via API (rm / rmdir / unlink equivalent via code path).
// Use only in sandboxed environments where the filesystem mount is scoped.

// Cloud metadata endpoint (169.254.169.254) must be blocked at the network
// layer (iptables / bwrap --unshare-net). The Firma schema has no resource
// host attribute, so the block cannot be expressed in Cedar.

// Payment — auto-deny.
forbid (
    principal,
    action in [
        Firma::Action::"payment.transfer",
        Firma::Action::"payment.purchase",
        Firma::Action::"browser.purchase"
    ],
    resource
);

// IAM and repo admin — never automatic.
forbid (
    principal,
    action in [
        Firma::Action::"account.permission.change",
        Firma::Action::"repo.admin"
    ],
    resource
);

// Credential writes — auto-deny.
forbid (
    principal,
    action == Firma::Action::"credential.write",
    resource
);

// Cross-namespace memory.
forbid (
    principal,
    action in [
        Firma::Action::"memory.cross_namespace.read",
        Firma::Action::"memory.cross_namespace.write"
    ],
    resource
);

// ─── Permits ──────────────────────────────────────────────────────────────────

permit (
    principal,
    action == Firma::Action::"system.install",
    resource
);

permit (
    principal,
    action == Firma::Action::"credential.read",
    resource
);

permit (
    principal,
    action in [
        Firma::Action::"code.read",
        Firma::Action::"code.review.read",
        Firma::Action::"issue.read",
        Firma::Action::"security.alert.read",
        Firma::Action::"notification.manage"
    ],
    resource
);

permit (
    principal,
    action in [
        Firma::Action::"code.write",
        Firma::Action::"code.review.submit",
        Firma::Action::"issue.write"
    ],
    resource
);

permit (
    principal,
    action == Firma::Action::"code.merge",
    resource
);

// Destructive allowed — scoped by sandbox layer (bwrap mount limits blast radius).
permit (
    principal,
    action == Firma::Action::"code.destructive",
    resource
);

permit (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
);

permit (
    principal,
    action == Firma::Action::"communication.internal.send",
    resource
);
