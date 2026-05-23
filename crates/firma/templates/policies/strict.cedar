// Strict posture — communication only.
//
// Permits: credential.read, communication.external.send, communication.internal.send.
// Everything else is default-deny. Hard forbids remain for defense-in-depth.

// Cloud metadata endpoint.
forbid (
    principal,
    action,
    resource
) when {
    resource.id like "169.254.169.254*"
};

// Payment — auto-deny.
forbid (
    principal,
    action in [
        Firma::Action::"payment.transfer",
        Firma::Action::"payment.purchase",
        Firma::Action::"payment.refund",
        Firma::Action::"payment.payout",
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

// Destructive operations.
forbid (
    principal,
    action == Firma::Action::"code.destructive",
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
    action == Firma::Action::"credential.read",
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
