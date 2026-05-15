// Baseline Cedar policy for a generic LLM agent — v0.1.
//
// Covers network-level host blocks, package install gating, and semantic
// action class enforcement for classified HTTP traffic.
//
// Filesystem path containment and shell command filtering are enforced at the
// sandbox layer (firma-run / bwrap / seccomp) and are not repeated here.
//
// HITL v0.1: all HITL-candidate actions (payment.*, credential.write,
// account.permission.change) auto-deny. Terminal HITL flow is a planned
// extension.
//
// Resource: Firma::Resource::"<host><path>" (e.g., "api.example.com/v1/endpoint").
// resource.id = host + path; use `like` for prefix/wildcard matching.
//
// Cedar: no permit = DENY (default-deny). forbid beats permit always.
// Load alongside provider-specific files (github.cedar, stripe.cedar) as needed,
// or use this as a self-contained starting point.

// ─── Network: defense-in-depth host blocks ────────────────────────────────────
//
// Primary filtering is at the normalizer: hosts absent from the mapping TOML
// are denied as UNCLASSIFIED_INTENT before Cedar sees them. These Cedar forbids
// add a defense-in-depth layer for deployments that use wildcard mapping rules.
//
// RFC-1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) cannot be
// expressed as CIDR in Cedar. Enforce them at the OS / network layer instead:
//
//   iptables -I OUTPUT -d 10.0.0.0/8 -j DROP
//   iptables -I OUTPUT -d 172.16.0.0/12 -j DROP
//   iptables -I OUTPUT -d 192.168.0.0/16 -j DROP
//
// Or via firma-run bwrap --unshare-net + explicit allow-list.

// Cloud metadata endpoint — highest-priority deny.
// A compromised agent can steal the host IAM token with a single unauthenticated
// GET to 169.254.169.254. Block any action, any principal, any path variant.
forbid (
    principal,
    action,
    resource
) when {
    resource.id like "169.254.169.254*"
};

// ─── Package install ──────────────────────────────────────────────────────────
//
// Permitted unconditionally. The mapping TOML controls which hosts are
// classified as system.install; unrecognised hosts are denied before Cedar.

permit (
    principal,
    action == Firma::Action::"system.install",
    resource
);

// ─── Hard-blocks ──────────────────────────────────────────────────────────────

// Payment actions — v0.1 HITL decision: auto-deny.
// Remove after HITL infrastructure ships.
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

// Credential writes — v0.1 HITL decision: auto-deny.
forbid (
    principal,
    action == Firma::Action::"credential.write",
    resource
);

// Destructive code operations (force-push, branch delete, file delete via API).
forbid (
    principal,
    action == Firma::Action::"code.destructive",
    resource
);

// Cross-namespace memory access.
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

// Outbound HTTP — only hosts classified by the mapping TOML reach Cedar.
// default_protected = true in [sidecar.mapping] ensures unclassified hosts are
// denied before this rule fires.
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
