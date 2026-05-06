// Baseline Cedar policy for a generic LLM agent — v0.1.
//
// Covers enforcement layers 1 (network) and 4 (semantic action classes).
// Layers 2 (command) and 3 (filesystem path) are enforced at the sandbox level
// (firma-run / seccomp); the rules here apply to classified HTTP traffic that
// reaches Cedar evaluation.
//
// HITL v0.1: all HITL-candidate actions (payment.*, credential.write,
// account.permission.change) auto-deny. Terminal HITL flow is a planned
// extension.
//
// Resource: Firma::Resource::"<host><path>" (e.g., "api.example.com/v1/endpoint").
//
// Cedar: no permit = DENY (default-deny). forbid beats permit always.
// Load alongside provider-specific files (github.cedar, stripe.cedar) as needed,
// or use this as a self-contained starting point.
//
// ─── LAYER 1: Network — defense-in-depth host blocks ─────────────────────────
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
// resource.id = host + path; `like` matches all path suffixes with one rule.
forbid (
    principal,
    action,
    resource
) when {
    resource.id like "169.254.169.254*"
};

// ─── LAYER 2: Command execution ───────────────────────────────────────────────
//
// Cedar gates execution by action class only. Command-pattern blocking
// (rm -rf, curl|sh, sudo, crontab, etc.) is enforced at the seccomp-unotify
// / ESF layer — those patterns are not expressible in Cedar without structured
// params inspection.

// Execution permitted. Dangerous command patterns blocked at sandbox layer.
permit (
    principal,
    action == Firma::Action::"system.execute",
    resource
);

// system.install is blocked by default: persistent side-effect, supply-chain risk.
// Uncomment only for an agent explicitly tasked with managing dependencies.
//
// permit (
//     principal,
//     action == Firma::Action::"system.install",
//     resource
// );

// ─── LAYER 3: Filesystem ──────────────────────────────────────────────────────
//
// Cedar gates by action class only. Path-level isolation (workspace-only access,
// blocking ~/.ssh, ~/.aws, ~/.config/gcloud, .env files, /etc/shadow, etc.) is
// enforced by firma-run via bwrap bind mounts. Do not rely on Cedar alone for
// filesystem path containment.

permit (
    principal,
    action == Firma::Action::"filesystem.read",
    resource
);

permit (
    principal,
    action == Firma::Action::"filesystem.write",
    resource
);

// Deletes are blocked: destructive and irreversible without path-level verification.
// Enable only if firma-run sandbox already confines the delete to the workspace.
forbid (
    principal,
    action == Firma::Action::"filesystem.delete",
    resource
);

// ─── LAYER 4: Semantic — action class circuit-breakers ───────────────────────

// Hard-block: payment actions.
// v0.1 HITL decision: auto-deny. Remove these forbids only after HITL
// infrastructure ships.
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

// Hard-block: IAM and repo admin operations.
// Account permission changes and repo admin actions are never automatic.
forbid (
    principal,
    action in [
        Firma::Action::"account.permission.change",
        Firma::Action::"repo.admin"
    ],
    resource
);

// Hard-block: credential writes.
// v0.1 HITL decision: auto-deny. Requires explicit operator authorization.
forbid (
    principal,
    action == Firma::Action::"credential.write",
    resource
);

// Hard-block: destructive code operations (force-push, branch delete, file delete via API).
forbid (
    principal,
    action == Firma::Action::"code.destructive",
    resource
);

// Hard-block: cross-namespace memory access.
forbid (
    principal,
    action in [
        Firma::Action::"memory.cross_namespace.read",
        Firma::Action::"memory.cross_namespace.write"
    ],
    resource
);

// Credential reads — permitted; writes remain hard-blocked above.
permit (
    principal,
    action == Firma::Action::"credential.read",
    resource
);

// Code read operations — permitted; lower blast radius.
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

// Code write operations — permitted.
permit (
    principal,
    action in [
        Firma::Action::"code.write",
        Firma::Action::"code.review.submit",
        Firma::Action::"issue.write"
    ],
    resource
);

// Merge — permanent change to the repository record.
permit (
    principal,
    action == Firma::Action::"code.merge",
    resource
);

// External communication — permits outbound to hosts classified by the mapping
// TOML. default_protected = true in sidecar.toml ensures only explicitly
// mapped hosts reach Cedar evaluation.
permit (
    principal,
    action == Firma::Action::"communication.external.send",
    resource
);

// Internal communication — low blast radius, always permitted.
permit (
    principal,
    action == Firma::Action::"communication.internal.send",
    resource
);
