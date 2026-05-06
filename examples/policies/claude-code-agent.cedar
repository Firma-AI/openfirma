// Baseline Cedar policy for Claude Code / generic LLM agent — v0.1.
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
// Principal:  Firma::Agent::"claude-code-agent" — substitute your agent ID.
// Resource:   Firma::Resource::"<host><path>" (e.g., "api.anthropic.com/v1/messages").
//
// Cedar: no permit = DENY (default-deny). forbid beats permit always.
// Load alongside provider-specific files (github.cedar, stripe.cedar) as needed,
// or use this as a self-contained starting point.

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
// resource_display() = host + path, so enumerate the common forms.
forbid (
    principal,
    action,
    resource == Firma::Resource::"169.254.169.254"
);

forbid (
    principal,
    action,
    resource == Firma::Resource::"169.254.169.254/"
);

forbid (
    principal,
    action,
    resource == Firma::Resource::"169.254.169.254/latest/meta-data/"
);

forbid (
    principal,
    action,
    resource == Firma::Resource::"169.254.169.254/latest/meta-data/iam/security-credentials/"
);

forbid (
    principal,
    action,
    resource == Firma::Resource::"169.254.169.254/computeMetadata/v1/"
);

// ─── LAYER 2: Command execution ───────────────────────────────────────────────
//
// Cedar gates execution by risk score only. Command-pattern blocking
// (rm -rf, curl|sh, sudo, crontab, etc.) is enforced at the seccomp-unotify
// / ESF layer (FIR-79) — those patterns are not expressible in Cedar without
// structured params inspection.

// Execution permitted at low risk. High-risk execution is denied by the
// global circuit-breaker at the bottom of this file.
permit (
    principal == Firma::Agent::"claude-code-agent",
    action == Firma::Action::"system.execute",
    resource
) when {
    context.risk_score < 30
};

// system.install is blocked by default: persistent side-effect, supply-chain risk.
// Uncomment only for an agent explicitly tasked with managing dependencies.
//
// permit (
//     principal == Firma::Agent::"claude-code-agent",
//     action == Firma::Action::"system.install",
//     resource
// ) when {
//     context.risk_score < 20
// };

// ─── LAYER 3: Filesystem ──────────────────────────────────────────────────────
//
// Cedar gates by action class only. Path-level isolation (workspace-only access,
// blocking ~/.ssh, ~/.aws, ~/.config/gcloud, .env files, /etc/shadow, etc.) is
// enforced by firma-run via bwrap bind mounts. Do not rely on Cedar alone for
// filesystem path containment.

permit (
    principal == Firma::Agent::"claude-code-agent",
    action == Firma::Action::"filesystem.read",
    resource
);

permit (
    principal == Firma::Agent::"claude-code-agent",
    action == Firma::Action::"filesystem.write",
    resource
) when {
    context.risk_score < 70
};

// Deletes are blocked: destructive and irreversible without path-level verification.
// Enable only if firma-run sandbox already confines the delete to the workspace.
forbid (
    principal,
    action == Firma::Action::"filesystem.delete",
    resource
);

// ─── LAYER 4: Semantic — action class circuit-breakers ───────────────────────

// Hard-block: payment actions.
// v0.1 HITL decision: auto-deny. A coding agent must not initiate financial
// transactions. Remove these forbids only after HITL infrastructure ships.
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
// v0.1 HITL decision: auto-deny. An agent planting or rotating credentials
// is a high-severity operation requiring explicit operator authorization.
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
// A coding agent has no business reading or writing other agents' memory.
forbid (
    principal,
    action in [
        Firma::Action::"memory.cross_namespace.read",
        Firma::Action::"memory.cross_namespace.write"
    ],
    resource
);

// Credential reads — permitted at low risk.
permit (
    principal == Firma::Agent::"claude-code-agent",
    action == Firma::Action::"credential.read",
    resource
) when {
    context.risk_score < 50
};

// Code read operations — issue read, notifications, security alerts.
// Lower blast radius; gated at moderate risk.
permit (
    principal == Firma::Agent::"claude-code-agent",
    action in [
        Firma::Action::"code.read",
        Firma::Action::"code.review.read",
        Firma::Action::"issue.read",
        Firma::Action::"security.alert.read",
        Firma::Action::"notification.manage"
    ],
    resource
) when {
    context.risk_score < 60
};

// Code write operations — pull request creation, review submission, issue write.
// Tighter risk gate than reads.
permit (
    principal == Firma::Agent::"claude-code-agent",
    action in [
        Firma::Action::"code.write",
        Firma::Action::"code.review.submit",
        Firma::Action::"issue.write"
    ],
    resource
) when {
    context.risk_score < 40
};

// Merge — permanent change to the repository record; requires lowest risk.
permit (
    principal == Firma::Agent::"claude-code-agent",
    action == Firma::Action::"code.merge",
    resource
) when {
    context.risk_score < 20
};

// External communication — permits outbound to hosts classified by the mapping
// TOML (LLM API, package registries). default_protected = true in sidecar.toml
// ensures only explicitly mapped hosts reach Cedar evaluation.
permit (
    principal == Firma::Agent::"claude-code-agent",
    action == Firma::Action::"communication.external.send",
    resource
) when {
    context.risk_score < 60
};

// Internal communication — low blast radius, always permitted.
permit (
    principal == Firma::Agent::"claude-code-agent",
    action == Firma::Action::"communication.internal.send",
    resource
);

// ─── Global circuit-breaker ───────────────────────────────────────────────────

// Hard-block all actions at critical risk. Fires before any permit above and
// cannot be overridden by a permit — Cedar forbid beats permit always.
forbid (
    principal,
    action,
    resource
) when {
    context.risk_score >= 80
};
