// Demo 1b — same host, same service, two paths, two decisions.
//
// Canonical action class taxonomy in scope for this demo (the same vocabulary
// the normalizer assigns regardless of provider or transport):
//
//   filesystem.read   GET api.internal/usage     → ALLOW (permit below)
//   credential.read   GET api.internal/billing   → DENY  (default deny)
//
// Cedar evaluates the action class, not the host or the path. Two endpoints
// on the same host map to two different action classes because they describe
// two different things the agent is doing — and the policy expresses what
// the agent is allowed to do, not where the packet may go.

permit (
    principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"filesystem.read",
    resource
);
