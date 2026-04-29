// Demo 1 — path-level enforcement on the same host.
//
// api.internal/usage (filesystem.read) → permitted
// api.internal/billing (credential.read) → no permit → default deny
//
// The OSS demo uses httpbin.org as a public stand-in for api.internal.
// Same agent, same tool, same host. The forbidden path is unreachable —
// enforced at execution time.

permit (
    principal == Firma::Agent::"demo1-agent",
    action == Firma::Action::"filesystem.read",
    resource
);
