// Demo 1 — path-level enforcement on the same host.
//
// /get (filesystem.read)    → permitted
// /anything/billing (data.query) → no permit → default deny
//
// Both paths hit httpbin.org. Same agent, same tool, same host.
// The forbidden path is unreachable — enforced at execution time.

permit (
    principal == Firma::Agent::"demo1-agent",
    action == Firma::Action::"filesystem.read",
    resource
);
