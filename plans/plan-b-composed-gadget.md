# Plan B — Loopback guard: allow in-jail listeners, deny the rest

## Context

The loopback egress guard (`crates/firma-run/src/egress_guard.rs`) traps the
sandboxed agent's `connect(2)` and blocks any loopback destination whose port is
not in a hardcoded allow-list (proxy + DNS-stub ports, built in
`routing.rs:511-522`). The block is `EACCES`.

Problem: running the repo's own test suite (or nested `firma`) inside a wrapped
agent spins up loopback TCP servers on ephemeral ports and connects to them as a
client. Those connects hit the guard and fail `EACCES`, even though the target
is a listener the agent itself started **inside its own jail**.

Key facts established:

- The guard runs **only** in structural mode — `start_loopback_guard` is called
  solely from `prepare_structural_runtime` (`routing.rs:451`), i.e. when
  `enforce_network_namespace == true`. Flat/shared-net mode sets
  `_egress_guard: None` (`routing.rs:406`).
- In that mode the agent has a **private network namespace**. A loopback
  `connect` there can only reach a listener inside the same netns; it physically
  cannot reach a host `lo` service. So every loopback destination is inside-jail
  by construction, and the current port-allowlist block is a pure false-positive
  for the agent's own services.

Colleague's rule: _a loopback port listened by something inside the jail should
always be allowed; one listened outside should be denied._ This plan implements
that rule literally by inspecting the agent netns's own listening sockets,
rather than relying only on the netns boundary. It fixes the tests, keeps the
guard active, and stays correct even if the guard is ever wired into a
shared-net mode.

Intended outcome: guard allows a loopback connect when the destination port has
a listener in the connecting process's network namespace (plus the existing
sanctioned proxy/DNS ports); otherwise it blocks and audits as today.

## Approach

All changes are local to `crates/firma-run/src/egress_guard.rs`. No signature
changes ripple out to `routing.rs`; `allow_ports` stays as an explicit
always-allow overlay.

### 1. Add an in-jail listener reader

New `pub(crate)` helper, host-side, reads the connecting pid's netns socket
tables and returns the set of local ports in a listening/bound state:

```rust
fn netns_local_ports(pid: u32) -> io::Result<BTreeSet<u16>>
```

- Read `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` via `fs::read_to_string`
  (mirrors the existing `/proc` read pattern in
  `supervisor.rs:192-205` and `backend/platform.rs:32-49`).
- Per line (skip header): `split_whitespace`; token[1] = `local_address`
  (`HEXIP:HEXPORT`), token[3] = state hex.
  - TCP: keep when state == `0A` (TCP_LISTEN).
  - UDP: keep when state == `07` (bound). UDP is included because the
    sockaddr gives no protocol, so a connect could target an in-jail UDP
    service; not covering it would risk a false block.
- Parse the port with `u16::from_str_radix(port_hex, 16)` — no `hex::decode`,
  no address decoding needed (we match on port only, consistent with the
  existing port-only `classify`).
- Pure string parsing + file reads: **no `unsafe`, no unwrap/expect/panic**.
  Return `io::Result` and let the caller fail closed.

Include focused unit tests parsing sample `/proc/net/tcp` and `tcp6` blobs
(LISTEN vs ESTABLISHED vs UDP-bound), following the existing test style in the
module.

### 2. Wire it into the block path only

In `classify_notification` (`egress_guard.rs:798`), the check runs **only** on
the would-be-block branch, so the extra `/proc` read happens exclusively for a
loopback connect to a non-sanctioned port (the rare path), never for allowed or
external connects:

- Keep the current flow: read sockaddr, `parse_sockaddr`, then `classify`.
- When `classify` returns `Verdict::Block`:
  - Call `netns_local_ports(req.pid)`.
  - On `Ok(ports)` and `ports.contains(&addr.port())` → `NotifOutcome::Allow`
    (in-jail listener; log at debug).
  - Otherwise → `NotifOutcome::Block(Some(addr))` as today (genuine block,
    audited).
  - On `Err(_)` reading `/proc` → **fail closed**: `NotifOutcome::Block` (keeps
    the fail-closed invariant; matches the existing unreadable-sockaddr
    handling).

`classify` stays unchanged (still the pure, unit-tested port matcher);
`SupervisorConfig`, `NotifOutcome`, and the `routing.rs` call site are untouched.

### 3. Audit

No new `RunAuditEvent` variant. Genuine blocks still emit
`RunAuditEvent::LoopbackBlocked` via the existing `AuditSink` path
(`egress_guard.rs:761-782`). An in-jail allow is a `tracing::debug!` only — it is
the expected, safe case and should not spam the signed audit channel.

### Why not the simpler "audit-only in structural mode"

Downgrading the guard to allow-all-loopback whenever `enforce_network_namespace`
also fixes the tests and is defensible (netns already isolates host loopback).
But it removes the block entirely in the only mode the guard runs, discarding the
direct-socket deny + its audit for a truly unsanctioned loopback target. Plan B
keeps a real deny for any port with no in-jail listener and remains correct if
the guard is later enabled in shared-net mode, so it is preferred.

## Files

- `crates/firma-run/src/egress_guard.rs` — add `netns_local_ports`, extend
  `classify_notification` block branch, add unit tests. Only file changed.

## Verification

1. `just fmt && just lint` — dprint + clippy (no unwrap/expect/panic/unsafe in
   new code).
2. `cargo nextest run -p firma-run egress_guard` — new parser unit tests +
   existing `classify_notification` / `guard_blocks_and_allows_real_connects`
   suite pass.
3. Extend the real-seccomp round-trip test
   (`guard_blocks_and_allows_real_connects`, `egress_guard.rs:1348`): it already
   binds a real `TcpListener` on `127.0.0.1:0` and installs a live filter. With
   Plan B, that bound port now appears in `/proc/self/net/tcp`, so the connect
   should be **allowed** even though the port is not in `allow_ports` — assert
   allow (in-jail listener), and assert a connect to a loopback port with **no**
   listener is still blocked with `EACCES`.
4. End-to-end: run `just test` inside a `firma run`-wrapped agent (structural
   bwrap mode). Previously loopback-connecting tests (authority e2e, sidecar
   integration) should now pass without disabling the guard.
