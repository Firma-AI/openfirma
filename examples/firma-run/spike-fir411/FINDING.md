# FIR-411 finding: the `firma run <harness>` enforced boundary

This is a time-boxed spike on Linux, using the bwrap structural path. I ran it
on a Linux VM against local fake services, so no cloud and no real secrets. All
the numbers below come from the throwaway harness in this directory. To
reproduce them, run `cargo build -p firma` and then `./run-all.sh`.

Short version: the network boundary holds, and it works across harnesses
without writing a custom shim for each one. But the thing actually doing the
containment is the set of kernel **namespaces**, not the process tree. So the
idea that "wrap the process tree and you've contained it" is wrong. Two exits
that don't touch the network get out trivially, and a detached process keeps
running after the box is torn down. These are product gaps. I'm documenting
them here, I'm not fixing them.

## Does it actually work, demo by demo

| demo                    | bare (no boundary)                                                | boxed (`firma run`)                                                                                                                        |
| ----------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| 1: credential leak      | approved-api sees the placeholder, the sink logs the token (leak) | the broker injects the real token (approved-api sees `real`), the exfil is denied at the proxy, the sink stays empty                       |
| 2: child-process escape | the child's raw socket reaches the sink (leak)                    | the child inherits the netns, so the DNS stub refuses the name and the egress guard EPERMs the literal `::1` connect, the sink stays empty |
| 3: scoped secret read   | the `~/.aws` file reads fine (leak)                               | `~/.aws` is tmpfs-masked, so the file just isn't there (denied)                                                                            |

All three reproduce reliably. Demo 1 is the only one doing anything new, the
placeholder-to-real bearer brokering. Demos 2 and 3 just re-confirm containment
codex already had, the netns and the sensitive-home masking.

## Break-out: what escaped, what held

| id | surface                | result                    | does it defeat the hypothesis?                                                                                                         |
| -- | ---------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| b1 | shared bind-mount      | escaped                   | yes. the host watcher acted for the agent through the shared filesystem, no network, the sidecar never saw it                          |
| b2 | AF_UNIX to host daemon | escaped                   | yes. AF_UNIX isn't governed by the egress guard, which only filters AF_INET and AF_INET6                                               |
| b3 | non-HTTP over tunnel   | contained (unclassified)  | no. the bytes reached the bridge but nothing was forwarded, it fails closed and the sidecar can't evaluate a protocol it doesn't parse |
| b4 | detached process       | partial, survived         | partial. the `setsid` writer kept writing after `firma run` exited, there's no cgroup reap                                             |
| b5 | egress guard degraded  | active, degrades to netns | no. the guard EPERMs non-allowed loopback ports, and if it fails open the netns still contains                                         |

The two escapes, b1 and b2, have the same root cause. The boundary is the set
of namespaces the agent runs in. The shared writable bind-mount and any
reachable AF_UNIX socket live inside those namespaces, but outside the netns
funnel. Neither one touches the network, so the destination HTTP enforcement
never even runs, no matter how good it is.

## Is HTTP-only enough? (design question #2)

For the network side, yes. Destination-based HTTP enforcement plus bearer
brokering handled every classified call. The non-HTTP tunnel attempt (b3)
failed closed at the netns: the raw bytes reached the allow-listed bridge port
but were never forwarded, and the sidecar correctly refused to reason about a
protocol it doesn't parse. Nothing here says you need TLS interception or
payload inspection to contain the agent. The netns already fails closed on
anything the proxy can't classify.

The real problem isn't the protocol. It's the scope of the funnel. The netns
only governs the network. The filesystem (b1) and AF_UNIX (b2) are
side-channels that skip the sidecar entirely. So my recommendation is simple:
don't spend time on TLS or payload inspection for containment. Spend it on the
non-network boundary, so AF_UNIX governance, tighter filesystem scoping, and
cgroup-based reaping.

## Does the wrap generalize across harnesses?

Both new harnesses ran under the generic wrap with only provider-key
passthrough added to the profile. No custom shim.

| harness  | launches in box | traffic funnels to sidecar                                                                                                            | shim needed |
| -------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| opencode | yes (v1.18.2)   | yes. `api.anthropic.com`, plus the server split's `models.dev` and `registry.npmjs.org` telemetry, all hit the sidecar and got denied | none        |
| pi       | yes (v0.73.1)   | yes. `api.anthropic.com` hit the sidecar and got denied                                                                               | none        |

The OpenCode client/server split was the risk I flagged going in. Its
background server launched inside the box, and its outbound calls funneled
through the sidecar instead of detaching to the host. Node's CA needs were
already covered by the auto-injected `NODE_EXTRA_CA_CERTS`, and with MITM off,
the denied CONNECTs never needed a trusted cert anyway. Pi is a single-process
TUI and did exactly what I expected.

## Per-action latency

These numbers come from a debug build (`target/debug/firma`), so a release
build would be faster.

| measurement                      | bare   | boxed        | overhead     |
| -------------------------------- | ------ | ------------ | ------------ |
| per approved-api call (N=30)     | ~2.6ms | ~54 to 61 ms | ~50 to 58 ms |
| cold start (`firma run -- true`) | n/a    | ~1.0s        | ~1.0s        |

The ~55ms per-action cost is the whole round trip: the proxy bridge hop, the
normalizer, capability validation, Cedar evaluation, and a fresh connector
dispatch to the upstream with no keep-alive on this path. That's fine for an
interactive coding agent. I'd profile it before running high-throughput
autonomous workloads on it.

## Setup friction: getting to a working `firma run opencode`

1. `cargo build -p firma`.
2. `npm i -g opencode-ai` and `npm i -g @mariozechner/pi-coding-agent`. The
   binaries are `opencode` and `pi`. Watch the package-name collisions noted in
   the README.
3. Pass an absolute `--config` path. With a relative path the authority
   `key_file` stays relative, and the autostarted authority, which launches
   from a per-run dir, then fails with "failed to read key file". This one is
   worth fixing in the product.
4. The mapping rules and the credential `target_host` match the envelope host
   including the port, so the fixed demo ports are part of the match. Real
   deployments use default ports, so this only bites local multi-service setups
   like this spike.
5. The provider keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) are already passed
   through by the new profiles, so there's no extra wiring.

## Verdict

It's worth investing in the reframe, but with conditions. The network
containment is real, it generalizes across harnesses for free, and the
bearer-brokering story is a good one for the autonomous, unattended target. But
if we ship this for high-blast-radius agents, we have to be honest that the
boundary is the namespace set, not the process tree, and we have to close the
non-network gaps this spike found:

- Govern or cut off AF_UNIX reachability from inside the box (b2).
- Treat a shared writable bind-mount as an exfil channel, not a convenience
  (b1). Scope it, or mediate whatever reads it on the host side.
- Reap the whole process group, or the cgroup, at teardown (b4).

If we scope the reframe to "network egress is brokered and audited, and the
filesystem and IPC surface is hardened", then it's worth building. If we sell
it as "the process tree is the boundary", it isn't, because that claim is
false, and this spike shows three ways around it.
