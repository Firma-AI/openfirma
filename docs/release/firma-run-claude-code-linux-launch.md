# Firma Run + Claude Code (Linux) Launch Notes

Status: launch-ready  
Owners: Runtime + Sidecar teams

## 1. What shipped

`firma run` now supports:

```bash
firma run --profile claude-code -- claude
```

Delivered capabilities:
- Linux-first sandboxed Claude runtime path (`bwrap` backend).
- Claude settings injection with:
  - `sandbox.autoAllowBashIfSandboxed = true`
- End-to-end identity attribution into sidecar decisions/audit:
  - `x-firma-agent=claude-code`
  - `x-firma-user=<runtime user>`
  - `x-firma-session-id=<uuid>`
  - `x-firma-sandbox-id=<uuid>`
  - `x-firma-profile=claude-code`
- Unified E2E harness for generic + Claude acceptance flows.

## 1.1 Platform posture (adoption transparency)

Claude users are frequently macOS-first. To reduce adoption friction while
keeping launch scope realistic:

- Linux (`bwrap`): full structural confinement target for this launch slice.
- macOS (`vz`): anticipated support now includes `sandbox-exec` deny rules for
  common sensitive paths plus runtime-home isolation, with reduced guarantees
  versus Linux structural mode.
- Windows (`wsl2`): supported in compatibility mode for `claude-code` profile,
  with reduced guarantees versus Linux structural mode.

Compatibility mode still routes through Firma runtime + sidecar policy plane,
but should not be represented as parity with Linux structural confinement.

## 2. Proxy routing model

Current implementation mapping:
- sandboxed process uses local proxy env (`HTTP[S]_PROXY=127.0.0.1:<sandbox-proxy-port>`),
- `firma-run` internal proxy bridge forwards sandbox proxy TCP traffic to host-side sidecar endpoint,
- attribution headers are injected per request before sidecar policy evaluation.

This ensures all sandbox-originated HTTP/HTTPS proxy traffic is mediated by the Firma sidecar path.

## 3. Coverage delta (launch copy)

Compared with running Claude Code standalone sandbox controls:
- **Whole-process boundary**: Firma wraps the whole agent process, not only Bash tool descendants.
- **Externalized policy plane**: governance logic is outside the agent process.
- **Cross-agent reuse**: same policy plane applies to Claude/Codex/custom agents.
- **Durable central audit**: stable attribution + audit across agent restarts.
- **Structural interception stance**: mediation is runtime-boundary based, not prompt-UX based.

This is an architectural distinction, not a blanket immunity claim.

## 4. Acceptance coverage (implemented)

`examples/firma-run/e2e/run.sh --claude-acceptance` covers:
- shell `curl` egress interception + deny,
- child-process `wget` interception + deny,
- write outside working directory blocked by sandbox filesystem policy,
- sensitive path reads (for example SSH key path) blocked by masked filesystem pathing.

## 5. MITM stabilization shipped during validation

During Claude real-session validation, HTTPS CONNECT/MITM behavior surfaced edge cases.
Root causes and fixes included:
- CONNECT preface handling around CR/LF + TLS handshake start,
- strict/non-strict fallback semantics hardening,
- CONNECT-level enforcement preservation when fallback paths are possible.

Outcome:
- deterministic CONNECT classification behavior,
- no spurious `InvalidContentType` handshake failures from CR/LF replay,
- no non-strict fallback bypass of destination-level CONNECT policy.

## 6. Operator usage

Run Claude under Firma:

```bash
cargo run -p firma-run -- run --profile claude-code -- claude
```

Run acceptance harness:

```bash
examples/firma-run/e2e/run.sh --claude-acceptance
```

## 7. Current non-goals

- macOS seatbelt path not in this launch slice.
- no eBPF/syscall interception in this scope.
- no Claude source patching; integration is configuration/runtime wrapping.

## 8. Fast-follow for macOS parity (v1.1)

Planned fast-follow scope:
- tighten macOS confinement backend guarantees for `claude-code`,
- add macOS-specific acceptance matrix equivalent to Linux shell-governance
  checks where technically feasible,
- publish a capability matrix update once parity thresholds are met.
