# Generic agent — baseline policy bundle

Reference Cedar / mapping / sidecar configuration for running a generic
LLM agent (Claude Code or comparable) under Firma. Use as a starting
template; copy and narrow per deployment profile.

## Run

```bash
bash examples/generic-agent/run.sh
```

Builds `firma-authority` + `firma-sidecar`, generates keys on first boot
into `.runtime/`, starts both processes, prints curl smoke-test commands.

## Layer coverage

| Layer | Mechanism | Status in this example |
|-------|-----------|------------------------|
| 1 — Network (host / IP allowlist) | mapping rules + Cedar | covered |
| 2 — Command / syscall | seccomp-unotify / ESF | deferred (FIR-79) |
| 3 — Filesystem | firma-run sandbox | not configured here |
| 4 — Semantic (HTTP action classes) | Cedar policy bundle | covered |

Layer 3 and Layer 2 are enforced outside the sidecar. The Cedar policy
in `policies/llm-agent.cedar` does not duplicate filesystem path or
syscall rules — those belong to firma-run / bwrap / seccomp.

## Files

| File | Purpose |
|------|---------|
| `firma.toml` | unified config — `[authority]` points to `policies/` and `issuance-policies/`; `[sidecar.*]` is the HTTP proxy on `:7474`, MITM for github / gmail / pypi, `default_protected = true` |
| `policies/llm-agent.cedar` | enforcement policy bundle streamed to the sidecar |
| `issuance-policies/issuance.cedar` | gates capability token issuance at the Authority |
| `mapping-rules.toml` | supplemental host/method/path → action class rules (CONNECT tunnels, package managers, localhost) |
| `run.sh` | startup script + curl smoke tests |

The shipped provider mappings in `crates/firma-sidecar/config/mappings/`
(`github.toml`, `gmail.toml`) are merged on top — see
`firma.toml [sidecar.mapping] rules_paths`.

## Issuance vs enforcement

The Authority evaluates two distinct Cedar policy sets:

- **Issuance** (`issuance-policies/`) — controls whether the Authority
  will mint a capability token at all. Permissive in this template
  (`permit(principal, action, resource)`).
- **Enforcement** (`policies/`) — streamed to the sidecar and evaluated
  on every intercepted call. Narrow: hard-blocks on payment.\*,
  credential.write, code.destructive, account.permission.change,
  memory.cross_namespace.\*, repo.admin; permits read/write/merge code
  and communication.

The split lets operators issue broad tokens at session start while the
sidecar enforces fine-grained limits per call.

## Network rules (Layer 1)

Allowlist via `mapping-rules.toml`:

- `api.anthropic.com` (LLM, CONNECT-tunneled, no MITM)
- `api.github.com`, `gmail.googleapis.com` (MITM)
- `pypi.org`, `files.pythonhosted.org`, `crates.io`, `static.crates.io`,
  `registry.npmjs.org` (package registries)
- `localhost`, `127.0.0.1` (loopback — assumes trusted)

Defense-in-depth Cedar `forbid` on `169.254.169.254*` (cloud metadata).
Unmapped hosts are denied before Cedar by `default_protected = true`.

RFC-1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) cannot be
expressed as CIDR in Cedar. Enforce at the OS / network layer:

```bash
iptables -I OUTPUT -d 10.0.0.0/8     -j DROP
iptables -I OUTPUT -d 172.16.0.0/12  -j DROP
iptables -I OUTPUT -d 192.168.0.0/16 -j DROP
```

Or via `firma-run --unshare-net` plus an explicit allow-list.

## Semantic rules (Layer 4)

Hard-block (auto-deny in v0.1; HITL terminal flow planned):

- `payment.transfer`, `payment.purchase`, `payment.refund`,
  `payment.payout`, `browser.purchase`
- `account.permission.change`, `repo.admin`
- `credential.write`
- `code.destructive` (force-push, branch delete, file delete via API)
- `memory.cross_namespace.read`, `memory.cross_namespace.write`

Permit:

- `system.install` (host-restricted by mapping rules above)
- `credential.read`
- `code.read`, `code.review.read`, `issue.read`,
  `security.alert.read`, `notification.manage`
- `code.write`, `code.review.submit`, `issue.write`
- `code.merge`
- `communication.external.send`, `communication.internal.send`

`system.install` is currently auto-permit. The FIR-80 spec recommends
HITL gating; downgrade to `forbid` if running unattended.

## Smoke tests

The proxy expects `x-firma-session-id: preflight-session` on each
request to bind it to the preflight-issued capability token. The
`run.sh` output prints the exact curl invocations.

| Target | Expected |
|--------|----------|
| crates.io GET | 200 |
| pypi.org GET | 200 |
| api.github.com GET /repos/* | 200 |
| api.github.com DELETE /repos/*/git/refs/* | 403 (`code.destructive`) |
| evil.com GET | 403 (unmapped) |
| 169.254.169.254 GET | 403 (Cedar forbid) |

## Pointing an agent at the proxy

```bash
export HTTP_PROXY=http://127.0.0.1:7474
export HTTPS_PROXY=http://127.0.0.1:7474
export REQUESTS_CA_BUNDLE=examples/generic-agent/.runtime/generated-firma-ca/firma-ca.crt
export SSL_CERT_FILE=$REQUESTS_CA_BUNDLE
export NODE_EXTRA_CA_CERTS=$REQUESTS_CA_BUNDLE
```

The agent must inject `x-firma-session-id: preflight-session` on every
outbound HTTP request. Long-term this header should default to the
preflight session_id when absent — tracked separately.

## NOT FOR PRODUCTION

The Mini Authority and this template are local-dev / testing only.
PASETO keys, audit signing keys, and the generated MITM CA all live in
`.runtime/` — copy nothing from here to production.
