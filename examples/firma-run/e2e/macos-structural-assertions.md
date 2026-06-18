# macOS structural confinement E2E assertion schema

This document defines the acceptance test cases that must pass on macOS before
any experimental macOS structural mode graduates to the default backend mode and
before macOS can claim structural confinement parity with Linux `bwrap`.

The schema mirrors the Linux suite in `run.sh` and the cross-platform structural
acceptance cases. Each assertion maps to one required runtime invariant.

## Environment prerequisites

```
# Intermediate sandbox-exec structural mode:
FIRMA_RUN_VZ_STRUCTURAL_NETWORK=1
firma run --profile generic ...
```

macOS 12+ (Monterey). Apple Silicon or Intel with sandbox-exec available for
the intermediate mode. VZ guest mode is a follow-up path that will require an
operator-provided runner and guest image bundle. Production deployment should
sign and package the runner for macOS.

---

## Invariant: sidecar-only egress

### MACOS-001 — cooperative HTTP request is mediated

```bash
firma run -- curl -x "$HTTP_PROXY" https://api.anthropic.com/v1/messages
```

Expected:

- Exit 0 or Sidecar-denied exit (policy may block the request)
- Sidecar audit log contains a mediated request for `api.anthropic.com`
- No direct connection from the process appears in network capture

### MACOS-002 — proxy-env-unset direct request is blocked

```bash
firma run -- env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
  curl https://api.anthropic.com/v1/messages
```

Expected:

- `curl` cannot resolve or connect to `api.anthropic.com`
- Exit non-zero (connection refused, network unreachable, or DNS failure)
- Sidecar audit log has NO entry for this request

### MACOS-003 — raw TCP connection is blocked

```bash
firma run -- python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(('1.1.1.1', 443))
    print('BYPASS: connection succeeded')
except Exception as e:
    print(f'BLOCKED: {e}')
"
```

Expected:

- Output contains `BLOCKED`
- `BYPASS` must not appear
- Exit 0 (script ran to completion, but the connect failed)

---

## Invariant: DNS confinement

### MACOS-004 — external DNS query fails

```bash
firma run -- python3 -c "
import socket
try:
    addr = socket.getaddrinfo('api.anthropic.com', 443)
    print(f'BYPASS: resolved to {addr[0][4]}')
except Exception as e:
    print(f'BLOCKED: {e}')
"
```

Expected:

- Output contains `BLOCKED`
- Exit 0 (script ran; resolution failed cleanly)

### MACOS-005 — direct UDP DNS to external resolver is blocked

```bash
firma run -- python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' +
             b'\x07example\x03com\x00\x00\x01\x00\x01', ('8.8.8.8', 53))
    print('BYPASS: UDP DNS to 8.8.8.8 sent')
except Exception as e:
    print(f'BLOCKED: {e}')
"
```

Expected:

- Output contains `BLOCKED`

---

## Invariant: fail-closed startup

### MACOS-006 — sidecar unreachable at startup prevents launch

```bash
# Point sidecar at a closed port, do not autostart
firma run --sidecar tcp://127.0.0.1:19999 --no-autostart -- echo hello
```

Expected:

- Exit non-zero
- Error message references sidecar unreachable or fail-closed
- `hello` is NOT printed

---

## Invariant: fail-closed runtime (mid-session sidecar loss)

### MACOS-007 — sidecar killed mid-session causes egress failure

```bash
# Start with autostart, kill sidecar after agent launches, observe egress failure
firma run -- bash -c 'sleep 1; curl https://api.anthropic.com/v1/messages; echo exit=$?'
# (kill firma-sidecar process after the sleep)
```

Expected:

- After sidecar kill, `curl` returns a connection error or non-200 status
- Subsequent requests from the agent cannot reach external services
- The agent process may continue running but all outbound is broken

---

## Invariant: direct-bypass resistance — child process

### MACOS-008 — child process inherits network confinement

```bash
firma run -- bash -c 'curl https://api.anthropic.com/v1/messages'
```

Expected:

- Child `curl` process is confined by the same sandbox-exec policy
- If `HTTP_PROXY` is set: request is mediated via Sidecar (may be denied by policy)
- If `HTTP_PROXY` unset in child: direct connection fails (blocked by MAC)

### MACOS-009 — exec in child does not escape confinement

```bash
firma run -- bash -c 'exec python3 -c "
import socket
try:
    socket.create_connection((\"8.8.8.8\", 80), timeout=2)
    print(\"BYPASS\")
except Exception as e:
    print(f\"BLOCKED: {e}\")
"'
```

Expected:

- Output contains `BLOCKED`
- `exec` across process boundary does not remove the MAC sandbox label

---

## Invariant: interactive CLI usability

### MACOS-010 — exit code propagated correctly

```bash
firma run -- bash -c 'exit 42'
echo "exit=$?"
```

Expected:

- Shell prints `exit=42`

### MACOS-011 — SIGINT forwarded and agent exits cleanly

```bash
# Start a long-running agent, send SIGINT
firma run -- sleep 300 &
PID=$!
sleep 0.5
kill -INT $PID
wait $PID
echo "exit=$?"
```

Expected:

- Process exits promptly after SIGINT
- Exit code is 130 (128 + SIGTERM/SIGINT signal number) or similar non-zero

### MACOS-012 — stdout/stderr pass through correctly

```bash
firma run -- bash -c 'echo stdout; echo stderr >&2'
```

Expected:

- `stdout` appears on stdout
- `stderr` appears on stderr

---

## Known limits and residual caveats

| Limit                               | Description                                                                                                                                                                                             |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sandbox-exec` deprecated           | Apple deprecated `sandbox-exec`; policy is TrustedBSD MAC but the tool may be removed in future macOS versions. Track for VZ guest graduation.                                                          |
| DNS confine via denial only         | `/etc/resolv.conf` cannot be bind-mounted (no namespace). DNS confinement works by denying UDP/TCP to non-loopback, not via a controlled resolver. An agent could read `/etc/hosts` for `.local` names. |
| Port 53 stub not on standard port   | Host DNS stub runs on an ephemeral port; `FIRMA_DNS_STUB_ADDR` is set but agents that hardcode port 53 will get ECONNREFUSED (blocked) rather than a REFUSED DNS response.                              |
| Loopback allows all of 127.0.0.1    | The sandbox profile allows any connection to `127.0.0.1`, not just the specific bridge port. A compromised agent could reach other host services on loopback.                                           |
| No structural proof until E2E green | The runtime logs `network_confinement=macos_sandbox_network_deny` but the docs claim boundary remains non-structural until MACOS-001 through MACOS-009 are verified on supported hardware.              |

## Graduation criteria

When all MACOS-001 through MACOS-009 assertions pass on macOS 12+ (both Apple
Silicon and Intel x86_64), the following changes are permitted:

1. Remove the `FIRMA_RUN_VZ_STRUCTURAL_NETWORK` gate and make structural mode default on macOS.
2. Update `EnforcementProof.detail` to reference the verified E2E run.
3. Update `llms.txt` to note that macOS `vz` now provides structural confinement via TrustedBSD MAC.
4. Keep the VZ guest path as the next graduation step for stronger isolation.
