#!/usr/bin/env python3
"""Demo agent for the firma run secret-redaction example.

Runs inside the bwrap sandbox. Exercises the two-phase secret-mediation flow:

1. Intercept — calls mock-vault (shimmed); the firma run broker intercepts
   stdout, extracts real values, and replaces them with firma-secret://demo/
   placeholders. The agent only ever sees the placeholder tokens.

2. Redact (HTTP) — embeds a placeholder in a JSON POST to the capture server
   via the Sidecar HTTP proxy. The Sidecar resolves the placeholder to the real
   secret before forwarding the request; the capture server receives (and logs)
   the real value. The Sidecar then masks the real value back to the placeholder
   in the response before the agent reads it.

The two assertions at the end verify that both directions worked:
  - the response body must contain the placeholder, not the real secret
  - the capture server log (checked by run.sh) must contain the real secret
"""

import json
import os
import subprocess
import sys
import urllib.request

CAPTURE_URL = "http://127.0.0.1:19876/capture"


def banner(label: str) -> None:
    print(f"\n--- {label} ---", flush=True)


# ── Step 1: intercept ─────────────────────────────────────────────────────────
banner("Step 1: intercept — calling mock-vault (shimmed by firma run broker)")

result = subprocess.run(["mock-vault"], capture_output=True, text=True)
if result.returncode != 0:
    print(
        f"[fail] mock-vault exited {result.returncode}", file=sys.stderr
    )
    print(f"stdout: {result.stdout!r}", file=sys.stderr)
    print(f"stderr: {result.stderr!r}", file=sys.stderr)
    sys.exit(1)
vault_output = json.loads(result.stdout)

print("Agent sees (placeholders only, real values never left the broker):")
print(json.dumps(vault_output, indent=2))

token = next(item["value"] for item in vault_output if item["key"] == "login-password")
if not token.startswith("firma-secret://"):
    print(f"[fail] expected a placeholder, got: {token!r}", file=sys.stderr)
    sys.exit(1)
print(f"\nPlaceholder for login-password: {token!r}")


# ── Step 2: redact via HTTP proxy ─────────────────────────────────────────────
banner("Step 2: redact — POST placeholder to capture server via Sidecar proxy")

# firma run sets HTTP_PROXY to the host bridge; use it explicitly so that
# urllib routes the loopback request through the proxy (bypassing no_proxy).
proxy_url = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy") or ""
if not proxy_url:
    print("[fail] HTTP_PROXY is not set — firma run should inject it", file=sys.stderr)
    sys.exit(1)
print(f"Using proxy: {proxy_url}")

opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url}))

body = json.dumps({"token": token}).encode()
req = urllib.request.Request(
    CAPTURE_URL,
    data=body,
    method="POST",
    headers={"Content-Type": "application/json"},
)
try:
    with opener.open(req, timeout=10) as resp:
        response_json = json.loads(resp.read())
except urllib.error.HTTPError as e:
    body = e.read().decode(errors="replace")
    print(f"[fail] HTTP {e.code} from proxy: {body!r}", file=sys.stderr)
    sys.exit(1)
except OSError as e:
    print(f"[fail] connection error: {e}", file=sys.stderr)
    sys.exit(1)

print("Response from capture server (Sidecar masked real secret in response):")
print(json.dumps(response_json, indent=2))

captured = response_json.get("captured", "")
if "firma-secret://" not in captured:
    print(
        f"[fail] response should contain the masked placeholder, got: {captured!r}",
        file=sys.stderr,
    )
    sys.exit(1)
if "S3cr3tP" in captured:
    print(
        f"[fail] response must not contain the real secret value, got: {captured!r}",
        file=sys.stderr,
    )
    sys.exit(1)

print("\nDemo complete — agent handled only placeholders throughout.", flush=True)
