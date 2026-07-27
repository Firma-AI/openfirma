#!/usr/bin/env python3
"""Demo agent for the firma run HTTP-vault redaction example.

Runs inside the bwrap sandbox. Exercises the two-phase secret-mediation flow,
with the fetch phase going through an HTTP vault instead of a CLI shim:

1. Fetch (HTTP-vault intercept) — GETs a secret from the mock HTTP vault via
   the Sidecar HTTP proxy. The Sidecar's own HTTP path matches the response
   against the configured provider, extracts the real value from the JSON
   response, and replaces it with a firma-secret://demo-http-vault/
   placeholder before the agent's HTTP client sees the response body. No
   shim, no firma-run broker round-trip for the fetch itself.

2. Use (HTTP redact) — embeds the placeholder in a JSON POST to the capture
   server via the same Sidecar proxy. The Sidecar resolves the placeholder to
   the real secret (pushed to the broker during step 1) before forwarding;
   the capture server receives (and logs) the real value. The Sidecar then
   masks the real value back to the placeholder in the response before the
   agent reads it.

The two assertions at the end verify that both directions worked:
  - the vault response must contain the placeholder, not the real secret
  - the capture server log (checked by run.sh) must contain the real secret
"""

import json
import os
import sys
import urllib.request

VAULT_URL = "http://127.0.0.1:19877/secret/login-password"
CAPTURE_URL = "http://127.0.0.1:19876/capture"


def banner(label: str) -> None:
    print(f"\n--- {label} ---", flush=True)


# firma run sets HTTP_PROXY to the host bridge; use it explicitly so that
# urllib routes the loopback requests through the proxy (bypassing no_proxy).
proxy_url = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy") or ""
if not proxy_url:
    print("[fail] HTTP_PROXY is not set — firma run should inject it", file=sys.stderr)
    sys.exit(1)
print(f"Using proxy: {proxy_url}")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url}))


# ── Step 1: fetch via HTTP vault ─────────────────────────────────────────────
banner("Step 1: fetch — GET login-password from the HTTP vault (Sidecar intercept)")

req = urllib.request.Request(VAULT_URL, method="GET")
try:
    with opener.open(req, timeout=10) as resp:
        vault_response = json.loads(resp.read())
except urllib.error.HTTPError as e:
    body = e.read().decode(errors="replace")
    print(f"[fail] HTTP {e.code} from proxy: {body!r}", file=sys.stderr)
    sys.exit(1)
except OSError as e:
    print(f"[fail] connection error: {e}", file=sys.stderr)
    sys.exit(1)

print("Agent sees (placeholder only, real value never left the Sidecar):")
print(json.dumps(vault_response, indent=2))

token = vault_response.get("SecretString", "")
if not token.startswith("firma-secret://"):
    print(f"[fail] expected a placeholder, got: {token!r}", file=sys.stderr)
    sys.exit(1)
print(f"\nPlaceholder for login-password: {token!r}")


# ── Step 2: use via HTTP redact ──────────────────────────────────────────────
banner("Step 2: use — POST placeholder to capture server via Sidecar proxy")

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
