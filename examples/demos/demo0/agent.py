# /// script
# requires-python = ">=3.12"
# dependencies = ["requests", "urllib3"]
# ///
"""Demo 0 agent — Same Rule, Four Systems, One Failure.

Makes four HTTP calls through the Firma sidecar proxy, each mapping to a
different canonical action class. The Cedar policy permits only read actions;
write/destructive calls are denied before reaching the upstream service.

Run via firma-demo-tui or directly:
    uv run examples/demos/demo0/agent.py
"""
import os
import sys
import time

import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROXY = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or "http://127.0.0.1:8080"
PROXIES = {"http": PROXY, "https": PROXY}
TIMEOUT = 8


def call(label: str, method: str, url: str, **kwargs) -> None:
    print(f"\n[AGENT] {label}", flush=True)
    print(f"        {method} {url}", flush=True)
    try:
        r = requests.request(
            method, url,
            proxies=PROXIES,
            verify=False,
            timeout=TIMEOUT,
            **kwargs,
        )
        verdict = "ALLOWED" if r.status_code < 400 else f"DENIED  (HTTP {r.status_code})"
        print(f"        -> {verdict}", flush=True)
    except requests.exceptions.ProxyError as exc:
        print(f"        -> DENIED  (proxy blocked: {exc})", flush=True)
    except requests.exceptions.ConnectionError as exc:
        print(f"        -> DENIED  (connection error: {exc})", flush=True)
    except requests.exceptions.Timeout:
        print(f"        -> TIMEOUT", flush=True)


def main() -> None:
    print("=" * 60, flush=True)
    print("  Demo 0: Same Rule, Four Systems, One Failure", flush=True)
    print("  Rule: read-only. No writes. No destructive actions.", flush=True)
    print("=" * 60, flush=True)
    time.sleep(0.5)

    # 1. GitHub PR read — action: code.review.read — ALLOWED by Cedar
    call(
        "Read GitHub PR #41 (code.review.read)",
        "GET", "https://api.github.com/repos/acme/api/pulls/41",
        headers={"Authorization": "Bearer demo-token", "Accept": "application/vnd.github+json"},
    )
    time.sleep(0.5)

    # 2. Gmail send — action: communication.external.send — DENIED by Cedar
    call(
        "Send email via Gmail (communication.external.send)",
        "POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        json={"raw": "base64-encoded-message"},
        headers={"Authorization": "Bearer demo-token"},
    )
    time.sleep(0.5)

    # 3. Stripe refund — action: payment.transfer — DENIED by Cedar
    call(
        "Create Stripe refund $50 (payment.transfer)",
        "POST", "https://api.stripe.com/v1/refunds",
        data={"charge": "ch_demo123", "amount": "5000"},
        headers={"Authorization": "Bearer sk-demo-stripe"},
    )
    time.sleep(0.5)

    # 4. Backend DELETE — action: account.permission.change — DENIED by Cedar
    # httpbin.org/delete is a real DELETE endpoint, stands in for api.internal/users/42
    call(
        "DELETE user 42 from backend (account.permission.change)",
        "DELETE", "https://httpbin.org/delete",
        json={"user_id": 42},
    )

    print("\n" + "=" * 60, flush=True)
    print("  Demo complete.", flush=True)
    print("  Firma enforced the rule at every call — one policy,", flush=True)
    print("  one evaluation point, regardless of provider.", flush=True)
    print("=" * 60, flush=True)


if __name__ == "__main__":
    main()
    sys.exit(0)
