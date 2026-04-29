# /// script
# requires-python = ">=3.12"
# dependencies = ["requests", "urllib3"]
# ///
"""Demo 1 agent — The Path That Doesn't Exist.

Two endpoints on the same host. One allowed, one forbidden.
Enforcement happens at the path level before the upstream is reached.

Run via firma-demo-tui or directly:
    uv run examples/demos/demo1/agent.py
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


def fetch(label: str, url: str) -> None:
    print(f"\n[AGENT] {label}", flush=True)
    print(f"        GET {url}", flush=True)
    try:
        r = requests.get(url, proxies=PROXIES, verify=False, timeout=TIMEOUT)
        if r.status_code < 400:
            print(f"        -> ALLOWED  (HTTP {r.status_code}) — response received", flush=True)
        else:
            print(f"        -> DENIED   (HTTP {r.status_code}) — upstream not reached", flush=True)
    except requests.exceptions.ProxyError as exc:
        print(f"        -> DENIED   (proxy blocked: {exc})", flush=True)
    except requests.exceptions.ConnectionError as exc:
        print(f"        -> DENIED   (connection error: {exc})", flush=True)
    except requests.exceptions.Timeout:
        print(f"        -> TIMEOUT", flush=True)


def main() -> None:
    print("=" * 60, flush=True)
    print("  Demo 1: The Path That Doesn't Exist", flush=True)
    print("  Same host. Same protocol. Different path.", flush=True)
    print("=" * 60, flush=True)
    time.sleep(0.5)

    # Step 1: Usage endpoint — filesystem.read — ALLOWED
    fetch(
        "Fetch usage data (filesystem.read — permitted)",
        "https://httpbin.org/get",
    )
    time.sleep(0.8)

    # Step 2: Billing endpoint — data.query — DENIED (no Cedar permit)
    fetch(
        "Fetch billing data (data.query — no permit → deny)",
        "https://httpbin.org/anything/billing",
    )

    print("\n" + "=" * 60, flush=True)
    print("  Demo complete.", flush=True)
    print("  The billing path was never reached.", flush=True)
    print("  Enforcement happened before execution, outside the app.", flush=True)
    print("=" * 60, flush=True)


if __name__ == "__main__":
    main()
    sys.exit(0)
