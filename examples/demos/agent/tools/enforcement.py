"""Tools for demo0 and demo1.

Plain synchronous httpx calls. No LLM, no agent framework — the demo
scripts call these in a fixed order so the audit log is deterministic.
Mapping of tool to canonical action class is documented in
`examples/demos/demo*/mapping-rules.toml`.
"""
import os

import httpx

_CA_BUNDLE = os.environ.get("SSL_CERT_FILE", True)
_DEFAULT_HEADERS = {
    "x-firma-session-id": os.environ.get("FIRMA_SESSION_ID", ""),
}


def _client(**kwargs) -> httpx.Client:
    headers = {**_DEFAULT_HEADERS, **kwargs.pop("headers", {})}
    return httpx.Client(verify=_CA_BUNDLE, timeout=15.0, headers=headers, **kwargs)


# ── Demo 0 tools ─────────────────────────────────────────────────────────────

def read_github_pr(repo: str, pr_number: int) -> str:
    """Read a GitHub pull request and return the response."""
    gh_token = os.environ.get("GITHUB_TOKEN", "demo-token")
    with _client() as client:
        response = client.get(
            f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
            headers={
                "Authorization": f"Bearer {gh_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        return f"HTTP {response.status_code}\n{response.text[:800]}"


def send_gmail_message(to: str, subject: str, body: str) -> str:
    """Send an email via Gmail and return the response."""
    gh_token = os.environ.get("GITHUB_TOKEN", "demo-token")
    with _client() as client:
        response = client.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={"Authorization": f"Bearer {gh_token}"},
            json={"raw": "base64-encoded-message"},
        )
        return f"HTTP {response.status_code}\n{response.text[:500]}"


def create_stripe_refund(charge_id: str, amount_cents: int) -> str:
    """Create a Stripe refund and return the response."""
    with _client() as client:
        response = client.post(
            "https://api.stripe.com/v1/refunds",
            headers={"Authorization": "Bearer sk-demo"},
            data={"charge": charge_id, "amount": str(amount_cents)},
        )
        return f"HTTP {response.status_code}\n{response.text[:500]}"


def delete_backend_user() -> str:
    """Delete demo user (id 42) from the internal backend service.

    Uses httpbin.org/delete as the public stand-in for the private
    api.internal endpoint.
    """
    with _client() as client:
        response = client.request(
            "DELETE",
            "https://httpbin.org/delete",
            json={"user_id": "42"},
        )
        return f"HTTP {response.status_code}\n{response.text[:500]}"


# ── Demo 1 tools ─────────────────────────────────────────────────────────────

def fetch_usage(user_id: str) -> str:
    """Fetch customer usage metrics from api.internal/usage."""
    with _client() as client:
        response = client.get(
            "https://httpbin.org/get",
            params={"user": user_id},
        )
        return f"HTTP {response.status_code}\n{response.text[:800]}"


def fetch_billing(user_id: str) -> str:
    """Fetch billing data from api.internal/billing."""
    with _client() as client:
        response = client.get(
            "https://httpbin.org/anything/billing",
            params={"user": user_id},
        )
        return f"HTTP {response.status_code}\n{response.text[:800]}"
