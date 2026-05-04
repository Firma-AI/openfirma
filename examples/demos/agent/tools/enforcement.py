"""Tools for demo0 and demo1.

Docstrings are kept neutral on purpose — the LLM must not be told in
advance whether a call is allowed or denied. The whole point of the
demos is that the agent issues every call and only discovers the
outcome from the HTTP response. Mapping of tool to canonical action
class is documented in `examples/demos/demo*/mapping-rules.toml`.
"""
import os

import httpx
from agents import function_tool

_CA_BUNDLE = os.environ.get("SSL_CERT_FILE", True)
_DEFAULT_HEADERS = {
    "x-firma-session-id": os.environ.get("FIRMA_SESSION_ID", ""),
}


def _client(**kwargs) -> httpx.AsyncClient:
    headers = {**_DEFAULT_HEADERS, **kwargs.pop("headers", {})}
    return httpx.AsyncClient(verify=_CA_BUNDLE, timeout=15.0, headers=headers, **kwargs)


# ── Demo 0 tools ─────────────────────────────────────────────────────────────

@function_tool
async def read_github_pr(repo: str, pr_number: int) -> str:
    """Read a GitHub pull request and return the response."""
    gh_token = os.environ.get("GITHUB_TOKEN", "demo-token")
    async with _client() as client:
        response = await client.get(
            f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
            headers={
                "Authorization": f"Bearer {gh_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        return f"HTTP {response.status_code}\n{response.text[:800]}"


@function_tool
async def send_gmail_message(to: str, subject: str, body: str) -> str:
    """Send an email via Gmail and return the response."""
    gh_token = os.environ.get("GITHUB_TOKEN", "demo-token")
    async with _client() as client:
        response = await client.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={"Authorization": f"Bearer {gh_token}"},
            json={"raw": "base64-encoded-message"},
        )
        return f"HTTP {response.status_code}\n{response.text[:500]}"


@function_tool
async def create_stripe_refund(charge_id: str, amount_cents: int) -> str:
    """Create a Stripe refund and return the response."""
    async with _client() as client:
        response = await client.post(
            "https://api.stripe.com/v1/refunds",
            headers={"Authorization": "Bearer sk-demo"},
            data={"charge": charge_id, "amount": str(amount_cents)},
        )
        return f"HTTP {response.status_code}\n{response.text[:500]}"


@function_tool
async def delete_backend_user() -> str:
    """Delete the demo user (id 42) from the internal backend service.

    No arguments. Uses httpbin.org/delete as the public stand-in for the
    private api.internal endpoint.
    """
    async with _client() as client:
        response = await client.delete(
            "https://httpbin.org/delete",
            json={"user_id": "42"},
        )
        return f"HTTP {response.status_code}\n{response.text[:500]}"


# ── Demo 1 tools ─────────────────────────────────────────────────────────────

@function_tool
async def fetch_usage(user_id: str) -> str:
    """Fetch customer usage metrics from api.internal/usage."""
    async with _client() as client:
        response = await client.get(
            "https://httpbin.org/get",
            params={"user": user_id},
        )
        return f"HTTP {response.status_code}\n{response.text[:800]}"


@function_tool
async def fetch_billing(user_id: str) -> str:
    """Fetch billing data from api.internal/billing."""
    async with _client() as client:
        response = await client.get(
            "https://httpbin.org/anything/billing",
            params={"user": user_id},
        )
        return f"HTTP {response.status_code}\n{response.text[:800]}"
