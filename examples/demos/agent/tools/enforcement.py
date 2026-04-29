"""Tools for demo0 — four systems, one enforcement gap.

Each tool maps to a specific URL intercepted by the sidecar:
  read_github_pr        GET  api.github.com         /repos/*/*/pulls/*                code.review.read      ALLOW
  send_gmail_message    POST gmail.googleapis.com   /gmail/v1/users/*/messages/send   communication.ext.send DENY
  create_stripe_refund  POST api.stripe.com         /v1/refunds                       payment.transfer      DENY
  delete_backend_user   DEL  httpbin.org            /delete                           account.permission.change DENY

And for demo1 — same host, different path:
  fetch_usage           GET  httpbin.org /get                filesystem.read   ALLOW
  fetch_billing         GET  httpbin.org /anything/billing   credential.read   DENY
"""
import os

import httpx
from agents import function_tool

_CA_BUNDLE = os.environ.get("SSL_CERT_FILE", True)


def _client(**kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=_CA_BUNDLE, timeout=15.0, **kwargs)


# ── Demo 0 tools ─────────────────────────────────────────────────────────────

@function_tool
async def read_github_pr(repo: str, pr_number: int) -> str:
    """Read a GitHub pull request. Allowed (code.review.read)."""
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
    """Send an email via Gmail API. DENIED by policy (communication.external.send)."""
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
    """Create a Stripe refund. DENIED by policy (payment.transfer)."""
    async with _client() as client:
        response = await client.post(
            "https://api.stripe.com/v1/refunds",
            headers={"Authorization": "Bearer sk-demo"},
            data={"charge": charge_id, "amount": str(amount_cents)},
        )
        return f"HTTP {response.status_code}\n{response.text[:500]}"


@function_tool
async def delete_backend_user(user_id: int) -> str:
    """Delete a user via the internal backend API. DENIED by policy (account.permission.change).
    Uses httpbin.org/delete as a stand-in for the internal backend.
    """
    async with _client() as client:
        response = await client.delete(
            "https://httpbin.org/delete",
            json={"user_id": user_id},
        )
        return f"HTTP {response.status_code}\n{response.text[:500]}"


# ── Demo 1 tools ─────────────────────────────────────────────────────────────

@function_tool
async def fetch_usage(user_id: str) -> str:
    """Fetch customer usage metrics. Allowed (filesystem.read)."""
    async with _client() as client:
        response = await client.get(
            "https://httpbin.org/get",
            params={"user": user_id},
        )
        return f"HTTP {response.status_code}\n{response.text[:800]}"


@function_tool
async def fetch_billing(user_id: str) -> str:
    """Fetch customer billing data. DENIED by policy (credential.read not permitted)."""
    async with _client() as client:
        response = await client.get(
            "https://httpbin.org/anything/billing",
            params={"user": user_id},
        )
        return f"HTTP {response.status_code}\n{response.text[:800]}"
