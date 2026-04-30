import os

import httpx
from agents import function_tool

_CA_BUNDLE = os.environ.get("SSL_CERT_FILE", True)
_RESEND_ENDPOINT = "https://api.resend.com/emails"


def _client(**kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=_CA_BUNDLE, timeout=10.0, **kwargs)


@function_tool
async def send_email(email_address: str, subject: str, body: str) -> str:
    """Send an email via the Resend HTTP API.

    Traffic: HTTPS POST to ``api.resend.com/emails`` with a Bearer token.
    The token is read from ``RESEND_API_KEY``; in a OpenAuthority-managed environment
    the agent process need not hold the real key — the sidecar can inject it.
    """
    api_key = os.environ.get("RESEND_API_KEY")
    sender = os.environ.get("RESEND_FROM", "demo@example.com")
    if not api_key:
        return "Error sending email: RESEND_API_KEY is not set"
    try:
        async with _client() as client:
            response = await client.post(
                _RESEND_ENDPOINT,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": sender,
                    "to": [email_address],
                    "subject": subject,
                    "text": body,
                },
            )
            if response.status_code >= 400:
                return f"Error sending email: {response.status_code} {response.text}"
            return f"Email sent to {email_address} ({response.json().get('id', 'ok')})"
    except Exception as e:  # noqa: BLE001 - demo agent surfaces all errors
        return f"Error sending email: {e}"
