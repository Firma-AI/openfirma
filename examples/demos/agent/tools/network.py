"""Generic HTTP tools. Proxy is read from HTTP_PROXY / HTTPS_PROXY env vars."""
import os

import httpx
from agents import function_tool

_CA_BUNDLE = os.environ.get("SSL_CERT_FILE", True)


def _client(**kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=_CA_BUNDLE, timeout=15.0, **kwargs)


@function_tool
async def fetch_url(url: str) -> str:
    """Fetch content from a URL via GET and return the response text."""
    async with _client() as client:
        response = await client.get(url)
        return f"HTTP {response.status_code}\n{response.text[:2000]}"


@function_tool
async def post_data(url: str, data: str) -> str:
    """POST data to a URL and return the response."""
    async with _client() as client:
        response = await client.post(url, content=data)
        return f"HTTP {response.status_code}\n{response.text[:2000]}"
