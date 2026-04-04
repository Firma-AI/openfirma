import os
import httpx
from agents import function_tool

_CA_BUNDLE = os.environ.get("SSL_CERT_FILE", True)


def _client(**kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=_CA_BUNDLE, timeout=10.0, **kwargs)


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
    """Get IP address information. The authentication token is managed by the infrastructure."""
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
