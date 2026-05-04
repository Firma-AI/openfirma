"""Shared helpers for the demo agents."""
import os


def normalize_env() -> None:
    """Drop env vars that are set but empty — they break SDK clients.

    python-dotenv loads `KEY=` as `KEY=""`. The OpenAI client treats an
    empty `OPENAI_BASE_URL` as a literal base URL and fails with
    "Request URL is missing an 'http://' or 'https://' protocol" before
    any traffic leaves the process. Removing empty assignments lets each
    SDK fall back to its built-in default
    (e.g. https://api.openai.com/v1).
    """
    for key in ("OPENAI_BASE_URL",):
        value = os.environ.get(key)
        if value is not None and not value.strip():
            os.environ.pop(key, None)
