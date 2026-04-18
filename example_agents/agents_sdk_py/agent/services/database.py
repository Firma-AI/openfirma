import os

from supabase import Client, create_client

_client: Client | None = None


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"{name} is required. Set it in .env (see .env.sample). "
            "The Firma demo agents rely on Supabase for db_query and file tools."
        )
    return value


def get_client() -> Client:
    """Return a singleton Supabase client.

    All traffic goes to ``<SUPABASE_URL>/rest/v1/...`` or ``/storage/v1/...``
    over HTTPS. When ``HTTPS_PROXY`` points at the Firma sidecar, every call
    is visible to enforcement.
    """
    global _client
    if _client is None:
        url = _require_env("SUPABASE_URL")
        key = _require_env("SUPABASE_ANON_KEY")
        _client = create_client(url, key)
    return _client


def storage_bucket() -> str:
    return os.environ.get("SUPABASE_STORAGE_BUCKET", "firma-demo")
