from agents import function_tool

from agent.services.database import get_client, storage_bucket


@function_tool
def read_file(path: str) -> str:
    """Read and return the contents of a file from Supabase Storage.

    Traffic: HTTPS GET to ``<SUPABASE_URL>/storage/v1/object/<bucket>/<path>``.
    OpenAuthority sees the full request when ``HTTPS_PROXY`` is set.
    """
    try:
        data = get_client().storage.from_(storage_bucket()).download(path)
        return data.decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001 - demo agent surfaces all errors
        return f"Error reading file: {e}"


@function_tool
def write_file(path: str, content: str) -> str:
    """Write content to a file in Supabase Storage (upsert).

    Traffic: HTTPS POST/PUT to ``<SUPABASE_URL>/storage/v1/object/<bucket>/<path>``.
    """
    try:
        payload = content.encode("utf-8")
        get_client().storage.from_(storage_bucket()).upload(
            path,
            payload,
            file_options={"content-type": "text/plain", "upsert": "true"},
        )
        return f"Successfully wrote {len(payload)} bytes to {path}"
    except Exception as e:  # noqa: BLE001 - demo agent surfaces all errors
        return f"Error writing file: {e}"
