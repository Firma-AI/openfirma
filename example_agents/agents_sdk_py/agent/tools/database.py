import json

from agents import function_tool

from agent.services.database import get_client


@function_tool
def db_query(query: str) -> str:
    """Execute a SQL query against the hosted Postgres database and return results.

    The agent passes a raw SQL string; it is forwarded to a Supabase RPC
    (``execute_sql``) via HTTPS POST to ``/rest/v1/rpc/execute_sql``. This is
    intentionally insecure — it demonstrates what happens when an agent has
    unrestricted SQL access and why OpenAuthority must enforce at the network layer,
    not inside the agent.
    """
    try:
        response = get_client().rpc("execute_sql", {"query": query}).execute()
        return json.dumps(response.data, indent=2, default=str)
    except Exception as e:  # noqa: BLE001 - demo agent surfaces all errors
        return f"Database error: {e}"
