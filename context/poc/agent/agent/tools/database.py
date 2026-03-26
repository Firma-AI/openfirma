import json

from agents import function_tool

from agent.services.database import get_engine


@function_tool
def db_query(query: str) -> str:
    """Execute a SQL query against the local database and return results."""
    from sqlalchemy import text

    engine = get_engine()
    try:
        with engine.connect() as conn:
            result = conn.execute(text(query))
            if result.returns_rows:
                rows = [dict(row._mapping) for row in result]
                return json.dumps(rows, indent=2, default=str)
            else:
                conn.commit()
                return f"Query executed. Rows affected: {result.rowcount}"
    except Exception as e:
        return f"Database error: {e}"
