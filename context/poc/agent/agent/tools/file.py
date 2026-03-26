import os

from agents import function_tool


@function_tool
def read_file(path: str) -> str:
    """Read and return the contents of a file."""
    try:
        with open(path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return f"Error: File not found: {path}"
    except Exception as e:
        return f"Error reading file: {e}"


@function_tool
def write_file(path: str, content: str) -> str:
    """Write content to a file, creating parent directories if needed."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return f"Successfully wrote {len(content)} bytes to {path}"
    except Exception as e:
        return f"Error writing file: {e}"
