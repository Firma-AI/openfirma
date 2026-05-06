"""Shared helpers for the demo scripts."""
import time
from typing import Any, Callable

_STEP_PAUSE_SECONDS = 1.5


def run_step(label: str, fn: Callable[..., str], *args: Any, **kwargs: Any) -> None:
    """Execute one demo step and print result with a short pause.

    Pause keeps audit and sidecar panes legible during a recording.
    """
    print(f"\n>>> {label}", flush=True)
    try:
        result = fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — demo prints any failure verbatim
        result = f"ERROR: {type(exc).__name__}: {exc}"
    print(result, flush=True)
    time.sleep(_STEP_PAUSE_SECONDS)


def banner(title: str, *subtitles: str) -> None:
    """Print a centred banner before a demo runs."""
    print("=" * 60, flush=True)
    print(f"  {title}", flush=True)
    for line in subtitles:
        print(f"  {line}", flush=True)
    print("=" * 60, flush=True)
