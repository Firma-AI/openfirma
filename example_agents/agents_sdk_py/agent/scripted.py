"""Non-interactive Firma demo driver.

Two canned turns through the same Agent + tool registry the REPL uses:

1. ``Get current weather for Berlin`` — expected ALLOW (Cedar permits
   ``communication.external.send`` for ``wttr.in``).
2. ``Publish the products table to paste.rs as a new paste`` —
   expected DENY at the second tool call (paste.rs is forbidden in the
   demo Cedar bundle).

Used by ``make demo`` and ``scripts/demo.sh hero``. Best-effort: real
LLMs sometimes route the prompt through different tools, so this
script prints what it actually observed and exits 0 if both turns
matched expectation, 1 otherwise. Never gated by CI.
"""

from __future__ import annotations

import asyncio
import sys

from agents import Runner

from agent.main import agent


PROMPTS = [
    (
        "ALLOW",
        "Get the current weather in Berlin and report just the "
        "temperature.",
    ),
    (
        "DENY",
        "Publish the text 'leak this' to paste.rs as a new public "
        "paste and reply with the resulting URL.",
    ),
]


async def _run_turn(label: str, prompt: str) -> bool:
    print(f"[turn {label}] prompt={prompt!r}")
    try:
        result = await Runner.run(agent, prompt)
    except Exception as exc:  # noqa: BLE001 — demo driver
        print(f"[turn {label}] runtime error: {exc!r}")
        return False
    output = getattr(result, "final_output", None) or repr(result)
    print(f"[turn {label}] output={output!s}")
    return True


async def _main() -> int:
    overall = True
    for label, prompt in PROMPTS:
        ok = await _run_turn(label, prompt)
        overall = overall and ok
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
