"""Deterministic agent driver for the Policy Control example."""

from __future__ import annotations

import argparse
import time
from typing import Sequence

from .tools import TOOLS, AgentConfig, run_tool, validate_tools

OPERATIONS = "operations"


def run_operations(delay: float, config: AgentConfig) -> None:
    """Run the operations workflow and print a compact trace."""

    print(f"agent task: {OPERATIONS}", flush=True)
    for tool_name in TOOLS:
        result = run_tool(tool_name, config)
        call = result.call
        status = _display_status(result.status)
        print(
            f"{call.name:<28} {call.method:<4} {status:<3} {call.label}",
            flush=True,
        )
        if delay > 0:
            time.sleep(delay)


def _display_status(status: int | None) -> str:
    return "000" if status is None else str(status)


def main(argv: Sequence[str] | None = None) -> int:
    """Run deterministic demo-agent operations."""

    parser = argparse.ArgumentParser(
        description="Run deterministic Policy Control demo-agent traffic.",
    )
    parser.add_argument(
        "workflow",
        nargs="?",
        default=OPERATIONS,
        choices=(OPERATIONS,),
        help="agent workflow to run",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="repeat the selected workflow until interrupted",
    )
    parser.add_argument(
        "--interval",
        default=2.0,
        type=float,
        help="seconds to wait between loop iterations",
    )
    parser.add_argument(
        "--delay",
        default=0.0,
        type=float,
        help="seconds to wait between tool calls",
    )
    args = parser.parse_args(argv)

    try:
        validate_tools()
    except ValueError as error:
        parser.error(f"invalid agent catalog: {error}")

    try:
        config = AgentConfig.from_env()
    except ValueError as error:
        parser.error(str(error))

    while True:
        run_operations(args.delay, config)
        if not args.loop:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
