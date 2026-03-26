import asyncio
import os

from agents import Agent, Runner


agent = Agent(
    name="firma-demo-agent",
    model="gpt-4.1",
    instructions=(
        "You are the Firma Demo Agent. You have access to tools for checking weather, "
        "looking up IP information, querying a product database, reading and writing files, "
        "and sending emails. Use your tools when appropriate to answer user requests. "
        "Be concise and helpful."
    ),
    tools=[],
)


def _register_tools() -> None:
    from agent.tools.network import get_weather, get_ip_info, fetch_url, post_data
    from agent.tools.database import db_query
    from agent.tools.file import read_file, write_file
    from agent.tools.email import send_email
    from agent.tools.shell import run_shell

    agent.tools = [
        get_weather, get_ip_info, fetch_url, post_data,
        db_query, read_file, write_file, send_email, run_shell,
    ]


async def run_interactive() -> None:
    print("=" * 60)
    print("  Firma Demo Agent")
    print("  Type your message and press Enter. Type 'exit' to quit.")
    print("=" * 60)
    print()

    while True:
        try:
            user_input = input("> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nfirma-agent: Goodbye!")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit"):
            print("firma-agent: Goodbye!")
            break

        try:
            result = await Runner.run(agent, user_input)
            print(f"\n{result.final_output}\n")
        except Exception as e:
            print(f"\nfirma-agent: Error: {e}\n")


def main() -> None:
    from agent.services.database import initialize_database
    initialize_database()
    _register_tools()
    asyncio.run(run_interactive())


if __name__ == "__main__":
    main()
