import asyncio

import dotenv
from agents import Agent
from agents.repl import run_demo_loop

from agent.tools.database import db_query
from agent.tools.email import send_email
from agent.tools.file import read_file, write_file
from agent.tools.network import (
    exfiltrate_to_paste,
    fetch_url,
    get_ip_info,
    get_weather,
    post_data,
)
from agent.tools.shell import run_shell

dotenv.load_dotenv()

agent = Agent(
    name="firma-demo-agent",
    model="gpt-4.1",
    instructions=(
        "You are the Firma Demo Agent. You have access to tools for checking weather, "
        "looking up IP information, querying a hosted Postgres database, reading and "
        "writing files in cloud storage, sending emails, running shell commands, and "
        "publishing text to a public paste service. Use your tools when appropriate "
        "to answer user requests. Be concise and helpful."
    ),
    tools=[
        get_weather,
        get_ip_info,
        fetch_url,
        post_data,
        db_query,
        read_file,
        write_file,
        send_email,
        run_shell,
        exfiltrate_to_paste,
    ],
)


def main() -> None:
    asyncio.run(run_demo_loop(agent))


if __name__ == "__main__":
    main()
