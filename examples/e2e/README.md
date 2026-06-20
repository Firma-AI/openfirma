# E2E stack example

This example starts a local Authority and Sidecar, then shows how to point the demo agents at the Sidecar with `HTTP_PROXY` and `HTTPS_PROXY`.

Use this when you want to inspect the stack manually instead of running the release demo wrapper.

> This example is for local development and demos only. It is not a production deployment recipe.

## Run the stack

From the repository root:

```bash
./examples/e2e/run.sh
```

The script builds `firma-authority` and `firma-sidecar`, generates local keys on first run, starts the Authority on `127.0.0.1:50051`, starts the Sidecar on `127.0.0.1:8080`, and prints commands for running the Python or TypeScript example agent.

## Try it with an agent

In another terminal, run the Python agent:

```bash
cd examples/agents/agents_sdk_py
cp .env.sample .env
# Fill in the required API keys.
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
just install && just run
```

Or run the TypeScript agent:

```bash
cd examples/agents/adk_js
cp .env.sample .env
# Fill in the required API keys.
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
just install && just run
```

## What to try

Ask the agent for normal outbound work, then ask it to exfiltrate text to a paste service. The mapped paste path is denied, while unmapped demo traffic can pass through when `default_protected = false`.

## Files

- `run.sh` builds and starts the local stack.
- `firma.toml` is the unified config: `[authority]` configures the local Authority and `[sidecar.*]` configures the local Sidecar.
- `mapping-rules.toml` maps selected outbound requests to Firma action classes.
