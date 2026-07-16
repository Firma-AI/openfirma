#!/usr/bin/env python3
"""Simulated agent for the firma run secret-redaction demo.

Runs inside the bwrap sandbox. Exercises both secret-mediation modes:

1. Intercept — calls mock-vault (shimmed); sees only firma-secret:// placeholder
   tokens in the output. Real values stay in the out-of-sandbox broker.

2. Redact — embeds a placeholder in a tools/call to mock-mcp-server (shimmed);
   the broker rehydrates it to the real secret on the server's stdin, then masks
   any reflected secret back to the placeholder on stdout before the agent reads.
"""
import json
import subprocess
import sys


def banner(label: str) -> None:
    print(f"\n--- {label} ---", flush=True)


# --- Step 1: intercept ---
banner("Fetching secrets via vault CLI (intercept mode)")

result = subprocess.run(
    ["mock-vault"],
    capture_output=True,
    text=True,
    check=True,
)
vault_output = json.loads(result.stdout)

print("Agent sees (placeholders, not real values):")
print(json.dumps(vault_output, indent=2))

password_token = next(
    item["value"] for item in vault_output if item["key"] == "login-password"
)
if not password_token.startswith("firma-secret://"):
    print(f"[fail] expected a placeholder, got: {password_token!r}", file=sys.stderr)
    sys.exit(1)

print(f"\nToken for login-password: {password_token!r}")


# --- Step 2: redact ---
banner("Calling MCP tool with placeholder (redact mode)")

msgs = [
    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                           "clientInfo": {"name": "demo-agent"}}}),
    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized",
                "params": {}}),
    json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "type_password",
                           "arguments": {"value": password_token}}}),
]

proc = subprocess.Popen(
    ["mock-mcp-server"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    text=True,
)
proc.stdin.write("\n".join(msgs) + "\n")
proc.stdin.close()
raw_output = proc.stdout.read()
proc.wait()

print("Messages sent (broker rehydrates placeholders on mock-mcp-server's stdin):")
for msg in msgs:
    print(f"  {msg}")

print("\nResponses received (broker masks any real secret back to placeholder):")
for line in raw_output.splitlines():
    if not line.strip():
        continue
    print(f"  {line}")
    parsed = json.loads(line)
    for item in parsed.get("result", {}).get("content", []):
        text = item.get("text", "")
        if text and "firma-secret://" not in text:
            print(f"\n[fail] response contains an unmasked value: {text!r}", file=sys.stderr)
            sys.exit(1)

print("\nDemo complete — agent handled only placeholders throughout.", flush=True)
