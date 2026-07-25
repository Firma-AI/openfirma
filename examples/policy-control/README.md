# Policy Control Example

Runs `firma control` against a local Authority, Sidecar, policy bundle, audit
file, fixture service, and deterministic agent.

## Run

From the repository root:

```bash
just policy-control
```

This starts the local stack, opens the Policy Control TUI, and starts agent
traffic in the background. Exiting the TUI stops the stack.

Background traffic writes its trace to `.firma/state/traffic.log`. To run the
same traffic in the foreground:

```bash
cd examples/policy-control
just agent operations
```

The operations workflow runs 30 local calls. Each call reaches the fixture
service through the Sidecar, is classified by mapping rules, and appears in the
audit stream with an allow or deny decision.

Press `h` in the TUI for key bindings.

For lower-level debugging, run the lifecycle recipes directly:

```bash
cd examples/policy-control
just start
just control
just agent operations
just stop
```

Agent traffic:

- `just agent operations`: run the operations workflow once

Runtime files are written under `.firma/state/` and are ignored by git.
