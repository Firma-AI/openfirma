---
title: Secure Visual Studio Code
description: Run VS Code under firma run with an isolated project-local profile and a per-run code shim.
---

Visual Studio Code behaves more like a browser than a normal CLI. The desktop
app can open marketplace, sync, account, update, and GitHub endpoints.
Extensions can also make network requests and spawn local commands.

The built-in `vscode` profile is a compatibility profile for that shape. It
wraps the `code` launcher with a per-run shim, keeps the VS Code process
attached to `firma run`, and routes cooperative HTTP traffic through the
Sidecar.

## What the vscode profile does

| Concern                | Behavior                                                          |
| ---------------------- | ----------------------------------------------------------------- |
| Launch command         | Supports `firma run --profile vscode -- code .`                   |
| Process lifetime       | Forces `--wait` and `--new-window` through a runtime `code` shim  |
| VS Code state          | Persists user-data and extensions under `.firma/vscode/`          |
| Desktop runtime        | Uses a writable per-run `XDG_RUNTIME_DIR` for VS Code IPC         |
| Chromium inner sandbox | Disabled because `firma run` provides the outer sandbox boundary  |
| GitHub sign-in         | Prefers VS Code's device-code flow inside the isolated profile    |
| Mapping                | CONNECT rules for VS Code, marketplace, accounts, GitHub, Copilot |
| Sandbox CA trust store | system roots + firma-ca (`AppendSystemRoots`)                     |

The shim is created inside the per-run runtime directory. It is not installed
globally, does not replace `/usr/bin/code`, and only affects the current
`firma run` session.

VS Code user data and installed extensions persist next to the resolved config
under `.firma/vscode/user-data` and `.firma/vscode/extensions`. The per-run
runtime directory is still used for the shim, desktop IPC files, and other
process-local state.

## Step 1: Scaffold the config

```bash
firma config --profile vscode --posture dev
```

This selects the `vscode` mapping. The mapping is CONNECT-level in v1: VS Code
core services, marketplace hosts, Settings Sync, and Microsoft and GitHub
account or repository flows are classified as `communication.external.send`.
That includes GitHub.com, hosted GitHub Enterprise (`*.ghe.com`), and the
Google and Apple identity-provider hosts GitHub can use during sign-in.

GitHub Copilot works out of the box: the mapping covers the Copilot service
hosts (`*.githubcopilot.com` plus the plan-scoped
`*.individual.githubcopilot.com`, `*.business.githubcopilot.com`, and
`*.enterprise.githubcopilot.com`), so Copilot chat, completions, and telemetry
are classified without extra configuration. For other embedded agents, such as
OpenAI/Codex or Anthropic/Claude, add the matching extra mapping.

## Step 2: Run VS Code

```bash
firma run --config .firma/firma.toml --profile vscode -- code .
```

`firma run -- code .` also auto-selects the `vscode` profile because `code` is
an alias for the profile. Passing `--profile vscode` keeps scripts explicit.

The profile rejects VS Code arguments that would bypass the managed runtime
state, including `--reuse-window`, `--user-data-dir`, and `--extensions-dir`.
Use the default command shape above unless you are deliberately testing launch
behavior.

GitHub sign-in uses VS Code's device-code flow by default inside the isolated
profile. This avoids browser callback paths that can break across the sandbox
network namespace while still supporting GitHub.com, hosted GitHub Enterprise,
and GitHub social sign-in through Google or Apple.

## State Cleanup

To reset the isolated VS Code profile for a project, remove the project-local
state directory:

```bash
rm -rf .firma/vscode
```

This does not remove the host VS Code profile under `~/.config/Code` or host
extensions under `~/.vscode/extensions`.

## Sharp edges

- **Project-local state.** Accounts, extensions, Settings Sync state, and
  extension installs live under `.firma/vscode` for the resolved config. The
  state is intentionally separate from the host VS Code profile.
- **Linux desktop integration.** The profile passes through display-related
  environment, creates a writable per-run desktop runtime directory, and links
  the host Wayland and D-Bus sockets into it when present. This keeps VS Code's
  own IPC files writable without making the host runtime directory writable.
- **Chromium sandboxing.** The shim adds `--no-sandbox` for VS Code's inner
  Chromium sandbox on Linux. The bwrap backend remains the sandbox boundary.
- **Extensions are broad.** Extensions run with VS Code's permissions. Their
  network traffic is only covered when it uses the sandboxed process and
  reaches hosts covered by the mapping, extra selected mappings, or your added
  rules.
- **Idle adapter relays are closed.** On Linux bwrap, idle sandbox-to-Sidecar
  adapter relays are closed after two minutes so browser-style keep-alive
  sockets do not exhaust the local bridge during extension installs.
- **Integrated terminal commands are not governed in v1.** Network egress from
  terminal commands is still constrained by the backend boundary. Per-command
  local-exec decisions for integrated terminals depend on the separate command
  interception work.
- **Linux bwrap is the validated path.** macOS `vz` and Windows/WSL2 `wsl2`
  remain proxy-only compatibility backends unless you opt into a structural
  mode documented in [Wrap an agent with firma run](../firma-run/).

## What's next

- [Wrap an agent with firma run](../firma-run/) for backend guarantees and
  non-structural caveats.
- [Extend the action-class mapping](../extend-mapping/) when an extension needs
  another host.
- [Enable HTTPS MITM](../https-mitm/) if you need per-endpoint classification
  for a specific REST API.
