---
title: Secure GitHub Copilot CLI
description: Wrap the GitHub Copilot CLI with firma run so its outbound calls are policed, using the built-in copilot profile.
---

The GitHub Copilot CLI is a coding agent like Codex or Claude Code, but it has two traits that need a dedicated profile rather than the generic `codex` one:

- It talks to **real GitHub hosts** (`github.com`, `api.github.com`) that you usually do not want to MITM, alongside the Copilot API hosts.
- Because it reaches non-intercepted hosts, the sandbox CA store must contain the **system roots in addition to firma-ca** — otherwise the agent hits `UnknownIssuer` on the real GitHub TLS.

The built-in `copilot` profile handles all three automatically. You opt in with `firma run --profile copilot` (or `firma run -- copilot`, which auto-selects it).

## What the copilot profile does

| Concern                | Generic profile        | Copilot profile                                               |
| ---------------------- | ---------------------- | ------------------------------------------------------------- |
| GitHub hosts           | intercepted / denied   | added to `https_mitm.bypass_hosts` (real upstream TLS)        |
| Sandbox CA trust store | firma-ca only (`Sole`) | system roots + firma-ca (`AppendSystemRoots`)                 |
| Auth                   | none                   | passes through `GITHUB_TOKEN`, `GH_TOKEN`, `GH_COPILOT_TOKEN` |

Copilot's **SQLite session store** under `~/.copilot/*.db` needs `unlink`/`rename` for journal cleanup. This works under any profile: the managed seccomp baseline no longer denies `filesystem.delete`, and deletes inside the read-write workspace and runtime home succeed while the read-only rootfs still blocks deletes elsewhere.

The CA-append behavior comes from the built-in profile, so you do not configure it by hand. `firma config --profile copilot` writes the matching mapping and the `https_mitm.bypass_hosts` entries.

## Step 1: Scaffold the config

```bash
firma config --profile copilot --posture dev
```

This selects the `copilot` mapping (CONNECT classification for the Copilot and GitHub hosts) and seeds `https_mitm.bypass_hosts` with `github.com`, `api.github.com`, and `uploads.github.com` so those hosts pass through untouched while firma-ca still covers any intercepted host.

The generated `firma.toml` keeps MITM enabled (the bypass list alone keeps `[sidecar.interceptor.https_mitm].enabled = true`) and lists `mappings/copilot.toml` under `rules_paths`.

## Step 2: Run Copilot

```bash
GITHUB_TOKEN=ghp_... \
firma run --config .firma/firma.toml --profile copilot -- copilot
```

`firma run -- copilot` auto-selects the profile from the command name, so `--profile copilot` is optional when you invoke the standalone `copilot` binary. The token is passed through to the sandboxed agent; the SQLite session store lives on the per-session runtime home and is not persisted to the host.

## Sharp edges

- **`gh copilot` vs `copilot`.** Auto-selection keys off the first command word. The standalone `copilot` binary is detected; the `gh copilot` extension is not (the command word is `gh`). For `gh copilot`, pass `--profile copilot` explicitly.
- **bwrap only.** The profile is validated on Linux `bwrap`. macOS `vz` and Windows/WSL2 `wsl2` are proxy-only compatibility backends and are not validated for Copilot.
- **CA append is opt-in.** Only the copilot profile sets `AppendSystemRoots`; every other profile keeps the `Sole` firma-ca trust store unchanged.

## What's next

- [Wrap an agent with firma run](../firma-run/) — the full runtime wrapper reference.
- [Secure a local coding agent](../secure-a-coding-agent/) — the same model for Claude Code and Codex.
- [Enable HTTPS MITM](../https-mitm/) — how interception and bypass interact.
