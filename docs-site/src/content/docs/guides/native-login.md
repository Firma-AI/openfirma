---
title: Log in to Firma Team
description: Authorize the firma CLI for a Firma Team Workspace in the browser.
---

Run `firma login --control-plane-origin https://your-team-control-plane`.
The browser opens the Control Plane: sign in, choose a Workspace, and approve.
The browser hands a one-time code to the CLI's local listener; you can then
close the window. The CLI exchanges the code and confirms the login with one
Workspace request.

If the browser cannot reach a listener on this machine, for example over SSH,
add `--terminal-code`. The browser then shows the code: paste it into the
hidden prompt. Never put the code on the command line or share it. It works
once and expires ten minutes after you approve.

For a local development Control Plane, add `--development-loopback` and use a
loopback HTTP origin. The CLI never prints its access token.

A successful login is saved on this machine: the Control Plane origin, the
Workspace and the Membership, in `connection.json` under the `firma` folder of
your user configuration directory (`~/.config/firma` on Linux,
`~/Library/Application Support/firma` on macOS, `%APPDATA%\firma` on
Windows; set `FIRMA_CONNECTION_DIR` to choose another absolute path).

On Linux and macOS, login requests a renewable credential and saves it in the
operating system credential store. If that store is unavailable, login fails
unless you explicitly add `--allow-plaintext-refresh-token`, which permits a
private `0600` file. Windows currently saves an access-only connection.

One machine holds one connection. Login refuses an existing saved connection;
run `firma logout` before logging in again. If the initial save fails, the CLI
reports an error without attempting compensating revocation. The unused newly
issued credential is allowed to expire on the server.

`firma logout` attempts to revoke the renewable credential on the Control Plane,
then removes the local connection even if reading or revoking the credential
failed. If remote revocation is not confirmed, the CLI warns that the remote
family may remain valid until expiry; a local removal failure is an error.
If login or process termination leaves credential state uncertain, run
`firma logout`, then a fresh `firma login`.

Refresh retries reuse one memory-only UUID within the running process;
they do not provide recovery after a crash.

With the Linux bubblewrap backend, `firma run` hides the host connection
directory from the sandboxed command, including a custom location or one
selected through `XDG_CONFIG_HOME`.
Choose a separate directory from paths the sandbox needs for its own runtime
or protected application state; a conflicting path causes the run to fail.
If no connection was saved, logout reports that fact without creating a
configuration directory. If login or logout warns that an old credential may
remain, inspect the operating system credential store for the `firma` service.
If it warns that the local change may not survive a crash, repeat the command
after the machine restarts.
