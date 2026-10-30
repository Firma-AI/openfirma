---
title: Log in to Firma Team
description: Authorize the firma CLI for a Firma Team Workspace in the browser.
---

Run `firma login`. It connects to the Firma SaaS Control Plane at
`https://app.firma.ai`; to use another Control Plane, such as an on-premise
deployment, add `--control-plane-origin https://your-team-control-plane`.
The browser opens the Control Plane: sign in, choose a Workspace, and approve.
The browser hands a one-time code to the CLI's local listener; you can then
close the window. The CLI exchanges the code and confirms the login with one
Workspace request, then prints what to run next:
`firma run --agent <agent handle> -- <your agent command>`. Each Agent's handle
is on the Agents page of the Control Plane.

If the browser cannot reach a listener on this machine, for example over SSH,
add `--terminal-code`. The browser then shows the code: paste it into the
hidden prompt. Never put the code on the command line or share it. It works
once and expires ten minutes after you approve.

For a local development Control Plane, add `--development-loopback` and pass a
loopback HTTP origin with `--control-plane-origin`.
The CLI never prints its access token.

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
`firma logout`, then a fresh `firma login` with the same
`--control-plane-origin`; the CLI's error message prints that command.

Refresh retries reuse one memory-only UUID within the running process;
they do not provide recovery after a crash.

## Use a Firma Team Agent

`firma run --agent <handle> -- <command>` resolves the Agent with that handle in
the Workspace of the saved login, starts a run of it, and reports the
Agent's identity, profile, Policy Set and configuration generation with the
run and Sidecar identities. It then runs the command as that run: a
Sidecar started for it alone authenticates to the Authority the Control Plane
named with the run's runtime credential, and the run stays live on
the Control Plane while that Sidecar streams.

The report goes to stderr, leaving stdout to the wrapped command. Host backend
checks run before the start, using the same profile and environment as launch,
including `FIRMA_RUN_ALLOW_NON_STRUCTURAL` for a proxy-only backend.
Managed decisions use WAL delivery to the resolved Authority. The journal's
base path is `<state_dir>/audit.wal`, outside disposable run markers; Sidecar
configuration isolates runtime journals by run and retains old evidence.
Project runs keep their existing file-audit defaults.

The run uses the Agent's profile as configured on the Control Plane and
reads or writes nothing under a project `.firma/`. The Authority must be
reachable over `https` on another host, verified against the platform's
trusted roots, or over plain `http` on a loopback host. Each run renews the
saved login without the browser.

When the command ends, `firma run` stops the Sidecar and closes the run
on the Control Plane: `completed` when the command exits 0, `failed` when it
exits with another code or the run fails before it starts, and `cancelled` when
`firma run` is interrupted while the command runs, unless the workspace had
already stopped it. On macOS, and when `firma`
itself runs inside a WSL Linux distribution, `firma run` cannot tell an
interrupt from a signal the command sends itself, so there the outcome comes
from the exit code alone. `firma run` exits with the command's code; on
Linux and macOS, a command killed by a signal gives 128 plus the signal number.

The workspace can end a run while its command runs: the Agent is deleted, the
key that started the run expires, or the run loses contact with the Control
Plane for too long. The Sidecar learns of it at its next heartbeat, sent every
quarter of the run's inactivity window (75 seconds with the default 300), and
stops. `firma run` then sends the command SIGTERM, and SIGKILL if it still runs
60 seconds later; a Ctrl-C in between kills it at once. It restores the
terminal the command started from, prints why the run was stopped, closes it
as `failed` and exits 1 if the command exited 0.
The `Closed:` line on stderr shows the outcome the Control Plane recorded. The
close first renews the access token if it is about to expire. It makes at
most three attempts for transport failures or HTTP 408, 429, 500, 502, 503 and
504, honoring a delta-seconds `Retry-After` capped at 15 seconds (missing,
malformed or HTTP-date values use a one-second delay), so without an answer it
can take a couple of minutes. If it
fails, or Ctrl-C or SIGTERM stops the close request, the line reports it as
unconfirmed: the exit code stays the same and, if the run is still open,
it expires within its inactivity window. From the sandbox start on, Ctrl-C and
SIGTERM go to the command while it runs; after it, while the Sidecar stops (up
to 10 seconds), the sandbox is torn down and the token is renewed, `firma run`
ignores them, so a supervisor should allow that time before it kills `firma`.
Interrupting `firma run` before the sandbox starts stops it without a close, and
the run expires the same way.

The start is never retried, because each start creates a run and
returns its credential once: if it fails or its answer is lost, run the command
again; a run nobody holds the credential of expires. The only replay
follows a refused access token, which gets one immediate renewal, because the
Control Plane refuses a token before it starts anything. Closes get the same
one renewal, separate from their retry budget.

A managed run refuses an `https` Authority on a loopback host, whose
certificate would be checked against a local CA rather than the platform's
roots, and a plain `http` Authority on another host. Resolution snapshots the
active capability-signing public key; it does not distribute a live key set.
After rotating that key, restart managed runs so they resolve the new key. The
Authority's retiring-key grace period does not refresh running Sidecars.

The Control Plane supplies the Agent's profile and governance, so `--agent`
cannot be combined with any other `firma run` option or a `--config` on the command line; a
`FIRMA_CONFIG` in the environment is ignored. If the Control Plane no longer
renews the login, run `firma logout`, then the `firma login` command the
error message prints, which names the saved Control Plane.

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
