# Remote Control Agent

Standalone Remote Control Agent for Linux x64/ARM64 and Linux running under WSL2. The public repository contains the Agent and immutable Release archives. The Cloudflare MCP Worker and its owner-authorized pairing service live in `lirtual/mcp-workers`.

## Current Linux v2 release

Native Windows full-tools support is reviewed as a Draft branch, separate from published Linux releases. See [Windows preview notes](apps/remote-control-agent/docs/WINDOWS-PREVIEW.md).


The published immutable **v0.1.11** Agent enables file reads, file writes,
Shell and managed sessions for approved paired devices. It runs as the user's
systemd service and authenticates to the approved Worker over signed outbound
WSS. There are no per-feature switches and no need to pair again during an
approved version upgrade.

## Installation and upgrades

The approved Worker serves a pinned Release installer. Its GitHub assets are
SHA-256 verified before any bundled executable runs:

    curl -fsSL https://YOUR_APPROVED_WORKER/install.sh | sh

For an already-paired permanent installation, the existing one-time
read-only to full-tools migration uses an explicit flag:

    curl -fsSL https://YOUR_APPROVED_WORKER/install.sh | sh -s -- --upgrade

The next CLI revision adds **rca upgrade** without manually specifying a
tag or Git commit. It reads only the reviewed immutable Release metadata
from the device's already-configured Worker installer, then uses the existing
GitHub Release verifier, pinned SHA-256 checks, installer, and binary
activation/rollback. Fetched shell content is never executed by this CLI.

### One-time v0.1.11 -> next v2 version

The published v0.1.11 is already full-tools but has no in-process upgrade
handshake. **Only after a newer immutable Agent Release has been approved and
pinned by the Worker**, the owner can perform this single offline cutover from
the **ordinary WSL/Linux terminal**, in a maintenance window:

1. Finish all Remote Control Shell, file-writing, and other operations. The
   old Agent cannot prove quiescence; this is an explicit operator decision.
2. Stop **only the v2 Agent**: `systemctl --user stop remote-control-v2-agent.service`.
   Do not use Remote Control to initiate the stop: the connection will drop.
3. In the *same local terminal*, run the approved Worker installer:
   `curl -fsSL https://YOUR_APPROVED_WORKER/install.sh | sh -s -- --upgrade`.
   It requires service `inactive/dead`, PID 0, an unlocked/intact SQLite
   receipt store, exact old v0.1.11 program/identity ownership, and the
   interactive `OFFLINE-V2-UPGRADE` confirmation.
4. Check `rca version`, the local service, and signed MCP connectivity. The
   private identity and historical SQLite receipts remain in place.

If installation fails **before activation**, the old service may remain
stopped. Inspect it locally; after an explicit decision, it can be started
again using `systemctl --user start remote-control-v2-agent.service`.
An activation failure uses the existing durable systemd rollback to restore
the previous v2 unit. No operation is replayed by the installer.

Future full-tools v2 releases use the owner-local Unix-socket freeze instead:
new work is rejected after the freeze begins; active, starting or unknown work
blocks upgrade. No v1 compatibility layer or additional service is required.
The immutable v0.1.11 binary is unchanged by this source PR.

## Platform and trust requirements

- Linux x64/ARM64 with glibc and supported kernel/pidfd process-group features; WSL2 can use the Linux Agent while the distribution is running. Native Windows/macOS, WSL1 and musl are not covered by this release.
- A non-root interactive terminal; the installer requires a real local TTY.
- A trusted HTTPS Worker origin with authorized owner-mediated pairing. No direct public Shell listener is created.
- Do not copy or paste device private keys, access tokens, or unredacted logs.
- `rca status` reports local state and does not independently prove remote signed-WSS connectivity. Verify that via authenticated MCP.
- Local uninstall preserves identity and SQLite receipts and **does not revoke** the remote grant. Revoke the device separately through authenticated MCP.

## Next release checklist

1. Review the one-time offline v0.1.11 cutover and future in-process freeze.
2. Verify safe rejection, exact identity and receipt preservation, rollback,
   and native x64/ARM64 archive tests under existing Agent CI.
3. Only after source review and release approval, publish the immutable new
   version and update the existing Worker Release pin. No separate deployer.

A source PR and passing CI do not update the installed v0.1.11 Agent.
