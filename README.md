# Remote Control Agent

Standalone Remote Control Agent for Linux x64/ARM64 and Linux running under WSL2. The public repository contains the Agent and immutable Release archives. The Cloudflare MCP Worker and its owner-authorized pairing service live in `lirtual/mcp-workers`.

## Current Linux v2 release

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

**Important:** v0.1.11 is already full-tools but has no in-process upgrade
handshake. This Draft adds an owner-local Unix socket to future Agent releases:
an upgrade first freezes new file/Shell admissions and verifies that no task is
running, starting or uncertain. Active tasks reject the upgrade without being
terminated. If the installer cannot prove quiescence, it fails closed; a
definitive local activation failure still rolls back the owned systemd unit.

An installed v0.1.11 cannot retroactively provide that handshake. Therefore
a direct unattended/in-place v0.1.11 -> newer full-tools upgrade is **not**
authorized by this PR: a separately reviewed one-time owner-controlled
transition is still necessary. No v1 compatibility or coexisting v1 service
is supported. The proposed code is not part of the immutable v0.1.11 binary.

## Platform and trust requirements

- Linux x64/ARM64 with glibc and supported kernel/pidfd process-group features; WSL2 can use the Linux Agent while the distribution is running. Native Windows/macOS, WSL1 and musl are not covered by this release.
- A non-root interactive terminal; the installer requires a real local TTY.
- A trusted HTTPS Worker origin with authorized owner-mediated pairing. No direct public Shell listener is created.
- Do not copy or paste device private keys, access tokens, or unredacted logs.
- `rca status` reports local state and does not independently prove remote signed-WSS connectivity. Verify that via authenticated MCP.
- Local uninstall preserves identity and SQLite receipts and **does not revoke** the remote grant. Revoke the device separately through authenticated MCP.

## Next release checklist

1. Review and test the new CLI against the live reviewed Worker pin, including
   malformed/redirected responses and same-version no-op behavior.
2. Add a minimal authoritative quiescence check before permitting
   full-tools-to-full-tools service replacement.
3. Validate preserved identity/SQLite receipts and rollback using the existing
   native CI, then publish and pin the immutable Release through the established
   workflow. Do not change v1 services or grant authorizations.

A source PR and passing CI do not update the installed v0.1.11 Agent.
