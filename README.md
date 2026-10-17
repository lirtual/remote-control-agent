# Remote Control Agent

Standalone **Linux/WSL2** Remote Control Agent source (x86_64 and ARM64 target).

This repository is the **public Agent source and future GitHub Release origin** for `lirtual/mcp-workers`, whose Cloudflare MCP Worker, owner-scoped Durable Object, Portal authentication and production configuration remain private. The Agent connects outbound over signed Ed25519 WSS after explicit owner MCP approval and independent confirmation in its own terminal.

**Current status: source migration preview only.** There is **no official published standalone release**, supported public one-line installer, or production rollout yet. Do not use fabricated download URLs or assume a private Worker deployment exists.

The `apps/remote-control-agent` source layout and the archive-internal paths are deliberately retained during the initial split to preserve the current versioned binary contract. This is not a second Worker or dependency on private Worker source. Initial development uses Node.js 24 and the native C helper; the future verified release is designed to bundle its own Node.js and native helper.

For signed onboarding, first choose permanent user-systemd or 24-hour temporary foreground mode. Installing does not automatically allow Shell/file writes; those capabilities require independent approval. Local uninstall does **not** revoke cloud grants.

Public repository does not include private Worker code, Cloudflare Secrets, device private keys, identity files, SQLite operation history, internal Preview-specific host scripts or private Git commit history.

Release publication, native ARM64 acceptance, clean-host x64/ARM64 integration, independent security review and actual one-device 48-hour observation remain gated.
