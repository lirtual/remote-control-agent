# Linux Agent — one-time canonical service cutover

Status (2026-10-23): **source implementation and isolated CI tests only; no immutable new release or production cutover**. The installed WSL2 identity is still connected through the existing `v0.1.11` signed-WSS Agent.

## Stable target

- One canonical systemd unit: `remote-control-agent.service`; runtime configuration `REMOTE_CONTROL_AGENT_ENDPOINT` / `REMOTE_CONTROL_AGENT_KEY_PATH`
- Retain semantic Release versions `v0.1.x`, exactly the same Ed25519 identity, device ID, signed Cloudflare WSS grant and SQLite operation receipts
- Old loopback Agent and Tunnel services become inactive/disabled; the **Cloudflare tunnel resource and DNS records are not deleted** by this migration
- Protocol version numbers and signing domains remain unchanged. They are cryptographic contracts, not rollout flags

## Source mechanism

The immutable Release bootstrap stages and digest-verifies the new Linux Agent before any executable is run. **Only** an explicit local `--upgrade` with both expected historical unit headers is routed to the one-time `migrate-linux-service.mjs` utility.

The utility is constrained to the three named user units. It refuses root, remote/headless execution, missing local confirmation, wrong/modified service template, symlink, unowned unit, invalid device ID or key ownership, unexpected CPU, equal/older Release, compromised SQLite receipt store, systemd drop-ins, active service or unknown systemd state. A release verified against its published SHA-256 is still required before use.

An actual cutover requires all three services already `inactive/dead` with `MainPID=0`; the utility **never stops its own live Remote Control transport**. Once validated locally, it saves exact prior service files in `~/.local/share/mcp-workers/remote-control/cutover-backup/` under private permissions, records hashes and a journal, installs the canonical unit atomically, disables both old names, activates the new name and checks the local systemd result. The identity and receipt paths are never rewritten. A new signed-WSS connection and MCP read still require independent remote verification.

If new-service activation fails, the utility attempts to restore old files and restart the former signed-WSS/Tunnel services. An uncertain rollback preserves all private backup evidence rather than claiming success. After a crash, the owner must first stop **all three** services locally and may use the explicit `--rollback` action; it verifies journal hashes and the unchanged device identity before restoring. No unattended resurrection or automatic new pairing occurs.

## Real WSL2 cutover prerequisites

1. Identify and retire any remaining consumers of the old Cloudflare Tunnel (currently still has active connections). Do not infer it is unused merely because the ChatGPT MCP Portal uses the signed-WSS Worker.
2. Upgrade the installed **`v0.1.11 → v0.1.12`** from the real WSL2 terminal using the already-reviewed current Worker release. `v0.1.11` lacks the process-quiescence handshake, so remote stop/upgrade is unsafe.
3. Publish and independently review a **newer immutable Agent Release** containing this migration utility; update the Worker Release pin through the normal project GitHub Actions release procedure. The current pinned `v0.1.12` is not this release.
4. Validate local archive staging, the exact installed unit templates, failure-injection rollback and interrupted migration recovery in isolated environments.
5. From the ordinary WSL2 terminal, finish outstanding work; stop the existing signed-WSS Agent, old loopback Agent and Tunnel. Do **not** issue `systemctl stop` over Remote Control because the authenticated WSS channel terminates.
6. Run the verified Worker `install.sh --upgrade` **only once the newer reviewed Release is pinned**. It enters the owner-local migration program for the exact old collision and requests `MIGRATE-REMOTE-CONTROL` on the local terminal. Any mismatch fails closed rather than overwriting a foreign service.
7. Confirm `remote-control-agent.service` is active with the correct immutable executable, the old unit names and Tunnel are disabled, the **original exact device ID** reconnects, read-only MCP operation succeeds, and earlier receipts remain queryable.
8. Keep the private backups until the cutover has been independently accepted. Do not remove the old Cloudflare tunnel/DNS or source history automatically.

The bundled migration program also offers `--rollback` for **owner-local offline** recovery after all three named units have been stopped. It never revokes the existing device grant, resets keys or replays earlier Shell operations.

## Non-goals

This is **not** an automatic service conversion by merging a PR or deploying a Worker. A source-only test pass does not install, publish, stop any WSL2 process, create or revoke devices, modify Tunnel credentials or authorize a production release. Unrelated Windows Agent installations and all other Linux services are unaffected.
