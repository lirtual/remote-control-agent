# Linux Agent — one-time canonical service cutover

Status (2026-10-24): **source implementation and isolated CI tests only; no canonical production cutover**. The installed WSL2 identity still connects through the existing `v0.1.11` signed-WSS Agent. Read-only host inspection confirmed the exact historical signed unit and separately active loopback, Tunnel and WSS units.

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

1. Identify all consumers of the old Cloudflare Tunnel **before retiring it**. Read-only Cloudflare review on 2026-10-24 found the Tunnel healthy with four active connections; the two accessible account Zones had no CNAME pointing to its Tunnel ID, but the API returned no ingress configuration. This does not establish that the Tunnel is unused. Keep the loopback Agent and Tunnel unchanged until the consumer audit is conclusive.
2. On a genuine WSL2 terminal, complete the **one-time offline upgrade of the signed WSS Agent from `v0.1.11` to the currently reviewed Worker-pinned stable Release**. The bound Worker pinned `v0.1.20` when inspected on 2026-10-24; re-check it immediately before proceeding. That immutable Release's Linux installer implements the `v0.1.11` offline confirmation (`OFFLINE-V2-UPGRADE`) and preserves the old `remote-control-v2-agent.service` unit name. Stop this signed WSS service **from the WSL2 terminal**, confirm pending Shell work has completed, and run the reviewed owner-local `rca upgrade`; never initiate stop/upgrade over its own MCP session. The immutable `v0.1.12` bundle has also been independently hash-verified and staged, but it is **not a mandatory intermediate hop** if the current reviewed pin supports the direct offline path.
3. After independently verifying the upgraded WSS Agent reconnects under the **same device ID** and preserves receipts, review and publish a **newer immutable Release containing this canonical migration utility**, then update the Worker Release pin through the normal GitHub Actions process. A pre-cutover Release such as `v0.1.20` does not include this migration utility.
4. Validate local archive staging, the exact installed unit templates, failure-injection rollback and interrupted migration recovery in isolated environments.
5. From the ordinary WSL2 terminal, finish outstanding work and stop the upgraded signed-WSS Agent, old loopback Agent and Tunnel **only when all Tunnel consumers have been identified and the cutover is authorized**. Do **not** stop the Agent over Remote Control because its authenticated WSS channel terminates.
6. Run the verified Worker `install.sh --upgrade` **only once the newer reviewed Release is pinned**. It enters the owner-local migration program for the exact old collision and requests `MIGRATE-REMOTE-CONTROL` on the local terminal. Any mismatch fails closed rather than overwriting a foreign service.
7. Confirm `remote-control-agent.service` is active with the correct immutable executable, the old unit names and Tunnel are disabled, the **original exact device ID** reconnects, read-only MCP operation succeeds, and earlier receipts remain queryable. If the signed-WSS upgrade in step 2 or canonical cutover in step 6 fails, use only the documented owner-local rollback path and preserve all private backup evidence.
8. Keep the private backups until the cutover has been independently accepted. Do not remove the old Cloudflare tunnel/DNS or source history automatically.

The bundled migration program also offers `--rollback` for **owner-local offline** recovery after all three named units have been stopped. It never revokes the existing device grant, resets keys or replays earlier Shell operations.

## Non-goals

This is **not** an automatic service conversion by merging a PR or deploying a Worker. A source-only test pass does not install, publish, stop any WSL2 process, create or revoke devices, modify Tunnel credentials or authorize a production release. Unrelated Windows Agent installations and all other Linux services are unaffected.
