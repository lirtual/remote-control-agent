# macOS Remote Control-only Upgrade — Spec #657

Status: **source candidate only**, no production release, Worker pin, or real Mac upgrade authorized by this change.

## User-visible contract

An owner-approved permanent Mac already connected to RCA may initiate an upgrade from a Remote Control `run_command` without typing in a local Terminal. The initiator uses the **public Worker-pinned HTTPS source**, with a future explicit `--remote-upgrade` action (not an unverified branch/checkout). The public script checks the exact architecture, SHA-256-pinned immutable Agent asset, reviewed `macos-local.sh` source and correct original Worker endpoint. The existing `--upgrade` remains interactive. Source merge/CI by itself does not make a remote upgrade executable on the installed `v0.1.49-rc.4`.

## One-shot dispatch

The verified new package's `macos-local.sh remote-upgrade` stages its reviewed bundle under a private per-operation directory, validates the already-permanent device's UID, owned LaunchAgent/CLI, approved identity, connection generation, endpoint, live LaunchAgent, original receipts, no intentional STOP, no unresolved switch journal and no existing remote operation. It creates an idempotency marker and dispatches exactly one **same-user `launchctl submit` job** running the bundled Node/manager from the durable stage, outside the managed Agent Shell. The launcher returns `status=launched` and the unique operation ID. It is not an upgrade-success receipt. Unknown dispatch state is not automatically retried.

The detached job requires the same owner UID, exact operation record and launchd job label with its own PID, with launchd as its parent, before allowing noninteractive confirmation. This does not weaken the ordinary terminal requirement. It reuses the current native manager's pin validation, active-work freeze, side-by-side candidate, signed WSS post-switch verification and rollback/Unknown behavior. No new pairing, cloud grant override, production data mutation or persistent updater is created.

A private per-operation result is either `connected_observed` or `needs_attention`; keep records for audit and check the new cloud device session, version, unchanged device ID, signed WSS, LaunchAgent and original SQLite receipts independently. The job is one-shot, but any abandoned/uncertain state remains blocked for explicit reconciliation. Do not manually delete pending locks, guess an outcome or replay old commands.

## Mandatory gates

1. Existing native macOS ARM64 and Intel hosted CI, plus Linux/Windows regression, must pass the exact Agent candidate. Include rejection of false launchd job PID/context, missing key, forged/expired approval, owner STOP, bad endpoint/source/OS, existing upgrade marker, duplicate operation, busy sessions and uncertain activate/rollback.
2. Release new native macOS Agent assets via the **existing protected Agent GitHub Actions** after separate owner authorization. Only after immutable SHA readback, update the **existing RCA Worker installer** to pin this Release and expose `--remote-upgrade`; Worker release needs separate production authorization.
3. For first hop, do **not** rely on the installed rc.4 CLI having a new switch. The future Worker-served, independently SHA-validated temporary bootstrap dispatches the one-shot launchd job using the newly published helper. The launch does not claim completion.
4. Only after approved real Mac execution, independently verify original identity, new version and signed WSS + SQLite receipts. Previously waived physical login/sleep/fault/Intel tests remain Waived; non-waived Gatekeeper/TCC/APFS negatives are not implied Pass.

Cross-platform precedent: `docs/remote-shell-upgrade.md` implements the same independent task principle using `systemd-run --user` (Linux) or one-shot same-user Scheduled Task (Windows). Mac uses launchd; no `upgrade_agent` MCP tool or additional long-lived service.
