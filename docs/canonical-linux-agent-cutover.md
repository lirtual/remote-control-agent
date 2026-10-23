# Linux Agent — one-time canonical service cutover

Status: **Design / migration gate, not an executable production procedure.**
The source refactor is reviewed separately from the immutable Release and actual WSL2 activation.

## Target

- Exactly one managed Linux Agent unit: `remote-control-agent.service`.
- Exactly one outbound signed-WSS connection to the existing Worker and SQLite device coordinator.
- Stable `REMOTE_CONTROL_AGENT_ENDPOINT` and `REMOTE_CONTROL_AGENT_KEY_PATH` configuration names.
- Preserve Ed25519 private key, paired device ID, authorization grant, and existing SQLite operation receipts.
- Preserve semantic software Release versions (`v0.1.x`). Do not expose development-stage labels as current feature switches or service names.
- Retain protocol-version/domain-separation bytes needed to authenticate already-paired identities until an explicitly designed protocol migration; these are not feature flags.

## Current WSL2 deployment observed 2026-10-23

- Historical loopback `remote-control-agent.service` (active, disabled) and its `remote-control-tunnel.service` (active, enabled) are distinct from the signed-WSS Agent.
- The signed-WSS Agent is the existing `remote-control-v2-agent.service`, running the immutable `v0.1.11` Linux package.
- The production Portal uses the signed-WSS Worker; the old Cloudflare Tunnel still has active connections, so do **not** infer there are no other consumers from a lack of documented callers.
- The legacy unit currently **occupies the canonical target name**. Simply changing the source `UNIT` constant cannot migrate it.

## Hard prerequisites

1. Identify and explicitly retire any remaining inbound dependencies on the historical loopback/Tunnel. Confirm the tunnel serves no independent application before disabling it or removing its DNS/Cloudflare configuration.
2. Publish and independently verify a new immutable Agent Release implementing a **one-time transaction** for the old-unit-to-canonical-unit transition, with rollback and interrupted-switch recovery. Merely merging this PR is insufficient.
3. Exercise that transaction on an isolated systemd user manager, including service name collision, foreign unit owner, corrupted receipt database, active/uncertain Shell sessions, failed activation and simulated crash.
4. For installed `v0.1.11`, first complete the reviewed `v0.1.11 → v0.1.12` **owner-local, offline** upgrade as documented in the published README. Its Shell-enabled runtime lacks an authoritative in-process quiescence handshake.
5. Perform final service replacement only from a real WSL2 terminal, not by issuing a Remote Control command to stop its own WSS transport. Require a local confirmation, prove both old services are stopped, back up exact owned unit files and verify the private identity was not modified.
6. Install the verified canonical service; activate it, confirm exact executable, signed device reconnect, read-only MCP probe, session/receipt continuity and that no old service or Tunnel remains enabled. Retain exact backups until acceptance.
7. Roll back **only** under a documented local owner action: stop the new service, restore the prior verified unit(s), and restart the previous Agent as needed. Never re-pair silently, rotate the key, delete receipts or replay an uncertain external operation.

## Fail-closed behavior for this source PR

The new canonical installer treats the preexisting loopback `remote-control-agent.service` as **foreign**. Its ownership marker differs, so existing `readOwnedUnit` guards must reject it rather than overwrite or start a second competing Agent.

The source PR **does not** remove, stop or rename installed services, rewrite the user’s systemd units, publish an Agent package, update the Worker Release pin or mutate existing device grants. No automated migration/release should be inferred from its passing tests.
