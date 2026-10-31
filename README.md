# Remote Control Agent

Standalone Remote Control Agent for Linux x64/ARM64 (including WSL2) and native Windows x64. The public repository contains the Agent and immutable Release archives. The Cloudflare MCP Worker and its owner-authorized pairing service live in `lirtual/mcp-workers`.

## Current verified release (2026-10-31)

The immutable **v0.1.40** Agent Release includes Linux x64/ARM64 and native
Windows x64 archives with SHA256SUMS. The Remote Control Worker serves
version-pinned public installers. One native Windows and two WSL2 permanently
paired devices were verified online on v0.1.40 with their original device
identities preserved.

Agent CI/Release publication, Worker deployment, device-local interactive
upgrades and authenticated device pairing are separate operations. Browser
Handoff (Spec #280) and MCP-initiated `upgrade_agent` were retired; existing
paired-device file, search, Shell, Session and receipt tools remain supported in production.

**Spec #628 delivered (2026-10-31):** RCA-owned Browser/Computer executable
tools and GUI-only bundles were retired in the formally released Worker and
Agent v0.1.40. Bundled Node.js 24, Windows Job Object, Linux pidfd, pairing,
receipts and local upgrade/rollback remain. Historical GUI receipts stay
readable but cannot be admitted or replayed as new effects. The independently
deployed Browser MCP #418 is unchanged. All three paired devices passed core
checks; separately authorized precise Windows GUI Profile/Grant/Stop cleanup
was verified. See [Spec #628 acceptance](https://github.com/lirtual/mcp-workers/issues/628#issuecomment-6542642703).

## One-command onboarding and local upgrades

The existing Remote Control Worker serves the public installers at
`https://rca.lirtual.dpdns.org/`. For a new device, the workflow is
**install → approve once through authenticated MCP → verify online**.

- Windows PowerShell: `irm https://rca.lirtual.dpdns.org/install.ps1 | iex`
- Linux x64/ARM64, including WSL2: `curl -fsSL https://rca.lirtual.dpdns.org/install.sh | sh`

The Linux one-liner is for interactive installation. POSIX `sh` reports the
last pipeline command's exit status: if `curl` fails before downloading any
script, the empty `sh` may still exit 0. Inspect download errors, and never
treat pipeline success as proof of installation, approval or online status;
confirm the device through authenticated MCP before declaring success.

As verified 2026-10-31, both production installers were pinned to reviewed
v0.1.40 source and immutable Release assets. A successful script download or
local install does not prove remote approval, connectivity or successful
upgrade; verify the signed device through authenticated MCP.

The CLI's two options are **永久** (user-logon task on Windows, systemd user unit
on Linux) and **临时** (foreground, with existing 24-hour cloud grant). Selection
requires a real TTY and an explicit key press; one authenticated MCP approval
is still mandatory. Running the public installer on a paired Windows device checks the existing
user-logon task and target version. If an upgrade is available, it asks for one
explicit confirmation, installs the SHA-256 verified new Release side by side,
and reuses the existing transactional `rca upgrade` switch. It never re-keys or
re-pairs the approved identity. A previously stopped Windows task remains
stopped; an active task is restarted only as part of the confirmed switch.
A cancelled or rejected upgrade leaves the old device untouched. A successful
local switch still requires an authenticated MCP online check. Local
installation, owner authorization and remote online state remain distinct.

Historical root `install.sh` and `install-windows.ps1` were removed from this repository; they were
not the canonical public installation URLs. Historical immutable Release tags
remain unchanged; upgrades are separate explicitly authorized operations.

## Installation and upgrades

The approved Worker serves immutable, SHA-256-verified Release assets. Use
its Linux installer from an ordinary user terminal:

```sh
curl -fsSL https://YOUR_APPROVED_WORKER/install.sh | sh
```

To upgrade an existing **permanently paired** Linux Agent to a newer pinned
release, use the same installer with an explicit upgrade option:

```sh
curl -fsSL https://YOUR_APPROVED_WORKER/install.sh | sh -s -- --upgrade
```

The currently installed signed-WSS service is upgraded **in place**.
Installations using the historical `remote-control-v2-agent.service`
filename retain that filename during upgrades; new installations use
`remote-control-agent.service`. No extra service-name migration, loopback
Agent, Cloudflare Tunnel, or separate `MIGRATE-REMOTE-CONTROL` prompt is
required. The service's display description, environment variable names and
actual binary refer to the current Agent.

Upgrades require an intact signed device identity, validated local service
template and verified newer Release. Active Agents must prove there are no
outstanding or uncertain operations via the local freeze handshake. If the
service is busy, has foreign systemd modifications, or state is uncertain,
the upgrade fails closed. Activation failure restores the prior unit, with
owner-private recovery evidence kept if rollback itself fails.

The published, Worker-pinned Agent supports the local direct-upgrade path.
Existing immutable Release assets are never changed retroactively. Verify
the same device ID, signed WSS/MCP connectivity, file and Shell tools, and
durable receipts after each locally approved upgrade. Do not stop an Agent
using the Shell of that same Agent.

## Native Windows x64 installation and upgrade

Run the single reviewed public installer in an interactive Windows PowerShell
terminal (not elevated, as the intended Windows user):

```powershell
irm https://rca.lirtual.dpdns.org/install.ps1 | iex
```

A new device follows one owner-approved pairing. When an existing paired
Windows Agent is found, the installer shows the old and new versions and asks
for a single explicit Yes/No choice (No is the safe default). After Yes, it
verifies the pinned immutable Release source and Windows archive checksums,
installs alongside older versions, and performs the transactional task switch.
For a healthy cloud grant, the original private key, device ID and task
running state are preserved. The installer also checks the signed cloud grant
before it exits. If the old grant has disappeared, it continues through the
existing same-key re-pair protocol and waits for **one explicit authenticated
MCP owner approval**, then requests the user's Windows task to start. This
does not implicitly approve a grant or rotate the private key.

`rca task-status` reports local task state, not authenticated online status.
Verify signed WebSocket connectivity separately through authenticated MCP.

RCA no longer supplies the retired Browser/Computer capabilities. Use the
separate Browser MCP for authorized Chrome/Edge automation;
RCA Shell permissions are unchanged.

### Recover a Windows grant that is missing from the production Worker

Use the **same one-line installer** above, including for a safe retry after
an interrupted owner approval. It verifies a fresh signed public-key grant.
A matching approved ID is kept unchanged; a different approved ID is
restored without a second owner approval. Only a confirmed missing grant
(HTTP 404) initiates pending re-pair with the original Ed25519 private key.

The terminal prints one pairing code and fingerprint for owner confirmation
through authenticated MCP `pairing_lookup` and `pairing_approve`. After
approval the Agent verifies the signed response, stages and seals the local
device ID with its protected Windows ACL, and requests task startup. No
manual `re-pair`, `start` or `task-status` sequence is needed for normal
recovery. If the task is explicitly stopped and its grant is still healthy,
the repeat installer leaves it stopped and does not silently restart it.

On 401/403, transient network failure, approval timeout or ACL conflict,
recovery fails closed and does not silently approve, rotate or delete an
identity. Actual online status and a harmless remote read must still be
confirmed with an authenticated MCP call. The explicit management commands
remain available for exceptional operator diagnostics.

## Platform and trust requirements

- Linux x64/ARM64 with glibc and supported kernel/pidfd process-group features; WSL2 can use the Linux Agent while the distribution is running. Native Windows x64 is supported by a separate reviewed package; macOS, WSL1 and musl are not supported.
- A non-root interactive terminal; the installer requires a real local TTY.
- A trusted HTTPS Worker origin with authorized owner-mediated pairing. No direct public Shell listener is created.
- Do not copy or paste device private keys, access tokens, or unredacted logs.
- `rca status` reports local state and does not independently prove remote signed-WSS connectivity. Verify that via authenticated MCP.
- Local uninstall preserves identity and SQLite receipts and **does not revoke** the remote grant. Revoke the device separately through authenticated MCP.

## File mutation reliability

`write_file(mode=rewrite)` remains an explicit overwrite, and `append`
retains its existing behavior. On verified Linux filesystems, creation in an owner-private
directory is staged and linked exclusively, preserving the normal new-file
permission mode and preventing partially visible new files. Existing files
retain their legacy in-place rewrite semantics: a private 0600 regular file
can still carry xattrs, ACLs, active external handles or inode observers that
cannot be safely detected with the current built-in APIs. Replacing its inode
would silently discard metadata or change those observers. Staging errors do not silently downgrade
to a second direct write. Symlinks, hardlinks, existing files (including files with open handles),
native Windows ACL/sharing cases and other unverified targets retain legacy
direct writing, including possible partial contents after interruption. This does not guarantee that every
external open handle or filesystem attribute is observable.

`replace_text` keeps UTF-8 and exact-count validation and rejects source
changes it can detect before write/commit. This is best-effort revalidation,
not cross-process compare-and-swap: external writers can still race the final
check, and an atomic rename is not a power-loss durability guarantee. A
pre-commit staging failure proven not to affect the target is reported as a
definite failure; an unconfirmed commit or legacy partial-write error remains
`unknown`, protected by the existing durable operation receipt. Staged
temporary files are operation-owned and cleaned up on normal exits where
safe; a crashed process can leave an orphan without proving target state.

## Release and verification

Use the existing Linux x64/ARM64 and native Windows x64 CI to validate each
candidate. Publish only through the established immutable, reviewed Release
pin workflow, then separately update the Worker's installer pins and deploy
through its existing manual workflow. A source commit, Release or Worker
rollout never updates installed devices; after an explicitly approved local
upgrade, verify the original device identity, signed connection, service/task
state and retained SQLite operation receipts.
