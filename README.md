# Remote Control Agent

Standalone Remote Control Agent for Linux x64/ARM64 and Linux running under WSL2. The public repository contains the Agent and immutable Release archives. The Cloudflare MCP Worker and its owner-authorized pairing service live in `lirtual/mcp-workers`.

## Current Linux v2 release

Native Windows x64 full-tools and the pinned Playwright browser runtime are packaged separately from the Linux Agent. Publication requires a reviewed, single-file approval commit on `main` after Agent CI succeeds. Merging source does not install, upgrade or re-pair any device.


The published immutable **v0.1.11** Agent enables file reads, file writes,
Shell and managed sessions for approved paired devices. It runs as the user's
systemd service and authenticates to the approved Worker over signed outbound
WSS. There are no per-feature switches and no need to pair again during an
approved version upgrade.

## New one-command onboarding (Spec #24 · source under review)

The canonical public entry point is intended to be `https://rca.lirtual.dpdns.org/`,
served by the existing Remote Control Worker. It will display the OS-specific
commands and the three steps: **install → approve once through authenticated
Remote Control MCP → verify online through authenticated MCP**.

- Windows PowerShell: `irm https://rca.lirtual.dpdns.org/install.ps1 | iex`
- Linux x64/ARM64, including WSL2: `curl -fsSL https://rca.lirtual.dpdns.org/install.sh | sh`

The Linux one-liner is for interactive installation. POSIX `sh` reports the
last pipeline command's exit status: if `curl` fails before downloading any
script, the empty `sh` may still exit 0. Inspect download errors, and never
treat pipeline success as proof of installation, approval or online status;
confirm the device through authenticated MCP before declaring success.

**These commands describe the proposed public contract, not a claim of working
production onboarding.** The new Windows bootstrap requires a reviewed, immutable
Windows Release that contains the `onboard` CLI, a separately checked source
commit, source-script SHA-256 and official ZIP SHA-256. Until those artifacts are
published and explicitly pinned by the Worker, `/install.ps1` returns HTTP 503.
The landing page and updated Linux script also require a separately authorized
Worker deployment. Merely merging an Agent PR does not install, deploy, update,
or pair anything.

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

Historical root `install.sh` and `install-windows.ps1` have been removed from this branch; they were
not the canonical public installation URLs. Historical immutable Release tags
remain unchanged; upgrades are separate explicitly authorized operations.

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

Browser actions require owner authorization. HTTP redirection and private
network/SSRF egress isolation are not guaranteed; use the browser capability
only on an approved trusted personal Windows device.

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
3. After the reviewed three-platform candidate CI succeeds, commit one exact
   `.github/release-pins/<tag>.json` on `main`. GitHub Actions automatically
   publishes that pinned Release after verifying source, artifacts and SHA-256.
   Ordinary source pushes do not publish Releases; existing pins can also be
   dispatched manually. The Worker Release pins and deployment remain separate.

A source PR and passing CI do not update the installed v0.1.11 Agent.
