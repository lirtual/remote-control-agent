# #660–#661 — macOS ARM64 / Intel x64 offline permanent LaunchAgent candidate

This is **unpublished source/CI only**. It does not create a public macOS
installer, change the official Agent Release pin, deploy a Worker, or
demonstrate real personal Mac authorization.

The owner obtains an independently reviewed native darwin-arm64 or darwin-x64 candidate, its
exact SHA-256 and the reviewed Git commit. The local first-stage script in
scripts/macos-local.sh checks CPU, OS, real TTY, SHA-256 and strict USTAR
membership **before** executing the bundled Node 24 binary.

Reviewed local usage (not a published installation command):

    sh scripts/macos-local.sh install --archive /absolute/reviewed.tar.gz --sha256 REVIEWED_SHA256 --source-sha REVIEWED_COMMIT --endpoint https://trusted-owner-endpoint/

First installation requires an explicit owner-approved permanent pairing code.
The user-scoped LaunchAgent never enrolls or silently re-keys. Non-root Agent
state lives in private ~/.local/share/mcp-workers/remote-control; a login-scoped
LaunchAgent plist is in ~/Library/LaunchAgents. It cannot run while logged out
and must not claim to be online merely because launchctl is running.

For owner-approved upgrades, use the reviewed offline command with upgrade
instead of install. The old version is retained alongside the staged candidate;
the shared local upgrade socket freezes admissions only when there are no
in-flight operations or owned Managed Sessions. An owner-intentionally-stopped
service remains stopped. The switch journal and prior plist are retained until
new signed WSS generation has been observed. If activation/rollback cannot be
proved, the operation stays Blocked/Unknown; no re-pairing, automatic second
switch or replay of Unknown operations is permitted. Historical receipts remain.

The unsigned candidate may trigger Gatekeeper. No automated bypass, quarantine
removal, privilege escalation, TCC change, Full Disk Access or LaunchDaemon is
allowed. If macOS blocks the trusted executable, owner manual review through
Apple-supported UI (where supported) is separate; otherwise Blocked.

## Evidence boundaries

Hosted native macOS CI checks synthetic LaunchAgent/plist, candidate-package
integrity, stopped-state and rollback cases using mocked launchctl and cloud
connectivity. That is **not** a personal Mac Terminal/LaunchAgent, Gatekeeper,
TCC/APFS, login/logout/sleep, real owner pairing or live WSS upgrade test.
Mark those Not performed until real device evidence exists **per architecture**.
Intel x64 native hosted CI is covered by #661; this is not an Intel owner Mac.
Official five-asset Release and Worker installer route are #662 and require
separate production authorization.
