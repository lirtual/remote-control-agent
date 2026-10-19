# Native Windows preview (development only)

This is the **first Windows-native, foreground-only** implementation, not a
released Windows installer. It does not use WSL2, install a service, update
existing Linux devices or grant remote Shell/file writes.

## Developer smoke (Windows 11 x64, Node.js 24 and an approved HTTPS Worker)

From a reviewed clone of this repository, run in **Windows PowerShell as your
normal user**, not Administrator/SYSTEM:

```powershell
cd apps/remote-control-agent
node --experimental-strip-types src/windows-v2.ts pair --endpoint https://rca.lirtual.dpdns.org/
```

The terminal shows one 10-character code. In the authenticated Remote Control
MCP, check it using `pairing_lookup`, then approve the reviewed fingerprint
with `pairing_approve`. The terminal does not ask for a second challenge.

```powershell
node --experimental-strip-types src/windows-v2.ts run --endpoint https://rca.lirtual.dpdns.org/
```

The WSS connection stays online only while this foreground process runs. A
normal Ctrl+C disconnects it. The separate native Windows device has its own
key and device ID (not the WSL2 identity). To view local metadata without
connecting:

```powershell
node --experimental-strip-types src/windows-v2.ts status
```

The private key lives under `%LOCALAPPDATA%\mcp-workers\remote-control`.
The Windows PowerShell ACL helper initializes two protected directories,
permits only the current user's SID and SYSTEM, and checks existing key and
device-ID ACLs. Existing identities are never overwritten or rotated by
pairing. Do not share the PEM file, modify ACLs or put secrets in the CLI.

For native Windows file operations use drive-absolute paths such as
`C:\Users\...`. UNC shares, Windows device namespaces, drive-relative
paths, ADS and URL schemes are rejected. This preview enables only the
existing bounded read/list/search tools; writes and Shell remain disabled.

## Unpublished portable candidate

The Windows CI constructs an offline preview containing `bin/node.exe`, the reviewed
JS runtime, protected identity ACL helper, and a convenient `rca.cmd` launcher.
In a reviewed/unpacked candidate directory, `.ca.cmd status` works
without system-wide Node, Git or npm. `.ca.cmd pair --endpoint HTTPS_ORIGIN/`
and `.ca.cmd run --endpoint HTTPS_ORIGIN/` are **foreground-only**
development commands. The CI reopens the ZIP, verifies its file inventory
and runs the bundled manager. No public Windows Release exists yet.

## Still to implement before production

- Immutable Windows x64 bundled-Node Release and SHA-256 verified one-command
  PowerShell bootstrap without prerequisites.
- Protected per-user background lifecycle, service manager, and native `rca`
  status/re-pair/logs/upgrade/rollback/uninstall (without revoking cloud grant).
- Real Windows 11 explicit-device signed WSS / read-only MCP acceptance.
  Windows CI can run synthetic ACL/path and protocol tests, but does not prove
  live pairing, production reliability, or service persistence.

This preview must not be described as a completed Windows rollout.
