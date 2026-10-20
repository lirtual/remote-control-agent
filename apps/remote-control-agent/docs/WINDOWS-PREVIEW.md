# Native Windows preview (development only)

This is the **Windows-native read-only preview** implementation, not a
released Windows installer. It does not use WSL2, install a service, update
existing Linux devices or grant remote Shell/file writes. A limited per-user logon task is available in the source candidate; it does not provide a boot-time Windows service.

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

## Source-only Windows installation and user-logon task

The repository now contains `install-windows.ps1`. The normal mode requires
a **published immutable** GitHub Release and its official asset SHA-256
before downloading/extracting the reviewed Windows ZIP. It refuses unexpected
ZIP members, unreviewed files, modified checksums, reparse entries and
replacing an existing version. The installed runtime bundles Node.js; no
system Node or Git is needed for installed `rca.cmd`.

**No approved Windows Release has been published**, so this installer is not
yet a working public one-line installation URL. CI uses an isolated fixture
and test-only archive input, not a real Release or cloud pairing.

Once the user has approved the device's one pairing code, the reviewed
portable candidate supports:

```powershell
.\rca.cmd enable --endpoint https://rca.lirtual.dpdns.org/
.\rca.cmd task-status
.\rca.cmd start
.\rca.cmd stop
.\rca.cmd disable
```

`enable` recovers the approved device ID by signed proof when necessary; it
never approves a pending pairing automatically. The limited Task Scheduler
task starts **when that same Windows user logs in**, not at machine boot
before login. `disable` preserves the device's key, ID and cloud grant.
Local task state is not proof of live WSS connectivity. Real Windows user
task registration/restart/upgrade and remote reads still require field
acceptance.

## Still to implement before production

- Owner-authorized published immutable Windows x64 Release and a verified public
  one-line PowerShell entrypoint (source-only installer and offline CI tests exist).
- Real non-admin user logon-task acceptance, plus native `rca` logs,
  re-pair, upgrade/rollback/uninstall lifecycle and receipt preservation.
- Real Windows 11 explicit-device signed WSS / read-only MCP acceptance.
  Windows CI can run synthetic ACL/path and protocol tests, but does not prove
  live pairing, production reliability, or service persistence.

This preview must not be described as a completed Windows rollout.
