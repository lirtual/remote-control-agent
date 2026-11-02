# #661 — macOS ARM64 / Intel x64 candidate evidence

This is the **source/CI candidate** for both native Mac architectures.
The exact reviewed Node.js v24.21.0 binary, native Mach-O Supervisor, Git
commit, immutable archive checksum and expected CPU must match in each
macOS 15+ job. The same runtime, Operation Receipt and private LaunchAgent
code is reused. No Rosetta, host Node, runtime compiler, new Worker or
separate release flow is permitted.

Native GitHub-hosted macOS 15 ARM64 and macos-15-intel jobs test binary
architectures, deterministic packaging, unpacked signed-WSS adapter, native
file and SQLite effects, bounded Sessions, unrelated-process isolation,
stop/timeout/revocation, local upgrade freeze and synthetic failure rollback.

**Hosted CI is not a real owner Mac.** Before promoting either architecture
to supported status, record *independent owner-approved host* evidence for
each architecture separately:

- OS version, physical CPU, checked-in Agent commit and full candidate SHA-256,
  exact Node and helper Mach-O architecture; confirm no translation.
- Owner-terminal explicit permanent and temporary pairing, fingerprint,
  device ID continuity, signed WSS initial connection and recovery after
  logout/login and sleep/wake; server-enforced temporary 24-hour expiry
  and revocation.
- Real file read/write/append/rewrite/search, APFS case-sensitive and
  case-insensitive volumes, symlinks, protected folders, TCC denial and
  Terminal vs genuine LaunchAgent permission differences.
- Owned Session spawn/input/output/termination, deadline, descendants,
  unrelated PID preservation, uncertain result no-blind-replay and durable
  SQLite receipts across restart.
- Owner-confirmed offline upgrade while idle, denial while busy, deliberately
  stopped state, failed activation recovery preserving Ed25519 key/device ID,
  past Unknown receipts and prior version.
- Unsigned/unnotarized first launch under Gatekeeper: owner's Apple-supported
  manual permission for the exact trusted executable, or explicitly Blocked.
  Never remove quarantine or modify Gatekeeper/TCC for the user.

For missing genuine devices, mark the relevant fields **Not performed** and
leave the relevant tickets open. Linux x64/ARM64 and Windows x64 existing
CI remain mandatory. Formal immutable five-asset GitHub Release, production
Worker installer and after-release real-host verification belong to #662
and require separate production authorization.
