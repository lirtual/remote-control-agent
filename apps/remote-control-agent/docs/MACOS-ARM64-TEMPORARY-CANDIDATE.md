# Unpublished macOS ARM64 temporary Agent candidate (mcp-workers#658)

This is a source/CI candidate, not an installer or supported Release.
It is limited to macOS 15+ Apple Silicon, an unprivileged interactive
owner, and Temporary (nonrenewable 24-hour cloud grant).
There is no LaunchAgent, permanent enrollment, native Managed Session
helper, Shell capability, GUI, auto-update or public macOS installer.

## Candidate evidence and trust boundary

The existing Agent CI macOS-15 ARM64 job builds this candidate on a native
runner with the official Node.js v24.21.0 darwin-arm64 archive; its SHA-256
is independently pinned in CI. The builder rejects ELF, FAT, wrong CPU
and non-native Node, validates the Node 24 runtime and assembles a private,
deterministic self-contained archive.

This is NOT an immutable GitHub Release nor an approved publisher signature.
The CI runner exercises unpacking, native Node startup, syntax, non-tty
refusal and file/receipt tests without creating a cloud grant.
Current Linux/Windows release pins and Worker distribution are unchanged.

## Future owner-controlled real Mac acceptance

Only after reviewing the candidate source commit and digest, safely extract
on an owner-controlled native Mac under a private, owner-owned directory.
No host Node/Python/Xcode/Homebrew required. From inside the archive:

    ./bin/node apps/remote-control-agent/src/macos-temporary.js --endpoint https://rca.lirtual.dpdns.org/

The CLI requires a real TTY, explicit 2 Temporary selection, and prints
one 10-character code and public-key fingerprint. The authenticated owner
must inspect and explicitly approve the Temporary key using existing RCA MCP.
Only successful signed device-ID recovery enables a signed WSS connection.
Ctrl+C disconnects the foreground Agent but does NOT revoke the cloud grant.
Resume a previously approved identity with --resume, never silently
create another grant or extend the server-side expiry. If the first pending
request failed or its 10-minute code expired before owner approval, use
`--retry-pairing` instead: explicitly select Temporary again and review
the new code and unchanged key fingerprint. Only use this while there is
no approved local device ID. The old pending code becomes invalid; an
approved/revoked identity conflict is denied, not rotated. If approval may
already have occurred, first attempt `--resume` so an approved key
is recovered without creating another pending request.

Key and SQLite receipt files stay in private owner-owned local directories.
If an unsigned candidate fails macOS Gatekeeper or TCC, record Blocked.
Never clear quarantine, disable Gatekeeper/TCC, escalate privilege or
simulate owner approval.

## Acceptance status

- Linux source file/WSS adapter and SQLite idempotency: existing tests pass.
- Darwin native ARM64 self-contained archive: macOS CI passed, including
  unpacked Mach-O Node, WSS file/receipt/Unknown smoke and deterministic digest.
- Personal Mac signed WSS, file/replay and SQLite receipts: Not performed.
- Real macOS TCC, APFS and security permission failures: Not performed.
- Intel Mac, owned Sessions, LaunchAgent, upgrades: later tickets.
- Formal immutable Release, Worker deployment, production grant: Not performed.

A hosted macOS CI runner is not an independently approved personal Mac.
Do not close Spec #657 or claim native macOS production support from CI.
