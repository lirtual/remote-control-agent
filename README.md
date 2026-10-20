# Remote Control Agent

Standalone Remote Control Agent for Linux x64/ARM64 and Linux running under WSL2. The public repository contains the Agent and immutable Release archives. The Cloudflare MCP Worker and its owner-authorized pairing service live in `lirtual/mcp-workers`.

## Current public release versus upcoming full-tools release

- **v0.1.8** is the most recent published immutable test prerelease. It has Linux x64/ARM64 archives, SHA256SUMS, and the reviewed **read-only** upgrade profile.
- The latest `main` source supports file read/write, search, Shell and managed sessions **after pairing**. It has not yet been published as a full-tools Release.
- **v0.1.9** is the proposed *candidate* tag for that full-tools source. The CI workflow can validate both native archives for this tag. A successful CI run is **not** a published GitHub Release and does not update the running Agent.

The Agent connects outward to its approved Worker over signed WSS. No per-feature `readOnly`, `writeFile`, or `shell` setup switches are needed for the full-tools profile. Operations run with the Agent's normal OS user privileges, not as root. Pairing/authorization, explicit device revocation, operation IDs and durable SQLite receipts remain required.

## Install and one-time read-only → full-tools upgrade

The Worker already offers a single installer endpoint whose contents are pinned to one **immutable** GitHub Release, checked against reviewed x64 and ARM64 SHA-256 digests, and whose Agent endpoint is derived from the Worker origin.

Once the full-tools Release has been published, its official asset digests independently verified, **and** the reviewed pin updated on the deployment serving `/install.sh`, use the *same* installer with an explicit upgrade flag:

```sh
curl -fsSL https://YOUR_APPROVED_WORKER/install.sh | sh -s -- --upgrade
```

This invokes the **new release's installer**, not the old local `rca upgrade` command. It is the migration path for already-paired permanent installations where the old CLI does not recognize the full-tools package.

An upgrade must fail closed unless the current installed runtime is the approved, installer-owned **read-only/no-Shell** profile. It preserves the existing Ed25519 key, device ID, approved Worker origin and SQLite receipts; there is **no re-pair** or cloud grant change. The procedure uses the existing systemd program switch, recoverable unit backup and local startup/rollback checks. Only the pinned new executable is installed.

**Do not run the upgrade command until the Worker's installer pin has actually been updated to the published full-tools Release.** Until that moment, `/install.sh` still serves v0.1.8. Do not replace the installer with an unpinned `main` script or bypass SHA-256 checks.

A second **full-tools → full-tools** in-place upgrade is deliberately blocked until a verifiable managed-session quiescence protocol exists. This avoids interrupting Shell processes or treating unknown receipts as completed. New installations and local read-only operations are unaffected.

## Platform and trust requirements

- Linux x64/ARM64 with glibc and supported kernel/pidfd process-group features; WSL2 can use the Linux Agent while the distribution is running. Native Windows/macOS, WSL1 and musl are not covered by this release.
- A non-root interactive terminal; the installer requires a real local TTY.
- A trusted HTTPS Worker origin with authorized owner-mediated pairing. No direct public Shell listener is created.
- Do not copy or paste device private keys, access tokens, or unredacted logs.
- `rca status` reports local state and does not independently prove remote signed-WSS connectivity. Verify that via authenticated MCP.
- Local uninstall preserves identity and SQLite receipts and **does not revoke** the remote grant. Revoke the device separately through authenticated MCP.

## Release gate for v0.1.9

1. Run **Agent CI** with `workflow_dispatch`, `release_tag=v0.1.9` on the reviewed exact `main` commit. Both x64 and ARM64 candidates must pass typecheck, native tests, self-contained bundle validation and the offline minimal-container check.
2. Independently check archive SHA-256 values, tag-to-commit resolution and signed/immutable GitHub Release metadata. Publish the official assets and `SHA256SUMS` only after review.
3. Update the Worker's `InstallReleasePin` with the **actual** immutable tag, peeled source commit and verified per-architecture digests; set `upgradeMode: "explicit-v1"`. Never use placeholders or an unreviewed `latest` fallback.
4. Smoke-test the approved `/install.sh --upgrade` on one already-paired *disposable read-only* installation. Confirm unchanged key, device ID, endpoint and SQLite receipts, and successful file-write, Shell, session and operation-status tools. Previously verified read-only functionality does not need blanket re-testing.
5. Roll out to additional devices only after that single real migration is confirmed.

Passing source CI or merging a PR does not perform any Release publication or production upgrade.
