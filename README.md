# Remote Control Agent

Standalone **Linux/WSL2** Remote Control Agent for x86_64 and ARM64. This is the **public source and GitHub Release repository**; the Cloudflare MCP Worker, owner-scoped Durable Object, Portal authorization and production configuration stay in the private `lirtual/mcp-workers` repository.

## Published test prerelease

**[v0.1.0 — test prerelease](https://github.com/lirtual/remote-control-agent/releases/tag/v0.1.0)** is publicly available and **immutable**. It includes the native Linux x64 and ARM64 Agent archives plus `SHA256SUMS`. This is **not** a production Agent rollout, and it does not authorize or connect any device by itself.

- **Pinned source/tag:** `e82b90287374797ce20072ce18892055e4a17980`
- **Native CI:** [#38996153946](https://github.com/lirtual/remote-control-agent/actions/runs/38996153946), both architectures passed
- **Runtime:** self-contained verified official Node.js **24.21.0**, compiled native process-group Supervisor and reviewed JS entrypoints
- **Compatibility:** Linux glibc **2.34+**, kernel **6.9+** with the required pidfd process-group features; WSL2 when running. Native Windows/macOS, WSL1 and musl are unsupported
- **Preflight:** Python 3, curl, an approved nonproduction Worker HTTPS origin, and a **nonroot interactive terminal**. No system Node, npm, git or C compiler needed on the target

### Pinned first-install command for an approved nonproduction Worker

Run **only on an isolated, unpaired test host** after the Worker origin and owner approval are confirmed. Replace `https://APPROVED_PREVIEW_WORKER_ORIGIN/` with the real approved HTTPS origin; the placeholder is **not** a runnable endpoint.

```sh
bash -c 'set -eu; code=$(curl -fsSL --proto =https --tlsv1.2 "https://raw.githubusercontent.com/lirtual/remote-control-agent/e82b90287374797ce20072ce18892055e4a17980/apps/remote-control-agent/scripts/bootstrap-v2.py"); exec python3 -c "$code" --tag v0.1.0 --commit e82b90287374797ce20072ce18892055e4a17980 --endpoint https://APPROVED_PREVIEW_WORKER_ORIGIN/'
```

This intentionally pins both the public GitHub source and immutable Release, checks the **official GitHub asset digest** before installing, then prompts locally for Permanent (systemd) or Temporary (24-hour foreground) mode. A first pair must separately pass authenticated MCP `pairing_lookup` and `pairing_prepare` with owner approval plus a **12-character target-terminal challenge**. Initial capabilities are **read-only** by default; installer execution never enables Shell/file writes. Do not paste local keys, secret tokens or the 12-character challenge into public issues or logs.

The above command has passed a real public-GitHub download and staging smoke test on x64 using an isolated disposable HOME, an invalid mode choice and **zero device enrollments**. ARM64 native offline packaging and CLI refusal paths passed CI, but actual owner-confirmed enrollment, end-to-end lifecycle and the one-device **48 elapsed-hour** observation remain open: [release gate #1](https://github.com/lirtual/remote-control-agent/issues/1).

The source and archive retain `apps/remote-control-agent` layout for v2 compatibility while the private repository finishes staged migration. No private Git history, private Worker source, Cloudflare secrets, local device keys or SQLite receipt databases are included. Local uninstall does not revoke a cloud grant; cloud revocation is a separate owner MCP action.

### `rca` (Remote Control Agent) local manager — next unreleased version (Draft)

The optional **local Agent-management** command is under development; this is **not an AI chat tool** and has no direct permission to call remote Shell or bypass MCP owner approval. Existing **v0.1.0** remains the immutable published test version without this manager.

The next candidate **v0.1.1** will offer a short pinned GitHub installer (only **after** a separately authorized immutable GitHub Release is actually published):

```sh
curl -fsSL https://raw.githubusercontent.com/lirtual/remote-control-agent/v0.1.1/install.sh | sh
```

The version-tagged bootstrap checks the *published immutable* GitHub Release and peels the actual tag commit before fetching the exact reviewed Python bootstrap; the Python bootstrap independently checks the matching tag, official asset SHA-256, architecture/ABI, ownership and TTY before executing packaged Node. An actual user terminal is required for endpoint selection, mode choice and the independent 10+12-character pairing flow. There is no "latest" installation fallback.

After successful **permanent** install, only the installer's verified user-owned launcher is created at `~/.local/bin/rca`. The installer adds one Bash PATH line if a normal owned `~/.bashrc` is available, and offers to open the manager. If your current terminal has an old PATH, open a new terminal or run `export PATH="$HOME/.local/bin:$PATH"`.

```sh
rca             # local interactive menu
rca status      # local version/systemd; remote signed WSS unconfirmed
rca logs        # local journalctl; do not publicly share unredacted logs
rca pair        # explicit owner-mediated existing-identity repair
rca upgrade v0.1.1 <reviewed-40-character-commit>
rca uninstall   # local-only, explicit; cloud grant NOT revoked
```

The manager uses **existing** Agent lifecycle actions, never includes an account secret, refuses foreign `~/.local/bin` entries, and preserves keys/device IDs/SQLite receipts by default on uninstall. CLI status is not a remote-health attestation. Upgrade requires an explicit immutable tag and reviewed 40-character commit, and is restricted to the current read-only/no-Shell profile.

**Do not run the v0.1.1 installer yet:** it has no authorized published Release. This draft change does not modify the running `rc-v010-acceptance` v0.1.0 device, its ongoing 48-hour observation or v1 production.

**No production cutover** is implied by this public prerelease.
