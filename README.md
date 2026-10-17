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

**No production cutover** is implied by this public prerelease.
