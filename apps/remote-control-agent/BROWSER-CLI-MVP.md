# Trusted-device browser CLI adapter — source-only PoC

Status: **Draft implementation, not shipped, no new MCP/browser tools advertised** (2026-10-20).

## Why this exists

The owner chose to narrow phase one to personal already-paired Windows/WSL devices. Existing Remote Control authenticates and routes to the Agent; the browser automation implementation should leverage **one** mature CLI, not build MXC/WFP/proxy + CDP infrastructure before ordinary browser workflows work.

A real paired Windows side-by-side PoC (recorded in [mcp-workers PR #117](https://github.com/lirtual/mcp-workers/pull/117)) confirmed that `agent-browser@0.39.1` and `@playwright/cli@0.1.22` both open normal pages, capture Snapshot refs, fill/click TodoMVC, close sessions, and release tagged Chrome processes. The first integration candidate is **agent-browser** only. This file documents the initial `src/browser-cli.ts` adaptation.

## Deliberately small boundary

- One named local browser session and one dedicated automation Profile beneath the existing Agent-private data directory.
- Internal methods: `start`, `status`, `navigate`, `snapshot`, `close`.
- The browser CLI runs via absolute Node executable and a trusted absolute package entrypoint (and optionally a configured absolute Chrome executable) using `execFile(shell:false)`; caller arguments cannot select CLI binaries, profiles, arbitrary CLI flags, JS, CDP, Shell, or scripts.
- No external action methods (`click`, `fill`, `submit`, `upload`) are published. Snapshot output is capped at 8,000 characters. The adapter does not log page text by default.
- A single in-process action at a time; a failed/unknown navigation remains blocked from automatic replay and requires explicitly closing the uncertain session. Successful close preserves the automation Profile.
- Normal idle eligibility is 30 minutes. Unclean process crashes and failed/uncertain close are **not** presented as verified cleanup.

## Threat and scope limitations

This is **not** an OS sandbox or production SSRF barrier; local/internal URL hygiene checks cannot protect against DNS resolution changes, redirects, service workers, WebSockets, subresources or already-authorized Agent Shell networking. No guaranteed per-site low-impact classifier or exact one-use high-impact user confirmation exists yet. Therefore this adapter is **not wired to WSS/Worker, not enabled, not automatically installed**; do not infer that full browsing can be safely shipped merely because CLI unit tests pass.

Future wiring must use the existing authenticated Worker→Agent tool/receipt boundary and a narrow explicit MCP contract; effectful navigation must have a durable operation ID and unknown-effect reconciliation. Any website changes require verifiably scoped user approval or remain disabled. Never turn the `runnerForTests` seam into an end-user / remote argument.

Before release: exact-pin and provenance-check the `agent-browser` package/native platform binary; provide an explicit secure setup path (no arbitrary PATH fallback or auto-download during a tool call); test genuine bundled Windows startup/reconnect/cleanup, WSS dispatch timeouts, structured errors, page output confidentiality, and profile ownership. The installed Agent is unchanged by this Draft.

Strict MXC/WFP/browser-wide hostile-egress P0 remains **DEFERRED/UNVERIFIED** and applies only to a future separately scoped untrusted-execution product, not this trusted-device first phase.

## Tests

```sh
pnpm --filter remote-control-agent typecheck
node --experimental-strip-types --test apps/remote-control-agent/tests/browser-cli.test.ts
pnpm --filter remote-control-agent test
```

The isolated mock runner tests cover explicit profile and session argument shape, stale IDs, bad URL refusal, output caps, uncertain-effect non-replay, recoverable failed startup, concurrency, and absence of generic command/effect tools. These tests are **not** a substitute for future real packaged browser and MCP end-to-end tests.

## Live Windows adapter smoke (2026-10-20)

Through the existing authorized Remote Control Shell on paired native Windows device `71b4b4d8-6496-4898-9b80-1ea3a03f6ccd`, staged this exact Draft source and `agent-browser@0.39.1` inside a disposable user Temp tree. Used the installed Node v24 and Chrome executable, *with a separate temporary automation Profile*; did not attach a personal profile or install a production Agent dependency.

- `BrowserCliAdapter.start()` — **PASS**.
- `navigate()` to `https://demo.playwright.dev/todomvc/` — **PASS**.
- `snapshot()` — **PASS**, 175 characters, expected TodoMVC textbox present, no truncation.
- `close()` — **PASS**.
- Tagged Chrome process count two seconds after close — **0**.
- Removed the exact disposable source, CLI package and Profile tree; subsequent check `TEMP_REMAINS=False`, `TAGGED_PROCESS_COUNT=0`.

This is a **real direct Windows adapter-level smoke**, not ChatGPT→MCP→Worker→Agent browser-tool acceptance. No browser tool was registered or deployed. The existing browser-wide hostile-egress and verified one-use consequential-action consent gates remain untested/unpassed.

## Authenticated transport + durable receipt stage (2026-10-20)

Source now includes a **staged, explicitly injected** BrowserOperationGateway in the existing Agent execution engine and signed WSS dispatcher. Browser mutations (`browser_start`, `browser_navigate`, `browser_close`) use the **same SQLite ReceiptStore** and existing `get_operation_status`; fast `running` acknowledgement keeps the current 5-second Durable Object request budget. Duplicate same-ID requests never replay the underlying browser action, and lost/failed effects remain `unknown`. Read requests (`browser_status`, bounded `browser_snapshot`) use the same authenticated device WSS read mechanism; arbitrary CLI/JS/CDP args are rejected. Device revocation tries to close the owned browser session and truthfully reports `uncertain` if cleanup cannot be established. No extra D1 table, Worker, approval service or async queue.

**Activation deliberately missing:** production `maintainAuthenticatedDeviceSession()` is not passed a browser implementation or installed CLI by default. Worker MCP browser tool advertising/calling remains disabled. These stage files MUST NOT be described as currently usable on installed devices. In isolation, the Agent WSS+receipt tests passed and an integrated internal Worker Durable Object ↔ signed socket ↔ Agent test passed, using a fake browser driver. The actual Windows adapter smoke was separately proven, but no shipped end-to-end browser tool acceptance exists.

**Known gating risks:** native binary pin/provenance and distribution, platform-specific installed Agent runtime acceptance, restart/unknown browser ownership, abnormal/idle process cleanup, prompt-injected page navigation and high-impact exact-action owner consent. The existing low-level URL hygiene is not OS enforced network isolation; strict hostile-execution egress remains deferred/unverified. Do not enable browser tools until the real packaged Windows path has been audited.
