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
